//! In-process per-project change feed: an event bus plus the SSE endpoint.
//!
//! Delivery is strictly best-effort — the stream is a latency optimization
//! layered on top of delta sync (`GET .../issues/delta`). Subscribers that
//! fall behind get a `resync` signal instead of a replay, streams are capped
//! at the access-token lifetime (reconnecting re-checks permissions), and
//! clients advance their durable sync cursor only from delta/board responses,
//! never from events. Correctness must never depend on this stream.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use intellipilot_auth::ACCESS_TTL_SECS;
use intellipilot_core::backlog::{Epic, Issue};
use intellipilot_core::perms::Permission;
use serde_json::json;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::projects::ProjectContext;
use crate::state::AppState;

/// Per-project buffer; a subscriber this far behind is told to resync.
const CHANNEL_CAPACITY: usize = 256;
/// SSE comment heartbeat — keeps proxies from idling the stream out and lets
/// clients detect a dead connection by its absence.
const KEEP_ALIVE_SECS: u64 = 25;

/// One broadcast payload: pre-serialized JSON, shared across subscribers.
#[derive(Debug, Clone)]
pub struct ProjectEvent(Arc<String>);

impl ProjectEvent {
    /// The pre-serialized JSON payload broadcast to subscribers.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What happened to an issue.
#[derive(Debug, Clone, Copy)]
pub enum IssueEventKind {
    Created,
    Updated,
}

impl IssueEventKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "issue.created",
            Self::Updated => "issue.updated",
        }
    }
}

/// What happened to an epic. Mirrors [`IssueEventKind`].
#[derive(Debug, Clone, Copy)]
pub enum EpicEventKind {
    Created,
    Updated,
}

impl EpicEventKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "epic.created",
            Self::Updated => "epic.updated",
        }
    }
}

/// What happened to a comment. The payload carries only identifiers — the
/// comment body may be long and subscribers re-read the thread anyway.
#[derive(Debug, Clone, Copy)]
pub enum CommentEventKind {
    Created,
    Updated,
    Deleted,
}

impl CommentEventKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "comment.created",
            Self::Updated => "comment.updated",
            Self::Deleted => "comment.deleted",
        }
    }
}

/// Lazily-created per-project broadcast channels. A project's channel is
/// dropped when a publish finds it without subscribers.
#[derive(Debug, Default)]
pub struct EventBus {
    channels: Mutex<HashMap<Uuid, broadcast::Sender<ProjectEvent>>>,
}

impl EventBus {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, broadcast::Sender<ProjectEvent>>> {
        self.channels.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Subscribe to a project's change feed (creates the channel on demand).
    pub fn subscribe(&self, project_id: Uuid) -> broadcast::Receiver<ProjectEvent> {
        self.lock()
            .entry(project_id)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }

    fn publish(&self, project_id: Uuid, payload: &serde_json::Value) {
        let event = ProjectEvent(Arc::new(payload.to_string()));
        let mut map = self.lock();
        let Some(tx) = map.get(&project_id) else {
            return;
        };
        if tx.receiver_count() == 0 {
            map.remove(&project_id);
            return;
        }
        let tx = tx.clone();
        drop(map);
        // Send can only fail with zero receivers, checked just above.
        drop(tx.send(event));
    }

    /// An issue was created or updated (any field, status move, reorder).
    /// Carries the full entity so clients can apply it without a follow-up
    /// fetch; `actor_id` lets clients suppress self-echo effects.
    pub fn publish_issue(&self, kind: IssueEventKind, actor_id: Uuid, issue: &Issue) {
        self.publish(
            issue.project_id,
            &json!({
                "event": kind.as_str(),
                "project_id": issue.project_id,
                "actor_id": actor_id,
                "issue": issue,
            }),
        );
    }

    /// An issue was (soft-)deleted.
    pub fn publish_issue_deleted(&self, project_id: Uuid, actor_id: Uuid, issue_id: Uuid) {
        self.publish(
            project_id,
            &json!({
                "event": "issue.deleted",
                "project_id": project_id,
                "actor_id": actor_id,
                "issue_id": issue_id,
            }),
        );
    }

    /// An epic was created or updated. Carries the full entity so an open
    /// detail view can apply it without a follow-up fetch, exactly as
    /// [`Self::publish_issue`] does.
    pub fn publish_epic(&self, kind: EpicEventKind, actor_id: Uuid, epic: &Epic) {
        self.publish(
            epic.project_id,
            &json!({
                "event": kind.as_str(),
                "project_id": epic.project_id,
                "actor_id": actor_id,
                "epic": epic,
            }),
        );
    }

    /// An epic was deleted.
    pub fn publish_epic_deleted(&self, project_id: Uuid, actor_id: Uuid, epic_id: Uuid) {
        self.publish(
            project_id,
            &json!({
                "event": "epic.deleted",
                "project_id": project_id,
                "actor_id": actor_id,
                "epic_id": epic_id,
            }),
        );
    }

    /// A comment was posted, edited or removed on `target_type`/`target_id`.
    pub fn publish_comment(
        &self,
        kind: CommentEventKind,
        project_id: Uuid,
        actor_id: Uuid,
        target_type: &str,
        target_id: Uuid,
        comment_id: Uuid,
    ) {
        self.publish(
            project_id,
            &json!({
                "event": kind.as_str(),
                "project_id": project_id,
                "actor_id": actor_id,
                "target_type": target_type,
                "target_id": target_id,
                "comment_id": comment_id,
            }),
        );
    }

    /// A board definition (name/config/columns) changed or was deleted.
    pub fn publish_board_changed(&self, project_id: Uuid, actor_id: Uuid, board_id: Uuid) {
        self.publish(
            project_id,
            &json!({
                "event": "board.changed",
                "project_id": project_id,
                "actor_id": actor_id,
                "board_id": board_id,
            }),
        );
    }
}

/// Promote an `access_token` query parameter to a Bearer header.
///
/// Runs before auth extraction and only when no `Authorization` header is
/// present. Browsers' native `EventSource` cannot set request headers, so the
/// web client passes its short-lived access token in the query string for
/// this route only.
pub async fn promote_query_token(mut req: Request, next: Next) -> Response {
    if !req.headers().contains_key(header::AUTHORIZATION)
        && let Some(tok) = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("access_token=")))
        && let Ok(v) = HeaderValue::from_str(&format!("Bearer {tok}"))
    {
        req.headers_mut().insert(header::AUTHORIZATION, v);
    }
    next.run(req).await
}

/// `GET /api/v1/projects/{project_id}/events` — SSE change feed.
///
/// Emits `change` events (JSON payloads from [`EventBus`]) and a `resync`
/// event when the subscriber lagged past the channel buffer. The stream ends
/// at the access-token lifetime; clients reconnect (refreshing auth) and run
/// a delta fetch to close any gap.
pub async fn project_events(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let rx = state.events.subscribe(ctx.project.id);
    let ttl = u64::try_from(ACCESS_TTL_SECS).unwrap_or(900);
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(ttl))
        .unwrap_or_else(tokio::time::Instant::now);
    let stream = futures::stream::unfold(
        rx,
        move |mut rx: broadcast::Receiver<ProjectEvent>| async move {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => None,
                msg = rx.recv() => match msg {
                    Ok(ev) => Some((
                        Ok::<Event, std::convert::Infallible>(
                            Event::default().event("change").data(ev.0.as_str()),
                        ),
                        rx,
                    )),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        Some((Ok(Event::default().event("resync").data("{}")), rx))
                    }
                    Err(broadcast::error::RecvError::Closed) => None,
                },
            }
        },
    );
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(KEEP_ALIVE_SECS))
                .text("hb"),
        )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn issue(project_id: Uuid) -> Issue {
        let now = time::OffsetDateTime::now_utc();
        Issue {
            id: Uuid::now_v7(),
            project_id,
            reference: 1,
            subject: "S".to_owned(),
            description: String::new(),
            status_id: None,
            type_id: None,
            priority_id: None,
            size_id: None,
            epic_id: None,
            parent_id: None,
            milestone_id: None,
            owner_id: None,
            assigned_to: None,
            qa_assignee_id: None,
            reviewer_id: None,
            category: None,
            customer_ids: Vec::new(),
            start_date: None,
            due_date: None,
            resolution: None,
            resolved_at: None,
            release_version_id: None,
            release_text: None,
            labels: Vec::new(),
            components: Vec::new(),
            component_versions: Vec::new(),
            watchers: Vec::new(),
            order: 1.0,
            version: 1,
            created_at: now,
            modified_at: now,
        }
    }

    #[tokio::test]
    async fn subscriber_receives_issue_event_with_actor() {
        let bus = EventBus::default();
        let project = Uuid::now_v7();
        let actor = Uuid::now_v7();
        let mut rx = bus.subscribe(project);
        let i = issue(project);
        bus.publish_issue(IssueEventKind::Created, actor, &i);
        let ev = rx.recv().await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&ev.0).unwrap();
        assert_eq!(v["event"], "issue.created");
        assert_eq!(v["actor_id"], actor.to_string());
        assert_eq!(v["issue"]["id"], i.id.to_string());
    }

    #[tokio::test]
    async fn events_do_not_cross_projects() {
        let bus = EventBus::default();
        let mine = Uuid::now_v7();
        let theirs = Uuid::now_v7();
        let mut rx = bus.subscribe(mine);
        bus.publish_issue_deleted(theirs, Uuid::now_v7(), Uuid::now_v7());
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn publish_without_subscribers_drops_channel() {
        let bus = EventBus::default();
        let project = Uuid::now_v7();
        drop(bus.subscribe(project));
        bus.publish_board_changed(project, Uuid::now_v7(), Uuid::now_v7());
        assert!(bus.lock().is_empty());
    }
}
