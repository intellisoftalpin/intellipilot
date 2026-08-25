//! Shared resolution of the `my_role` dimension — the "My Issues" board's
//! swimlane grouping and its matching filter.
//!
//! Both the board-data endpoint and the issues list accept `my_role`, and the
//! rail count needs the same actor context, so the lookup lives here once.

use intellipilot_db::{backlog as bl, mention_pattern, users};
use uuid::Uuid;

/// The accepted `my_role` values: every role the board lanes by, plus `any`
/// for "I hold at least one role".
fn is_known(role: &str) -> bool {
    role == "any" || bl::MY_ROLE_PREDICATES.iter().any(|(name, _)| *name == role)
}

/// Actor context for the role predicates: the caller's id and the `%@handle%`
/// pattern the `mentioned` role matches against.
#[derive(Debug, Default)]
pub struct Actor {
    pub id: Option<Uuid>,
    pub mention_like: Option<String>,
}

/// Look up the caller's mention pattern. A token outliving a deleted account
/// yields no pattern, which makes the `mentioned` role match nothing rather
/// than erroring.
pub async fn actor(client: &deadpool_postgres::Client, actor_id: Uuid) -> Actor {
    let mention_like = match users::find_by_id(client, actor_id).await {
        Ok(Some(u)) => Some(mention_pattern(&u.username)),
        _ => None,
    };
    Actor {
        id: Some(actor_id),
        mention_like,
    }
}

/// Validate the `my_role` query param and load the actor context when either
/// the filter or the swimlane grouping needs it.
///
/// `Err(())` means the value is not a known role — the caller should answer
/// 422 rather than silently dropping the filter, since dropping it would widen
/// the response to the whole project.
pub async fn resolve(
    client: &deadpool_postgres::Client,
    actor_id: Uuid,
    raw: Option<&str>,
    grouping_by_role: bool,
) -> Result<(Option<String>, Actor), ()> {
    let role = match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(r) if is_known(r) => Some(r.to_owned()),
        Some(_) => return Err(()),
    };
    if role.is_none() && !grouping_by_role {
        return Ok((None, Actor::default()));
    }
    Ok((role, actor(client, actor_id).await))
}
