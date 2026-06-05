//! Router construction.

use axum::Router;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, patch, post};
use intellipilot_core::error::DomainError;
use utoipa_scalar::{Scalar, Servable as ScalarServable};
use utoipa_swagger_ui::SwaggerUi;

use crate::middleware::rate_limit::RateLimiter;
use crate::middleware::{rate_limit, request_id, security_headers};
use crate::problem::problem_from_domain;
use crate::state::AppState;
use crate::{
    admin, attachments, auth, backlog, catalog, health, me, mfa, milestones, openapi, passkeys,
    projects, search, taxonomy, wiki,
};

#[allow(clippy::too_many_lines)] // a flat, readable route table
pub fn build_router(state: AppState) -> Router {
    let api_doc = openapi::document();

    let mut router = Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready));

    if state.dev.fault_endpoints {
        router = router.route("/_fault/panic", get(fault_panic));
    }

    // Identity & session routes are only mounted when an auth context (DB,
    // keys, mailer) is configured. These are rate-limited; health/docs are not
    // (so monitoring probes are never throttled).
    if state.auth.is_some() {
        let api_v1 = Router::new()
            .route("/api/v1/auth/register", post(auth::handlers::register))
            .route("/api/v1/auth/login", post(auth::handlers::login))
            .route("/api/v1/auth/refresh", post(auth::handlers::refresh))
            .route("/api/v1/auth/logout", post(auth::handlers::logout))
            .route(
                "/api/v1/auth/password/reset/request",
                post(auth::handlers::password_reset_request),
            )
            .route(
                "/api/v1/auth/password/reset/confirm",
                post(auth::handlers::password_reset_confirm),
            )
            .route("/api/v1/me", get(me::get_me))
            .route("/api/v1/me", patch(me::patch_me))
            .route("/api/v1/me", delete(me::delete_me))
            .route("/api/v1/me/export", get(me::export_me))
            // Two-factor: TOTP + recovery
            .route("/api/v1/auth/2fa/verify", post(mfa::two_factor_verify))
            .route("/api/v1/me/totp/start", post(mfa::totp_start))
            .route("/api/v1/me/totp/confirm", post(mfa::totp_confirm))
            .route("/api/v1/me/totp", delete(mfa::totp_disable))
            .route(
                "/api/v1/me/recovery-codes/regenerate",
                post(mfa::recovery_regenerate),
            )
            // Passkeys (WebAuthn)
            .route(
                "/api/v1/me/passkeys/register/start",
                post(passkeys::register_start),
            )
            .route(
                "/api/v1/me/passkeys/register/finish",
                post(passkeys::register_finish),
            )
            .route("/api/v1/me/passkeys", get(passkeys::list))
            .route("/api/v1/me/passkeys/{id}", delete(passkeys::delete))
            .route(
                "/api/v1/auth/passkeys/authenticate/start",
                post(passkeys::authenticate_start),
            )
            .route(
                "/api/v1/auth/passkeys/authenticate/finish",
                post(passkeys::authenticate_finish),
            )
            // Projects, roles, members, invitations
            .route("/api/v1/projects", post(projects::create_project))
            .route("/api/v1/projects", get(projects::list_projects))
            .route("/api/v1/projects/{project_id}", get(projects::get_project))
            .route("/api/v1/projects/{project_id}", patch(projects::update_project))
            .route("/api/v1/projects/{project_id}", delete(projects::delete_project))
            .route("/api/v1/projects/{project_id}/roles", get(projects::list_roles))
            .route("/api/v1/projects/{project_id}/roles", post(projects::create_role))
            .route(
                "/api/v1/projects/{project_id}/roles/{role_id}",
                patch(projects::update_role),
            )
            .route(
                "/api/v1/projects/{project_id}/roles/{role_id}",
                delete(projects::delete_role),
            )
            .route(
                "/api/v1/projects/{project_id}/members",
                get(projects::list_members).post(projects::add_member),
            )
            .route(
                "/api/v1/projects/{project_id}/members/{user_id}",
                patch(projects::change_member_role),
            )
            .route(
                "/api/v1/projects/{project_id}/members/{user_id}",
                delete(projects::remove_member),
            )
            .route(
                "/api/v1/projects/{project_id}/invitations",
                post(projects::invite),
            )
            .route(
                "/api/v1/projects/{project_id}/invitations",
                get(projects::list_invitations),
            )
            .route("/api/v1/invitations/accept", post(projects::accept_invitation))
            // Platform admin (V011) — all gated by SuperadminUser inside handlers
            .route("/api/v1/admin/users", get(admin::handlers::list_users))
            .route("/api/v1/admin/users", post(admin::handlers::create_user))
            .route("/api/v1/admin/users/{id}", patch(admin::handlers::update_user))
            .route("/api/v1/admin/users/{id}", delete(admin::handlers::delete_user))
            .route(
                "/api/v1/admin/users/{id}/reset-password",
                post(admin::handlers::reset_password),
            )
            .route(
                "/api/v1/admin/invitations",
                post(admin::handlers::create_invitation),
            )
            .route(
                "/api/v1/admin/invitations",
                get(admin::handlers::list_invitations),
            )
            .route(
                "/api/v1/admin/invitations/{id}",
                delete(admin::handlers::revoke_invitation),
            )
            .route("/api/v1/admin/settings", get(admin::handlers::get_settings))
            .route(
                "/api/v1/admin/settings",
                patch(admin::handlers::update_settings),
            )
            // Taxonomy (generic, per kind)
            .route(
                "/api/v1/projects/{project_id}/taxonomy/{kind}",
                get(taxonomy::list),
            )
            .route(
                "/api/v1/projects/{project_id}/taxonomy/{kind}",
                post(taxonomy::create),
            )
            .route(
                "/api/v1/projects/{project_id}/taxonomy/{kind}/{item_id}",
                patch(taxonomy::update),
            )
            .route(
                "/api/v1/projects/{project_id}/taxonomy/{kind}/{item_id}",
                delete(taxonomy::delete),
            )
            .route(
                "/api/v1/projects/{project_id}/taxonomy/{kind}/{item_id}/move",
                post(taxonomy::move_item),
            )
            // Backlog — epics
            .route("/api/v1/projects/{project_id}/epics", get(backlog::list_epics))
            .route("/api/v1/projects/{project_id}/epics", post(backlog::create_epic))
            .route("/api/v1/projects/{project_id}/epics/{id}", get(backlog::get_epic))
            .route("/api/v1/projects/{project_id}/epics/{id}", patch(backlog::update_epic))
            .route("/api/v1/projects/{project_id}/epics/{id}", delete(backlog::delete_epic))
            .route("/api/v1/projects/{project_id}/epics/{id}/move", post(backlog::move_epic))
            // Backlog — issues (unified: Story / Task / Bug / sub-task)
            .route("/api/v1/projects/{project_id}/issues", get(backlog::list_issues))
            .route("/api/v1/projects/{project_id}/issues", post(backlog::create_issue))
            .route("/api/v1/projects/{project_id}/issues/bulk", post(backlog::bulk_create_issues))
            .route("/api/v1/projects/{project_id}/issues/{id}", get(backlog::get_issue))
            .route("/api/v1/projects/{project_id}/issues/{id}", patch(backlog::update_issue))
            .route("/api/v1/projects/{project_id}/issues/{id}", delete(backlog::delete_issue))
            .route("/api/v1/projects/{project_id}/issues/{id}/move", post(backlog::move_issue))
            // Comments (polymorphic) + ref resolver
            .route("/api/v1/projects/{project_id}/{entity}/{id}/comments", get(backlog::list_comments))
            .route("/api/v1/projects/{project_id}/{entity}/{id}/comments", post(backlog::create_comment))
            .route("/api/v1/projects/{project_id}/{entity}/{id}/comments/{comment_id}", patch(backlog::update_comment))
            .route("/api/v1/projects/{project_id}/{entity}/{id}/comments/{comment_id}", delete(backlog::delete_comment))
            .route("/api/v1/projects/{project_id}/{entity}/{id}/history", get(backlog::list_history))
            .route("/api/v1/projects/{project_id}/resolve/{ref}", get(backlog::resolve_ref))
            // Labels & components (project-level)
            .route("/api/v1/projects/{project_id}/labels", get(catalog::list_labels))
            .route("/api/v1/projects/{project_id}/labels", post(catalog::create_label))
            .route("/api/v1/projects/{project_id}/labels/{label_id}", patch(catalog::update_label))
            .route("/api/v1/projects/{project_id}/labels/{label_id}", delete(catalog::delete_label))
            .route("/api/v1/projects/{project_id}/components", get(catalog::list_components))
            .route("/api/v1/projects/{project_id}/components", post(catalog::create_component))
            .route("/api/v1/projects/{project_id}/components/{component_id}", patch(catalog::update_component))
            .route("/api/v1/projects/{project_id}/components/{component_id}", delete(catalog::delete_component))
            // Milestones / sprints
            .route("/api/v1/projects/{project_id}/milestones", get(milestones::list))
            .route("/api/v1/projects/{project_id}/milestones", post(milestones::create))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}", get(milestones::get))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}", patch(milestones::update))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}", delete(milestones::delete))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}/close", post(milestones::close))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}/board", get(milestones::board))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}/stats", get(milestones::stats))
            // Attachments — the upload method router gets a raised body limit
            // (multipart of up to ~32 MiB; per-file size is enforced in-handler).
            .route(
                "/api/v1/projects/{project_id}/{entity}/{id}/attachments",
                get(attachments::list).merge(
                    post(attachments::upload)
                        .layer(axum::extract::DefaultBodyLimit::max(32 * 1024 * 1024)),
                ),
            )
            .route("/api/v1/projects/{project_id}/attachments/{attachment_id}", get(attachments::sign_url))
            .route("/api/v1/projects/{project_id}/attachments/{attachment_id}", delete(attachments::delete))
            .route("/api/v1/projects/{project_id}/attachments/{attachment_id}/download", get(attachments::download))
            // Wiki
            .route("/api/v1/projects/{project_id}/wiki", get(wiki::list))
            .route("/api/v1/projects/{project_id}/wiki", post(wiki::create))
            .route("/api/v1/projects/{project_id}/wiki/{wiki_id}", get(wiki::get))
            .route("/api/v1/projects/{project_id}/wiki/{wiki_id}", patch(wiki::update))
            .route("/api/v1/projects/{project_id}/wiki/{wiki_id}", delete(wiki::delete))
            .route("/api/v1/projects/{project_id}/wiki/{wiki_id}/revisions", get(wiki::list_revisions))
            .route("/api/v1/projects/{project_id}/wiki/{wiki_id}/revisions/{rev}", get(wiki::get_revision))
            .route("/api/v1/projects/{project_id}/wiki/{wiki_id}/revisions/{rev}/diff", get(wiki::diff))
            .route("/api/v1/projects/{project_id}/wiki/{wiki_id}/revisions/{rev}/restore", post(wiki::restore))
            // Unified search
            .route("/api/v1/search", get(search::search))
            .layer(axum::middleware::from_fn_with_state(
                RateLimiter::default(),
                rate_limit::layer,
            ));
        router = router.merge(api_v1);
    }

    // SwaggerUi mounts the spec at "/openapi.json" automatically.
    router = router
        .merge(SwaggerUi::new("/docs").url("/openapi.json", api_doc.clone()))
        .merge(Scalar::with_url("/reference", api_doc));

    router
        .with_state(state)
        .fallback(fallback_404)
        .method_not_allowed_fallback(fallback_405)
        .layer(axum::middleware::from_fn(security_headers::layer))
        .layer(axum::middleware::from_fn(request_id::layer))
}

async fn fault_panic() -> Response {
    let err = DomainError::Internal(Box::new(std::io::Error::other("simulated")));
    problem_from_domain(&err, "fault-injection")
}

async fn fallback_404() -> Response {
    problem_from_domain(&DomainError::NotFound, "fallback")
}

async fn fallback_405() -> Response {
    use crate::problem::Problem;
    Problem::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method Not Allowed",
        None,
        "fallback",
    )
    .into_response_with_status(StatusCode::METHOD_NOT_ALLOWED)
}
