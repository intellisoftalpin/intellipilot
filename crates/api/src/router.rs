//! Router construction.

use axum::Router;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::Response;
use axum::routing::{delete, get, patch, post, put};
use intellipilot_core::error::DomainError;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use utoipa_scalar::{Scalar, Servable as ScalarServable};
use utoipa_swagger_ui::SwaggerUi;

use crate::middleware::rate_limit::RateLimiter;
use crate::middleware::{rate_limit, request_id, security_headers};
use crate::problem::problem_from_domain;
use crate::state::AppState;
use crate::{
    admin, attachments, auth, avatar, backlog, boards, branding, catalog, customers, dashboard,
    epic_cover, health, issue_relations, issues_io, me, me_token, mfa, milestones, my_work,
    openapi, passkeys, project_icon, projects, releases, repositories, search, taxonomy,
    time_tracking, wiki,
};

#[allow(clippy::too_many_lines)] // a flat, readable route table
pub fn build_router(state: AppState) -> Router {
    let api_doc = openapi::document();

    let mut router = Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        // Public, unauthenticated, never rate-limited — usable by the SPA's
        // About box and by uptime/version probes.
        .route("/api/v1/version", get(health::version));

    if state.dev.fault_endpoints {
        router = router.route("/_fault/panic", get(fault_panic));
    }

    // Identity & session routes are only mounted when an auth context (DB,
    // keys, mailer) is configured. These are rate-limited; health/docs are not
    // (so monitoring probes are never throttled).
    if state.auth.is_some() {
        let api_v1 = Router::new()
            .route("/api/v1/auth/config", get(auth::handlers::config))
            // Public white-label icon (login screen renders it pre-auth).
            .route("/api/v1/branding/icon", get(branding::get_icon))
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
            .route("/api/v1/me/dashboard", get(dashboard::get_home))
            .route("/api/v1/me", get(me::get_me))
            .route("/api/v1/me", patch(me::patch_me))
            .route("/api/v1/me", delete(me::delete_me))
            .route("/api/v1/me/password", post(me::change_password))
            .route("/api/v1/me/export", get(me::export_me))
            // Personal app token (one per user, acts as the user)
            .route(
                "/api/v1/me/app-token",
                get(me_token::get_token)
                    .post(me_token::create_token)
                    .delete(me_token::delete_token),
            )
            .route("/api/v1/me/app-token/reset", post(me_token::reset_token))
            .route("/api/v1/me/app-token/disable", post(me_token::disable_token))
            .route("/api/v1/me/app-token/enable", post(me_token::enable_token))
            // Cross-project personal work feed
            .route("/api/v1/me/issues", get(my_work::list_my_issues))
            // Avatars: upload (raised body limit) / delete / emoji / serve.
            .route(
                "/api/v1/me/avatar",
                delete(avatar::delete_avatar).merge(
                    put(avatar::upload_avatar)
                        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024)),
                ),
            )
            .route("/api/v1/me/avatar/emoji", put(avatar::set_emoji_avatar))
            .route("/api/v1/users/{id}/avatar", get(avatar::serve_avatar))
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
            .route(
                // Short deep-link resolver: prefix → project, case-agnostic,
                // with rename-history fallback. Registered before the
                // `{project_id}` routes; the literal segment wins.
                "/api/v1/projects/by-prefix/{prefix}",
                get(projects::resolve_by_prefix),
            )
            .route(
                "/api/v1/projects/{project_id}/dashboard",
                get(dashboard::get_project),
            )
            .route("/api/v1/projects/{project_id}", get(projects::get_project))
            .route("/api/v1/projects/{project_id}", patch(projects::update_project))
            .route("/api/v1/projects/{project_id}", delete(projects::delete_project))
            // Project icon image (object-storage backed, like avatars)
            .route(
                "/api/v1/projects/{project_id}/icon",
                get(project_icon::serve_icon)
                    .delete(project_icon::delete_icon)
                    .merge(
                        put(project_icon::upload_icon)
                            .layer(axum::extract::DefaultBodyLimit::max(5 * 1024 * 1024)),
                    ),
            )
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
            .route("/api/v1/admin/activity", get(admin::handlers::list_activity))
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
            .route(
                "/api/v1/admin/app-tokens",
                get(admin::handlers::list_app_tokens).post(admin::handlers::create_app_token),
            )
            .route(
                "/api/v1/admin/app-tokens/{id}",
                get(admin::handlers::get_app_token).patch(admin::handlers::update_app_token),
            )
            .route(
                "/api/v1/admin/app-tokens/{id}/revoke",
                post(admin::handlers::revoke_app_token),
            )
            .route(
                "/api/v1/admin/short-link-history",
                get(admin::handlers::list_short_link_history),
            )
            .route(
                "/api/v1/admin/short-link-history/delete",
                post(admin::handlers::delete_short_link_history),
            )
            .route("/api/v1/admin/settings", get(admin::handlers::get_settings))
            .route(
                "/api/v1/admin/settings",
                patch(admin::handlers::update_settings),
            )
            .route(
                "/api/v1/admin/branding",
                patch(admin::handlers::update_branding),
            )
            .route(
                "/api/v1/admin/branding/icon",
                put(admin::handlers::upload_branding_icon)
                    .delete(admin::handlers::delete_branding_icon)
                    .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024)),
            )
            .route(
                "/api/v1/admin/ldap-settings",
                get(admin::handlers::get_ldap_settings).put(admin::handlers::update_ldap_settings),
            )
            .route(
                "/api/v1/admin/ldap-settings/test",
                post(admin::handlers::test_ldap_settings),
            )
            .route(
                "/api/v1/admin/notification-settings",
                get(admin::handlers::get_notification_settings)
                    .put(admin::handlers::update_notification_settings),
            )
            .route(
                "/api/v1/admin/notification-settings/test-mail",
                post(admin::handlers::test_mail),
            )
            .route(
                "/api/v1/admin/notification-settings/test-matrix",
                post(admin::handlers::test_matrix),
            )
            .route(
                "/api/v1/admin/notification-settings/test-telegram",
                post(admin::handlers::test_telegram),
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
            .route("/api/v1/projects/{project_id}/epics", delete(backlog::purge_epics))
            .route("/api/v1/projects/{project_id}/epics/{id}", get(backlog::get_epic))
            .route("/api/v1/projects/{project_id}/epics/{id}", patch(backlog::update_epic))
            .route("/api/v1/projects/{project_id}/epics/{id}", delete(backlog::delete_epic))
            .route("/api/v1/projects/{project_id}/epics/{id}/move", post(backlog::move_epic))
            // Epic cover image (object-storage backed, like avatars)
            .route(
                "/api/v1/projects/{project_id}/epics/{id}/cover-image",
                get(epic_cover::serve_cover)
                    .delete(epic_cover::delete_cover)
                    .merge(
                        put(epic_cover::upload_cover)
                            .layer(axum::extract::DefaultBodyLimit::max(5 * 1024 * 1024)),
                    ),
            )
            // Backlog — issues (unified: Story / Task / Bug / sub-task)
            .route("/api/v1/projects/{project_id}/issues", get(backlog::list_issues))
            .route("/api/v1/projects/{project_id}/issues", post(backlog::create_issue))
            .route("/api/v1/projects/{project_id}/issues", delete(backlog::purge_issues))
            .route("/api/v1/projects/{project_id}/issues/bulk", post(backlog::bulk_create_issues))
            .route("/api/v1/projects/{project_id}/issues/by-ref/{ref}", get(backlog::get_issue_by_ref))
            .route("/api/v1/projects/{project_id}/issues/{id}", get(backlog::get_issue))
            .route("/api/v1/projects/{project_id}/issues/{id}", patch(backlog::update_issue))
            .route("/api/v1/projects/{project_id}/issues/{id}", delete(backlog::delete_issue))
            .route("/api/v1/projects/{project_id}/issues/{id}/move", post(backlog::move_issue))
            // Issue import (JIRA / IntelliPilot CSV) + export (CSV / XLSX)
            .route(
                "/api/v1/projects/{project_id}/issues/export",
                get(issues_io::export_issues),
            )
            .route(
                "/api/v1/projects/{project_id}/issues/import/preview",
                post(issues_io::import_preview)
                    .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
            )
            .route(
                "/api/v1/projects/{project_id}/issues/import",
                post(issues_io::import_commit)
                    .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
            )
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
            // Git integration: SSH keys (per-project credential vault)
            .route("/api/v1/projects/{project_id}/ssh-keys", get(repositories::list_ssh_keys))
            .route("/api/v1/projects/{project_id}/ssh-keys", post(repositories::create_ssh_key))
            .route("/api/v1/projects/{project_id}/ssh-keys/{key_id}", patch(repositories::update_ssh_key))
            .route("/api/v1/projects/{project_id}/ssh-keys/{key_id}", delete(repositories::delete_ssh_key))
            // Git integration: repositories
            .route("/api/v1/projects/{project_id}/repositories", get(repositories::list_repositories))
            .route("/api/v1/projects/{project_id}/repositories", post(repositories::create_repository))
            .route("/api/v1/projects/{project_id}/repositories/branches", post(repositories::preview_branches))
            .route("/api/v1/projects/{project_id}/repositories/{repository_id}", patch(repositories::update_repository))
            .route("/api/v1/projects/{project_id}/repositories/{repository_id}", delete(repositories::delete_repository))
            .route("/api/v1/projects/{project_id}/repositories/{repository_id}/branches", get(repositories::repository_branches))
            // Git integration: component <-> repository links
            .route("/api/v1/projects/{project_id}/components/{component_id}/repositories", get(repositories::list_component_repositories))
            .route("/api/v1/projects/{project_id}/components/{component_id}/repositories", post(repositories::link_component_repository))
            .route("/api/v1/projects/{project_id}/components/{component_id}/repositories/{repository_id}", patch(repositories::update_component_repository))
            .route("/api/v1/projects/{project_id}/components/{component_id}/repositories/{repository_id}", delete(repositories::unlink_component_repository))
            // Customers (per-project registry)
            .route("/api/v1/projects/{project_id}/customers", get(customers::list))
            .route("/api/v1/projects/{project_id}/customers", post(customers::create))
            .route("/api/v1/projects/{project_id}/customers/{customer_id}", patch(customers::update))
            .route("/api/v1/projects/{project_id}/customers/{customer_id}", delete(customers::delete))
            // Kanban boards — first-class personal/shared boards + the
            // performant per-column board-data endpoint.
            .route(
                "/api/v1/projects/{project_id}/board",
                get(boards::board_data),
            )
            .route(
                "/api/v1/projects/{project_id}/boards",
                get(boards::list).post(boards::create),
            )
            .route(
                "/api/v1/projects/{project_id}/boards/last-opened",
                get(boards::get_last_opened),
            )
            .route(
                "/api/v1/projects/{project_id}/boards/{board_id}",
                get(boards::get).put(boards::update).delete(boards::delete),
            )
            .route(
                "/api/v1/projects/{project_id}/boards/{board_id}/last-opened",
                put(boards::set_last_opened),
            )
            // Releases + versions
            .route("/api/v1/projects/{project_id}/releases", get(releases::list_releases))
            .route("/api/v1/projects/{project_id}/releases", post(releases::create_release))
            .route("/api/v1/projects/{project_id}/release-versions", get(releases::list_all_release_versions))
            .route("/api/v1/projects/{project_id}/release-versions/for-components", post(releases::versions_for_components))
            .route("/api/v1/projects/{project_id}/releases/{release_id}", patch(releases::update_release))
            .route("/api/v1/projects/{project_id}/releases/{release_id}", delete(releases::delete_release))
            .route("/api/v1/projects/{project_id}/releases/{release_id}/versions", get(releases::list_versions))
            .route("/api/v1/projects/{project_id}/releases/{release_id}/versions", post(releases::create_version))
            .route("/api/v1/projects/{project_id}/releases/{release_id}/versions/{version_id}", patch(releases::update_version))
            .route("/api/v1/projects/{project_id}/releases/{release_id}/versions/{version_id}", delete(releases::delete_version))
            // Component <-> release links
            .route("/api/v1/projects/{project_id}/components/{component_id}/releases", get(releases::list_component_releases))
            .route("/api/v1/projects/{project_id}/components/{component_id}/releases", post(releases::link_component_release))
            .route("/api/v1/projects/{project_id}/components/{component_id}/releases/{release_id}", delete(releases::unlink_component_release))
            // Issue relationships + watchers
            .route("/api/v1/projects/{project_id}/issues/{id}/links", get(issue_relations::list_links))
            .route("/api/v1/projects/{project_id}/issues/{id}/links", post(issue_relations::create_link))
            .route("/api/v1/projects/{project_id}/issues/{id}/links/{link_id}", delete(issue_relations::delete_link))
            .route("/api/v1/projects/{project_id}/issues/{id}/watchers", get(issue_relations::list_watchers))
            .route("/api/v1/projects/{project_id}/issues/{id}/watchers", post(issue_relations::add_watcher))
            .route("/api/v1/projects/{project_id}/issues/{id}/watchers/{user_id}", delete(issue_relations::remove_watcher))
            // Milestones / sprints
            .route("/api/v1/projects/{project_id}/milestones", get(milestones::list))
            .route("/api/v1/projects/{project_id}/milestones", post(milestones::create))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}", get(milestones::get))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}", patch(milestones::update))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}", delete(milestones::delete))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}/close", post(milestones::close))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}/board", get(milestones::board))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}/stats", get(milestones::stats))
            .route("/api/v1/projects/{project_id}/milestones/{milestone_id}/epics", put(milestones::set_epics))
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
            // Time tracking — personal (own timesheet, absences, export)
            .route(
                "/api/v1/me/assigned-issues",
                get(time_tracking::list_my_assigned_issues),
            )
            .route(
                "/api/v1/me/loggable-issues",
                get(time_tracking::list_my_loggable_issues),
            )
            .route(
                "/api/v1/me/time-entries",
                get(time_tracking::list_my_entries).post(time_tracking::log_my_time),
            )
            .route(
                "/api/v1/me/time-entries/export",
                get(time_tracking::export_my_time),
            )
            .route(
                "/api/v1/me/time-entries/{id}",
                patch(time_tracking::update_my_entry).delete(time_tracking::delete_my_entry),
            )
            .route("/api/v1/me/absences", post(time_tracking::book_absence))
            .route(
                "/api/v1/me/absences/{booking_id}",
                delete(time_tracking::delete_absence_booking),
            )
            .route(
                "/api/v1/me/timesheet/summary",
                get(time_tracking::my_timesheet_summary),
            )
            .route(
                "/api/v1/me/vacation-balance",
                get(time_tracking::my_vacation_balance),
            )
            // Time tracking — project / team
            .route(
                "/api/v1/projects/{project_id}/time-entries",
                get(time_tracking::list_project_time).post(time_tracking::admin_log_time),
            )
            .route(
                "/api/v1/projects/{project_id}/time-entries/export",
                get(time_tracking::export_project_time),
            )
            .route(
                "/api/v1/projects/{project_id}/time-entries/{entry_id}",
                patch(time_tracking::admin_update_entry).delete(time_tracking::admin_delete_entry),
            )
            .route(
                "/api/v1/projects/{project_id}/time/summary",
                get(time_tracking::project_team_month),
            )
            .route(
                "/api/v1/projects/{project_id}/time/locks",
                get(time_tracking::list_locks).post(time_tracking::lock_period),
            )
            .route(
                "/api/v1/projects/{project_id}/time/locks/{year}/{month}",
                delete(time_tracking::unlock_period),
            )
            .route(
                "/api/v1/projects/{project_id}/availability",
                get(time_tracking::project_availability),
            )
            .route(
                "/api/v1/projects/{project_id}/issues/{id}/time",
                get(time_tracking::issue_time),
            )
            // Time tracking — superadmin (cross-project timesheet + vacation)
            .route(
                "/api/v1/admin/time/summary",
                get(time_tracking::global_team_month),
            )
            .route(
                "/api/v1/admin/time-entries",
                get(time_tracking::list_all_time),
            )
            .route(
                "/api/v1/admin/users/{id}/vacation-allowances",
                get(time_tracking::list_user_allowances),
            )
            .route(
                "/api/v1/admin/users/{id}/vacation-allowances/{year}",
                put(time_tracking::set_user_allowance),
            )
            .route(
                "/api/v1/admin/users/{id}/work-settings",
                patch(time_tracking::set_user_work_settings),
            )
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

    // CORS / preflight. The API authenticates with a Bearer token in the
    // `Authorization` header (the refresh cookie is SameSite=Strict and never
    // travels cross-site), so this is NOT a credentialed CORS setup — we mirror
    // the request's origin/method/headers and omit `allow-credentials`. This
    // lets the SPA call the API from any origin (and, crucially, answers the
    // browser's preflight `OPTIONS` with 204 instead of a 405). Same-origin
    // deployments are unaffected (no preflight is sent).
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
        .expose_headers([header::ETAG]);

    router
        .with_state(state)
        .fallback(fallback_404)
        .method_not_allowed_fallback(fallback_405)
        .layer(axum::middleware::from_fn(security_headers::layer))
        .layer(axum::middleware::from_fn(request_id::layer))
        .layer(cors)
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
