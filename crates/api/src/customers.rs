//! Per-project customer registry endpoints. View needs `project.view`; mutate
//! needs `project.modify`.
#![allow(clippy::result_large_err, clippy::implicit_hasher)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_db::customers as cdb;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

const MAX_CUSTOMERS_PER_PROJECT: i64 = 5000;

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateCustomerRequest {
    #[garde(length(min = 1, max = 200))]
    pub name: String,
    #[garde(length(max = 200))]
    #[serde(default)]
    pub company_name: Option<String>,
    #[garde(inner(email), length(max = 254))]
    #[serde(default)]
    pub contact_email: Option<String>,
    #[garde(length(max = 64))]
    #[serde(default)]
    pub phone: Option<String>,
    #[garde(length(max = 5000))]
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct UpdateCustomerRequest {
    #[garde(length(min = 1, max = 200))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(length(max = 200))]
    #[serde(default)]
    pub company_name: Option<String>,
    #[garde(inner(email), length(max = 254))]
    #[serde(default)]
    pub contact_email: Option<String>,
    #[garde(length(max = 64))]
    #[serde(default)]
    pub phone: Option<String>,
    #[garde(length(max = 5000))]
    #[serde(default)]
    pub notes: Option<String>,
}

fn problem(status: StatusCode, code: &'static str, detail: Option<String>, rid: &str) -> Response {
    Problem::new(status, code, code, detail, rid).into_response_with_status(status)
}
fn internal(rid: &str) -> Response {
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        None,
        rid,
    )
}
fn not_found(rid: &str) -> Response {
    problem(StatusCode::NOT_FOUND, "not_found", None, rid)
}
fn parse_body<T: serde::de::DeserializeOwned + Validate<Context = ()>>(
    body: Result<Json<T>, JsonRejection>,
    rid: &str,
) -> Result<T, Response> {
    let Ok(Json(v)) = body else {
        return Err(problem(StatusCode::BAD_REQUEST, "invalid_body", None, rid));
    };
    if v.validate().is_err() {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            None,
            rid,
        ));
    }
    Ok(v)
}
fn item_id(params: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    params.get(key).and_then(|s| Uuid::parse_str(s).ok())
}

/// `GET /api/v1/projects/{project_id}/customers`
pub async fn list(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match cdb::list(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "customers": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/customers`
pub async fn create(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateCustomerRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match cdb::count(&client, ctx.project.id).await {
        Ok(n) if n >= MAX_CUSTOMERS_PER_PROJECT => {
            return problem(
                StatusCode::CONFLICT,
                "limit_reached",
                Some("maximum number of customers reached".to_owned()),
                &ctx.rid,
            );
        }
        Ok(_) => {}
        Err(_) => return internal(&ctx.rid),
    }
    let w = cdb::CustomerWrite {
        name: &req.name,
        company_name: req.company_name.as_deref(),
        contact_email: req.contact_email.as_deref(),
        phone: req.phone.as_deref(),
        notes: req.notes.as_deref(),
    };
    match cdb::create(&client, ctx.project.id, ctx.actor_id, &w).await {
        Ok(c) => (StatusCode::CREATED, Json(c)).into_response(),
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            Some("customer name already used".to_owned()),
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/customers/{customer_id}`
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateCustomerRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "customer_id") else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // Merge patch over the existing record (full-replace write).
    let Ok(Some(old)) = cdb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    let name = req.name.unwrap_or(old.name);
    let company_name = req.company_name.or(old.company_name);
    let contact_email = req.contact_email.or(old.contact_email);
    let phone = req.phone.or(old.phone);
    let notes = req.notes.or(old.notes);
    let w = cdb::CustomerWrite {
        name: &name,
        company_name: company_name.as_deref(),
        contact_email: contact_email.as_deref(),
        phone: phone.as_deref(),
        notes: notes.as_deref(),
    };
    match cdb::update(&client, ctx.project.id, id, &w).await {
        Ok(Some(c)) => Json(c).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            Some("customer name already used".to_owned()),
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/customers/{customer_id}`
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "customer_id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match cdb::delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
