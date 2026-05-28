//! RFC 9457 Problem+JSON response type and conversion plumbing.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use intellipilot_core::error::{DomainError, FieldError};
use serde::Serialize;
use utoipa::ToSchema;

const PROBLEM_BASE: &str = "https://intellipilot.dev/problems/";
const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

#[derive(Debug, Serialize, ToSchema)]
pub struct Problem {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Short, human-readable summary.
    pub title: String,
    /// HTTP status code, duplicated for convenience.
    pub status: u16,
    /// Human-readable explanation. Must NOT leak internal details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URI reference identifying the specific occurrence — we use the
    /// request id.
    pub instance: String,
    /// Stable machine-readable code for client branching.
    pub code: String,
    /// Per-field validation errors when applicable.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldErrorView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FieldErrorView {
    pub field: String,
    pub code: String,
    pub message: String,
}

impl From<FieldError> for FieldErrorView {
    fn from(f: FieldError) -> Self {
        Self {
            field: f.field,
            code: f.code,
            message: f.message,
        }
    }
}

impl Problem {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        title: impl Into<String>,
        detail: Option<String>,
        request_id: &str,
    ) -> Self {
        Self {
            problem_type: format!("{PROBLEM_BASE}{code}"),
            title: title.into(),
            status: status.as_u16(),
            detail,
            instance: format!("/req/{request_id}"),
            code: code.to_owned(),
            errors: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = errors.into_iter().map(Into::into).collect();
        self
    }

    pub fn into_response_with_status(self, status: StatusCode) -> Response {
        let mut resp = (status, Json(&self)).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
        );
        resp
    }
}

/// Convert a domain error into the proper Problem+JSON response. Request id
/// is read from the response-time extension set by the request-id middleware.
pub fn problem_from_domain(err: &DomainError, request_id: &str) -> Response {
    let (status, title, detail): (StatusCode, &str, Option<String>) = match err {
        DomainError::Validation { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "Validation failed", None)
        }
        DomainError::NotFound => (StatusCode::NOT_FOUND, "Not Found", None),
        DomainError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden", None),
        DomainError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized", None),
        DomainError::Conflict(msg) => (StatusCode::CONFLICT, "Conflict", Some(msg.clone())),
        DomainError::PreconditionFailed => {
            (StatusCode::PRECONDITION_FAILED, "Precondition Failed", None)
        }
        DomainError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests", None),
        DomainError::Internal(source) => {
            tracing::error!(error = %source, "internal error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                Some("An unexpected error occurred".to_owned()),
            )
        }
    };

    let mut problem = Problem::new(status, err.code(), title, detail, request_id);
    if let DomainError::Validation { errors } = err {
        problem = problem.with_errors(errors.clone());
    }
    problem.into_response_with_status(status)
}

/// Wraps a [`DomainError`] so handlers can return `Result<T, DomainErrorResponse>`.
#[derive(Debug)]
pub struct DomainErrorResponse(pub DomainError);

impl From<DomainError> for DomainErrorResponse {
    fn from(e: DomainError) -> Self {
        Self(e)
    }
}

impl IntoResponse for DomainErrorResponse {
    fn into_response(self) -> Response {
        // request id is injected at the layer above; default to "unknown" if
        // somehow not set.
        problem_from_domain(&self.0, "unknown")
    }
}
