//! Domain error type. Mapped to RFC 9457 Problem+JSON at the HTTP boundary.

use thiserror::Error;

/// Stable error code string, surfaced in Problem+JSON `code` extension field
/// and used by clients for branching.
#[derive(Debug, Error)]
pub enum DomainError {
    #[error("validation failed")]
    Validation { errors: Vec<FieldError> },

    #[error("resource not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("unauthorized")]
    Unauthorized,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("precondition failed (etag mismatch)")]
    PreconditionFailed,

    #[error("rate limited")]
    RateLimited,

    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FieldError {
    pub field: String,
    pub code: String,
    pub message: String,
}

/// Stable machine-readable code for each domain error variant.
impl DomainError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation { .. } => "validation_failed",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::Unauthorized => "unauthorized",
            Self::Conflict(_) => "conflict",
            Self::PreconditionFailed => "precondition_failed",
            Self::RateLimited => "rate_limited",
            Self::Internal(_) => "internal_error",
        }
    }
}
