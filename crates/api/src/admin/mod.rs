//! Platform-admin endpoints (V011).
//!
//! Mounted under `/api/v1/admin/*` and gated by
//! [`crate::auth::SuperadminUser`]. See the module docs for the division of
//! responsibilities between platform-level and per-project admin.

pub mod dto;
pub mod handlers;
pub mod oidc;
