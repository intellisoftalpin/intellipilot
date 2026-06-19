//! Pure domain types and rules. No I/O.
//!
//! This crate must not depend on `axum`, `sqlx`, or any runtime — its types
//! are the contract shared by the HTTP layer and the persistence layer.

#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod attachment;
pub mod backlog;
pub mod catalog;
pub mod customer;
pub mod error;
pub mod ids;
pub mod milestone;
pub mod ordering;
pub mod perms;
pub mod project;
pub mod release;
pub mod repo;
pub mod search;
pub mod serde_date;
pub mod taxonomy;
pub mod user;
pub mod wiki;
