//! Pure domain types and rules. No I/O.
//!
//! This crate must not depend on `axum`, `sqlx`, or any runtime — its types
//! are the contract shared by the HTTP layer and the persistence layer.

#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod activity;
pub mod app_token;
pub mod attachment;
pub mod backlog;
pub mod board;
pub mod catalog;
pub mod customer;
pub mod dashboard;
pub mod error;
pub mod ids;
pub mod milestone;
pub mod my_work;
pub mod ordering;
pub mod perms;
pub mod project;
pub mod release;
pub mod repo;
pub mod search;
pub mod serde_date;
pub mod taxonomy;
pub mod time_tracking;
pub mod user;
pub mod wiki;
