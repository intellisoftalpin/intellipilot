//! IntelliPilot HTTP API.
//!
//! The library exposes the parts test code needs:
//! - [`AppState`] / [`AppStateBuilder`]
//! - [`ReadyCheck`] trait for `/health/ready`
//! - [`build_router`] to construct the axum [`axum::Router`].

#![allow(clippy::missing_const_for_fn)] // utoipa-derived items aren't const-friendly

pub mod admin;
pub mod attachments;
pub mod auth;
pub mod avatar;
pub mod backlog;
pub mod board_views;
pub mod branding;
pub mod catalog;
pub mod customers;
pub mod dashboard;
pub mod dto;
pub mod epic_cover;
pub mod health;
pub mod issue_relations;
pub mod issues_io;
pub mod ldap;
pub mod markdown;
pub mod me;
pub mod mfa;
pub mod middleware;
pub mod milestones;
pub mod notify;
pub mod openapi;
pub mod passkeys;
pub mod problem;
pub mod project_icon;
pub mod projects;
pub mod releases;
pub mod repositories;
pub mod router;
pub mod search;
pub mod state;
pub mod taxonomy;
pub mod time_tracking;
pub mod wiki;

pub use router::build_router;
pub use state::{AppState, AppStateBuilder, AuthConfig, AuthContext, DevToggles, Env, ReadyCheck};
