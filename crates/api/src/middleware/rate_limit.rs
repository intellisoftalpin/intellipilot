//! In-process per-IP rate limiting (fixed window).
//!
//! Section 9 decision: single-region/single-node, so in-memory buckets are
//! sufficient. Unauthenticated requests get a lower budget than authenticated
//! ones (presence of an `Authorization` header raises the limit). Buckets
//! reset on restart, which is acceptable for v1.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::client_ip;
use crate::problem::Problem;

const WINDOW: Duration = Duration::from_secs(60);
pub const UNAUTH_PER_MIN: u32 = 60;
pub const AUTH_PER_MIN: u32 = 600;

#[derive(Debug)]
struct Window {
    count: u32,
    started: Instant,
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<(IpAddr, bool), Window>>>,
    unauth_per_min: u32,
    auth_per_min: u32,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("unauth_per_min", &self.unauth_per_min)
            .field("auth_per_min", &self.auth_per_min)
            .finish_non_exhaustive()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(UNAUTH_PER_MIN, AUTH_PER_MIN)
    }
}

impl RateLimiter {
    #[must_use]
    pub fn new(unauth_per_min: u32, auth_per_min: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            unauth_per_min,
            auth_per_min,
        }
    }

    /// Record a hit. Returns `Ok(())` if under budget, or `Err(retry_after)`
    /// (seconds until the window resets) if the limit is exceeded.
    #[allow(clippy::significant_drop_tightening)]
    fn check(&self, ip: IpAddr, authenticated: bool) -> Result<(), u64> {
        let limit = if authenticated {
            self.auth_per_min
        } else {
            self.unauth_per_min
        };
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let window = buckets.entry((ip, authenticated)).or_insert(Window {
            count: 0,
            started: now,
        });

        if now.duration_since(window.started) >= WINDOW {
            window.count = 0;
            window.started = now;
        }
        window.count = window.count.saturating_add(1);

        if window.count > limit {
            let elapsed = now.duration_since(window.started);
            let retry_after = WINDOW.saturating_sub(elapsed).as_secs().max(1);
            Err(retry_after)
        } else {
            Ok(())
        }
    }
}

/// Middleware entrypoint, wired via `from_fn_with_state(limiter, layer)`.
pub async fn layer(State(limiter): State<RateLimiter>, req: Request, next: Next) -> Response {
    let ip = client_ip(req.headers());
    let authenticated = req.headers().contains_key(header::AUTHORIZATION);

    match limiter.check(ip, authenticated) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            let rid = req
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_owned();
            let mut resp = Problem::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too Many Requests",
                Some("rate limit exceeded; retry later".to_owned()),
                &rid,
            )
            .into_response_with_status(StatusCode::TOO_MANY_REQUESTS);
            if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, val);
            }
            resp.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let rl = RateLimiter::new(3, 100);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(rl.check(ip, false).is_ok());
        assert!(rl.check(ip, false).is_ok());
        assert!(rl.check(ip, false).is_ok());
        // 4th exceeds limit of 3
        let err = rl.check(ip, false);
        assert!(err.is_err());
        assert!(err.unwrap_err() >= 1, "retry-after must be >= 1s");
    }

    #[test]
    fn authenticated_has_separate_higher_budget() {
        let rl = RateLimiter::new(1, 5);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        // Unauth budget of 1 exhausts immediately on 2nd.
        assert!(rl.check(ip, false).is_ok());
        assert!(rl.check(ip, false).is_err());
        // Authenticated bucket is independent and larger.
        assert!(rl.check(ip, true).is_ok());
        assert!(rl.check(ip, true).is_ok());
    }
}
