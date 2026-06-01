//! Identity & session endpoints (Phase 1).

pub mod extractor;
pub mod handlers;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

pub use extractor::{AuthUser, SuperadminUser};

const UNKNOWN_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Read the request id the middleware stamped onto the request headers.
#[must_use]
pub fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_owned()
}

/// Best-effort client IP from reverse-proxy headers, else unspecified.
/// Production must set `x-forwarded-for`/`x-real-ip` at the proxy.
#[must_use]
pub fn client_ip(headers: &HeaderMap) -> IpAddr {
    let from_header = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .and_then(|s| s.parse::<IpAddr>().ok());
    from_header.unwrap_or(UNKNOWN_IP)
}

#[must_use]
pub fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

/// SHA-256 hex of a string, used to avoid storing raw identifiers in
/// `login_attempts`.
#[must_use]
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Progressive lockout curve. Returns the delay to apply before responding to
/// a login attempt given the number of recent failures (per IP/identifier).
///
/// - < 4 failures: no delay
/// - otherwise: 2^(failures-3) seconds, capped at 30s
///
/// So the 6th attempt (5 prior failures) delays 4s, satisfying the policy.
#[must_use]
pub fn lockout_delay(failures: i64) -> Duration {
    if failures < 4 {
        return Duration::ZERO;
    }
    let exponent = u32::try_from(failures.saturating_sub(3))
        .unwrap_or(u32::MAX)
        .min(5);
    let secs = 2u64.saturating_pow(exponent).min(30);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_curve() {
        assert_eq!(lockout_delay(0), Duration::ZERO);
        assert_eq!(lockout_delay(3), Duration::ZERO);
        assert_eq!(lockout_delay(4), Duration::from_secs(2));
        // 6th attempt sees 5 prior failures → >= 4s
        assert!(lockout_delay(5) >= Duration::from_secs(4));
        assert_eq!(lockout_delay(5), Duration::from_secs(4));
        assert_eq!(lockout_delay(6), Duration::from_secs(8));
        // capped at 30s
        assert_eq!(lockout_delay(100), Duration::from_secs(30));
    }

    #[test]
    fn sha256_hex_is_64_hex_chars() {
        let h = sha256_hex("alice@example.com");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, sha256_hex("alice@example.com"));
        assert_ne!(h, sha256_hex("bob@example.com"));
    }
}
