//! The loopback trust-boundary guards for the control API.
//!
//! `carapace-api` fronts a process holding `K_root` and vault plaintext, so every
//! request must clear three independent checks:
//!
//! 1. **Host** (`guard_host_origin`): the `Host` header must name a loopback host
//!    (`127.0.0.1`/`localhost`/`::1`, any port). A missing or non-loopback `Host`
//!    is refused, which blocks DNS-rebinding (a malicious name that resolves to
//!    `127.0.0.1` still carries its own hostname in `Host`).
//! 2. **Origin** (`guard_host_origin`): when an `Origin` header is present it must
//!    be a loopback origin, or the request is refused. A cross-site page in the
//!    user's browser therefore cannot drive the API (CSRF defense). A non-browser
//!    client (curl, the daemon's own tooling) sends no `Origin` and is allowed.
//! 3. **Bearer token** (`require_token`): every non-public route must carry
//!    `Authorization: Bearer <token>` matching the per-session token, compared in
//!    CONSTANT TIME. Missing or wrong => 401.
//!
//! The WebSocket route validates the token from a query parameter (browsers cannot
//! set an `Authorization` header on a `WebSocket` handshake), using the same
//! constant-time comparison. See `handlers::events`.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

/// Constant-time string comparison. `subtle`'s slice `ct_eq` returns a false
/// `Choice` for unequal lengths without early-return, so token length (a fixed,
/// public 64 hex chars) is the only thing a timing side channel could reveal.
#[must_use]
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Whether `host` (a `Host`/`:authority` value, with or without a port) names a
/// loopback host. Accepts `localhost`, and any address that parses as a loopback
/// IP (`127.0.0.0/8`, `::1`). Everything else - including a public name that
/// happens to resolve to loopback - is rejected.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    let hostname = if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]` or `[::1]:port`.
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return false,
        }
    } else {
        // `host:port` only when there is exactly one colon and the tail is a port;
        // a bare IPv6 literal (multiple colons) is left intact.
        match host.rsplit_once(':') {
            Some((h, port))
                if !h.contains(':')
                    && !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                h
            }
            _ => host,
        }
    };
    hostname == "localhost"
        || hostname
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Whether `origin` (a `scheme://host[:port]` Origin header) is a loopback origin.
/// A `null` origin, an opaque origin, or any non-loopback host is rejected.
#[must_use]
pub fn is_loopback_origin(origin: &str) -> bool {
    let Some((_scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    // An Origin has no path, but be defensive and cut anything after the authority.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    is_loopback_host(authority)
}

/// DNS-rebinding + CSRF guard applied to EVERY request (including the health check
/// and the static GUI). Rejects a non-loopback `Host`, and a present-but-non-loopback
/// `Origin`.
pub async fn guard_host_origin(req: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = req.headers();
    let host_ok = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(is_loopback_host)
        .unwrap_or(false);
    if !host_ok {
        return Err(StatusCode::FORBIDDEN);
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !is_loopback_origin(origin) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(next.run(req).await)
}

/// Bearer-token guard applied to every protected route. Missing or wrong token =>
/// 401. The comparison is constant-time (`ct_eq_str`).
pub async fn require_token(
    State(token): State<Arc<str>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let presented = bearer(req.headers().get(header::AUTHORIZATION));
    match presented {
        Some(t) if ct_eq_str(t, &token) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Extract the token from an `Authorization: Bearer <token>` header value.
fn bearer(value: Option<&axum::http::HeaderValue>) -> Option<&str> {
    let s = value?.to_str().ok()?;
    let (scheme, token) = s.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(token.trim())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts_accepted() {
        for h in [
            "127.0.0.1",
            "127.0.0.1:8080",
            "localhost",
            "localhost:3000",
            "::1",
            "[::1]",
            "[::1]:8080",
            "127.0.0.5:9",
        ] {
            assert!(is_loopback_host(h), "{h} should be loopback");
        }
    }

    #[test]
    fn non_loopback_hosts_rejected() {
        for h in [
            "evil.com",
            "evil.com:8080",
            "10.0.0.1",
            "1.2.3.4:80",
            "attacker.localhost.evil.com",
            "",
        ] {
            assert!(!is_loopback_host(h), "{h} must be rejected");
        }
    }

    #[test]
    fn origins() {
        assert!(is_loopback_origin("http://127.0.0.1:8080"));
        assert!(is_loopback_origin("http://localhost"));
        assert!(is_loopback_origin("https://[::1]:9000"));
        assert!(!is_loopback_origin("http://evil.com"));
        assert!(!is_loopback_origin("null"));
        assert!(!is_loopback_origin("https://127.0.0.1.evil.com"));
    }

    #[test]
    fn constant_time_compare_matches_semantics() {
        let t = "a".repeat(64);
        assert!(ct_eq_str(&t, &t));
        assert!(!ct_eq_str(&t, &"b".repeat(64)));
        assert!(!ct_eq_str(&t, "short"));
        assert!(!ct_eq_str(&t, ""));
    }
}
