//! Trust-boundary integration tests for the loopback control API.
//!
//! These start a REAL daemon + API on `127.0.0.1:0` and drive it over raw TCP so we
//! control every header (`Host`, `Origin`, `Authorization`) exactly - the point is
//! to attack the boundary the way a hostile local web page or a token-less client
//! would.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use carapace_api::{serve, ApiServer};
use carapaced::{Daemon, State};

/// Boot a daemon + API bound to an ephemeral loopback port. Returns the server, the
/// daemon (to read its node id), and the temp state dir (kept alive for the token).
async fn boot() -> (ApiServer, Arc<Daemon>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = State::from_seeds([7u8; 32], [9u8; 32]);
    let daemon = Arc::new(Daemon::start(state).await.unwrap());
    let api = serve(Arc::clone(&daemon), dir.path(), 0).await.unwrap();
    (api, daemon, dir)
}

/// Fire a raw HTTP/1.1 request and return `(status_code, full_response_text)`. Sends
/// `Connection: close` unless the caller already asked to upgrade, so a normal
/// response reads cleanly to EOF; a `101` upgrade is read up to a short timeout.
fn raw(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break, // timeout (e.g. an upgraded socket that stays open)
        }
        if buf.len() > 1 << 20 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let code = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (code, text)
}

fn get(addr: SocketAddr, path: &str, extra: &str) -> (u16, String) {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{extra}Connection: close\r\n\r\n",
        addr.port()
    );
    raw(addr, &req)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_is_open_without_a_token() {
    let (api, _d, _dir) = boot().await;
    let (code, body) = get(api.local_addr, "/api/health", "");
    assert_eq!(code, 200, "health must be reachable without auth: {body}");
    assert!(body.contains("\"ok\":true"), "body: {body}");
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_requires_the_bearer_token() {
    let (api, daemon, _dir) = boot().await;
    let addr = api.local_addr;

    // No token -> 401.
    let (code, _) = get(addr, "/api/status", "");
    assert_eq!(code, 401, "missing token must be 401");

    // Wrong token (same length as the real 64-hex token) -> 401. This exercises the
    // constant-time compare's equal-length, mismatched-content path.
    let wrong = "0".repeat(64);
    let (code, _) = get(
        addr,
        "/api/status",
        &format!("Authorization: Bearer {wrong}\r\n"),
    );
    assert_eq!(code, 401, "wrong token must be 401");

    // A short wrong token (unequal length) -> also 401.
    let (code, _) = get(addr, "/api/status", "Authorization: Bearer short\r\n");
    assert_eq!(code, 401, "short token must be 401");

    // Correct token -> 200, and the reported node id matches the real daemon.
    let (code, body) = get(
        addr,
        "/api/status",
        &format!("Authorization: Bearer {}\r\n", api.token),
    );
    assert_eq!(code, 200, "correct token must be 200: {body}");
    let node_hex = hex::encode(daemon.node_id());
    assert!(
        body.contains(&node_hex),
        "status must report the real node id {node_hex}: {body}"
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_loopback_host_is_rejected() {
    let (api, _d, _dir) = boot().await;
    // Even the public health check is refused when the Host is not loopback: this is
    // the DNS-rebinding defense (a hostile name resolving to 127.0.0.1 still carries
    // its own Host).
    let req = "GET /api/health HTTP/1.1\r\nHost: evil.com\r\nConnection: close\r\n\r\n";
    let (code, _) = raw(api.local_addr, req);
    assert_eq!(code, 403, "non-loopback Host must be forbidden");
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_origin_is_rejected_even_with_token() {
    let (api, _d, _dir) = boot().await;
    // A valid token does NOT save a cross-site browser request: a non-loopback Origin
    // is refused (CSRF defense).
    let (code, _) = get(
        api.local_addr,
        "/api/status",
        &format!(
            "Authorization: Bearer {}\r\nOrigin: http://evil.com\r\n",
            api.token
        ),
    );
    assert_eq!(code, 403, "cross-origin request must be forbidden");
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_upgrade_requires_the_token() {
    let (api, _d, _dir) = boot().await;
    let addr = api.local_addr;
    let ws_headers = "Upgrade: websocket\r\nConnection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";

    // Valid WS handshake headers but NO token -> 401, no upgrade.
    let req = format!(
        "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{ws_headers}\r\n",
        addr.port()
    );
    let (code, _) = raw(addr, &req);
    assert_eq!(code, 401, "WS upgrade without a token must be 401");

    // With the token in the query string -> 101 Switching Protocols.
    let req = format!(
        "GET /api/events?token={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{ws_headers}\r\n",
        api.token,
        addr.port()
    );
    let (code, _) = raw(addr, &req);
    assert_eq!(code, 101, "WS upgrade with the token must switch protocols");
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_file_is_written_owner_only() {
    let (api, _d, dir) = boot().await;
    let path = dir.path().join("api-token");
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        contents, api.token,
        "token file must hold the session token"
    );
    assert_eq!(contents.len(), 64, "token is 32 bytes hex");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "token file must be 0600");
    }
    api.shutdown();
}

/// Split a raw HTTP/1.1 response into `(headers_block, body)`.
fn split_response(resp: &str) -> (&str, &str) {
    match resp.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => (resp, ""),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn index_injects_the_token_and_references_built_assets() {
    let (api, _d, _dir) = boot().await;
    let (code, resp) = get(api.local_addr, "/", "");
    assert_eq!(code, 200, "GET / must serve the shell: {resp}");
    let (headers, body) = split_response(&resp);

    // The session token is injected verbatim into a script the page can read.
    let inject = format!("window.__CARAPACE_TOKEN__=\"{}\"", api.token);
    assert!(
        body.contains(&inject),
        "index must inject the session token: {body}"
    );

    // The built SvelteKit bundle is referenced (immutable entry + stylesheet).
    assert!(
        body.contains("/_app/immutable/"),
        "index must reference built assets: {body}"
    );

    // The token page is not cacheable, is nosniff, and carries the strict CSP.
    let lower = headers.to_ascii_lowercase();
    assert!(lower.contains("cache-control: no-store"), "{headers}");
    assert!(
        lower.contains("x-content-type-options: nosniff"),
        "{headers}"
    );
    assert!(
        lower.contains("content-security-policy:"),
        "must set a CSP: {headers}"
    );
    assert!(lower.contains("default-src 'self'"), "{headers}");
    // `connect-src` is same-origin only: no loopback wildcards that would let a
    // post-XSS script beacon to other local ports.
    assert!(lower.contains("connect-src 'self';"), "{headers}");
    assert!(
        !lower.contains("ws://"),
        "no ws:// wildcards in CSP: {headers}"
    );
    assert!(lower.contains("object-src 'none'"), "{headers}");
    assert!(lower.contains("frame-ancestors 'none'"), "{headers}");
    assert!(lower.contains("base-uri 'none'"), "{headers}");
    // The inline token script must run under a nonce, never 'unsafe-inline' scripts.
    assert!(
        lower.contains("script-src 'self' 'nonce-"),
        "script-src must be nonce-gated: {headers}"
    );
    assert!(
        !lower.contains("'unsafe-inline'") || !lower.contains("script-src 'self' 'unsafe-inline'"),
        "inline scripts must not be blanket-allowed: {headers}"
    );

    // The injected script and SvelteKit's bootstrap both carry that nonce.
    let nonce = headers
        .lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with("content-security-policy:")
        })
        .and_then(|l| l.split("'nonce-").nth(1))
        .and_then(|s| s.split('\'').next())
        .expect("csp carries a nonce");
    assert_eq!(nonce.len(), 32, "nonce is 16 bytes hex: {nonce}");
    let nonced = format!("<script nonce=\"{nonce}\">");
    assert!(
        body.matches(&nonced).count() >= 2,
        "both inline scripts must carry the nonce: {body}"
    );

    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn built_asset_is_served_with_a_sane_content_type() {
    let (api, _d, _dir) = boot().await;
    // Pull a real hashed JS path out of the served index rather than hardcoding it.
    let (_c, index) = get(api.local_addr, "/", "");
    let js_path = index
        .split('"')
        .find(|s| s.starts_with("/_app/immutable/") && s.ends_with(".js"))
        .expect("index references a built JS asset")
        .to_string();

    let (code, resp) = get(api.local_addr, &js_path, "");
    assert_eq!(code, 200, "built asset must be 200: {resp}");
    let (headers, _body) = split_response(&resp);
    let lower = headers.to_ascii_lowercase();
    assert!(
        lower.contains("content-type: text/javascript")
            || lower.contains("content-type: application/javascript"),
        "JS must have a JS content-type: {headers}"
    );
    assert!(
        lower.contains("x-content-type-options: nosniff"),
        "assets must be nosniff: {headers}"
    );

    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spa_fallback_serves_the_shell_for_unknown_routes() {
    let (api, _d, _dir) = boot().await;
    let (code, resp) = get(api.local_addr, "/vaults/deep/link", "");
    assert_eq!(
        code, 200,
        "unknown route must fall back to the shell: {resp}"
    );
    let (_h, body) = split_response(&resp);
    assert!(
        body.contains("window.__CARAPACE_TOKEN__="),
        "fallback shell must still inject the token: {body}"
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_api_path_is_404_json_not_the_token_shell() {
    let (api, _d, _dir) = boot().await;
    // An unmatched `/api/*` path is a missing endpoint: it must 404 as JSON, never
    // fall through to the token-injected SPA shell (which would echo the token).
    let (code, resp) = get(
        api.local_addr,
        "/api/does-not-exist",
        &format!("Authorization: Bearer {}\r\n", api.token),
    );
    assert_eq!(code, 404, "unknown /api path must be 404: {resp}");
    let (_h, body) = split_response(&resp);
    assert!(
        !body.contains("window.__CARAPACE_TOKEN__="),
        "unknown /api path must not serve the token shell: {resp}"
    );
    assert!(body.contains("\"error\""), "404 body must be JSON: {resp}");
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_page_is_not_served_cross_origin() {
    let (api, _d, _dir) = boot().await;
    // A cross-site page's request carries a non-loopback Origin. The global guard must
    // refuse it BEFORE the shell (and thus the embedded token) is ever rendered.
    let (code, resp) = get(api.local_addr, "/", "Origin: http://evil.com\r\n");
    assert_eq!(
        code, 403,
        "cross-origin request for the shell must be forbidden"
    );
    assert!(
        !resp.contains(&api.token),
        "the token must never appear in a cross-origin response: {resp}"
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_split_round_trips_over_the_api() {
    let (api, _d, _dir) = boot().await;
    let body = r#"{"rsid":1,"scope":{"kind":"root"},"m":2,"n":3}"#;
    let req = format!(
        "POST /api/recovery/split HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\
         Authorization: Bearer {}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        api.local_addr.port(),
        api.token,
        body.len()
    );
    let (code, resp) = raw(api.local_addr, &req);
    assert_eq!(code, 200, "split must succeed: {resp}");
    assert!(
        resp.contains("\"shares\""),
        "response must carry shares: {resp}"
    );
    assert!(!resp.contains("\"error\""), "no error expected: {resp}");
    api.shutdown();
}
