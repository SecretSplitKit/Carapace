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
