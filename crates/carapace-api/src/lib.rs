//! carapace-api: the loopback control API for the Carapace daemon.
//!
//! This crate fronts a process that holds `K_root` and vault plaintext, so it is a
//! trust boundary. It binds `127.0.0.1` ONLY, mints a per-session bearer token, and
//! gates every privileged request behind that token (constant-time), a loopback
//! `Host` check (DNS-rebinding defense), and a loopback `Origin` check (CSRF
//! defense). See [`auth`] for the guards and [`handlers`] for the endpoints.
//!
//! Public routes (no token): `GET /api/health`, the WebSocket `GET /api/events`
//! (which validates the token from a query parameter instead, since browsers cannot
//! set an `Authorization` header on a WS handshake), and the embedded static GUI.
//!
//! The GUI is embedded with `rust-embed` from `static/` (the SvelteKit build). The
//! served `index.html` gets the session token injected as `window.__CARAPACE_TOKEN__`
//! under a strict per-response CSP nonce; see [`handlers::static_asset`].

mod auth;
mod handlers;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use carapaced::{Daemon, MaintenanceConfig, MaintenanceHandle};

/// Shared handler state: the daemon and the per-session token.
#[derive(Clone)]
pub struct AppState {
    /// The daemon this API fronts.
    pub daemon: Arc<Daemon>,
    /// The per-session bearer token (hex of 32 CSPRNG bytes).
    pub token: Arc<str>,
}

/// A running control API. Dropping or [`ApiServer::shutdown`] stops it.
pub struct ApiServer {
    /// The per-session bearer token, also written to `<state_dir>/api-token`.
    pub token: String,
    /// The actual bound loopback address (the port is concrete even if 0 was asked).
    pub local_addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    /// The daemon's background maintenance loop (§10.1/§10.2), torn down with the API.
    _maintenance: MaintenanceHandle,
}

impl ApiServer {
    /// The base URL the GUI/clients hit.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Stop serving.
    pub fn shutdown(self) {
        self.handle.abort();
    }
}

/// Assemble the router: token-gated `/api` action routes, the public health check
/// and WebSocket events feed, and the embedded GUI fallback, all wrapped in the
/// global Host/Origin guard.
pub fn app(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/status", get(handlers::status))
        .route(
            "/api/vaults",
            get(handlers::list_vaults).post(handlers::publish_vault),
        )
        .route(
            "/api/vaults/{vid}/replicas",
            get(handlers::list_replicas).post(handlers::place_replicas),
        )
        .route("/api/vaults/{vid}/grants", post(handlers::disclose))
        .route(
            "/api/friends",
            get(handlers::list_friends).post(handlers::add_friend),
        )
        .route("/api/friends/ticket", post(handlers::issue_ticket))
        .route(
            "/api/friends/{user_pubkey}/unfriend",
            post(handlers::unfriend),
        )
        .route("/api/grants/fetch", post(handlers::fetch_grant))
        .route("/api/recovery/split", post(handlers::recovery_split))
        .route("/api/recovery/extend", post(handlers::recovery_extend))
        .route("/api/recovery/resplit", post(handlers::recovery_resplit))
        .route(
            "/api/recovery/{rsid}/resplit-status",
            get(handlers::resplit_status),
        )
        .route(
            "/api/recovery/{rsid}/resplit-start",
            post(handlers::resplit_start),
        )
        .route("/api/recovery/{rsid}/paper", get(handlers::recovery_paper))
        .route("/api/recovery/ceremony", get(handlers::ceremony_status))
        .route("/api/recovery/ceremony/open", post(handlers::ceremony_open))
        .route(
            "/api/recovery/ceremony/approve",
            post(handlers::ceremony_approve),
        )
        .route(
            "/api/recovery/ceremony/abort",
            post(handlers::ceremony_abort),
        )
        .layer(middleware::from_fn_with_state(
            state.token.clone(),
            auth::require_token,
        ));

    let public = Router::new()
        .route("/api/health", get(handlers::health))
        .route("/api/events", get(handlers::events));

    // `with_state` is applied once at the end so the static/SPA fallback (which reads
    // the session token to inject it) shares the same `AppState` as the `/api` routes.
    Router::new()
        .merge(protected)
        .merge(public)
        .fallback(handlers::static_asset)
        .layer(middleware::from_fn(auth::guard_host_origin))
        .with_state(state)
}

/// Generate a 32-byte CSPRNG token, hex-encode it, and write it to
/// `<state_dir>/api-token` with `0600` permissions on unix.
fn mint_and_write_token(state_dir: &Path) -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow::anyhow!("generate api token: {e}"))?;
    let token = hex::encode(raw);
    write_token_file(&state_dir.join("api-token"), &token)?;
    Ok(token)
}

/// Write the token so it is `0600` from the instant it exists - never a window
/// where another local user can read `K_root`'s gate. `O_CREAT|O_EXCL` (`create_new`)
/// also refuses to follow a pre-planted symlink: an existing path (regular file or
/// symlink) fails `EEXIST` rather than redirecting the write. A regular stale file
/// from a prior session is unlinked first; a symlink is refused outright.
#[cfg(unix)]
fn write_token_file(path: &Path, token: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!("refusing to write api token through symlink {path:?}");
        }
        Ok(_) => {
            std::fs::remove_file(path).with_context(|| format!("remove stale token {path:?}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat token path {path:?}")),
    }

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create token {path:?} (0600, no-follow)"))?;
    f.write_all(token.as_bytes())
        .with_context(|| format!("write {path:?}"))
}

#[cfg(not(unix))]
fn write_token_file(path: &Path, token: &str) -> Result<()> {
    // ponytail: no OS-ACL restriction here (needs a Windows-specific crate). The
    // token still gates every request; tighten the file ACL on non-unix if the
    // state dir is shared.
    std::fs::write(path, token).with_context(|| format!("write {path:?}"))
}

/// Start the loopback control API for `daemon`.
///
/// Binds `127.0.0.1:port` (use `0` for an ephemeral port) - and refuses to bind
/// anything that is not loopback. Mints the per-session token, writes it to
/// `<state_dir>/api-token` (0600), publishes the bound URL to `<state_dir>/api-url`
/// so the CLI can discover the ephemeral port, and spawns the server. Returns
/// immediately with the bound address and token.
pub async fn serve(daemon: Arc<Daemon>, state_dir: &Path, port: u16) -> Result<ApiServer> {
    let token = mint_and_write_token(state_dir)?;

    // Loopback ONLY. This is the trust boundary: a non-loopback bind would expose a
    // process holding K_root to the network. The address is constructed loopback, so
    // this assertion is a belt-and-braces guard against a future refactor.
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    ensure!(
        addr.ip().is_loopback(),
        "refusing to bind non-loopback address {addr}"
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind loopback control API on {addr}"))?;
    let local_addr = listener.local_addr().context("read bound local addr")?;

    // Publish the actually-bound URL so the CLI can discover it from the state dir
    // (the port is ephemeral by default, so a guessed default would point where the
    // daemon isn't). Not secret - readable is fine, unlike the token.
    let url = format!("http://{local_addr}");
    let url_path = state_dir.join("api-url");
    std::fs::write(&url_path, &url).with_context(|| format!("write {url_path:?}"))?;

    // Start the daemon's background maintenance loop (§10.1 PoR+repair, §10.2
    // attestation cadence + self-validation + drift) alongside the API. The API is
    // the production entry point that already holds an `Arc<Daemon>`; the loop holds
    // only a `Weak` and is torn down when this `ApiServer` drops.
    let maintenance = Arc::clone(&daemon).run_maintenance(MaintenanceConfig::default());

    let state = AppState {
        daemon,
        token: Arc::from(token.as_str()),
    };
    let app = app(state);

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("carapace-api: server exited: {e}");
        }
    });

    Ok(ApiServer {
        token,
        local_addr,
        handle,
        _maintenance: maintenance,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::write_token_file;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn token_file_is_0600_from_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token");
        write_token_file(&path, "sekret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "token must be 0600, not umask-default");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sekret");
    }

    #[test]
    fn refuses_to_follow_a_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("attacker-readable");
        let path = dir.path().join("api-token");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let err = write_token_file(&path, "sekret").unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(
            !target.exists(),
            "token must not be written through the symlink"
        );
    }

    #[test]
    fn overwrites_a_stale_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token");
        std::fs::write(&path, "old-loose-perms").unwrap();
        write_token_file(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "rewritten token must be 0600");
    }
}
