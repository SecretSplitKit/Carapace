//! JSON action + status handlers over an `Arc<Daemon>`. Every handler here sits
//! behind the loopback guards in [`crate::auth`] (the token guard, plus the global
//! Host/Origin guard); `health`, `events`, and the static GUI are the documented
//! exceptions to the token requirement (see [`crate::app`]).

use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use carapace_wire::messages::Message as _;
use carapace_wire::{CeremonyApprove, FileGrant, InviteTicket, RecoveryOpen, ShareGrant};
use carapaced::{Daemon, RecoveryScope};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth, AppState};

// ---- embedded GUI ------------------------------------------------------

#[derive(rust_embed::RustEmbed)]
#[folder = "static/"]
struct Assets;

/// Serve an embedded GUI asset, falling back to the token-injected `index.html` for
/// `/` and any unmatched non-`/api` path so a client-routed SPA works. No token auth:
/// the shell carries no secrets by itself and drives every privileged action through
/// the token-gated `/api` routes. The Host/Origin guard still applies (global layer),
/// so `index.html` - which DOES embed the session token - is only ever handed to a
/// same-origin loopback request; a cross-origin page cannot read it (same-origin
/// policy) even if it could reach the port.
pub async fn static_asset(State(st): State<AppState>, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    // An unmatched `/api/*` path is a missing endpoint, not a client route: 404 JSON,
    // never the token-injected shell. Only non-`/api` paths get the SPA fallback.
    if path == "api" || path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response();
    }
    // `index.html` must always route through injection, never be served raw.
    if path.is_empty() || path == "index.html" {
        return serve_index(&st.token);
    }
    match Assets::get(path) {
        Some(file) => (
            [
                (header::CONTENT_TYPE, file.metadata.mimetype()),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            file.data.into_owned(),
        )
            .into_response(),
        // SPA fallback: an unknown path is a client route, not a 404.
        None => serve_index(&st.token),
    }
}

/// A per-response CSP nonce: 16 CSPRNG bytes, hex. Unpredictable per response, so an
/// injected inline `<script>` cannot be forged by anything that didn't see this page.
fn gen_nonce() -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    Some(hex::encode(raw))
}

/// The session token is a 64-char lowercase-hex CSPRNG value (`hex::encode` of 32
/// bytes). Asserting the shape before injection guarantees it cannot break out of the
/// `<script>` context - there is no quote, angle bracket, or slash it could carry.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Inject the session token as `window.__CARAPACE_TOKEN__` and add the CSP nonce to
/// every inline `<script>` (the injected token script and SvelteKit's bootstrap), so
/// both run under a strict `script-src 'self' 'nonce-...'`. Returns `None` if the
/// token is not well-formed hex or the shell has no `</head>` to inject before - both
/// are impossible in practice and are treated as a loud 500 by the caller, never as a
/// tokenless page.
fn render_index(html: &str, token: &str, nonce: &str) -> Option<String> {
    if !is_hex64(token) || !html.contains("</head>") {
        return None;
    }
    let with_nonce = html.replace("<script>", &format!("<script nonce=\"{nonce}\">"));
    let inject =
        format!("<script nonce=\"{nonce}\">window.__CARAPACE_TOKEN__=\"{token}\"</script>");
    Some(with_nonce.replacen("</head>", &format!("{inject}</head>"), 1))
}

/// Serve the SPA shell with the token injected, a strict CSP, `nosniff`, and
/// `no-store` (the page embeds the session token, so it must never be cached).
fn serve_index(token: &str) -> Response {
    let Some(file) = Assets::get("index.html") else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "gui shell not embedded").into_response();
    };
    let html = String::from_utf8_lossy(&file.data);
    let Some(nonce) = gen_nonce() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "csprng unavailable").into_response();
    };
    let Some(rendered) = render_index(&html, token, &nonce) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "cannot render shell").into_response();
    };
    // No external origins. `script-src` is `'self'` plus this response's nonce; inline
    // style attributes in the built shell (e.g. `style="display: contents"`) force
    // `style-src 'unsafe-inline'`. The WS events feed is same-origin (the client builds
    // it from `location.host`), which `connect-src 'self'` covers under CSP Level 3 - no
    // loopback wildcards, so a post-XSS script can't beacon to other local ports.
    let csp = format!(
        "default-src 'self'; \
         script-src 'self' 'nonce-{nonce}'; \
         connect-src 'self'; \
         img-src 'self' data:; \
         style-src 'self' 'unsafe-inline'; \
         font-src 'self'; \
         object-src 'none'; \
         base-uri 'none'; \
         frame-ancestors 'none'"
    );
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, csp.as_str()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        rendered,
    )
        .into_response()
}

// ---- error type --------------------------------------------------------

/// A handler error rendered as a JSON body with an HTTP status.
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

/// A 400 from a bad-input message.
fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], ApiError> {
    let v = hex::decode(s).map_err(|_| bad(format!("invalid hex: {s}")))?;
    v.try_into()
        .map_err(|_| bad(format!("expected 32 bytes, got a different length: {s}")))
}

fn parse_hex16(s: &str) -> Result<[u8; 16], ApiError> {
    let v = hex::decode(s).map_err(|_| bad(format!("invalid hex: {s}")))?;
    v.try_into()
        .map_err(|_| bad(format!("expected 16 bytes: {s}")))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- health + status ---------------------------------------------------

/// `GET /api/health` (no auth): a liveness probe.
pub async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

/// Build the status snapshot pushed over WS and returned by `GET /api/status`.
fn status_snapshot(d: &Daemon) -> Value {
    let friends: Vec<String> = d.friend_ids().iter().map(|f| hexs(f)).collect();
    let vaults: Vec<Value> = d
        .published_vaults()
        .iter()
        .map(|(v, e)| json!({ "vid": hexs(v), "epoch": e }))
        .collect();
    let held: Vec<String> = d.held_replica_vids().iter().map(|v| hexs(v)).collect();
    let (sets, shares) = d.share_health_counts();
    let relay_url = d.advertised_relay_url();
    // W4 (§6 MUST): warn when the usable relay set spans fewer than 2 distinct
    // networks - a single relay is a single point of failure and metadata choke.
    let relay_networks = d.relay_network_count();
    json!({
        "node_id": hexs(&d.node_id()),
        "addr": d.dialable_addr_strings(),
        "relay_url": relay_url,
        "friends": { "count": friends.len(), "list": friends },
        "vaults": { "published": vaults, "held_replicas": held },
        "share_health": { "recovery_sets_owned": sets, "shares_held": shares },
        "reachability": if relay_url.is_some() { "relay" } else { "direct" },
        "relay_networks": relay_networks,
        "relay_diversity_warning": relay_networks < 2,
    })
}

/// `GET /api/status`.
pub async fn status(State(st): State<AppState>) -> Json<Value> {
    Json(status_snapshot(&st.daemon))
}

// ---- vaults ------------------------------------------------------------

#[derive(Deserialize)]
pub struct PublishReq {
    dir: String,
    vid: Option<String>,
}

/// `POST /api/vaults`: ingest + publish a directory as a vault.
pub async fn publish_vault(
    State(st): State<AppState>,
    Json(req): Json<PublishReq>,
) -> Result<Json<Value>, ApiError> {
    let vid = match req.vid {
        Some(h) => parse_hex32(&h)?,
        None => st.daemon.new_vid().0,
    };
    let epoch = st
        .daemon
        .publish_vault(std::path::Path::new(&req.dir), vid)
        .await?;
    Ok(Json(json!({ "vid": hexs(&vid), "epoch": epoch })))
}

/// `GET /api/vaults`.
pub async fn list_vaults(State(st): State<AppState>) -> Json<Value> {
    let vaults: Vec<Value> = st
        .daemon
        .published_vaults()
        .iter()
        .map(|(v, e)| json!({ "vid": hexs(v), "epoch": e }))
        .collect();
    Json(json!({ "published": vaults }))
}

// ---- friends -----------------------------------------------------------

/// `POST /api/friends/ticket`: issue a single-use invite ticket.
pub async fn issue_ticket(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let ticket = st.daemon.issue_ticket()?;
    Ok(Json(json!({
        "uri": ticket.uri(),
        "ticket_hex": hexs(&ticket.encode_frame()),
        "node_id": hexs(&st.daemon.node_id()),
        "addrs": st.daemon.dialable_addr_strings(),
        "relay_urls": ticket.relay_urls,
    })))
}

#[derive(Deserialize)]
pub struct AddFriendReq {
    ticket_hex: String,
    addrs: Option<Vec<String>>,
    grant_bytes: Option<u64>,
}

/// `POST /api/friends`: befriend via a ticket + optional storage grant.
pub async fn add_friend(
    State(st): State<AppState>,
    Json(req): Json<AddFriendReq>,
) -> Result<Json<Value>, ApiError> {
    let bytes = hex::decode(&req.ticket_hex).map_err(|_| bad("invalid ticket hex"))?;
    let ticket =
        InviteTicket::decode_frame(&bytes).map_err(|e| bad(format!("decode ticket: {e}")))?;
    ticket
        .verify()
        .map_err(|e| bad(format!("ticket signature invalid: {e}")))?;
    let addrs = req.addrs.unwrap_or_else(|| ticket.addrs.clone());
    let friendship = st
        .daemon
        .befriend_at(ticket.node, &addrs, &ticket, req.grant_bytes)
        .await?;
    Ok(Json(json!({
        "friend": hexs(&ticket.user),
        "established": friendship.established,
    })))
}

/// `GET /api/friends`.
pub async fn list_friends(State(st): State<AppState>) -> Json<Value> {
    let list: Vec<String> = st.daemon.friend_ids().iter().map(|f| hexs(f)).collect();
    Json(json!({ "count": list.len(), "list": list }))
}

// ---- replicas ----------------------------------------------------------

#[derive(Deserialize)]
pub struct PeerReq {
    node: String,
    addrs: Vec<String>,
}

#[derive(Deserialize)]
pub struct PlaceReq {
    peers: Vec<PeerReq>,
    r: usize,
}

/// `POST /api/vaults/{vid}/replicas`: place replicas on friend peers.
pub async fn place_replicas(
    Path(vid_hex): Path<String>,
    State(st): State<AppState>,
    Json(req): Json<PlaceReq>,
) -> Result<Json<Value>, ApiError> {
    let vid = parse_hex32(&vid_hex)?;
    let mut peers = Vec::with_capacity(req.peers.len());
    for p in &req.peers {
        peers.push((parse_hex32(&p.node)?, p.addrs.clone()));
    }
    let placed = st.daemon.place_replicas_at(vid, &peers, req.r).await?;
    Ok(Json(json!({
        "placed": placed.iter().map(|n| hexs(n)).collect::<Vec<_>>(),
    })))
}

/// `GET /api/vaults/{vid}/replicas`.
pub async fn list_replicas(
    Path(vid_hex): Path<String>,
    State(st): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let vid = parse_hex32(&vid_hex)?;
    let members: Vec<String> = st
        .daemon
        .replica_members(&vid)
        .iter()
        .map(|n| hexs(n))
        .collect();
    Ok(Json(json!({ "members": members })))
}

// ---- selective disclosure (§7.4) --------------------------------------

#[derive(Deserialize)]
pub struct DiscloseReq {
    paths: Vec<String>,
    audience: Vec<String>,
}

/// `POST /api/vaults/{vid}/grants`: disclose files to an audience of friends.
pub async fn disclose(
    Path(vid_hex): Path<String>,
    State(st): State<AppState>,
    Json(req): Json<DiscloseReq>,
) -> Result<Json<Value>, ApiError> {
    let vid = parse_hex32(&vid_hex)?;
    let paths: Vec<&str> = req.paths.iter().map(String::as_str).collect();
    let mut audience = Vec::with_capacity(req.audience.len());
    for a in &req.audience {
        audience.push(parse_hex32(a)?);
    }
    let grant = st.daemon.disclose_files(vid, &paths, &audience)?;
    Ok(Json(json!({ "grant_hex": hexs(&grant.encode_frame()) })))
}

#[derive(Deserialize)]
pub struct FetchGrantReq {
    grant_hex: String,
    owner: PeerReq,
    out_dir: String,
}

/// `POST /api/grants/fetch`: fetch + reconstruct disclosed files from the owner.
pub async fn fetch_grant(
    State(st): State<AppState>,
    Json(req): Json<FetchGrantReq>,
) -> Result<Json<Value>, ApiError> {
    let bytes = hex::decode(&req.grant_hex).map_err(|_| bad("invalid grant hex"))?;
    let grant = FileGrant::decode_frame(&bytes).map_err(|e| bad(format!("decode grant: {e}")))?;
    let owner_node = parse_hex32(&req.owner.node)?;
    let written = st
        .daemon
        .fetch_disclosed_at(
            &grant,
            owner_node,
            &req.owner.addrs,
            std::path::Path::new(&req.out_dir),
        )
        .await?;
    Ok(Json(json!({
        "written": written.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
    })))
}

// ---- recovery (§8) -----------------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ScopeReq {
    Root,
    Vault { vid: String },
}

fn to_scope(s: &ScopeReq) -> Result<RecoveryScope, ApiError> {
    Ok(match s {
        ScopeReq::Root => RecoveryScope::Root,
        ScopeReq::Vault { vid } => RecoveryScope::Vault(parse_hex32(vid)?),
    })
}

#[derive(Deserialize)]
pub struct SplitReq {
    rsid: u64,
    scope: ScopeReq,
    m: u8,
    n: u8,
    allow_over_cap: Option<bool>,
}

fn do_split(st: &AppState, req: &SplitReq) -> Result<Json<Value>, ApiError> {
    let scope = to_scope(&req.scope)?;
    let (shares, warnings) = st.daemon.recovery_split(
        req.rsid,
        scope,
        req.m,
        req.n,
        req.allow_over_cap.unwrap_or(false),
    )?;
    Ok(Json(json!({
        "shares": shares,
        "warnings": warnings.iter().map(|w| format!("{w:?}")).collect::<Vec<_>>(),
    })))
}

/// `POST /api/recovery/split`: split `K_root` or `K_vaultroot(vid)` M-of-N.
pub async fn recovery_split(
    State(st): State<AppState>,
    Json(req): Json<SplitReq>,
) -> Result<Json<Value>, ApiError> {
    do_split(&st, &req)
}

/// `POST /api/recovery/resplit`: re-split at (typically larger) M (§8.3). Same
/// operation as split; it overwrites the recorded split-state for the rsid.
pub async fn recovery_resplit(
    State(st): State<AppState>,
    Json(req): Json<SplitReq>,
) -> Result<Json<Value>, ApiError> {
    do_split(&st, &req)
}

#[derive(Deserialize)]
pub struct ExtendReq {
    rsid: u64,
    count: u8,
    allow_over_cap: Option<bool>,
}

/// `POST /api/recovery/extend`: issue more shares on a recorded split.
pub async fn recovery_extend(
    State(st): State<AppState>,
    Json(req): Json<ExtendReq>,
) -> Result<Json<Value>, ApiError> {
    let shares =
        st.daemon
            .recovery_extend(req.rsid, req.count, req.allow_over_cap.unwrap_or(false))?;
    Ok(Json(json!({ "shares": shares })))
}

#[derive(Deserialize)]
pub struct CeremonyOpenReq {
    open_hex: String,
    grant_hex: String,
}

/// `POST /api/recovery/ceremony/open`: begin tracking an inbound recovery ceremony.
pub async fn ceremony_open(
    State(st): State<AppState>,
    Json(req): Json<CeremonyOpenReq>,
) -> Result<Json<Value>, ApiError> {
    let open_bytes = hex::decode(&req.open_hex).map_err(|_| bad("invalid open hex"))?;
    let grant_bytes = hex::decode(&req.grant_hex).map_err(|_| bad("invalid grant hex"))?;
    let open =
        RecoveryOpen::decode_frame(&open_bytes).map_err(|e| bad(format!("decode open: {e}")))?;
    let grant =
        ShareGrant::decode_frame(&grant_bytes).map_err(|e| bad(format!("decode grant: {e}")))?;
    let (id, phase) = st.daemon.ceremony_open(&open, &grant, unix_now())?;
    Ok(Json(json!({
        "ceremony_id": hexs(&id),
        "phase": format!("{phase:?}"),
    })))
}

#[derive(Deserialize)]
pub struct CeremonyApproveReq {
    approve_hex: String,
}

/// `POST /api/recovery/ceremony/approve`: record a trustee's approval.
pub async fn ceremony_approve(
    State(st): State<AppState>,
    Json(req): Json<CeremonyApproveReq>,
) -> Result<Json<Value>, ApiError> {
    let bytes = hex::decode(&req.approve_hex).map_err(|_| bad("invalid approve hex"))?;
    let approve =
        CeremonyApprove::decode_frame(&bytes).map_err(|e| bad(format!("decode approve: {e}")))?;
    let approvals = st.daemon.ceremony_approve(&approve)?;
    Ok(Json(json!({ "approvals": approvals })))
}

#[derive(Deserialize)]
pub struct CeremonyAbortReq {
    ceremony_id: String,
}

/// `POST /api/recovery/ceremony/abort`: sign a subject abort for a ceremony.
pub async fn ceremony_abort(
    State(st): State<AppState>,
    Json(req): Json<CeremonyAbortReq>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_hex16(&req.ceremony_id)?;
    let abort = st.daemon.ceremony_abort(id)?;
    Ok(Json(json!({ "abort_hex": hexs(&abort.encode_frame()) })))
}

// ---- events (WebSocket) ------------------------------------------------

#[derive(Deserialize)]
pub struct TokenQuery {
    token: Option<String>,
}

/// `GET /api/events` (WebSocket). Browsers cannot set an `Authorization` header on a
/// WS handshake, so the token is passed as the `token` query parameter and validated
/// in CONSTANT TIME before the upgrade. A missing/wrong token => 401, no upgrade.
pub async fn events(
    ws: WebSocketUpgrade,
    Query(q): Query<TokenQuery>,
    State(st): State<AppState>,
) -> Response {
    let presented = q.token.unwrap_or_default();
    if !auth::ct_eq_str(&presented, &st.token) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response();
    }
    ws.on_upgrade(move |socket| push_status(socket, st))
}

/// Push a status snapshot immediately and then every 5 seconds until the socket
/// closes. A periodic full snapshot is the v1 live-status feed (§ design doc).
async fn push_status(mut socket: WebSocket, st: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        let snap = status_snapshot(&st.daemon).to_string();
        if socket.send(Message::Text(snap.into())).await.is_err() {
            break;
        }
        ticker.tick().await;
    }
}
