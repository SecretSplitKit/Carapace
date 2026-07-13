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

/// Serve an embedded GUI asset, falling back to `index.html` for unknown paths so a
/// client-routed SPA works. No auth: this is the app shell, which carries no secrets
/// and drives every privileged action through the token-gated `/api` routes.
pub async fn static_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if let Some(file) = Assets::get(path) {
        return (
            [(header::CONTENT_TYPE, file.metadata.mimetype())],
            file.data.into_owned(),
        )
            .into_response();
    }
    match Assets::get("index.html") {
        Some(file) => (
            [(header::CONTENT_TYPE, "text/html")],
            file.data.into_owned(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
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
    json!({
        "node_id": hexs(&d.node_id()),
        "addr": d.dialable_addr_strings(),
        "friends": { "count": friends.len(), "list": friends },
        "vaults": { "published": vaults, "held_replicas": held },
        "share_health": { "recovery_sets_owned": sets, "shares_held": shares },
        "reachability": "direct",
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
