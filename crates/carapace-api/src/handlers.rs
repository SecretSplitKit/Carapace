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
use carapace_wire::{FileGrant, InviteTicket};
use carapaced::{Daemon, RecoveryScope, ResplitStatus};
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
    // W4 (§10.2): per owned recovery set, the attested-live count, target, and drift
    // recommendation (healthy / extend / resplit) the maintenance loop keeps current.
    let recovery: Vec<Value> = d
        .recovery_health()
        .iter()
        .map(|r| {
            json!({
                "rsid": r.rsid,
                "live": r.live,
                "target": r.target,
                "recommendation": r.recommendation,
                "needed": r.needed,
            })
        })
        .collect();
    // W3 (§8, §7.3): per owned recovery set, which trustees hold a minted ShareGrant
    // and the announce-ref freshness (vid + epoch) the maintenance loop keeps current.
    let grants: Vec<Value> = d
        .recovery_grants()
        .iter()
        .map(|g| {
            json!({
                "rsid": g.rsid,
                "subject": hexs(&g.subject),
                "trustees": g.trustees.iter()
                    .map(|(u, delivered)| json!({ "user": hexs(u), "delivered": delivered }))
                    .collect::<Vec<_>>(),
                "refs": g.refs.iter()
                    .map(|(vid, epoch)| json!({ "vid": hexs(vid), "epoch": epoch }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    // W3 trustee side: subject users whose grants this daemon holds for others.
    let held_grants: Vec<String> = d.held_grant_subjects().iter().map(|u| hexs(u)).collect();
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
        "share_health": { "recovery_sets_owned": sets, "shares_held": shares, "recovery": recovery },
        "recovery_grants": { "minted": grants, "held": held_grants },
        // W2 (§8.5): live recovery ceremonies + the anti-silent-takeover alarm.
        "ceremonies": ceremony_rows(d),
        // W5 (§9.3 step 4): open trustee re-splits after an unfriend, with the live
        // reachability of the remaining friends who get the new share / destroy step.
        "resplits": d.resplit_statuses().iter().map(resplit_json).collect::<Vec<_>>(),
        "reachability": if relay_url.is_some() { "relay" } else { "direct" },
        "relay_networks": relay_networks,
        "relay_diversity_warning": relay_networks < 2,
    })
}

/// One re-split's §9.3 step-4 prompt surface as JSON: phase, new-set liveness gate,
/// old-set destroy progress, and each remaining friend's online/queued status.
fn resplit_json(rs: &ResplitStatus) -> Value {
    json!({
        "old_rsid": rs.old_rsid,
        "new_rsid": rs.new_rsid,
        "ex_trustee": hexs(&rs.ex_trustee),
        "phase": rs.phase,
        // New set going live is the destroy gate (>= M + slack attested).
        "new_attested": rs.new_attested,
        "new_total": rs.new_total,
        "new_set_live": rs.new_live,
        "old_destroyed": rs.old_destroyed,
        "old_total": rs.old_total,
        "remaining": rs.remaining.iter().map(|f| json!({
            "node": hexs(&f.node),
            "role": f.role,
            "online": f.online,
            "done": f.done,
            "status": if f.done { "done" } else if f.online { "online" } else { "will_queue" },
        })).collect::<Vec<_>>(),
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

/// `POST /api/friends/{user_pubkey}/unfriend`: terminate a friendship (§9.3). Runs the
/// full flow - `FriendshipEnd` + `DeleteRequest`s, delete-what-we-hold, re-place their
/// replicas, and (if they were a trustee) begin a re-split - and reports whether a
/// re-split was triggered plus the recovery-set ids so the GUI can raise the §9.3
/// step-4 prompt and poll `/api/recovery/{rsid}/resplit-status`.
pub async fn unfriend(
    Path(user_hex): Path<String>,
    State(st): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let user = parse_hex32(&user_hex)?;
    let outcome = st.daemon.unfriend(user).await?;
    Ok(Json(json!({
        "was_friend": outcome.was_friend,
        "resplit_triggered": !outcome.resplit_rsids.is_empty(),
        "recovery_set_ids": outcome.resplit_rsids,
    })))
}

/// `GET /api/recovery/{rsid}/resplit-status`: the §9.3 step-4 re-split prompt surface for
/// one open re-split (keyed by the old recovery-set id): phase, new-set attested count
/// vs the destroy gate, old-set destroy-ack count, and each remaining friend's
/// online/queued status. 404 if no re-split is tracked for that id.
pub async fn resplit_status(
    Path(rsid): Path<u64>,
    State(st): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    match st.daemon.resplit_status(rsid) {
        Some(rs) => Ok(Json(resplit_json(&rs))),
        None => Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("no open re-split for recovery set {rsid}"),
        )),
    }
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

/// Default owner abort window carried in a `ShareGrant` when the caller does not
/// override it (§8.5): 72 hours in seconds.
const DEFAULT_RECOVERY_DELAY_SECS: u64 = 72 * 3600;

#[derive(Deserialize)]
pub struct SplitReq {
    rsid: u64,
    scope: ScopeReq,
    m: u8,
    /// Total shares to issue when splitting to bare words (no `trustees` given).
    n: Option<u8>,
    /// W3: when present, mint + deliver one signed `ShareGrant` per trustee (each a
    /// hex user pubkey of an established friend) instead of returning bare words.
    /// `N` is the trustee count.
    trustees: Option<Vec<String>>,
    /// Owner abort window for the minted grants (§8.5); defaults to 72 h.
    recovery_delay: Option<u64>,
    allow_over_cap: Option<bool>,
}

async fn do_split(st: &AppState, req: &SplitReq) -> Result<Json<Value>, ApiError> {
    let scope = to_scope(&req.scope)?;
    let allow_over_cap = req.allow_over_cap.unwrap_or(false);

    // W3 grant path: split to trustees and deliver signed grants over the control
    // stream, so trustees hold the roster + delay + announce refs a ceremony needs.
    if let Some(trustee_hex) = &req.trustees {
        let trustees: Vec<[u8; 32]> = trustee_hex
            .iter()
            .map(|h| parse_hex32(h))
            .collect::<Result<_, _>>()?;
        let report = st
            .daemon
            .recovery_split_grant(
                req.rsid,
                scope,
                req.m,
                &trustees,
                req.recovery_delay.unwrap_or(DEFAULT_RECOVERY_DELAY_SECS),
                allow_over_cap,
            )
            .await?;
        return Ok(Json(json!({
            "rsid": report.rsid,
            "delivered": report.delivered.iter().map(|u| hexs(u)).collect::<Vec<_>>(),
            "undelivered": report.undelivered.iter().map(|u| hexs(u)).collect::<Vec<_>>(),
            "warnings": report.warnings.iter().map(|w| format!("{w:?}")).collect::<Vec<_>>(),
        })));
    }

    // Bare-words path (no trustee set): return each share's JSON carrier.
    let n = req
        .n
        .ok_or_else(|| bad("split requires either `n` or `trustees`"))?;
    let (shares, warnings) = st
        .daemon
        .recovery_split(req.rsid, scope, req.m, n, allow_over_cap)?;
    Ok(Json(json!({
        "shares": shares,
        "warnings": warnings.iter().map(|w| format!("{w:?}")).collect::<Vec<_>>(),
    })))
}

/// `POST /api/recovery/split`: split `K_root` or `K_vaultroot(vid)` M-of-N. With a
/// `trustees` list, mints + delivers a signed `ShareGrant` to each (W3); otherwise
/// returns the bare share words.
pub async fn recovery_split(
    State(st): State<AppState>,
    Json(req): Json<SplitReq>,
) -> Result<Json<Value>, ApiError> {
    do_split(&st, &req).await
}

/// `POST /api/recovery/resplit`: re-split at (typically larger) M (§8.3). Same
/// operation as split; it overwrites the recorded split-state for the rsid.
pub async fn recovery_resplit(
    State(st): State<AppState>,
    Json(req): Json<SplitReq>,
) -> Result<Json<Value>, ApiError> {
    do_split(&st, &req).await
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
    /// Hex user pubkey of the subject whose secret is being recovered. This daemon
    /// must hold that subject's grant (only a trustee may open, §8.5 step 1).
    subject: String,
    /// The key-less claimant's display name.
    claimant_display: String,
    /// Hex X25519 ceremony pubkey the claimant generated on the new device; trustees
    /// seal their shares to it.
    ceremony_enc: String,
    /// Hex node id of the claimant's new device (re-delegated after recovery).
    new_node: String,
    /// The sponsor's stated reason.
    reason: String,
}

/// `POST /api/recovery/ceremony/open`: a trustee opens a recovery ceremony for a
/// subject it holds a grant for (§8.5 step 1) and fans the signed open out to the
/// co-trustees and the subject's devices (step 2). Returns the signed open (hex) - the
/// sponsor hands it to the claimant - and the ceremony id.
pub async fn ceremony_open(
    State(st): State<AppState>,
    Json(req): Json<CeremonyOpenReq>,
) -> Result<Json<Value>, ApiError> {
    let subject = parse_hex32(&req.subject)?;
    let ceremony_enc = parse_hex32(&req.ceremony_enc)?;
    let new_node = parse_hex32(&req.new_node)?;
    let (open, id) = st.daemon.ceremony_sponsor_open(
        subject,
        req.claimant_display,
        ceremony_enc,
        new_node,
        req.reason,
        unix_now(),
    )?;
    let reached = st.daemon.ceremony_fanout(&open).await.unwrap_or(0);
    Ok(Json(json!({
        "ceremony_id": hexs(&id),
        "open_hex": hexs(&open.encode_frame()),
        "fanout_reached": reached,
    })))
}

#[derive(Deserialize)]
pub struct CeremonyApproveReq {
    ceremony_id: String,
}

/// `POST /api/recovery/ceremony/approve`: a trustee approves after out-of-band
/// verification (§8.5 step 4) and broadcasts the approval to the co-trustees.
pub async fn ceremony_approve(
    State(st): State<AppState>,
    Json(req): Json<CeremonyApproveReq>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_hex16(&req.ceremony_id)?;
    let ap = st.daemon.ceremony_approve(id, unix_now())?;
    let reached = st.daemon.ceremony_broadcast_approve(&ap).await.unwrap_or(0);
    Ok(Json(json!({
        "approve_hex": hexs(&ap.encode_frame()),
        "broadcast_reached": reached,
    })))
}

#[derive(Deserialize)]
pub struct CeremonyAbortReq {
    ceremony_id: String,
}

/// `POST /api/recovery/ceremony/abort`: the subject signs an authoritative abort
/// (§8.5 step 3) and broadcasts it to the trustees, cancelling the ceremony.
pub async fn ceremony_abort(
    State(st): State<AppState>,
    Json(req): Json<CeremonyAbortReq>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_hex16(&req.ceremony_id)?;
    let ab = st.daemon.ceremony_abort(id)?;
    let reached = st.daemon.ceremony_broadcast_abort(&ab).await.unwrap_or(0);
    Ok(Json(json!({
        "abort_hex": hexs(&ab.encode_frame()),
        "broadcast_reached": reached,
    })))
}

/// The recovery-ceremony status rows (§8.5 step 2/6) for the status surface: each
/// ceremony this device has seen, its phase, approvals, and the alarm flags.
fn ceremony_rows(d: &Daemon) -> Vec<Value> {
    d.ceremony_statuses()
        .iter()
        .map(|c| {
            json!({
                "ceremony_id": hexs(&c.ceremony_id),
                "subject": hexs(&c.subject),
                "sponsor": hexs(&c.sponsor),
                "claimant_display": c.claimant_display,
                "reason": c.reason,
                "phase": c.phase,
                "approvals": c.approvals,
                "threshold": c.threshold,
                "is_self_subject": c.is_self_subject,
                "takeover": c.takeover,
                "trustee": c.trustee,
                "approved": c.approved,
                // The anti-silent-takeover banner: a live ceremony against OUR account.
                "alarm": c.is_self_subject && !c.takeover,
            })
        })
        .collect()
}

/// `GET /api/recovery/ceremony`: the recovery-ceremony status (§8.5 step 2/6).
pub async fn ceremony_status(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "ceremonies": ceremony_rows(&st.daemon) }))
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
