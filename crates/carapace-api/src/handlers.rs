//! JSON action + status handlers over an `Arc<Daemon>`. Every handler here sits
//! behind the loopback guards in [`crate::auth`] (the token guard, plus the global
//! Host/Origin guard); `health`, `events`, and the static GUI are the documented
//! exceptions to the token requirement (see [`crate::app`]).

use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use carapace_wire::messages::Message as _;
use carapace_wire::{AnnounceRef, FileGrant, InviteTicket};
use carapaced::{Daemon, PendingResplitStatus, RecoveryScope, ResplitStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

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
        return error_response(StatusCode::NOT_FOUND, "not found");
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
    let cookie = format!("carapace_session={token}; HttpOnly; SameSite=Strict; Path=/api/events");
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, csp.as_str()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
            (header::SET_COOKIE, cookie.as_str()),
        ],
        rendered,
    )
        .into_response()
}

// ---- error type --------------------------------------------------------

/// Sequence for references that connect a safe client error to the server log.
static ERROR_REFERENCE: AtomicU64 = AtomicU64::new(1);

/// A handler error rendered as a JSON body with an HTTP status.
pub struct ApiError {
    status: StatusCode,
    client_message: String,
    internal: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    UpstreamFailure,
    Internal,
}

#[derive(Serialize)]
pub(crate) struct ApiErrorBody {
    pub(crate) code: ApiErrorCode,
    pub(crate) error: String,
}

pub(crate) fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    let code = match status {
        StatusCode::BAD_REQUEST => ApiErrorCode::BadRequest,
        StatusCode::UNAUTHORIZED => ApiErrorCode::Unauthorized,
        StatusCode::FORBIDDEN => ApiErrorCode::Forbidden,
        StatusCode::NOT_FOUND => ApiErrorCode::NotFound,
        StatusCode::CONFLICT => ApiErrorCode::Conflict,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => ApiErrorCode::UpstreamFailure,
        _ => ApiErrorCode::Internal,
    };
    (
        status,
        Json(ApiErrorBody {
            code,
            error: message.into(),
        }),
    )
        .into_response()
}

impl ApiError {
    fn client(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            client_message: message.into(),
            internal: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let message = match self.internal {
            Some(detail) => {
                let reference = ERROR_REFERENCE.fetch_add(1, Ordering::Relaxed);
                let _ = detail;
                crate::ops::log("api.internal_error", Some(reference));
                format!("internal server error; reference {reference}")
            }
            None => self.client_message,
        };
        error_response(self.status, message)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            client_message: "internal server error".to_string(),
            internal: Some(format!("{e:#}")),
        }
    }
}

/// A 400 from a bad-input message.
fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::client(StatusCode::BAD_REQUEST, msg)
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

#[derive(Clone, Debug, Serialize)]
pub struct PeerOptionResponse {
    user: String,
    display: String,
    node: String,
    addrs: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublishedVaultResponse {
    vid: String,
    epoch: u64,
    name: String,
}

#[derive(Clone, Debug, Serialize)]
struct FriendGrantResponse {
    user: String,
    grant_bytes: u64,
}
#[derive(Clone, Debug, Serialize)]
struct FriendsResponse {
    count: usize,
    list: Vec<String>,
    grants: Vec<FriendGrantResponse>,
}
#[derive(Clone, Debug, Serialize)]
struct VaultsResponse {
    published: Vec<PublishedVaultResponse>,
    held_replicas: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RecoveryScopeResponse {
    Root,
    Vault { vid: String },
}
#[derive(Clone, Debug, Serialize)]
struct TrusteeDeliveryResponse {
    user: String,
    delivered: bool,
}
#[derive(Clone, Debug, Serialize)]
struct RecoverySetResponse {
    rsid: u64,
    scope: RecoveryScopeResponse,
    threshold: usize,
    issued: usize,
    trustees: Vec<TrusteeDeliveryResponse>,
    warnings: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
struct RecoveryHealthResponse {
    rsid: u64,
    live: usize,
    target: usize,
    recommendation: String,
    needed: usize,
}
#[derive(Clone, Debug, Serialize)]
struct ShareHealthResponse {
    recovery_sets_owned: usize,
    shares_held: usize,
    sets: Vec<RecoverySetResponse>,
    recovery: Vec<RecoveryHealthResponse>,
}
#[derive(Clone, Debug, Serialize)]
struct AnnounceRefResponse {
    vid: String,
    epoch: u64,
}
#[derive(Clone, Debug, Serialize)]
struct MintedGrantResponse {
    rsid: u64,
    subject: String,
    trustees: Vec<TrusteeDeliveryResponse>,
    refs: Vec<AnnounceRefResponse>,
}
#[derive(Clone, Debug, Serialize)]
struct RecoveryGrantsResponse {
    minted: Vec<MintedGrantResponse>,
    held: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
struct CeremonyResponse {
    ceremony_id: String,
    subject: String,
    sponsor: String,
    claimant_display: String,
    reason: String,
    phase: String,
    approvals: usize,
    threshold: usize,
    is_self_subject: bool,
    takeover: bool,
    trustee: bool,
    approved: bool,
    alarm: bool,
}
#[derive(Clone, Debug, Serialize)]
struct ResplitFriendResponse {
    node: String,
    role: String,
    online: bool,
    done: bool,
    status: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ResplitResponse {
    old_rsid: u64,
    new_rsid: u64,
    ex_trustee: String,
    phase: String,
    new_attested: usize,
    new_total: usize,
    new_set_live: bool,
    old_destroyed: usize,
    old_total: usize,
    remaining: Vec<ResplitFriendResponse>,
}
#[derive(Clone, Debug, Serialize)]
struct PendingTrusteeResponse {
    user: String,
    node: Option<String>,
    online: bool,
}
#[derive(Clone, Debug, Serialize)]
struct PendingResplitResponse {
    old_rsid: u64,
    ex_trustee: String,
    suggested: Vec<PendingTrusteeResponse>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusSnapshot {
    node_id: String,
    addr: Vec<String>,
    relay_url: Option<String>,
    friends: FriendsResponse,
    peers: Vec<PeerOptionResponse>,
    vaults: VaultsResponse,
    share_health: ShareHealthResponse,
    recovery_grants: RecoveryGrantsResponse,
    ceremonies: Vec<CeremonyResponse>,
    resplits: Vec<ResplitResponse>,
    pending_resplits: Vec<PendingResplitResponse>,
    reachability: &'static str,
    relay_networks: usize,
    relay_diversity_warning: bool,
    por_latency_anomaly_count: usize,
}

/// Build the status snapshot pushed over WS and returned by `GET /api/status`.
fn status_snapshot(d: &Daemon) -> StatusSnapshot {
    let friends: Vec<String> = d.friend_ids().iter().map(|f| hexs(f)).collect();
    let friend_grants: Vec<FriendGrantResponse> = d
        .friend_grants()
        .iter()
        .map(|report| FriendGrantResponse {
            user: hexs(&report.user),
            grant_bytes: report.grant_bytes,
        })
        .collect();
    let vaults: Vec<PublishedVaultResponse> = d
        .vault_options()
        .iter()
        .map(|vault| PublishedVaultResponse {
            vid: hexs(&vault.vid),
            epoch: vault.epoch,
            name: vault.name.clone(),
        })
        .collect();
    let peers = d
        .peer_options()
        .iter()
        .map(|peer| PeerOptionResponse {
            user: hexs(&peer.user),
            display: peer.display.clone(),
            node: hexs(&peer.node),
            addrs: peer.addrs.clone(),
        })
        .collect();
    let held: Vec<String> = d.held_replica_vids().iter().map(|v| hexs(v)).collect();
    let (sets, shares) = d.share_health_counts();
    let recovery_sets: Vec<RecoverySetResponse> = d
        .recovery_sets()
        .iter()
        .map(|set| {
            let scope = match set.scope {
                RecoveryScope::Root => RecoveryScopeResponse::Root,
                RecoveryScope::Vault(vid) => RecoveryScopeResponse::Vault { vid: hexs(&vid) },
            };
            RecoverySetResponse {
                rsid: set.rsid,
                scope,
                threshold: set.threshold,
                issued: set.issued,
                trustees: set
                    .trustees
                    .iter()
                    .map(|(user, delivered)| TrusteeDeliveryResponse {
                        user: hexs(user),
                        delivered: *delivered,
                    })
                    .collect(),
                warnings: set
                    .warnings
                    .iter()
                    .map(|warning| format!("{warning:?}"))
                    .collect(),
            }
        })
        .collect();
    // W4 (§10.2): per owned recovery set, the attested-live count, target, and drift
    // recommendation (healthy / extend / resplit) the maintenance loop keeps current.
    let recovery: Vec<RecoveryHealthResponse> = d
        .recovery_health()
        .iter()
        .map(|r| RecoveryHealthResponse {
            rsid: r.rsid,
            live: r.live,
            target: r.target,
            recommendation: r.recommendation.to_owned(),
            needed: r.needed,
        })
        .collect();
    // W3 (§8, §7.3): per owned recovery set, which trustees hold a minted ShareGrant
    // and the announce-ref freshness (vid + epoch) the maintenance loop keeps current.
    let grants: Vec<MintedGrantResponse> = d
        .recovery_grants()
        .iter()
        .map(|g| MintedGrantResponse {
            rsid: g.rsid,
            subject: hexs(&g.subject),
            trustees: g
                .trustees
                .iter()
                .map(|(u, delivered)| TrusteeDeliveryResponse {
                    user: hexs(u),
                    delivered: *delivered,
                })
                .collect(),
            refs: g
                .refs
                .iter()
                .map(|(vid, epoch)| AnnounceRefResponse {
                    vid: hexs(vid),
                    epoch: *epoch,
                })
                .collect(),
        })
        .collect();
    // W3 trustee side: subject users whose grants this daemon holds for others.
    let held_grants: Vec<String> = d.held_grant_subjects().iter().map(|u| hexs(u)).collect();
    let relay_url = d.advertised_relay_url();
    // W4 (§6 MUST): warn when the usable relay set spans fewer than 2 distinct
    // networks - a single relay is a single point of failure and metadata choke.
    let relay_networks = d.relay_network_count();
    StatusSnapshot {
        node_id: hexs(&d.node_id()),
        addr: d.dialable_addr_strings(),
        relay_url: relay_url.clone(),
        friends: FriendsResponse {
            count: friends.len(),
            list: friends,
            grants: friend_grants,
        },
        peers,
        vaults: VaultsResponse {
            published: vaults,
            held_replicas: held,
        },
        share_health: ShareHealthResponse {
            recovery_sets_owned: sets,
            shares_held: shares,
            sets: recovery_sets,
            recovery,
        },
        recovery_grants: RecoveryGrantsResponse {
            minted: grants,
            held: held_grants,
        },
        ceremonies: ceremony_rows(d),
        resplits: d.resplit_statuses().iter().map(resplit_json).collect(),
        pending_resplits: d
            .pending_resplit_statuses()
            .iter()
            .map(pending_resplit_json)
            .collect(),
        reachability: if relay_url.is_some() {
            "relay"
        } else {
            "direct"
        },
        relay_networks,
        relay_diversity_warning: relay_networks < 2,
        por_latency_anomaly_count: d.por_latency_anomaly_count(),
    }
}

/// One re-split's §9.3 step-4 prompt surface as JSON: phase, new-set liveness gate,
/// old-set destroy progress, and each remaining friend's online/queued status.
fn resplit_json(rs: &ResplitStatus) -> ResplitResponse {
    ResplitResponse {
        old_rsid: rs.old_rsid,
        new_rsid: rs.new_rsid,
        ex_trustee: hexs(&rs.ex_trustee),
        phase: rs.phase.to_owned(),
        new_attested: rs.new_attested,
        new_total: rs.new_total,
        new_set_live: rs.new_live,
        old_destroyed: rs.old_destroyed,
        old_total: rs.old_total,
        remaining: rs
            .remaining
            .iter()
            .map(|f| ResplitFriendResponse {
                node: hexs(&f.node),
                role: f.role.to_owned(),
                online: f.online,
                done: f.done,
                status: if f.done {
                    "done"
                } else if f.online {
                    "online"
                } else {
                    "will_queue"
                },
            })
            .collect(),
    }
}

/// One PENDING re-split's §9.3.4 prompt surface as JSON: the ex-trustee and the suggested
/// new trustee set with each member's live reachability, so the GUI can render the prompt
/// and pre-fill `POST /api/recovery/{rsid}/resplit-start`.
fn pending_resplit_json(p: &PendingResplitStatus) -> PendingResplitResponse {
    PendingResplitResponse {
        old_rsid: p.old_rsid,
        ex_trustee: hexs(&p.ex_trustee),
        suggested: p
            .suggested
            .iter()
            .map(|t| PendingTrusteeResponse {
                user: hexs(&t.user),
                node: t.node.map(|n| hexs(&n)),
                online: t.online,
            })
            .collect(),
    }
}

/// `GET /api/status`.
pub async fn status(State(st): State<AppState>) -> Json<StatusSnapshot> {
    Json(status_snapshot(&st.daemon))
}

const METRIC_COUNT_LIMIT: usize = 1_000_000;

#[derive(Serialize)]
struct MetricLimits {
    count_ceiling: usize,
}
#[derive(Serialize)]
struct StorageMetrics {
    owned_vaults: u64,
    held_replica_vaults: u64,
    refetch_needed: u64,
}
#[derive(Serialize)]
struct ReplicaMetrics {
    peer_capacity_count: u64,
    held_count: u64,
    assignments: u64,
    granted_capacity_bytes: u64,
}
#[derive(Serialize)]
struct MaintenanceMetrics {
    running: bool,
    recovery_sets_checked: u64,
    relay_networks: u64,
    last_completed_at: u64,
    last_failure_at: u64,
    last_failure_count: u64,
    consecutive_failed_rounds: u64,
}
#[derive(Serialize)]
struct GarbageCollectionMetrics {
    last_succeeded: bool,
    live_set_capacity: usize,
}
#[derive(Serialize)]
struct CeremonyMetrics {
    active_or_retained: u64,
    active_tracked: u64,
    capacity_ceiling: u64,
    per_subject_capacity: u64,
    fanout_capacity: u64,
    tombstones: u64,
    tombstone_capacity: u64,
    subject_rate_keys: u64,
    sponsor_rate_keys: u64,
    at_capacity: bool,
    tombstones_at_capacity: bool,
}
#[derive(Serialize)]
struct MigrationMetrics {
    required: bool,
    state_schema_ready: bool,
    legacy_migration_is_explicit: bool,
}
#[derive(Serialize)]
struct RecoveryMetrics {
    owned_sets: u64,
    held_shares: u64,
    open_resplits: u64,
    pending_resplits: u64,
}
#[derive(Serialize)]
pub struct MetricsSnapshot {
    schema: u8,
    limits: MetricLimits,
    storage: StorageMetrics,
    replicas: ReplicaMetrics,
    maintenance: MaintenanceMetrics,
    garbage_collection: GarbageCollectionMetrics,
    ceremonies: CeremonyMetrics,
    migrations: MigrationMetrics,
    recovery: RecoveryMetrics,
}

fn bounded_count(value: usize) -> u64 {
    value.min(METRIC_COUNT_LIMIT) as u64
}

/// `GET /api/metrics`: authenticated, identity-free operational health and capacity.
pub async fn metrics(State(st): State<AppState>) -> Json<MetricsSnapshot> {
    let published = st.daemon.published_vaults().len();
    let held_replicas = st.daemon.held_replica_vids().len();
    let friends = st.daemon.friend_ids().len();
    let (recovery_sets, held_shares) = st.daemon.share_health_counts();
    let recovery = st.daemon.recovery_health();
    let ceremonies = ceremony_rows(&st.daemon);
    let resplits = st.daemon.resplit_statuses();
    let pending_resplits = st.daemon.pending_resplit_statuses();
    let capacity = st.daemon.operational_capacity();
    let history = st.daemon.operational_history();
    Json(MetricsSnapshot {
        schema: 1,
        limits: MetricLimits {
            count_ceiling: METRIC_COUNT_LIMIT,
        },
        storage: StorageMetrics {
            owned_vaults: bounded_count(published),
            held_replica_vaults: bounded_count(held_replicas),
            refetch_needed: bounded_count(capacity.storage_refetch_needed),
        },
        replicas: ReplicaMetrics {
            peer_capacity_count: bounded_count(friends),
            held_count: bounded_count(held_replicas),
            assignments: bounded_count(capacity.replica_assignments),
            granted_capacity_bytes: capacity.replica_grant_bytes,
        },
        maintenance: MaintenanceMetrics {
            running: true,
            recovery_sets_checked: bounded_count(recovery.len()),
            relay_networks: bounded_count(st.daemon.relay_network_count()),
            last_completed_at: history.last_maintenance_at,
            last_failure_at: history.last_failure_at,
            last_failure_count: bounded_count(history.last_failure_count),
            consecutive_failed_rounds: history
                .consecutive_failed_rounds
                .min(METRIC_COUNT_LIMIT as u64),
        },
        garbage_collection: GarbageCollectionMetrics {
            last_succeeded: history.last_gc_succeeded,
            live_set_capacity: 1_000_000,
        },
        ceremonies: CeremonyMetrics {
            active_or_retained: bounded_count(ceremonies.len()),
            active_tracked: bounded_count(capacity.ceremony_active),
            capacity_ceiling: bounded_count(capacity.ceremony_capacity),
            per_subject_capacity: bounded_count(capacity.ceremony_per_subject_capacity),
            fanout_capacity: bounded_count(capacity.ceremony_fanout_capacity),
            tombstones: bounded_count(capacity.ceremony_tombstones),
            tombstone_capacity: bounded_count(capacity.ceremony_tombstone_capacity),
            subject_rate_keys: bounded_count(capacity.ceremony_subject_rate_keys),
            sponsor_rate_keys: bounded_count(capacity.ceremony_sponsor_rate_keys),
            at_capacity: capacity.ceremony_active >= capacity.ceremony_capacity,
            tombstones_at_capacity: capacity.ceremony_tombstones
                >= capacity.ceremony_tombstone_capacity,
        },
        migrations: MigrationMetrics {
            required: false,
            state_schema_ready: true,
            legacy_migration_is_explicit: true,
        },
        recovery: RecoveryMetrics {
            owned_sets: bounded_count(recovery_sets),
            held_shares: bounded_count(held_shares),
            open_resplits: bounded_count(resplits.len()),
            pending_resplits: bounded_count(pending_resplits.len()),
        },
    })
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
) -> Result<Json<ResplitResponse>, ApiError> {
    match st.daemon.resplit_status(rsid) {
        Some(rs) => Ok(Json(resplit_json(&rs))),
        None => Err(ApiError::client(
            StatusCode::NOT_FOUND,
            format!("no open re-split for recovery set {rsid}"),
        )),
    }
}

/// `GET /api/recovery/{rsid}/paper`: the W15 paper-card backstop (§8, §10.2). Renders the
/// owned recovery set's retained shares as a printable HTML document (one page per share),
/// recoverable from the words alone, offline, with no Carapace software. Behind the same
/// loopback/token/Host+Origin guards as every other recovery route. 404 if `rsid` is not an
/// owned recovery set.
///
/// SECURITY: the body embeds share WORDS (a bearer secret). Same trust boundary as the
/// recovery endpoints - handed only to the owner's authenticated loopback GUI, never logged.
/// `no-store` keeps it out of the browser cache; `nosniff` fixes the type.
pub async fn recovery_paper(
    Path(rsid): Path<u64>,
    State(st): State<AppState>,
) -> Result<Response, ApiError> {
    let html = st
        .daemon
        .paper_cards(rsid)
        .map_err(|e| ApiError::client(StatusCode::NOT_FOUND, format!("{e:#}")))?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        html,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct ResplitStartReq {
    /// Override of the suggested new trustee set (hex user pubkeys of established friends or
    /// old trustees). Omit (or send an empty body) to use the pre-filled suggested set.
    trustees: Option<Vec<String>>,
}

/// `POST /api/recovery/{rsid}/resplit-start`: start the re-split the §9.3.4 prompt was
/// raised for (keyed by the old recovery-set id). The optional body overrides the suggested
/// new trustee set. Stands up the new set and begins delivering ShareGrants; returns the
/// resulting re-split status (same shape as `resplit-status`). 404 if there is no pending
/// (or open) re-split for that id; 400 if the chosen set cannot form a working set.
pub async fn resplit_start(
    Path(rsid): Path<u64>,
    State(st): State<AppState>,
    body: Option<Json<ResplitStartReq>>,
) -> Result<Json<ResplitResponse>, ApiError> {
    let override_set = match body.and_then(|Json(b)| b.trustees) {
        Some(hexes) => {
            let mut users = Vec::with_capacity(hexes.len());
            for h in &hexes {
                users.push(parse_hex32(h)?);
            }
            Some(users)
        }
        None => None,
    };
    // 404 only when nothing is tracked for this id; a chosen-set failure is a 400.
    let tracked = st.daemon.resplit_status(rsid).is_some()
        || st
            .daemon
            .pending_resplit_statuses()
            .iter()
            .any(|p| p.old_rsid == rsid);
    if !tracked {
        return Err(ApiError::client(
            StatusCode::NOT_FOUND,
            format!("no pending or open re-split for recovery set {rsid}"),
        ));
    }
    let status = st
        .daemon
        .start_pending_resplit(rsid, override_set)
        .await
        .map_err(|e| bad(format!("{e:#}")))?;
    Ok(Json(resplit_json(&status)))
}

// ---- replicas ----------------------------------------------------------

#[derive(Deserialize)]
pub struct PeerReq {
    node: String,
    addrs: Vec<String>,
}

#[derive(Deserialize)]
pub struct SyncReq {
    peer: PeerReq,
    out_dir: String,
}

#[derive(Deserialize)]
struct RestartHandoff {
    r#type: String,
    version: u8,
    trustees: Vec<PeerReq>,
    announce_refs: Vec<RestartRef>,
}

#[derive(Deserialize)]
struct RestartRef {
    vid: String,
    epoch: u64,
    digest: String,
}

#[derive(Deserialize)]
pub struct RestartRestoreReq {
    out_dir: String,
}

/// Restore retained vaults after claimant activation. The durable public handoff
/// limits results to the maximum signed-grant epoch for each vault.
pub async fn restart_restore(
    State(st): State<AppState>,
    Json(req): Json<RestartRestoreReq>,
) -> Result<Json<Value>, ApiError> {
    let path = st.state_dir.join("recovery-restart-handoff.json");
    let bytes = std::fs::read(&path).map_err(|_| {
        ApiError::client(
            StatusCode::NOT_FOUND,
            "no claimant restart handoff is available",
        )
    })?;
    let handoff: RestartHandoff =
        serde_json::from_slice(&bytes).map_err(|_| bad("invalid claimant restart handoff"))?;
    if handoff.r#type != "carapace.recovery-restart-handoff" || handoff.version != 1 {
        return Err(bad("unsupported claimant restart handoff"));
    }
    let mut refs = Vec::new();
    for reference in handoff.announce_refs {
        let vid = parse_hex32(&reference.vid)?;
        let digest = parse_hex32(&reference.digest)?;
        refs.push(AnnounceRef {
            vid,
            epoch: reference.epoch,
            digest,
        });
    }
    let mut trustees = Vec::new();
    for trustee in handoff.trustees {
        trustees.push((parse_hex32(&trustee.node)?, trustee.addrs));
    }
    let maximum_refs = carapaced::max_epoch_refs(&refs).len();
    let restored = st
        .daemon
        .recover_retained_at(&trustees, &refs, std::path::Path::new(&req.out_dir))
        .await?;
    Ok(Json(json!({
        "restored": restored.iter().map(|vault| json!({
            "vid": hexs(&vault.vid),
            "epoch": vault.epoch,
            "out_dir": vault.out_dir.display().to_string(),
        })).collect::<Vec<_>>(),
        "maximum_epoch_refs": maximum_refs,
    })))
}

/// `POST /api/sync`: pull owned-vault documents and blobs from another authorized device.
pub async fn sync_owned(
    State(st): State<AppState>,
    Json(req): Json<SyncReq>,
) -> Result<Json<Value>, ApiError> {
    let node = parse_hex32(&req.peer.node)?;
    let restored = st
        .daemon
        .sync_from_at(node, &req.peer.addrs, std::path::Path::new(&req.out_dir))
        .await?;
    Ok(Json(json!({
        "restored": restored.iter().map(|v| json!({
            "vid": hexs(&v.vid),
            "epoch": v.epoch,
            "out_dir": v.out_dir.display().to_string(),
        })).collect::<Vec<_>>(),
    })))
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
        let warnings: Vec<String> = report.warnings.iter().map(|w| format!("{w:?}")).collect();
        let mut body = json!({
            "rsid": report.rsid,
            "delivered": report.delivered.iter().map(|u| hexs(u)).collect::<Vec<_>>(),
            "undelivered": report.undelivered.iter().map(|u| hexs(u)).collect::<Vec<_>>(),
            "warnings": warnings,
        });
        // §8.3: an over-cap issuance MUST surface "re-split with a larger M".
        if warnings.iter().any(|w| w == "OverSoftCap") {
            body["recommendation"] = json!("re-split with a larger M");
        }
        return Ok(Json(body));
    }

    // Bare-words path (no trustee set): return each share's JSON carrier.
    let n = req
        .n
        .ok_or_else(|| bad("split requires either `n` or `trustees`"))?;
    let (shares, warnings) = st
        .daemon
        .recovery_split(req.rsid, scope, req.m, n, allow_over_cap)?;
    let warnings: Vec<String> = warnings.iter().map(|w| format!("{w:?}")).collect();
    let mut body = json!({
        "shares": shares,
        "warnings": warnings,
    });
    // §8.3: an over-cap issuance MUST surface "re-split with a larger M".
    if warnings.iter().any(|w| w == "OverSoftCap") {
        body["recommendation"] = json!("re-split with a larger M");
    }
    Ok(Json(body))
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
    let (shares, warnings) =
        st.daemon
            .recovery_extend(req.rsid, req.count, req.allow_over_cap.unwrap_or(false))?;
    let warnings: Vec<String> = warnings.iter().map(|w| format!("{w:?}")).collect();
    let mut body = json!({
        "shares": shares,
        "warnings": warnings,
    });
    // §8.3: an over-cap issuance MUST surface "re-split with a larger M" as the
    // recommended alternative alongside the warning.
    if warnings.iter().any(|w| w == "OverSoftCap") {
        body["recommendation"] = json!("re-split with a larger M");
    }
    Ok(Json(body))
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
    let trustee_hints = st.daemon.claimant_trustee_hints(&subject)?;
    let announce_refs = st.daemon.claimant_announce_refs(&subject)?;
    let roster: Vec<String> = trustee_hints
        .iter()
        .map(|trustee| hexs(&trustee.user))
        .collect();
    let trustees: Vec<Value> = trustee_hints
        .iter()
        .map(|trustee| {
            json!({
                "node": hexs(&trustee.node),
                "addrs": trustee.addrs,
            })
        })
        .collect();
    let sponsor_package = json!({
        "type": "carapace.sponsor-ceremony",
        "version": 1,
        "open_hex": hexs(&open.encode_frame()),
        "roster": roster,
        "trustees": trustees,
        "announce_refs": announce_refs.iter().map(|reference| json!({
            "vid": hexs(&reference.vid),
            "epoch": reference.epoch,
            "digest": hexs(&reference.digest),
        })).collect::<Vec<_>>(),
    });
    Ok(Json(json!({
        "ceremony_id": hexs(&id),
        "open_hex": hexs(&open.encode_frame()),
        "fanout_reached": reached,
        "sponsor_package": sponsor_package.to_string(),
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
fn ceremony_rows(d: &Daemon) -> Vec<CeremonyResponse> {
    d.ceremony_statuses()
        .iter()
        .map(|c| CeremonyResponse {
            ceremony_id: hexs(&c.ceremony_id),
            subject: hexs(&c.subject),
            sponsor: hexs(&c.sponsor),
            claimant_display: c.claimant_display.clone(),
            reason: c.reason.clone(),
            phase: c.phase.to_owned(),
            approvals: c.approvals,
            threshold: c.threshold,
            is_self_subject: c.is_self_subject,
            takeover: c.takeover,
            trustee: c.trustee,
            approved: c.approved,
            alarm: c.is_self_subject && !c.takeover,
        })
        .collect()
}

/// `GET /api/recovery/ceremony`: the recovery-ceremony status (§8.5 step 2/6).
pub async fn ceremony_status(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "ceremonies": ceremony_rows(&st.daemon) }))
}

// ---- events (WebSocket) ------------------------------------------------

/// `GET /api/events` (WebSocket). The browser sends the short-lived, HTTP-only session
/// cookie that the loopback shell sets. This keeps the bearer value out of URLs and logs.
pub async fn events(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(st): State<AppState>,
) -> Response {
    let presented = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == "carapace_session").then_some(value)
            })
        })
        .unwrap_or_default();
    if !auth::ct_eq_str(presented, &st.token) {
        return error_response(StatusCode::UNAUTHORIZED, "missing or invalid token");
    }
    ws.on_upgrade(move |socket| push_status(socket, st))
}

/// Push a status snapshot immediately and then every 5 seconds until the socket
/// closes. A periodic full snapshot is the v1 live-status feed (§ design doc).
async fn push_status(mut socket: WebSocket, st: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    while let Ok(snap) = serde_json::to_string(&status_snapshot(&st.daemon)) {
        if socket.send(Message::Text(snap.into())).await.is_err() {
            break;
        }
        ticker.tick().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gui_status_contract_fixture_matches_typed_server_shape() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../gui/tests/fixtures/status-contract.json"
        ))
        .unwrap();
        let expected = serde_json::to_value(StatusSnapshot {
            node_id: String::new(),
            addr: Vec::new(),
            relay_url: None,
            friends: FriendsResponse {
                count: 0,
                list: Vec::new(),
                grants: Vec::new(),
            },
            peers: Vec::new(),
            vaults: VaultsResponse {
                published: Vec::new(),
                held_replicas: Vec::new(),
            },
            share_health: ShareHealthResponse {
                recovery_sets_owned: 0,
                shares_held: 0,
                sets: Vec::new(),
                recovery: Vec::new(),
            },
            recovery_grants: RecoveryGrantsResponse {
                minted: Vec::new(),
                held: Vec::new(),
            },
            ceremonies: Vec::new(),
            resplits: Vec::new(),
            pending_resplits: Vec::new(),
            reachability: "direct",
            relay_networks: 0,
            relay_diversity_warning: true,
            por_latency_anomaly_count: 0,
        })
        .unwrap();
        assert_eq!(fixture, expected);
    }

    #[test]
    fn internal_error_detail_is_not_the_client_message() {
        let error = ApiError::from(anyhow::anyhow!(
            "secret path /private/state/root.key could not be read"
        ));

        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.client_message, "internal server error");
        assert!(error
            .internal
            .as_deref()
            .is_some_and(|detail| detail.contains("/private/state/root.key")));
        assert!(!error.client_message.contains("root.key"));
    }

    #[test]
    fn expected_client_error_has_no_internal_detail() {
        let error = bad("invalid recovery set");

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.client_message, "invalid recovery set");
        assert!(error.internal.is_none());
    }
}
