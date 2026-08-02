//! A separate loopback API for a device that does not yet have an identity.
//!
//! This router cannot call normal daemon handlers because its state has no `Daemon`.
//! The process owns the claimant ceremony key and node seed. The browser receives only
//! their public values. On completion, the process reconstructs `K_root` in memory and
//! sends it directly to the operating-system credential-store activation boundary.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use carapace_wire::{messages::Message as _, messages::Signed as _, RecoveryOpen};
use carapaced::{activate_recovered_identity, ClaimantDevice};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

const CLAIMANT_HTML: &[u8] = include_bytes!("../static/claimant.html");
const CLAIMANT_SCRIPT: &[u8] = include_bytes!("../static/claimant.js");
const CLAIMANT_STYLESHEET: &[u8] = include_bytes!("../static/claimant.css");

fn claimant_asset(path: &str) -> Option<&'static [u8]> {
    match path {
        "claimant.html" => Some(CLAIMANT_HTML),
        "claimant.js" => Some(CLAIMANT_SCRIPT),
        "claimant.css" => Some(CLAIMANT_STYLESHEET),
        _ => None,
    }
}

/// State for the claimant-only server. It deliberately has no normal daemon.
#[derive(Clone)]
pub struct ClaimantState {
    pub(crate) claimant: Arc<Mutex<Option<ClaimantDevice>>>,
    pub(crate) state_dir: Arc<PathBuf>,
    pub(crate) token: Arc<str>,
}

impl ClaimantState {
    pub(crate) fn new(state_dir: PathBuf, token: Arc<str>) -> Result<Self> {
        Ok(Self {
            claimant: Arc::new(Mutex::new(Some(ClaimantDevice::new()?))),
            state_dir: Arc::new(state_dir),
            token,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TrusteeAddress {
    node: String,
    #[serde(default)]
    addrs: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct RecoveryAnnounceRef {
    vid: String,
    epoch: u64,
    digest: String,
}

#[derive(Deserialize)]
pub(crate) struct CompleteRequest {
    open_hex: String,
    confirmed_subject: String,
    roster: Vec<String>,
    trustees: Vec<TrusteeAddress>,
    #[serde(default)]
    announce_refs: Vec<RecoveryAnnounceRef>,
}

#[derive(Deserialize)]
pub(crate) struct PreviewRequest {
    open_hex: String,
}

fn bad(message: impl Into<String>) -> ClaimantError {
    ClaimantError(StatusCode::BAD_REQUEST, message.into())
}

#[derive(Debug)]
pub(crate) struct ClaimantError(StatusCode, String);

impl IntoResponse for ClaimantError {
    fn into_response(self) -> Response {
        crate::handlers::error_response(self.0, self.1)
    }
}

/// Serve the claimant-only shell. The token is a fixed-length hexadecimal value.
pub(crate) async fn shell(State(state): State<ClaimantState>) -> Response {
    let Some(asset) = claimant_asset("claimant.html") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let html = String::from_utf8_lossy(asset).replace("__CARAPACE_CLAIMANT_TOKEN__", &state.token);
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            ),
        ],
        html,
    )
        .into_response()
}

/// Serve one fixed claimant asset. No normal GUI asset fallback is available here.
pub(crate) async fn asset(path: &'static str, content_type: &'static str) -> Response {
    let Some(asset) = claimant_asset(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        asset,
    )
        .into_response()
}

pub(crate) async fn script() -> Response {
    asset("claimant.js", "text/javascript; charset=utf-8").await
}

pub(crate) async fn stylesheet() -> Response {
    asset("claimant.css", "text/css; charset=utf-8").await
}

/// Return the public inputs that a sponsor must put in `RecoveryOpen`.
pub(crate) async fn status(State(state): State<ClaimantState>) -> Json<Value> {
    let guard = state.claimant.lock().await;
    match guard.as_ref() {
        Some(claimant) => {
            let ceremony_enc = hex::encode(claimant.ceremony_enc());
            let new_node = hex::encode(claimant.new_node());
            let handoff = json!({
                "type": "carapace.claimant-handoff",
                "version": 1,
                "ceremony_enc": ceremony_enc.clone(),
                "new_node": new_node.clone(),
            })
            .to_string();
            Json(json!({
                "phase": "waiting_for_open",
                "handoff": handoff,
                "ceremony_enc": ceremony_enc,
                "new_node": new_node,
            }))
        }
        None => Json(json!({
            "phase": "activation_complete",
            "restart_required": true,
        })),
    }
}

/// Cancel the current attempt, drop its secret keys, and create a fresh retry session.
pub(crate) async fn cancel(
    State(state): State<ClaimantState>,
) -> Result<Json<Value>, ClaimantError> {
    let fresh = ClaimantDevice::new().map_err(|_| {
        ClaimantError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not create a fresh claimant session".into(),
        )
    })?;
    let old = state.claimant.lock().await.replace(fresh);
    drop(old);
    crate::ops::log("claimant.cancelled", None);
    Ok(Json(json!({
        "phase": "waiting_for_open",
        "cancelled": true,
        "retry_ready": true,
    })))
}

fn decode_open(open_hex: &str) -> Result<RecoveryOpen, ClaimantError> {
    let open_bytes =
        hex::decode(open_hex).map_err(|error| bad(format!("invalid open hex: {error}")))?;
    let open = RecoveryOpen::decode_frame(&open_bytes)
        .map_err(|error| bad(format!("invalid recovery open: {error}")))?;
    open.verify()
        .map_err(|_| bad("the recovery open signature is invalid"))?;
    Ok(open)
}

/// Verify a signed open and show its subject before any share collection or activation.
pub(crate) async fn preview(
    State(state): State<ClaimantState>,
    Json(request): Json<PreviewRequest>,
) -> Result<Json<Value>, ClaimantError> {
    let open = decode_open(&request.open_hex)?;
    let guard = state.claimant.lock().await;
    let claimant = guard.as_ref().ok_or_else(|| {
        ClaimantError(
            StatusCode::CONFLICT,
            "claimant activation is complete".into(),
        )
    })?;
    if open.ceremony_enc != claimant.ceremony_enc() || open.new_node != claimant.new_node() {
        return Err(bad("the recovery open does not name this claimant session"));
    }
    Ok(Json(json!({
        "subject": hex::encode(open.subject),
        "sponsor": hex::encode(open.by),
        "claimant_display": open.claimant_display,
        "reason": open.reason,
        "session_bound": true,
    })))
}

/// Collect sealed shares, reconstruct in memory, and activate secure local state.
pub(crate) async fn complete(
    State(state): State<ClaimantState>,
    Json(request): Json<CompleteRequest>,
) -> Result<Json<Value>, ClaimantError> {
    let open = decode_open(&request.open_hex)?;
    let confirmed_subject = decode_32("confirmed subject", &request.confirmed_subject)?;
    if confirmed_subject != open.subject {
        return Err(bad(
            "the confirmed subject does not match the signed recovery open",
        ));
    }
    let roster = request
        .roster
        .iter()
        .map(|value| decode_32("roster user", value))
        .collect::<Result<Vec<_>, _>>()?;
    let trustees = request
        .trustees
        .iter()
        .map(|trustee| {
            Ok((
                decode_32("trustee node", &trustee.node)?,
                trustee.addrs.clone(),
            ))
        })
        .collect::<Result<Vec<_>, ClaimantError>>()?;
    if roster.is_empty() {
        return Err(bad("the trustee roster is empty"));
    }
    if !roster.contains(&open.by) {
        return Err(bad("the recovery-open signer is not in the trustee roster"));
    }
    if trustees.is_empty() {
        return Err(bad("the trustee address list is empty"));
    }

    // Take the claimant out during the network operation. This prevents two requests
    // from collecting and activating the same ceremony at the same time.
    let claimant = state.claimant.lock().await.take().ok_or_else(|| {
        ClaimantError(
            StatusCode::CONFLICT,
            "claimant activation is already complete or active".into(),
        )
    })?;

    if open.ceremony_enc != claimant.ceremony_enc() || open.new_node != claimant.new_node() {
        *state.claimant.lock().await = Some(claimant);
        return Err(bad("the recovery open does not name this claimant session"));
    }

    let recovered = match claimant.recover_at(&open, &roster, &trustees).await {
        Ok(recovered) => recovered,
        Err(error) => {
            let _ = error;
            crate::ops::log("claimant.recovery_failed", None);
            *state.claimant.lock().await = Some(claimant);
            return Err(ClaimantError(
                StatusCode::BAD_GATEWAY,
                "recovery did not complete".into(),
            ));
        }
    };
    if recovered.user_id != open.subject || recovered.new_node != open.new_node {
        *state.claimant.lock().await = Some(claimant);
        return Err(bad(
            "the recovered identity does not match the recovery open",
        ));
    }

    let user_id = recovered.user_id;
    let new_node = recovered.new_node;
    let node_seed = claimant.node_seed();
    if persist_restart_handoff(&state.state_dir, &request.trustees, &request.announce_refs).is_err()
    {
        *state.claimant.lock().await = Some(claimant);
        return Err(ClaimantError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the restart recovery handoff could not be saved".into(),
        ));
    }
    let activated =
        match activate_recovered_identity(&state.state_dir, node_seed, *recovered.k_root)
            .context("activate recovered identity")
        {
            Ok(activated) => activated,
            Err(error) => {
                let _ = error;
                let _ = fs::remove_file(state.state_dir.join("recovery-restart-handoff.json"));
                crate::ops::log("claimant.activation_failed", None);
                *state.claimant.lock().await = Some(claimant);
                return Err(ClaimantError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "recovered identity activation failed".into(),
                ));
            }
        };
    drop(activated);
    drop(recovered);
    drop(claimant);

    Ok(Json(json!({
        "phase": "activation_complete",
        "user_id": hex::encode(user_id),
        "new_node": hex::encode(new_node),
        "restart_required": true,
    })))
}

#[derive(Serialize)]
struct RestartHandoff<'a> {
    r#type: &'static str,
    version: u8,
    trustees: &'a [TrusteeAddress],
    announce_refs: &'a [RecoveryAnnounceRef],
}

fn persist_restart_handoff(
    state_dir: &Path,
    trustees: &[TrusteeAddress],
    announce_refs: &[RecoveryAnnounceRef],
) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = state_dir.join("recovery-restart-handoff.json");
    let temporary = state_dir.join(".recovery-restart-handoff.tmp");
    let bytes = serde_json::to_vec(&RestartHandoff {
        r#type: "carapace.recovery-restart-handoff",
        version: 1,
        trustees,
        announce_refs,
    })?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn decode_32(label: &str, value: &str) -> Result<[u8; 32], ClaimantError> {
    let bytes = hex::decode(value).map_err(|error| bad(format!("invalid {label} hex: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| bad(format!("{label} must contain 32 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use ed25519_dalek::SigningKey;
    use tower::ServiceExt;

    fn test_state(dir: PathBuf) -> ClaimantState {
        ClaimantState::new(dir, Arc::from("test-token")).unwrap()
    }

    #[tokio::test]
    async fn status_exposes_only_public_claimant_values() {
        let dir = tempfile::tempdir().unwrap();
        let Json(value) = status(State(test_state(dir.path().to_path_buf()))).await;
        let object = value.as_object().unwrap();
        assert_eq!(object.get("phase").unwrap(), "waiting_for_open");
        assert_eq!(
            object.get("ceremony_enc").unwrap().as_str().unwrap().len(),
            64
        );
        assert_eq!(object.get("new_node").unwrap().as_str().unwrap().len(), 64);
        let handoff: Value = serde_json::from_str(object["handoff"].as_str().unwrap()).unwrap();
        assert_eq!(handoff["type"], "carapace.claimant-handoff");
        assert_eq!(handoff["version"], 1);
        assert_eq!(handoff["ceremony_enc"], object["ceremony_enc"]);
        assert_eq!(handoff["new_node"], object["new_node"]);
        for secret_name in ["k_root", "node_seed", "ceremony_private", "shares"] {
            assert!(
                !object.contains_key(secret_name),
                "status exposed {secret_name}"
            );
        }
    }

    #[tokio::test]
    async fn complete_rejects_an_open_for_another_claimant_before_network_access() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf());
        let sponsor = SigningKey::from_bytes(&[5; 32]);
        let mut open = RecoveryOpen {
            ceremony_id: [1; 16],
            subject: [2; 32],
            rsid: 1,
            claimant_display: "Test claimant".into(),
            ceremony_enc: [3; 32],
            new_node: [4; 32],
            reason: "Test recovery".into(),
            opened_at: 1,
            by: [0; 32],
            sig: [0; 64],
        };
        open.sign(&sponsor);
        let request = CompleteRequest {
            open_hex: hex::encode(open.encode_frame()),
            confirmed_subject: hex::encode(open.subject),
            roster: vec![hex::encode(sponsor.verifying_key().to_bytes())],
            trustees: vec![TrusteeAddress {
                node: hex::encode([6; 32]),
                addrs: Vec::new(),
            }],
            announce_refs: Vec::new(),
        };
        let error = complete(State(state.clone()), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("does not name this claimant session"));
        assert!(
            state.claimant.lock().await.is_some(),
            "claimant must remain usable"
        );
    }

    #[tokio::test]
    async fn complete_rejects_an_invalid_open_signature_before_network_access() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf());
        let (ceremony_enc, new_node) = {
            let guard = state.claimant.lock().await;
            let claimant = guard.as_ref().unwrap();
            (claimant.ceremony_enc(), claimant.new_node())
        };
        let sponsor = SigningKey::from_bytes(&[7; 32]);
        let open = RecoveryOpen {
            ceremony_id: [1; 16],
            subject: [2; 32],
            rsid: 1,
            claimant_display: "Test claimant".into(),
            ceremony_enc,
            new_node,
            reason: "Test recovery".into(),
            opened_at: 1,
            by: sponsor.verifying_key().to_bytes(),
            sig: [0; 64],
        };
        let request = CompleteRequest {
            open_hex: hex::encode(open.encode_frame()),
            confirmed_subject: hex::encode(open.subject),
            roster: vec![hex::encode(sponsor.verifying_key().to_bytes())],
            trustees: vec![TrusteeAddress {
                node: hex::encode([6; 32]),
                addrs: Vec::new(),
            }],
            announce_refs: Vec::new(),
        };
        let error = complete(State(state.clone()), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1, "the recovery open signature is invalid");
        assert!(state.claimant.lock().await.is_some());
    }

    #[tokio::test]
    async fn preview_shows_the_signed_subject_and_complete_requires_that_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf());
        let (ceremony_enc, new_node) = {
            let guard = state.claimant.lock().await;
            let claimant = guard.as_ref().unwrap();
            (claimant.ceremony_enc(), claimant.new_node())
        };
        let sponsor = SigningKey::from_bytes(&[8; 32]);
        let mut open = RecoveryOpen {
            ceremony_id: [1; 16],
            subject: [9; 32],
            rsid: 1,
            claimant_display: "Test claimant".into(),
            ceremony_enc,
            new_node,
            reason: "Test recovery".into(),
            opened_at: 1,
            by: [0; 32],
            sig: [0; 64],
        };
        open.sign(&sponsor);
        let open_hex = hex::encode(open.encode_frame());
        let Json(value) = preview(
            State(state.clone()),
            Json(PreviewRequest {
                open_hex: open_hex.clone(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(value["subject"], hex::encode(open.subject));
        assert_eq!(value["session_bound"], true);

        let error = complete(
            State(state.clone()),
            Json(CompleteRequest {
                open_hex,
                confirmed_subject: hex::encode([7; 32]),
                roster: vec![hex::encode(sponsor.verifying_key().to_bytes())],
                trustees: vec![TrusteeAddress {
                    node: hex::encode([6; 32]),
                    addrs: Vec::new(),
                }],
                announce_refs: Vec::new(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("confirmed subject does not match"));
        assert!(state.claimant.lock().await.is_some());
    }

    #[tokio::test]
    async fn claimant_router_serves_only_the_claimant_shell_and_api() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf());
        let app = crate::claimant_app(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "127.0.0.1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Claimant mode"));
        assert!(html.contains("carapace-claimant-token"));
        for forbidden in ["K_root", "node_seed", "ceremony_private", "share_json"] {
            assert!(
                !html.contains(forbidden),
                "claimant shell exposed {forbidden}"
            );
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .header(header::HOST, "127.0.0.1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cancellation_replaces_keys_and_leaves_a_safe_retry_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf());
        let before = state.claimant.lock().await.as_ref().unwrap().ceremony_enc();
        let Json(result) = cancel(State(state.clone())).await.unwrap();
        let after = state.claimant.lock().await.as_ref().unwrap().ceremony_enc();
        assert_ne!(before, after);
        assert_eq!(result["cancelled"], true);
        assert_eq!(result["retry_ready"], true);
    }

    #[test]
    fn restart_handoff_is_public_versioned_and_private_on_unix() {
        let dir = tempfile::tempdir().unwrap();
        let trustees = vec![TrusteeAddress {
            node: hex::encode([3; 32]),
            addrs: vec!["127.0.0.1:9000".into()],
        }];
        let refs = vec![RecoveryAnnounceRef {
            vid: hex::encode([4; 32]),
            epoch: 7,
            digest: hex::encode([5; 32]),
        }];
        persist_restart_handoff(dir.path(), &trustees, &refs).unwrap();
        let path = dir.path().join("recovery-restart-handoff.json");
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("carapace.recovery-restart-handoff"));
        assert!(text.contains("\"epoch\":7"));
        for secret in ["k_root", "node_seed", "share_json", "ceremony_private"] {
            assert!(!text.contains(secret));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
