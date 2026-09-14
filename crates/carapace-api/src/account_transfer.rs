//! Token-gated explicit same-account device transfer.
use crate::{handlers, AppState};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use carapace_wire::messages::Message;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

#[derive(Deserialize)]
pub struct ExportRequest {
    passphrase: String,
}
pub async fn export(State(st): State<AppState>, Json(request): Json<ExportRequest>) -> Response {
    let passphrase = Zeroizing::new(request.passphrase);
    match st.daemon.account_export(passphrase.as_bytes()) {
        Ok((package,card)) => Json(json!({"package_hex":hex::encode(package),"user_id":hex::encode(card.user),"card_hex":hex::encode(card.encode_frame())})).into_response(),
        Err(_) => handlers::error_response(StatusCode::BAD_REQUEST,"account export failed; a nonempty passphrase is required"),
    }
}

#[derive(Deserialize)]
pub struct ImportRequest {
    package_hex: String,
    passphrase: String,
    destination: String,
}
pub async fn import(State(st): State<AppState>, Json(request): Json<ImportRequest>) -> Response {
    let passphrase = Zeroizing::new(request.passphrase);
    let package = match hex::decode(request.package_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            return handlers::error_response(StatusCode::BAD_REQUEST, "invalid transfer package")
        }
    };
    match st.daemon.account_import(&package,passphrase.as_bytes(),std::path::Path::new(&request.destination)).await {
        Ok(report)=>Json(json!({"user_id":hex::encode(report.user_id),"state_dir":report.state_dir,"card_hex":hex::encode(report.card.encode_frame()),"source_card_hex":hex::encode(report.source_card.encode_frame()),"restart_required":true})).into_response(),
        Err(error)=>{ crate::ops::log("account.import_failed",None); let _ = error; handlers::error_response(StatusCode::BAD_REQUEST,"account import failed; check the package, passphrase and fresh destination") }
    }
}
