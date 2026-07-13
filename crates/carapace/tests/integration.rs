//! Drives the real `carapace-api` (fronting a real `Daemon`) through the
//! `carapace` client's public entry point, over a real loopback socket.

use std::sync::Arc;

use carapace_api::serve;
use carapaced::{Daemon, State};

fn a(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_prints_the_real_node_id() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::from_seeds([3u8; 32], [4u8; 32]);
    let daemon = Arc::new(Daemon::start(state).await.unwrap());
    let api = serve(Arc::clone(&daemon), dir.path(), 0).await.unwrap();

    let node_id_hex: String = daemon
        .node_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let url = api.url();
    let token = api.token.clone();

    let out = tokio::task::spawn_blocking(move || {
        carapace::run(&a(&["--api-url", &url, "--token", &token, "status"]))
    })
    .await
    .unwrap()
    .unwrap();

    assert!(
        out.contains(&node_id_hex),
        "expected node id {node_id_hex} in output: {out}"
    );

    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_token_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::from_seeds([5u8; 32], [6u8; 32]);
    let daemon = Arc::new(Daemon::start(state).await.unwrap());
    let api = serve(Arc::clone(&daemon), dir.path(), 0).await.unwrap();
    let url = api.url();

    let err = tokio::task::spawn_blocking(move || {
        carapace::run(&a(&[
            "--api-url",
            &url,
            "--token",
            "0000000000000000000000000000000000000000000000000000000000000",
            "status",
        ]))
    })
    .await
    .unwrap()
    .unwrap_err();

    assert!(err.to_string().contains("401"), "{err}");
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_url_and_token_resolved_from_state_dir() {
    // No --api-url and no --token: both must come from the daemon's state dir, so the
    // CLI never falls back to a guessed URL that could leak the token to a squatter.
    let dir = tempfile::tempdir().unwrap();
    let state = State::from_seeds([8u8; 32], [9u8; 32]);
    let daemon = Arc::new(Daemon::start(state).await.unwrap());
    let api = serve(Arc::clone(&daemon), dir.path(), 0).await.unwrap();
    let state_dir = dir.path().to_str().unwrap().to_string();

    let out = tokio::task::spawn_blocking(move || {
        carapace::run(&a(&["--state-dir", &state_dir, "status"]))
    })
    .await
    .unwrap()
    .unwrap();

    let node_id_hex: String = daemon
        .node_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(out.contains(&node_id_hex), "{out}");

    api.shutdown();
    drop(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_resolved_from_state_dir_file() {
    let dir = tempfile::tempdir().unwrap();
    let state = State::from_seeds([1u8; 32], [2u8; 32]);
    let daemon = Arc::new(Daemon::start(state).await.unwrap());
    let api = serve(Arc::clone(&daemon), dir.path(), 0).await.unwrap();
    let url = api.url();
    let state_dir = dir.path().to_str().unwrap().to_string();

    let out = tokio::task::spawn_blocking(move || {
        carapace::run(&a(&[
            "--api-url",
            &url,
            "--state-dir",
            &state_dir,
            "status",
        ]))
    })
    .await
    .unwrap()
    .unwrap();

    let node_id_hex: String = daemon
        .node_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(out.contains(&node_id_hex), "{out}");

    api.shutdown();
    drop(dir);
}
