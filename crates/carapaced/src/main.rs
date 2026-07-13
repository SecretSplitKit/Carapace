//! `carapaced` CLI. The mandatory Phase 1 deliverable is the two-device sync
//! integration test; this binary is a thin operator surface over [`carapaced`].
//!
//! Usage:
//!   carapaced run --state-dir <PATH> [--publish <DIR> --vid <64-hex>]
//!
//! `run` binds the endpoint, serves the blob store + control protocol, prints
//! this device's node id and dialable address, optionally publishes a vault, and
//! idles until Ctrl-C.

use anyhow::{bail, Context, Result};
use carapaced::{Daemon, State};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") => run(args.collect()).await,
        Some(other) => bail!("unknown command {other:?}; try: carapaced run --state-dir <PATH>"),
        None => bail!("usage: carapaced run --state-dir <PATH> [--publish <DIR> --vid <64-hex>]"),
    }
}

async fn run(rest: Vec<String>) -> Result<()> {
    let mut state_dir: Option<PathBuf> = None;
    let mut publish: Option<PathBuf> = None;
    let mut vid_hex: Option<String> = None;

    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => state_dir = Some(it.next().context("--state-dir needs a value")?.into()),
            "--publish" => publish = Some(it.next().context("--publish needs a value")?.into()),
            "--vid" => vid_hex = Some(it.next().context("--vid needs a value")?),
            other => bail!("unknown flag {other:?}"),
        }
    }

    let state_dir = state_dir.context("--state-dir is required")?;
    let state = State::load_or_generate(&state_dir)?;
    let daemon = Daemon::start(state).await?;

    println!("node_id: {}", hex(&daemon.node_id()));
    match daemon.addr() {
        Ok(addr) => println!("addr: {addr:?}"),
        Err(e) => eprintln!("addr unavailable: {e}"),
    }

    if let Some(dir) = publish {
        let vid = match vid_hex {
            Some(h) => parse_vid(&h)?,
            None => {
                let (v, _nonce) = daemon.new_vid();
                v
            }
        };
        let epoch = daemon.publish_vault(&dir, vid).await?;
        println!("published vid {} at epoch {epoch}", hex(&vid));
    }

    println!("serving; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await.context("wait for Ctrl-C")?;
    daemon.shutdown().await;
    Ok(())
}

fn parse_vid(h: &str) -> Result<[u8; 32]> {
    if h.len() != 64 {
        bail!("--vid must be 64 hex chars");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).context("bad hex in --vid")?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}
