//! `carapaced` CLI: bind the daemon endpoint and start the loopback control API.
//!
//! Usage:
//!   carapaced run --state-dir <PATH> [--publish <DIR> --vid <64-hex>] [--api-port <PORT>]
//!
//! `run` loads/generates the device state, starts the daemon (serving the blob
//! store + `carapace/1` control protocol), optionally publishes a vault, starts the
//! loopback control API (127.0.0.1 + per-session bearer token), prints the API URL
//! and where the token lives, and idles until Ctrl-C.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use carapaced::{Daemon, State};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") => run(args.collect()).await,
        Some(other) => bail!("unknown command {other:?}; try: carapaced run --state-dir <PATH>"),
        None => bail!(
            "usage: carapaced run --state-dir <PATH> [--publish <DIR> --vid <64-hex>] [--api-port <PORT>]"
        ),
    }
}

async fn run(rest: Vec<String>) -> Result<()> {
    let mut state_dir: Option<PathBuf> = None;
    let mut publish: Option<PathBuf> = None;
    let mut vid_hex: Option<String> = None;
    let mut api_port: u16 = 0;

    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => {
                state_dir = Some(it.next().context("--state-dir needs a value")?.into())
            }
            "--publish" => publish = Some(it.next().context("--publish needs a value")?.into()),
            "--vid" => vid_hex = Some(it.next().context("--vid needs a value")?),
            "--api-port" => {
                api_port = it
                    .next()
                    .context("--api-port needs a value")?
                    .parse()
                    .context("--api-port must be a u16 port")?
            }
            other => bail!("unknown flag {other:?}"),
        }
    }

    let state_dir = state_dir.context("--state-dir is required")?;
    let state = State::load_or_generate(&state_dir)?;
    let daemon = Arc::new(Daemon::start(state).await?);

    println!("node_id: {}", hex(&daemon.node_id()));
    match daemon.addr() {
        Ok(addr) => println!("addr: {addr:?}"),
        Err(e) => eprintln!("addr unavailable: {e}"),
    }

    if let Some(dir) = publish {
        let vid = match vid_hex {
            Some(h) => parse_vid(&h)?,
            None => daemon.new_vid().0,
        };
        let epoch = daemon.publish_vault(&dir, vid).await?;
        println!("published vid {} at epoch {epoch}", hex(&vid));
    }

    let api = carapace_api::serve(Arc::clone(&daemon), &state_dir, api_port).await?;
    println!("control API: {}", api.url());
    println!(
        "api token: {} (bearer, 0600)",
        state_dir.join("api-token").display()
    );

    println!("serving; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await.context("wait for Ctrl-C")?;
    api.shutdown();
    match Arc::try_unwrap(daemon) {
        Ok(d) => d.shutdown().await,
        Err(_) => eprintln!("daemon still referenced at shutdown; skipping graceful close"),
    }
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
