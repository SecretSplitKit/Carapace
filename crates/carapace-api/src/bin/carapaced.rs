//! `carapaced` CLI: bind the daemon endpoint and start the loopback control API.
//!
//! Usage:
//!   carapaced run --state-dir <PATH> [--publish <DIR> --vid <64-hex>] [--api-port <PORT>]
//!
//! `run` loads/generates the device state, starts the daemon (serving the blob
//! store + `carapace/1` control protocol), optionally publishes a vault, starts the
//! loopback control API (127.0.0.1 + per-session bearer token), prints the API URL
//! and where the token lives, and idles until Ctrl-C.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use carapaced::{Daemon, NetConfig, State};

/// Default bind for the embedded relay when `--relay` is given no explicit socket.
const DEFAULT_RELAY_BIND: &str = "0.0.0.0:9991";

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
    let mut bind: Option<SocketAddr> = None;
    let mut relays: Vec<carapaced::RelayUrl> = Vec::new();
    let mut run_relay: Option<SocketAddr> = None;
    let mut relay_host: Option<String> = None;

    let mut it = rest.into_iter().peekable();
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
            "--bind" => {
                bind = Some(
                    it.next()
                        .context("--bind needs an ip:port value")?
                        .parse()
                        .context("--bind must be ip:port")?,
                )
            }
            // Run the embedded self-hosted relay (§6). Optional value = its bind
            // socket; defaults to `0.0.0.0:9991`. The next token is taken as the
            // bind only if it is not another flag.
            "--relay" => {
                let b = match it.peek() {
                    Some(v) if !v.starts_with("--") => it.next().unwrap(),
                    _ => DEFAULT_RELAY_BIND.to_string(),
                };
                run_relay = Some(b.parse().context("--relay bind must be ip:port")?);
            }
            // Host/IP to advertise in our relay URL (e.g. a public DNS name/WAN IP).
            "--relay-host" => {
                relay_host = Some(it.next().context("--relay-host needs a host or ip")?)
            }
            // A friend's self-hosted relay URL to consume (repeatable). These form
            // this node's usable relay set for relay fallback (§6).
            "--relay-url" => relays.push(
                it.next()
                    .context("--relay-url needs an http(s)://host:port url")?
                    .parse()
                    .context("--relay-url must be a valid relay url")?,
            ),
            other => bail!("unknown flag {other:?}"),
        }
    }

    let state_dir = state_dir.context("--state-dir is required")?;
    let state = State::load_or_generate(&state_dir)?;
    let networked = bind.is_some() || run_relay.is_some() || !relays.is_empty();
    let daemon = Arc::new(if networked {
        let cfg = NetConfig {
            bind,
            relays,
            run_relay,
            relay_host,
        };
        Daemon::start_on(state, carapaced::ReplicaLimits::default(), cfg).await?
    } else {
        Daemon::start(state).await?
    });

    println!("node_id: {}", hex(&daemon.node_id()));
    match daemon.addr() {
        Ok(addr) => println!("addr: {addr:?}"),
        Err(e) => eprintln!("addr unavailable: {e}"),
    }
    if let Some(url) = daemon.advertised_relay_url() {
        println!("relay_url: {url}");
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
