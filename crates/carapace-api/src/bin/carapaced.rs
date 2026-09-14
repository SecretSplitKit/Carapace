//! `carapaced` CLI: bind the daemon endpoint and start the loopback control API.
//!
//! Usage:
//!   carapaced run --state-dir <PATH> [--publish <DIR> [--watch] --vid <64-hex>] [--api-port <PORT>]
//!   carapaced claimant --state-dir <PATH> [--api-port <PORT>]
//!
//! `run` loads/generates the device state, starts the daemon (serving the blob
//! store + `carapace/1` control protocol), optionally publishes a vault, starts the
//! loopback control API (127.0.0.1 + per-session bearer token), prints the API URL
//! and where the token lives, and idles until Ctrl-C.

use std::ffi::OsStr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use carapaced::{Daemon, NetConfig, State};
use zeroize::Zeroizing;

#[path = "carapaced/state_ops.rs"]
mod state_ops;

/// Default bind for the embedded relay when `--relay` is given no explicit socket.
const DEFAULT_RELAY_BIND: &str = "0.0.0.0:9991";

const HELP: &str = "Usage: carapaced [run|claimant|inspect-state|initialize-empty|restore-backup|reset-security-state|migrate-legacy-state|migrate-keys] [OPTIONS]\nNo arguments: use the platform data directory and open the browser.\nrun options: --state-dir PATH --api-port PORT --open --publish DIR --watch --vid HEX --bind IP:PORT --relay [IP:PORT] --relay-url URL --relay-host HOST --terminal-passphrase --insecure-plaintext-keys";

trait PassphrasePrompt {
    fn read(&self) -> Result<Zeroizing<String>>;
}

struct ControllingTerminalPrompt;

impl PassphrasePrompt for ControllingTerminalPrompt {
    fn read(&self) -> Result<Zeroizing<String>> {
        #[cfg(unix)]
        let _terminal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("terminal-passphrase mode requires a controlling terminal")?;
        let passphrase = Zeroizing::new(
            rpassword::prompt_password("Carapace identity passphrase: ")
                .context("read passphrase from the controlling terminal")?,
        );
        ensure_nonempty_passphrase(passphrase)
    }
}

fn ensure_nonempty_passphrase(passphrase: Zeroizing<String>) -> Result<Zeroizing<String>> {
    if passphrase.is_empty() {
        bail!("the terminal passphrase is empty");
    }
    Ok(passphrase)
}

fn read_operator_passphrase(prompt: &dyn PassphrasePrompt) -> Result<Zeroizing<String>> {
    ensure_nonempty_passphrase(prompt.read()?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") => run(args.collect()).await,
        Some("--help" | "-h") => {
            println!("{HELP}");
            Ok(())
        }
        Some("--version" | "-V") => {
            println!("carapaced {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("claimant") => claimant(args.collect()).await,
        Some("inspect-state") => state_ops::inspect_state(args.collect()),
        Some("initialize-empty") => state_ops::initialize_empty(args.collect()),
        Some("restore-backup") => state_ops::restore_backup(args.collect()),
        Some("reset-security-state") => state_ops::reset_security_state(args.collect()),
        Some("migrate-legacy-state") => state_ops::migrate_legacy_state(args.collect()),
        Some("migrate-keys") => migrate_keys(args.collect()),
        Some(other) => {
            bail!("unknown command {other:?}; try: carapaced run, claimant, or a state operator command")
        }
        None => {
            run(vec![
                "--state-dir".into(),
                default_state_dir()?
                    .to_str()
                    .context("default state path is not UTF-8")?
                    .into(),
                "--api-port".into(),
                "43821".into(),
                "--bind".into(),
                "0.0.0.0:0".into(),
                "--open".into(),
            ])
            .await
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ClaimantArgs {
    state_dir: PathBuf,
    api_port: u16,
}

fn parse_claimant_args(rest: Vec<String>) -> Result<ClaimantArgs> {
    let mut state_dir = None;
    let mut api_port = 0;
    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => {
                state_dir = Some(it.next().context("--state-dir needs a value")?.into())
            }
            "--api-port" => {
                api_port = it
                    .next()
                    .context("--api-port needs a value")?
                    .parse()
                    .context("--api-port must be a u16 port")?
            }
            other => bail!("unknown claimant flag {other:?}"),
        }
    }
    Ok(ClaimantArgs {
        state_dir: state_dir.context("--state-dir is required")?,
        api_port,
    })
}

async fn claimant(rest: Vec<String>) -> Result<()> {
    let args = parse_claimant_args(rest)?;
    let api = carapace_api::serve_claimant(&args.state_dir, args.api_port).await?;
    println!("claimant API: {}", api.url());
    println!(
        "claimant API token: {} (bearer, 0600)",
        args.state_dir.join("claimant-api-token").display()
    );
    println!("claimant recovery is active; press Ctrl-C to stop");
    wait_for_stop().await?;
    api.shutdown();
    Ok(())
}

fn migrate_keys(rest: Vec<String>) -> Result<()> {
    let mut state_dir: Option<PathBuf> = None;
    let mut confirmed: Option<PathBuf> = None;
    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => {
                state_dir = Some(it.next().context("--state-dir needs a value")?.into())
            }
            "--confirm-state-dir" => {
                confirmed = Some(
                    it.next()
                        .context("--confirm-state-dir needs a value")?
                        .into(),
                )
            }
            other => bail!("unknown migrate-keys flag {other:?}"),
        }
    }
    let state_dir = state_dir.context("--state-dir is required")?;
    let confirmed = confirmed.context("--confirm-state-dir is required")?;
    let canonical = std::fs::canonicalize(&state_dir)
        .with_context(|| format!("resolve state directory {state_dir:?}"))?;
    let confirmed_canonical = std::fs::canonicalize(&confirmed)
        .with_context(|| format!("resolve confirmed state directory {confirmed:?}"))?;
    if canonical != confirmed_canonical {
        bail!("confirmed state directory does not match --state-dir");
    }
    let backup = State::migrate_legacy_keys(&canonical)?;
    println!(
        "key migration complete; protected backup: {}",
        backup.display()
    );
    Ok(())
}

async fn run(rest: Vec<String>) -> Result<()> {
    if rest
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!("{HELP}");
        return Ok(());
    }
    let mut state_dir: Option<PathBuf> = None;
    let mut publish: Option<PathBuf> = None;
    let mut watch = false;
    let mut vid_hex: Option<String> = None;
    let mut api_port: u16 = 0;
    let mut bind: Option<SocketAddr> = None;
    let mut relays: Vec<carapaced::RelayUrl> = Vec::new();
    let mut run_relay: Option<SocketAddr> = None;
    let mut relay_host: Option<String> = None;
    let mut insecure_plaintext_keys = false;
    let mut terminal_passphrase = false;
    let mut open = false;

    let mut it = rest.into_iter().peekable();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => {
                state_dir = Some(it.next().context("--state-dir needs a value")?.into())
            }
            "--publish" => publish = Some(it.next().context("--publish needs a value")?.into()),
            // §11 live sync: keep re-ingesting the published dir on local changes.
            "--watch" => watch = true,
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
            "--insecure-plaintext-keys" => insecure_plaintext_keys = true,
            "--terminal-passphrase" => terminal_passphrase = true,
            "--open" => open = true,
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
    let networked = bind.is_some() || run_relay.is_some() || !relays.is_empty();
    if insecure_plaintext_keys && networked {
        bail!("--insecure-plaintext-keys cannot be used with non-loopback or relay operation");
    }
    if insecure_plaintext_keys && terminal_passphrase {
        bail!("--terminal-passphrase cannot be combined with --insecure-plaintext-keys");
    }
    let state = if insecure_plaintext_keys {
        eprintln!(
            "carapace: WARNING insecure development mode stores identity secrets in local files"
        );
        State::load_or_generate_insecure(&state_dir)?
    } else if terminal_passphrase {
        eprintln!(
            "carapace: WARNING terminal-passphrase mode stays locked after unattended restart; recovery takeover delay and alarms cannot run while locked"
        );
        let passphrase = read_operator_passphrase(&ControllingTerminalPrompt)?;
        State::load_protected_local(&state_dir, passphrase.as_bytes())?
    } else {
        State::load_or_generate(&state_dir)?
    };
    let daemon = Arc::new(if networked || !insecure_plaintext_keys {
        let cfg = NetConfig {
            bind: bind.or(Some(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))),
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
    } else if watch {
        bail!("--watch requires --publish <DIR>");
    }

    let api = carapace_api::serve(Arc::clone(&daemon), &state_dir, api_port).await?;
    println!("control API: {}", api.url());
    if open {
        open_browser(&api.url());
    }
    println!(
        "api token: {} (bearer, 0600)",
        state_dir.join("api-token").display()
    );

    println!("serving; press Ctrl-C to stop");
    wait_for_stop().await?;
    api.shutdown();
    // `shutdown(&self)` flushes the blob store + closes the endpoint regardless of
    // how many `Arc<Daemon>` clones the API server / watcher tasks still hold — the
    // durability flush must never be skipped because of a lingering reference.
    daemon.shutdown().await;
    Ok(())
}

/// Block until a stop signal arrives. Handles SIGINT (Ctrl-C) AND, on unix,
/// SIGTERM — a normal OS reboot / service manager stop sends SIGTERM, and an
/// unhandled SIGTERM kills the process without running `Daemon::shutdown`, so
/// the blob store's last write batch would be lost. Both must take the same
/// graceful path.
async fn wait_for_stop() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r.context("wait for Ctrl-C")?,
            _ = term.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("wait for Ctrl-C")
    }
}

fn default_state_dir() -> Result<PathBuf> {
    default_state_dir_for(
        std::env::consts::OS,
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("LOCALAPPDATA").as_deref(),
        std::env::var_os("XDG_DATA_HOME").as_deref(),
    )
}

fn default_state_dir_for(
    os: &str,
    home: Option<&OsStr>,
    local_app_data: Option<&OsStr>,
    xdg_data_home: Option<&OsStr>,
) -> Result<PathBuf> {
    match os {
        "windows" => {
            Ok(PathBuf::from(local_app_data.context("LOCALAPPDATA is not set")?).join("Carapace"))
        }
        "macos" => Ok(PathBuf::from(home.context("HOME is not set")?)
            .join("Library/Application Support/Carapace")),
        _ => Ok(match xdg_data_home {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(home.context("HOME and XDG_DATA_HOME are not set")?)
                .join(".local/share"),
        }
        .join("carapace")),
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let result = Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let result = Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = Command::new("xdg-open").arg(url).spawn();
    if let Err(error) = result {
        eprintln!("could not open the web interface: {error}");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn values(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn desktop_directories_follow_platform_conventions() {
        use std::ffi::OsStr;
        assert_eq!(
            default_state_dir_for(
                "windows",
                None,
                Some(OsStr::new(r"C:\Users\Alice\AppData\Local")),
                None
            )
            .unwrap(),
            PathBuf::from(r"C:\Users\Alice\AppData\Local").join("Carapace")
        );
        assert_eq!(
            default_state_dir_for("macos", Some(OsStr::new("/Users/alice")), None, None).unwrap(),
            PathBuf::from("/Users/alice/Library/Application Support/Carapace")
        );
        assert_eq!(
            default_state_dir_for("linux", Some(OsStr::new("/home/alice")), None, None).unwrap(),
            PathBuf::from("/home/alice/.local/share/carapace")
        );
        assert!(default_state_dir_for("windows", None, None, None).is_err());
    }

    #[test]
    fn claimant_arguments_default_to_an_ephemeral_port() {
        let parsed = parse_claimant_args(values(&["--state-dir", "/tmp/claimant"])).unwrap();
        assert_eq!(parsed.state_dir, PathBuf::from("/tmp/claimant"));
        assert_eq!(parsed.api_port, 0);
    }

    #[test]
    fn claimant_arguments_accept_an_api_port() {
        let parsed = parse_claimant_args(values(&[
            "--state-dir",
            "/tmp/claimant",
            "--api-port",
            "4711",
        ]))
        .unwrap();
        assert_eq!(parsed.api_port, 4711);
    }

    #[test]
    fn claimant_arguments_reject_missing_and_extra_values() {
        let missing = parse_claimant_args(Vec::new()).unwrap_err();
        assert!(missing.to_string().contains("--state-dir is required"));
        let extra =
            parse_claimant_args(values(&["--state-dir", "/tmp/c", "--bind", "x"])).unwrap_err();
        assert!(extra.to_string().contains("unknown claimant flag"));
    }

    struct FakePrompt(&'static str);
    impl PassphrasePrompt for FakePrompt {
        fn read(&self) -> Result<Zeroizing<String>> {
            Ok(Zeroizing::new(self.0.to_string()))
        }
    }

    #[test]
    fn terminal_passphrase_prompt_rejects_empty_input() {
        assert!(read_operator_passphrase(&FakePrompt("")).is_err());
        assert_eq!(
            read_operator_passphrase(&FakePrompt("operator secret"))
                .unwrap()
                .as_str(),
            "operator secret"
        );
    }
}
