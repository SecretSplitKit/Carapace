//! `carapace`: the CLI client for the `carapace-api` loopback control API.
//!
//! This is a thin HTTP client, not a second implementation of daemon logic: it
//! reads the bearer token, sends a JSON request to a running `carapaced`, and
//! prints the response. See `main.rs` for the entry point; this module holds the
//! (testable) argument parsing, token resolution, and request dispatch.
//!
//! Usage: `carapace [--api-url URL] [--state-dir PATH] [--token TOKEN] [--json] <command>`
//!
//! Commands: `status`, `vault publish <dir> [--vid HEX]`, `vault list`,
//! `friend ticket`, `friend add <ticket-hex> [--storage BYTES] [--addr ADDR]...`,
//! `friend list`, `replica place <vid> <peer> [--addr ADDR]... [--r N]`,
//! `replica list <vid>`, `grant create <vid> <path>... --to USER [--to USER]...`,
//! `grant fetch <grant-hex> --owner-node HEX [--addr ADDR]... --out DIR`.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

// ---- config + command model ------------------------------------------

/// Global options, resolvable from flags, the environment, or the state dir.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// The API base URL. `None` means resolve it from `<state-dir>/api-url`; there is
    /// deliberately no guessed default (the daemon binds an ephemeral port, so a fixed
    /// default would send the bearer token to whatever squats that port).
    pub api_url: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub token: Option<String>,
    pub json: bool,
}

/// A parsed subcommand with its own arguments.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Status,
    VaultPublish {
        dir: String,
        vid: Option<String>,
    },
    VaultList,
    FriendTicket,
    FriendAdd {
        ticket_hex: String,
        storage: Option<u64>,
        addrs: Vec<String>,
    },
    FriendList,
    ReplicaPlace {
        vid: String,
        peer: String,
        addrs: Vec<String>,
        r: usize,
    },
    ReplicaList {
        vid: String,
    },
    GrantCreate {
        vid: String,
        paths: Vec<String>,
        to: Vec<String>,
    },
    GrantFetch {
        grant_hex: String,
        owner_node: String,
        owner_addrs: Vec<String>,
        out: String,
    },
}

/// A fully-parsed invocation: global config plus the command to run.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    pub config: Config,
    pub command: Command,
}

const USAGE: &str =
    "usage: carapace [--api-url URL] [--state-dir PATH] [--token TOKEN] [--json] <command>\n\
commands:\n  \
status\n  \
vault publish <dir> [--vid HEX]\n  \
vault list\n  \
friend ticket\n  \
friend add <ticket-hex> [--storage BYTES] [--addr ADDR]...\n  \
friend list\n  \
replica place <vid> <peer> [--addr ADDR]... [--r N]\n  \
replica list <vid>\n  \
grant create <vid> <path>... --to USER [--to USER]...\n  \
grant fetch <grant-hex> --owner-node HEX [--addr ADDR]... --out DIR";

/// Parse a full CLI invocation: global flags (which may appear anywhere) plus a
/// subcommand and its own arguments. Pure (no I/O): token/env resolution happens
/// later, in [`resolve_token`].
pub fn parse(args: &[String]) -> Result<Invocation> {
    let mut api_url: Option<String> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut token: Option<String> = None;
    let mut json = false;
    let mut rest: Vec<String> = Vec::new();

    let mut it = args.iter().cloned();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--api-url" => api_url = Some(it.next().context("--api-url needs a value")?),
            "--state-dir" => {
                state_dir = Some(it.next().context("--state-dir needs a value")?.into())
            }
            "--token" => token = Some(it.next().context("--token needs a value")?),
            "--json" => json = true,
            _ => rest.push(arg),
        }
    }

    let config = Config {
        api_url,
        state_dir,
        token,
        json,
    };

    let command = parse_command(&rest)?;
    Ok(Invocation { config, command })
}

fn parse_command(rest: &[String]) -> Result<Command> {
    let mut it = rest.iter().cloned();
    let head = it
        .next()
        .ok_or_else(|| anyhow!("missing command\n\n{USAGE}"))?;

    match head.as_str() {
        "status" => Ok(Command::Status),

        "vault" => match it.next().as_deref() {
            Some("publish") => {
                let dir = it.next().context("vault publish needs a <dir>")?;
                let mut vid = None;
                while let Some(flag) = it.next() {
                    match flag.as_str() {
                        "--vid" => vid = Some(it.next().context("--vid needs a value")?),
                        other => bail!("vault publish: unknown flag {other:?}"),
                    }
                }
                Ok(Command::VaultPublish { dir, vid })
            }
            Some("list") => Ok(Command::VaultList),
            Some(other) => bail!("unknown vault subcommand {other:?}; try: publish, list"),
            None => bail!("vault needs a subcommand: publish, list"),
        },

        "friend" => match it.next().as_deref() {
            Some("ticket") => Ok(Command::FriendTicket),
            Some("add") => {
                let ticket_hex = it.next().context("friend add needs a <ticket-hex>")?;
                let mut storage = None;
                let mut addrs = Vec::new();
                while let Some(flag) = it.next() {
                    match flag.as_str() {
                        "--storage" => {
                            storage = Some(
                                it.next()
                                    .context("--storage needs a value")?
                                    .parse()
                                    .context("--storage must be a byte count")?,
                            )
                        }
                        "--addr" => addrs.push(it.next().context("--addr needs a value")?),
                        other => bail!("friend add: unknown flag {other:?}"),
                    }
                }
                Ok(Command::FriendAdd {
                    ticket_hex,
                    storage,
                    addrs,
                })
            }
            Some("list") => Ok(Command::FriendList),
            Some(other) => bail!("unknown friend subcommand {other:?}; try: ticket, add, list"),
            None => bail!("friend needs a subcommand: ticket, add, list"),
        },

        "replica" => match it.next().as_deref() {
            Some("place") => {
                let vid = it.next().context("replica place needs a <vid>")?;
                let peer = it.next().context("replica place needs a <peer>")?;
                let mut addrs = Vec::new();
                let mut r = 1usize;
                while let Some(flag) = it.next() {
                    match flag.as_str() {
                        "--addr" => addrs.push(it.next().context("--addr needs a value")?),
                        "--r" => {
                            r = it
                                .next()
                                .context("--r needs a value")?
                                .parse()
                                .context("--r must be a positive integer")?
                        }
                        other => bail!("replica place: unknown flag {other:?}"),
                    }
                }
                Ok(Command::ReplicaPlace {
                    vid,
                    peer,
                    addrs,
                    r,
                })
            }
            Some("list") => {
                let vid = it.next().context("replica list needs a <vid>")?;
                Ok(Command::ReplicaList { vid })
            }
            Some(other) => bail!("unknown replica subcommand {other:?}; try: place, list"),
            None => bail!("replica needs a subcommand: place, list"),
        },

        "grant" => match it.next().as_deref() {
            Some("create") => {
                let vid = it.next().context("grant create needs a <vid>")?;
                let mut paths = Vec::new();
                let mut to = Vec::new();
                while let Some(arg) = it.next() {
                    match arg.as_str() {
                        "--to" => to.push(it.next().context("--to needs a value")?),
                        other => paths.push(other.to_string()),
                    }
                }
                if paths.is_empty() {
                    bail!("grant create needs at least one <path>");
                }
                if to.is_empty() {
                    bail!("grant create needs at least one --to <user>");
                }
                Ok(Command::GrantCreate { vid, paths, to })
            }
            Some("fetch") => {
                let grant_hex = it.next().context("grant fetch needs a <grant-hex>")?;
                let mut owner_node = None;
                let mut owner_addrs = Vec::new();
                let mut out = None;
                while let Some(flag) = it.next() {
                    match flag.as_str() {
                        "--owner-node" => {
                            owner_node = Some(it.next().context("--owner-node needs a value")?)
                        }
                        "--addr" => owner_addrs.push(it.next().context("--addr needs a value")?),
                        "--out" => out = Some(it.next().context("--out needs a value")?),
                        other => bail!("grant fetch: unknown flag {other:?}"),
                    }
                }
                Ok(Command::GrantFetch {
                    grant_hex,
                    owner_node: owner_node.context("grant fetch needs --owner-node <hex>")?,
                    owner_addrs,
                    out: out.context("grant fetch needs --out <dir>")?,
                })
            }
            Some(other) => bail!("unknown grant subcommand {other:?}; try: create, fetch"),
            None => bail!("grant needs a subcommand: create, fetch"),
        },

        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    }
}

// ---- api url resolution -------------------------------------------------

/// Resolve the API base URL: an explicit `--api-url` wins, else read the daemon's
/// published `<state-dir>/api-url`. There is no guessed default - the daemon binds an
/// ephemeral port, so a fixed guess could send the bearer token to a squatting process.
fn resolve_api_url(cfg: &Config) -> Result<String> {
    if let Some(u) = &cfg.api_url {
        return Ok(u.clone());
    }
    let dir = cfg
        .state_dir
        .as_ref()
        .context("no --api-url given; pass --api-url or --state-dir to read api-url")?;
    let path = dir.join("api-url");
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .with_context(|| format!("read api url from {path:?}"))
}

// ---- token resolution ---------------------------------------------------

/// Resolve the bearer token: an explicit flag wins, then the environment, then
/// `<state-dir>/api-token`. `env_token` is injected (rather than read directly via
/// `std::env::var` here) so this stays a pure, race-free unit under test; [`run`]
/// passes the real `CARAPACE_TOKEN`.
fn resolve_token(cfg: &Config, env_token: Option<String>) -> Result<String> {
    if let Some(t) = &cfg.token {
        return Ok(t.clone());
    }
    if let Some(t) = env_token {
        return Ok(t);
    }
    let dir = cfg
        .state_dir
        .as_ref()
        .context("no --token given; set CARAPACE_TOKEN or pass --state-dir to read api-token")?;
    let path = dir.join("api-token");
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .with_context(|| format!("read token from {path:?}"))
}

// ---- HTTP client --------------------------------------------------------

/// A thin wrapper over an [`ureq::Agent`] that always speaks to one API base URL
/// with one bearer token, and always inspects the status itself (rather than
/// letting a non-2xx become a bare `ureq::Error`) so we can surface the API's own
/// `{"error": ...}` body.
struct Client {
    agent: ureq::Agent,
    base: String,
    token: String,
}

impl Client {
    fn new(base: &str, token: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        Client {
            agent,
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    fn check(status: u16, body: Value) -> Result<Value> {
        if (200..300).contains(&status) {
            return Ok(body);
        }
        let msg = body
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| body.to_string());
        Err(anyhow!("api request failed ({status}): {msg}"))
    }

    fn get(&self, path: &str) -> Result<Value> {
        let mut resp = self
            .agent
            .get(format!("{}{path}", self.base))
            .header("Authorization", format!("Bearer {}", self.token))
            .call()
            .with_context(|| format!("GET {path}"))?;
        let status = resp.status().as_u16();
        let body: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        Self::check(status, body)
    }

    fn post(&self, path: &str, body: Value) -> Result<Value> {
        let mut resp = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("Authorization", format!("Bearer {}", self.token))
            .send_json(body)
            .with_context(|| format!("POST {path}"))?;
        let status = resp.status().as_u16();
        let out: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        Self::check(status, out)
    }
}

// ---- execution + formatting ---------------------------------------------

fn render(value: &Value, json: bool) -> String {
    if json {
        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
    } else {
        human(value)
    }
}

/// Best-effort human-readable rendering of an API response. Falls back to
/// pretty-printed JSON for shapes it doesn't special-case.
fn human(v: &Value) -> String {
    if let Some(node_id) = v.get("node_id").and_then(Value::as_str) {
        let addrs = v
            .get("addr")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let friends = v
            .get("friends")
            .and_then(|f| f.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let published = v
            .get("vaults")
            .and_then(|x| x.get("published"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let held = v
            .get("vaults")
            .and_then(|x| x.get("held_replicas"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        return format!(
            "node_id: {node_id}\naddr: {addrs}\nfriends: {friends}\nvaults published: {published}\nheld replicas: {held}"
        );
    }
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn execute(command: &Command, client: &Client, json: bool) -> Result<String> {
    let value = match command {
        Command::Status => client.get("/api/status")?,

        Command::VaultPublish { dir, vid } => {
            client.post("/api/vaults", json!({ "dir": dir, "vid": vid }))?
        }
        Command::VaultList => client.get("/api/vaults")?,

        Command::FriendTicket => client.post("/api/friends/ticket", json!({}))?,
        Command::FriendAdd {
            ticket_hex,
            storage,
            addrs,
        } => client.post(
            "/api/friends",
            json!({
                "ticket_hex": ticket_hex,
                "addrs": if addrs.is_empty() { Value::Null } else { json!(addrs) },
                "grant_bytes": storage,
            }),
        )?,
        Command::FriendList => client.get("/api/friends")?,

        Command::ReplicaPlace {
            vid,
            peer,
            addrs,
            r,
        } => client.post(
            &format!("/api/vaults/{vid}/replicas"),
            json!({ "peers": [{ "node": peer, "addrs": addrs }], "r": r }),
        )?,
        Command::ReplicaList { vid } => client.get(&format!("/api/vaults/{vid}/replicas"))?,

        Command::GrantCreate { vid, paths, to } => client.post(
            &format!("/api/vaults/{vid}/grants"),
            json!({ "paths": paths, "audience": to }),
        )?,
        Command::GrantFetch {
            grant_hex,
            owner_node,
            owner_addrs,
            out,
        } => client.post(
            "/api/grants/fetch",
            json!({
                "grant_hex": grant_hex,
                "owner": { "node": owner_node, "addrs": owner_addrs },
                "out_dir": out,
            }),
        )?,
    };
    Ok(render(&value, json))
}

/// Parse, resolve the token (flag > `CARAPACE_TOKEN` > `<state-dir>/api-token`),
/// and run the request against the real API, returning the text to print.
pub fn run(args: &[String]) -> Result<String> {
    let inv = parse(args)?;
    let api_url = resolve_api_url(&inv.config)?;
    let token = resolve_token(&inv.config, std::env::var("CARAPACE_TOKEN").ok())?;
    let client = Client::new(&api_url, &token);
    execute(&inv.command, &client, inv.config.json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_status() {
        let inv = parse(&a(&["status"])).unwrap();
        assert_eq!(inv.command, Command::Status);
        assert_eq!(inv.config.api_url, None);
        assert!(!inv.config.json);
    }

    #[test]
    fn parses_global_flags_anywhere() {
        let inv = parse(&a(&["--api-url", "http://127.0.0.1:9", "--json", "status"])).unwrap();
        assert_eq!(inv.config.api_url.as_deref(), Some("http://127.0.0.1:9"));
        assert!(inv.config.json);
        assert_eq!(inv.command, Command::Status);

        let inv2 = parse(&a(&["status", "--token", "abc"])).unwrap();
        assert_eq!(inv2.config.token.as_deref(), Some("abc"));
        assert_eq!(inv2.command, Command::Status);
    }

    #[test]
    fn parses_vault_publish() {
        let inv = parse(&a(&["vault", "publish", "/tmp/dir", "--vid", "ab"])).unwrap();
        assert_eq!(
            inv.command,
            Command::VaultPublish {
                dir: "/tmp/dir".to_string(),
                vid: Some("ab".to_string()),
            }
        );
    }

    #[test]
    fn vault_publish_missing_dir_errors() {
        let err = parse(&a(&["vault", "publish"])).unwrap_err();
        assert!(err.to_string().contains("<dir>"), "{err}");
    }

    #[test]
    fn parses_friend_add_with_addrs_and_storage() {
        let inv = parse(&a(&[
            "friend",
            "add",
            "deadbeef",
            "--storage",
            "1024",
            "--addr",
            "1.2.3.4:1",
            "--addr",
            "5.6.7.8:2",
        ]))
        .unwrap();
        assert_eq!(
            inv.command,
            Command::FriendAdd {
                ticket_hex: "deadbeef".to_string(),
                storage: Some(1024),
                addrs: vec!["1.2.3.4:1".to_string(), "5.6.7.8:2".to_string()],
            }
        );
    }

    #[test]
    fn friend_add_missing_ticket_errors() {
        let err = parse(&a(&["friend", "add"])).unwrap_err();
        assert!(err.to_string().contains("ticket-hex"), "{err}");
    }

    #[test]
    fn parses_replica_place() {
        let inv = parse(&a(&[
            "replica",
            "place",
            "vid1",
            "peer1",
            "--addr",
            "1.2.3.4:9",
            "--r",
            "2",
        ]))
        .unwrap();
        assert_eq!(
            inv.command,
            Command::ReplicaPlace {
                vid: "vid1".to_string(),
                peer: "peer1".to_string(),
                addrs: vec!["1.2.3.4:9".to_string()],
                r: 2,
            }
        );
    }

    #[test]
    fn replica_place_missing_peer_errors() {
        let err = parse(&a(&["replica", "place", "vid1"])).unwrap_err();
        assert!(err.to_string().contains("<peer>"), "{err}");
    }

    #[test]
    fn parses_grant_create() {
        let inv = parse(&a(&[
            "grant", "create", "vid1", "a.txt", "b.txt", "--to", "u1", "--to", "u2",
        ]))
        .unwrap();
        assert_eq!(
            inv.command,
            Command::GrantCreate {
                vid: "vid1".to_string(),
                paths: vec!["a.txt".to_string(), "b.txt".to_string()],
                to: vec!["u1".to_string(), "u2".to_string()],
            }
        );
    }

    #[test]
    fn grant_create_missing_to_errors() {
        let err = parse(&a(&["grant", "create", "vid1", "a.txt"])).unwrap_err();
        assert!(err.to_string().contains("--to"), "{err}");
    }

    #[test]
    fn grant_create_missing_paths_errors() {
        let err = parse(&a(&["grant", "create", "vid1", "--to", "u1"])).unwrap_err();
        assert!(err.to_string().contains("<path>"), "{err}");
    }

    #[test]
    fn parses_grant_fetch() {
        let inv = parse(&a(&[
            "grant",
            "fetch",
            "grantHex",
            "--owner-node",
            "node1",
            "--addr",
            "1.2.3.4:9",
            "--out",
            "/tmp/out",
        ]))
        .unwrap();
        assert_eq!(
            inv.command,
            Command::GrantFetch {
                grant_hex: "grantHex".to_string(),
                owner_node: "node1".to_string(),
                owner_addrs: vec!["1.2.3.4:9".to_string()],
                out: "/tmp/out".to_string(),
            }
        );
    }

    #[test]
    fn grant_fetch_missing_out_errors() {
        let err = parse(&a(&["grant", "fetch", "grantHex", "--owner-node", "node1"])).unwrap_err();
        assert!(err.to_string().contains("--out"), "{err}");
    }

    #[test]
    fn unknown_command_errors() {
        let err = parse(&a(&["frobnicate"])).unwrap_err();
        assert!(err.to_string().contains("unknown command"), "{err}");
    }

    #[test]
    fn no_command_errors() {
        let err = parse(&a(&[])).unwrap_err();
        assert!(err.to_string().contains("missing command"), "{err}");
    }

    #[test]
    fn unknown_subcommand_errors() {
        let err = parse(&a(&["vault", "teleport"])).unwrap_err();
        assert!(
            err.to_string().contains("unknown vault subcommand"),
            "{err}"
        );
    }

    // ---- token resolution precedence -------------------------------------

    #[test]
    fn token_flag_wins_over_env_and_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("api-token"), "file-token").unwrap();
        let cfg = Config {
            api_url: Some("http://x".into()),
            state_dir: Some(dir.path().to_path_buf()),
            token: Some("flag-token".into()),
            json: false,
        };
        let t = resolve_token(&cfg, Some("env-token".into())).unwrap();
        assert_eq!(t, "flag-token");
    }

    #[test]
    fn token_env_wins_over_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("api-token"), "file-token").unwrap();
        let cfg = Config {
            api_url: Some("http://x".into()),
            state_dir: Some(dir.path().to_path_buf()),
            token: None,
            json: false,
        };
        let t = resolve_token(&cfg, Some("env-token".into())).unwrap();
        assert_eq!(t, "env-token");
    }

    #[test]
    fn token_falls_back_to_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("api-token"), "file-token\n").unwrap();
        let cfg = Config {
            api_url: Some("http://x".into()),
            state_dir: Some(dir.path().to_path_buf()),
            token: None,
            json: false,
        };
        let t = resolve_token(&cfg, None).unwrap();
        assert_eq!(t, "file-token");
    }

    #[test]
    fn token_missing_everywhere_errors() {
        let cfg = Config {
            api_url: Some("http://x".into()),
            state_dir: None,
            token: None,
            json: false,
        };
        let err = resolve_token(&cfg, None).unwrap_err();
        assert!(err.to_string().contains("CARAPACE_TOKEN"), "{err}");
    }

    // ---- api url resolution ----------------------------------------------

    #[test]
    fn api_url_flag_wins_over_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("api-url"), "http://127.0.0.1:1").unwrap();
        let cfg = Config {
            api_url: Some("http://127.0.0.1:2".into()),
            state_dir: Some(dir.path().to_path_buf()),
            token: None,
            json: false,
        };
        assert_eq!(resolve_api_url(&cfg).unwrap(), "http://127.0.0.1:2");
    }

    #[test]
    fn api_url_falls_back_to_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("api-url"), "http://127.0.0.1:1234\n").unwrap();
        let cfg = Config {
            api_url: None,
            state_dir: Some(dir.path().to_path_buf()),
            token: None,
            json: false,
        };
        assert_eq!(resolve_api_url(&cfg).unwrap(), "http://127.0.0.1:1234");
    }

    #[test]
    fn api_url_missing_everywhere_errors() {
        // No --api-url and no state dir: must error, never a guessed default that could
        // leak the token to a port squatter.
        let cfg = Config {
            api_url: None,
            state_dir: None,
            token: None,
            json: false,
        };
        let err = resolve_api_url(&cfg).unwrap_err();
        assert!(err.to_string().contains("--api-url"), "{err}");
    }
}
