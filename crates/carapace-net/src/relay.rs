//! Embedded self-hosted relay (§6): the plain-HTTP `iroh-relay` server a capable
//! node runs so friends can relay through it.
//!
//! No TLS and no certificate: the relay is served in the clear, its URL is
//! `http://host:port`, and iroh's relay client speaks plain WebSocket to an
//! `http`-scheme relay (it only switches to TLS for `https`). This is the
//! "zero third-party infrastructure" relay of the spec - your usable relay set
//! is the relays your friends advertise, each one an instance of this server.
//!
//! Access is friend-gated (§6/§14). iroh-relay's default access is `AllowAll`
//! with no per-client rate limit, i.e. an open, unmetered forwarder for the whole
//! internet. That would let any reachable party register, forward relay datagrams
//! to your friends' node ids, exhaust connections/bandwidth, and use the relay as
//! a presence oracle for your friends' NodeIDs. So `CarapaceRelay::start` requires
//! a [`RelayAccessPolicy`] and admits only the endpoint ids it approves, and it
//! caps each admitted client's receive rate.

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::{EndpointId, RelayUrl};
use iroh_relay::server::{
    Access, AccessControl, ClientRateLimit, ClientRequest, RelayConfig, Server, ServerConfig,
};

/// Default per-client receive-rate cap for the embedded relay.
///
/// Generous enough for relay-fallback file sync between friends, low enough that
/// one admitted-but-abusive peer cannot saturate the operator's uplink or force
/// unbounded buffering. iroh-relay's default (`Limits::default().client_rx =
/// None`) applies no cap at all.
// ponytail: fixed 16 MiB/s per client; thread it through `start` if a relay
// operator ever needs to tune throughput.
const RELAY_CLIENT_RX_BYTES_PER_SEC: u32 = 16 * 1024 * 1024;

/// Decides which endpoint ids may register on and relay through this node's
/// embedded relay (§6/§14).
///
/// A relay must forward only among its operator's own devices and friends (plus,
/// for the invite bootstrap, a stranger presenting a valid outstanding invite
/// ticket), never arbitrary internet peers, so [`CarapaceRelay::start`] refuses
/// to run without one. The endpoint id passed to
/// [`allows`](RelayAccessPolicy::allows) is authenticated by the relay handshake
/// before the access hook runs, so a peer cannot forge a friend's id to pass the
/// gate. `auth_token` is the client's relay auth token (iroh
/// `RelayConfig::with_auth_token`), used to carry an invite-ticket token so a
/// not-yet-friend can reach the operator to complete the friendship handshake.
pub trait RelayAccessPolicy: fmt::Debug + Send + Sync + 'static {
    /// True iff a client with this `endpoint_id` and (optional) `auth_token` is
    /// permitted to use the relay.
    fn allows(&self, endpoint_id: &EndpointId, auth_token: Option<&str>) -> bool;
}

/// A static allow-list policy: admits exactly the given endpoint ids.
///
/// Useful for tests and for a fixed relay membership. A daemon with a live,
/// changing friend set implements [`RelayAccessPolicy`] over that set instead.
#[derive(Debug, Default)]
pub struct AllowList(std::collections::HashSet<[u8; 32]>);

impl AllowList {
    /// Build an allow-list from a set of 32-byte endpoint (node) ids.
    pub fn new(ids: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self(ids.into_iter().collect())
    }
}

impl RelayAccessPolicy for AllowList {
    fn allows(&self, endpoint_id: &EndpointId, _auth_token: Option<&str>) -> bool {
        self.0.contains(endpoint_id.as_bytes())
    }
}

/// Bridges a [`RelayAccessPolicy`] into iroh-relay's `AccessControl`, denying
/// every endpoint id the policy does not admit.
#[derive(Debug)]
struct PolicyAccess(Arc<dyn RelayAccessPolicy>);

impl AccessControl for PolicyAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self
            .0
            .allows(&request.endpoint_id(), request.auth_token().as_deref())
        {
            Access::Allow
        } else {
            Access::Deny {
                reason: Some("not a friend of this relay".to_string()),
            }
        }
    }
}

/// A running embedded relay server.
///
/// Dropping it stops the relay; prefer [`CarapaceRelay::shutdown`] for a
/// graceful stop that waits for the server tasks to finish.
#[derive(Debug)]
pub struct CarapaceRelay {
    server: Server,
    http_addr: SocketAddr,
}

impl CarapaceRelay {
    /// Spawn a plain-HTTP relay bound to `bind`, admitting only endpoint ids that
    /// `access` approves.
    ///
    /// Use `0.0.0.0:<port>` to be reachable by friends, or `127.0.0.1:0` for an
    /// in-process/ephemeral relay. TLS is disabled (no certificate needed) and
    /// QUIC address discovery is not served - QAD would require a TLS cert, and
    /// relayed packet forwarding (the actual fallback transport) works without
    /// it.
    ///
    /// `access` friend-gates every incoming connection (C1): iroh-relay defaults
    /// to `AllowAll`, an open forwarder, so a non-empty policy is mandatory. Each
    /// admitted client is additionally rate-limited to
    /// [`RELAY_CLIENT_RX_BYTES_PER_SEC`].
    pub async fn start(bind: SocketAddr, access: Arc<dyn RelayAccessPolicy>) -> Result<Self> {
        // `RelayConfig::new` leaves `tls: None`, so every HTTP service - including
        // the `/relay` WebSocket endpoint - is served in the clear on `bind`.
        let mut relay = RelayConfig::new(bind);
        // C1: friend-gate every connection (the default is `AllowAll`).
        relay.access = Arc::new(PolicyAccess(access));
        // C1: cap each admitted client's receive rate (the default leaves
        // `client_rx = None`, i.e. no per-client byte-rate limit at all).
        relay.limits.client_rx = Some(ClientRateLimit::new(
            NonZeroU32::new(RELAY_CLIENT_RX_BYTES_PER_SEC)
                .expect("RELAY_CLIENT_RX_BYTES_PER_SEC is nonzero"),
        ));
        // `ServerConfig` is `#[non_exhaustive]`, so it can only be built via
        // `default()` and then have its public fields assigned.
        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        // No QUIC server: QAD needs a TLS cert we deliberately do not have.
        config.quic = None;

        let server = Server::spawn(config).await.context("spawn relay server")?;
        let http_addr = server
            .http_addr()
            .context("relay has no bound HTTP address")?;
        Ok(Self { server, http_addr })
    }

    /// The relay's `http://host:port` URL, to advertise to friends and to place
    /// in an endpoint's relay map.
    pub fn relay_url(&self) -> RelayUrl {
        format!("http://{}", self.http_addr)
            .parse()
            .expect("http://<sockaddr> is a valid relay url")
    }

    /// The bound HTTP socket address.
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// Gracefully stop the relay, waiting for its tasks to finish.
    pub async fn shutdown(self) -> Result<()> {
        self.server.shutdown().await.context("relay shutdown")?;
        Ok(())
    }
}
