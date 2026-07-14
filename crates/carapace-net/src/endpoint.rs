//! Carapace endpoint: an iroh `Endpoint` bound to a supplied carapace node key
//! on ALPN `carapace/1` (plus the iroh-blobs ALPN), so its `EndpointId` is
//! exactly the carapace node id (§6).
//!
//! Connectivity uses ONLY self-hosted infrastructure (§6): the base preset is
//! [`presets::Minimal`] (no DNS, no n0 relays, no pkarr), relays come solely
//! from friends' advertised relay URLs as an [`iroh::RelayMode::Custom`] map,
//! the portmapper (UPnP/NAT-PMP/PCP) opens the local port on routable binds,
//! and peer addressing hints are injected out-of-band into a [`MemoryLookup`].
//! Between hole-punching and relay fallback this lets any two nodes connect
//! regardless of NAT, without ever touching third-party servers.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{presets, Connection, PortmapperConfig};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
};

/// The Carapace control-stream ALPN (§6).
pub const ALPN: &[u8] = b"carapace/1";

/// An iroh endpoint whose node identity is a carapace node key. Accepts both
/// the `carapace/1` control ALPN and the iroh-blobs ALPN.
///
/// Holds the [`MemoryLookup`] used to feed peer addressing hints (from cards and
/// tickets) into iroh's resolver, so peers can be dialed by node id alone.
pub struct CarapaceEndpoint {
    ep: Endpoint,
    /// Out-of-band peer address hints (id + relay url + direct addrs), fed from
    /// friends' ContactCards and tickets via [`CarapaceEndpoint::add_peer`].
    lookup: MemoryLookup,
}

impl CarapaceEndpoint {
    /// Bind on `127.0.0.1:0` using `node_key` as the endpoint secret key, with no
    /// relays configured. The resulting `EndpointId` equals `node_key`'s Ed25519
    /// public key, so the iroh NodeID is the carapace node id by construction.
    ///
    /// Loopback + no relays is the deterministic in-process setup: direct-address
    /// dialing only, portmapper suppressed.
    pub async fn bind(node_key: &SigningKey) -> Result<Self> {
        Self::bind_on(node_key, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &[]).await
    }

    /// Bind on a caller-chosen socket address, consuming friends' self-hosted
    /// relay URLs and enabling NAT traversal.
    ///
    /// - `bind`: pass `0.0.0.0:<port>` to listen on every interface so peers on
    ///   other hosts can dial this node (the loopback default of [`bind`] is for
    ///   in-process use).
    /// - `relays`: friends' advertised relay URLs (`http(s)://host:port`). Each
    ///   becomes an entry in an [`iroh::RelayMode::Custom`] relay map with QUIC
    ///   address discovery disabled (our embedded relays serve HTTP only). With
    ///   an empty slice the endpoint keeps `RelayMode::Disabled` (the Minimal
    ///   default) until relays are learned via [`add_relay`](Self::add_relay).
    ///
    /// The base preset is always [`presets::Minimal`] - never n0. The portmapper
    /// (UPnP/NAT-PMP/PCP) is enabled for routable binds so the node opens its
    /// own port for hole-punching; it is left off for loopback binds, which have
    /// no NAT to traverse and where SSDP discovery would only raise firewall
    /// prompts.
    pub async fn bind_on(
        node_key: &SigningKey,
        bind: SocketAddr,
        relays: &[RelayUrl],
    ) -> Result<Self> {
        let sk = SecretKey::from_bytes(&node_key.to_bytes());
        let alpns = vec![ALPN.to_vec(), iroh_blobs::ALPN.to_vec()];
        let lookup = MemoryLookup::new();

        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(sk)
            .alpns(alpns)
            .address_lookup(lookup.clone())
            .portmapper_config(portmapper_for(bind))
            .bind_addr(bind)
            .context("bind address")?;

        // Self-hosted relays only. `RelayMode::Custom` rejects an empty map, so
        // only switch away from the Minimal default (Disabled) when we have at
        // least one relay to offer.
        if !relays.is_empty() {
            builder = builder.relay_mode(RelayMode::Custom(relay_map(relays)));
        }

        let ep = builder.bind().await.context("bind iroh endpoint")?;
        Ok(Self { ep, lookup })
    }

    /// The underlying iroh endpoint (for building a `Router`, accepting, etc.).
    pub fn endpoint(&self) -> &Endpoint {
        &self.ep
    }

    /// The carapace node id (= iroh `EndpointId` bytes).
    pub fn node_id(&self) -> [u8; 32] {
        *self.ep.id().as_bytes()
    }

    /// The iroh [`EndpointId`] of this endpoint (= the carapace node id).
    pub fn id(&self) -> EndpointId {
        self.ep.id()
    }

    /// A directly dialable `EndpointAddr` (id + concrete bound socket),
    /// requiring no discovery service. Useful for same-host/LAN dialing.
    pub fn direct_addr(&self) -> Result<EndpointAddr> {
        let sock = self
            .ep
            .bound_sockets()
            .into_iter()
            .next()
            .context("endpoint has no bound socket")?;
        Ok(EndpointAddr::new(self.ep.id()).with_ip_addr(sock))
    }

    /// This endpoint's current addressing info for advertising to friends: its
    /// home relay URL (once [`online`](Self::online)) plus any discovered direct
    /// addresses. This is what populates a ContactCard NodeEntry's `relay_url`
    /// and direct-address hints (§6, Appendix B).
    pub fn addr(&self) -> EndpointAddr {
        self.ep.addr()
    }

    /// Inject a peer's addressing hints (id + optional relay url + direct addrs)
    /// so it can be dialed by node id. Called when a friend's ContactCard or
    /// ticket is learned. Augments any existing entry: new direct addresses are
    /// merged in and the relay url is overwritten (§6, "addresses are hints").
    pub fn add_peer(&self, addr: EndpointAddr) {
        self.hints().add_peer(addr);
    }

    /// Add (or refresh) a friend's relay URL in the live relay map, so this node
    /// can relay through it. Returns the previous config for that URL, if any.
    pub async fn add_relay(&self, url: RelayUrl) -> Option<Arc<RelayConfig>> {
        self.hints().add_relay(url).await
    }

    /// A cheaply-cloneable handle for feeding peer addressing hints and relay
    /// URLs into this live endpoint from tasks that don't hold the endpoint
    /// itself (e.g. the control-stream accept handler learning a friend's card).
    pub fn hints(&self) -> PeerHints {
        PeerHints {
            ep: self.ep.clone(),
            lookup: self.lookup.clone(),
        }
    }

    /// Wait until the endpoint has completed a handshake with at least one of its
    /// configured relays, so it can be reached (and reach others) via relay
    /// fallback. Returns immediately if the endpoint is already online; with no
    /// relays configured it never completes, so guard it with a timeout.
    pub async fn online(&self) {
        self.ep.online().await;
    }

    /// Open a connection to `addr` on the given ALPN. If `addr` carries no
    /// direct addresses or relay url, iroh resolves it through the injected peer
    /// hints (see [`add_peer`](Self::add_peer)).
    pub async fn connect(&self, addr: EndpointAddr, alpn: &[u8]) -> Result<Connection> {
        Ok(self.ep.connect(addr, alpn).await?)
    }

    /// Close the endpoint, terminating all connections.
    pub async fn close(&self) {
        self.ep.close().await;
    }
}

/// A cheaply-cloneable injector for peer addressing hints and relay URLs into a
/// live [`CarapaceEndpoint`]. Wraps clones of the endpoint and its
/// [`MemoryLookup`], so a background task (the accept handler, a sync loop) can
/// feed hints learned from friends' ContactCards and tickets without owning the
/// `CarapaceEndpoint`.
#[derive(Clone)]
pub struct PeerHints {
    ep: Endpoint,
    lookup: MemoryLookup,
}

impl PeerHints {
    /// See [`CarapaceEndpoint::add_peer`].
    pub fn add_peer(&self, addr: EndpointAddr) {
        self.lookup.add_endpoint_info(addr);
    }

    /// See [`CarapaceEndpoint::add_relay`].
    pub async fn add_relay(&self, url: RelayUrl) -> Option<Arc<RelayConfig>> {
        let config = Arc::new(RelayConfig::new(url.clone(), None));
        self.ep.insert_relay(url, config).await
    }

    /// Add (or refresh) a relay URL in the live relay map with a client auth
    /// token attached (iroh `RelayConfig::with_auth_token`). Used for the invite
    /// bootstrap (§6): a not-yet-friend presents its invite-ticket token so the
    /// issuer's friend-gated relay admits the connection to complete the
    /// friendship handshake. Returns the previous config for that URL, if any.
    pub async fn add_relay_with_token(
        &self,
        url: RelayUrl,
        token: String,
    ) -> Option<Arc<RelayConfig>> {
        let config = Arc::new(RelayConfig::new(url.clone(), None).with_auth_token(token));
        self.ep.insert_relay(url, config).await
    }
}

/// Build an `iroh::RelayMap` from friends' relay URLs. QUIC address discovery is
/// disabled per relay (`quic: None`) because the embedded self-hosted relays
/// serve plain HTTP and run no QUIC/QAD server; enabling it would only waste
/// probes against a closed port.
fn relay_map(relays: &[RelayUrl]) -> RelayMap {
    relays
        .iter()
        .cloned()
        .map(|url| RelayConfig::new(url, None))
        .collect()
}

/// Enable the portmapper (UPnP/NAT-PMP/PCP) only for routable binds. Loopback
/// binds are in-process/local: there is no NAT to punch, and the SSDP multicast
/// probe would only raise firewall dialogs (notably on macOS).
///
/// ponytail: `is_loopback` heuristic; take an explicit flag if a routable bind
/// ever needs portmapping suppressed.
fn portmapper_for(bind: SocketAddr) -> PortmapperConfig {
    if bind.ip().is_loopback() {
        PortmapperConfig::Disabled
    } else {
        // `Enabled {}` is a non-exhaustive variant we can't name directly; its
        // `Default` is exactly the all-protocols enabled config (UPnP/NAT-PMP/PCP).
        PortmapperConfig::default()
    }
}
