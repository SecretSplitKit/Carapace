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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32};
use std::sync::Arc;
use std::time::Duration;

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

/// Timeout for the relay liveness probe ([`CarapaceRelay::is_alive`]). The probe
/// targets the relay's own loopback socket, so a healthy listener answers in
/// microseconds; this only bounds the wait when the listener is gone.
const RELAY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether an IPv4 address is globally routable and thus safe to advertise to
/// friends as a relay's external address (§6/W6).
///
/// `Ipv4Addr::is_global` is still unstable, so this rejects the ranges that
/// matter here explicitly: RFC1918 private (10/8, 172.16/12, 192.168/16), CGNAT
/// (100.64.0.0/10), loopback (127/8), link-local (169.254/16), the unspecified
/// and broadcast addresses, and the TEST-NET documentation ranges. A mapped
/// address in any of these came from a double-NAT / carrier-grade-NAT gateway
/// and is not reachable from the wider internet.
fn is_globally_routable_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // CGNAT 100.64.0.0/10 == 100.64.0.0 .. 100.127.255.255.
    let is_cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || is_cgnat)
}

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
    /// NAT port-mapper for the relay's TCP/HTTP listen port (§6/W6). `Some` on a
    /// routable bind, `None` on loopback. iroh's endpoint port-mapper opens only
    /// the UDP/QUIC port, so a friend behind no manual forward could not reach
    /// this relay from the WAN; this maps the TCP port via UPnP/NAT-PMP/PCP and
    /// (via [`external_addr`](Self::external_addr)) reports the mapped WAN address
    /// to advertise. Best effort: with no NAT gateway it stays inert and callers
    /// fall back to a configured relay host / the bound address.
    portmap: Option<portmapper::Client>,
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
    ///
    /// `skip_portmap` suppresses the NAT port-mapper (UPnP/NAT-PMP/PCP): an
    /// operator with a stable configured relay host and a manual port forward
    /// does not need it, and skipping it avoids the SSDP/PCP traffic and firewall
    /// prompts. It is also always skipped for a loopback bind.
    pub async fn start(
        bind: SocketAddr,
        access: Arc<dyn RelayAccessPolicy>,
        skip_portmap: bool,
    ) -> Result<Self> {
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

        // W6 (§6): open the relay's TCP/HTTP port through the NAT on a routable
        // bind. Loopback binds have no NAT to traverse (and SSDP would only raise
        // firewall prompts), so the mapper is left off there. `portmapper::Client`
        // spawns its own service task and renews the mapping; dropping it (with the
        // relay) tears the mapping down.
        let portmap = if bind.ip().is_loopback() || skip_portmap {
            None
        } else {
            let client = portmapper::Client::new(portmapper::Config {
                protocol: portmapper::Protocol::Tcp,
                ..Default::default()
            });
            if let Some(port) = NonZeroU16::new(http_addr.port()) {
                client.update_local_port(port);
                client.procure_mapping();
            }
            Some(client)
        };

        Ok(Self {
            server,
            http_addr,
            portmap,
        })
    }

    /// The bound HTTP socket address.
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// A locally-reachable socket address for the relay: the bound address, with an
    /// unspecified bind IP (`0.0.0.0`/`[::]`) rewritten to loopback. Our own
    /// endpoint registers on / connects to the relay at this address (never at the
    /// advertised WAN address, which a home router may not hairpin), and the
    /// liveness probe connects here.
    fn local_socket(&self) -> SocketAddr {
        if self.http_addr.ip().is_unspecified() {
            match self.http_addr {
                SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, self.http_addr.port())),
                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, self.http_addr.port())),
            }
        } else {
            self.http_addr
        }
    }

    /// The relay's `http://host:port` URL as our own endpoint should register and
    /// reach it (loopback-substituted for unspecified binds). This is the URL an
    /// inbound relayed path carries, so it is also what peer-dialback matches
    /// against (§6/W6). It is *not* what friends advertise-consume: that is the
    /// WAN address (a configured relay host or the mapped [`external_addr`]).
    ///
    /// [`external_addr`]: Self::external_addr
    pub fn local_url(&self) -> RelayUrl {
        format!("http://{}", self.local_socket())
            .parse()
            .expect("http://<sockaddr> is a valid relay url")
    }

    /// The relay's mapped WAN address from the NAT port-mapper (§6/W6), or `None`
    /// when no mapping is (yet) established or no mapper is running (loopback bind,
    /// or no UPnP/NAT-PMP/PCP gateway). When present this is the address to
    /// advertise to friends so they reach the relay from the WAN.
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.portmap.as_ref().and_then(|c| {
            let addr = *c.watch_external_address().borrow();
            // Only advertise a mapping the wider internet can actually reach: a
            // NAT-PMP/PCP gateway can hand back a private, CGNAT, or otherwise
            // non-routable "external" address (double-NAT, carrier-grade NAT),
            // and folding that into the signed card would advertise an
            // unreachable relay and inflate the diversity count.
            addr.filter(|v4| is_globally_routable_v4(*v4.ip()))
                .map(SocketAddr::V4)
        })
    }

    /// Liveness probe (§6/W6): whether the relay's TCP listener is accepting
    /// connections. Connects to the relay's local socket with a short timeout; the
    /// iroh-relay `Server` handle exposes no non-blocking task-liveness accessor
    /// (only a blocking `join`, the bound address, and metrics), so this active
    /// probe is the concrete "is it alive" signal. It confirms the listener is up
    /// (detecting a crashed/torn-down server), not WAN reachability - that is
    /// established separately by peer-dialback.
    pub async fn is_alive(&self) -> bool {
        matches!(
            tokio::time::timeout(
                RELAY_PROBE_TIMEOUT,
                tokio::net::TcpStream::connect(self.local_socket()),
            )
            .await,
            Ok(Ok(_))
        )
    }

    /// Gracefully stop the relay, waiting for its tasks to finish.
    pub async fn shutdown(self) -> Result<()> {
        self.server.shutdown().await.context("relay shutdown")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globally_routable_v4_rejects_non_routable_ranges() {
        // Routable: public unicast addresses.
        assert!(is_globally_routable_v4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_globally_routable_v4(Ipv4Addr::new(1, 1, 1, 1)));

        // Rejected: RFC1918 private, CGNAT, loopback, link-local, unspecified,
        // broadcast, and documentation ranges.
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 5, 5),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),    // CGNAT low edge
            Ipv4Addr::new(100, 127, 255, 1), // CGNAT high edge
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(203, 0, 113, 1), // TEST-NET-3 documentation
        ] {
            assert!(!is_globally_routable_v4(ip), "{ip} must be non-routable");
        }

        // 100.63/100.128 are just outside CGNAT and are routable public space.
        assert!(is_globally_routable_v4(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(is_globally_routable_v4(Ipv4Addr::new(100, 128, 0, 1)));
    }
}
