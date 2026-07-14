//! Carapace endpoint: an iroh `Endpoint` bound to a supplied carapace node key
//! on ALPN `carapace/1` (plus the iroh-blobs ALPN), so its `EndpointId` is
//! exactly the carapace node id (§6).

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use std::net::{Ipv4Addr, SocketAddr};

/// The Carapace control-stream ALPN (§6).
pub const ALPN: &[u8] = b"carapace/1";

/// An iroh endpoint whose node identity is a carapace node key. Accepts both
/// the `carapace/1` control ALPN and the iroh-blobs ALPN.
pub struct CarapaceEndpoint {
    ep: Endpoint,
}

impl CarapaceEndpoint {
    /// Bind on `127.0.0.1:0` using `node_key` as the endpoint secret key. The
    /// resulting `EndpointId` equals `node_key`'s Ed25519 public key, so the
    /// iroh NodeID is the carapace node id by construction. Uses the `Minimal`
    /// preset (no DNS/relay discovery) for deterministic in-process operation.
    pub async fn bind(node_key: &SigningKey) -> Result<Self> {
        Self::bind_on(node_key, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await
    }

    /// Like [`bind`](Self::bind) but binds on a caller-chosen socket address.
    /// Pass `0.0.0.0:<port>` to listen on every interface so peers on other
    /// hosts can dial this node (the loopback default is for in-process use).
    pub async fn bind_on(node_key: &SigningKey, bind: SocketAddr) -> Result<Self> {
        let sk = SecretKey::from_bytes(&node_key.to_bytes());
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(sk)
            .alpns(vec![ALPN.to_vec(), iroh_blobs::ALPN.to_vec()]);
        let builder = builder.bind_addr(bind).context("bind address")?;
        let ep = builder.bind().await.context("bind iroh endpoint")?;
        Ok(Self { ep })
    }

    /// The underlying iroh endpoint (for building a `Router`, etc.).
    pub fn endpoint(&self) -> &Endpoint {
        &self.ep
    }

    /// The carapace node id (= iroh `EndpointId` bytes).
    pub fn node_id(&self) -> [u8; 32] {
        *self.ep.id().as_bytes()
    }

    /// A directly dialable `EndpointAddr` (id + concrete localhost socket),
    /// requiring no discovery service.
    pub fn direct_addr(&self) -> Result<EndpointAddr> {
        let sock = self
            .ep
            .bound_sockets()
            .into_iter()
            .next()
            .context("endpoint has no bound socket")?;
        Ok(EndpointAddr::new(self.ep.id()).with_ip_addr(sock))
    }

    /// Open a connection to `addr` on the given ALPN.
    pub async fn connect(&self, addr: EndpointAddr, alpn: &[u8]) -> Result<Connection> {
        Ok(self.ep.connect(addr, alpn).await?)
    }

    /// Close the endpoint, terminating all connections.
    pub async fn close(&self) {
        self.ep.close().await;
    }
}
