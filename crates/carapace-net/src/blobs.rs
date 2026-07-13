//! iroh-blobs-backed content-addressed store (§5, §6). A carapace `ChunkID` is
//! `BLAKE3-256(ciphertext)`, which is exactly an iroh-blobs blob hash, so a
//! sealed chunk added here has blob hash == its ChunkID by construction.
//!
//! [`IrohBlobStore`] implements the vault's synchronous [`ChunkStore`] trait on
//! top of the async iroh-blobs store. The sync methods bridge to async via the
//! runtime handle captured at construction; call them only from a blocking
//! context (e.g. inside `tokio::task::spawn_blocking`), never from an async
//! task, or `block_on` will panic. Use [`IrohBlobStore::add`],
//! [`IrohBlobStore::fetch`], and [`IrohBlobStore::get_bytes`] from async code.

use anyhow::{ensure, Context, Result};
use carapace_vault::{ChunkStore, StoreError};
use iroh::endpoint::Connection;
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode,
};
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::Hash;
use std::collections::HashMap;
use tokio::runtime::Handle;

/// Convert a carapace ChunkID into an iroh blob hash (identity mapping: both are
/// raw BLAKE3-256).
fn hash_of(id: [u8; 32]) -> Hash {
    Hash::from_bytes(id)
}

fn io_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

/// An iroh-blobs in-memory store presented as a carapace [`ChunkStore`].
///
/// Cloning shares the same underlying store and runtime handle (both are
/// cheap Arc-backed handles), so a clone serves and mutates the same blobs.
#[derive(Clone)]
pub struct IrohBlobStore {
    store: MemStore,
    handle: Handle,
}

impl IrohBlobStore {
    /// A fresh in-memory blob store. Must be called from within a tokio runtime
    /// (captures the current runtime handle for the sync `ChunkStore` bridge).
    pub fn new() -> Self {
        Self {
            store: MemStore::new(),
            handle: Handle::current(),
        }
    }

    /// The underlying iroh-blobs store, e.g. for
    /// `BlobsProtocol::new(store.mem(), None)`.
    pub fn mem(&self) -> &MemStore {
        &self.store
    }

    /// Add a blob, returning its hash (= ChunkID). Async; use from async code.
    pub async fn add(&self, data: &[u8]) -> Result<[u8; 32]> {
        let tag = self.store.add_slice(data).await.context("add_slice")?;
        Ok(*tag.hash.as_bytes())
    }

    /// Fetch the blob `id` from `conn`'s provider into this store. iroh-blobs
    /// verifies the BLAKE3 bao against `id` during transfer; we additionally
    /// assert the stored bytes re-hash to the requested ChunkID (§5, §6).
    pub async fn fetch(&self, conn: &Connection, id: [u8; 32]) -> Result<()> {
        self.store
            .remote()
            .fetch(conn.clone(), hash_of(id))
            .await
            .context("fetch blob")?;
        let got = self.get_bytes(id).await?;
        ensure!(
            *blake3::hash(&got).as_bytes() == id,
            "fetched blob hash != requested ChunkID"
        );
        Ok(())
    }

    /// Read a present blob's bytes. Async; use from async code.
    pub async fn get_bytes(&self, id: [u8; 32]) -> Result<Vec<u8>> {
        let bytes = self
            .store
            .get_bytes(hash_of(id))
            .await
            .context("get_bytes")?;
        Ok(bytes.to_vec())
    }
}

impl Default for IrohBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an [`EventSender`] that gates every incoming blob-read (`get`) request
/// through `authorize(node_id, chunk_id)`, for a [`BlobsProtocol::new`] served
/// store. This is the per-peer blob-read authorization hook the protocol needs to
/// enforce §7.4 fetch authorization (adversarial review D3): a dialer is served a
/// chunk only if `authorize` returns `true`; otherwise the transfer is refused
/// with [`AbortReason::Permission`] and the requester learns nothing.
///
/// A spawned task consumes provider events: it records each connection's
/// authenticated `EndpointId` (== carapace node id) from the intercepted
/// `ClientConnected` event, then answers each intercepted `GetRequestReceived`
/// with the `authorize` verdict for that node and the requested blob hash (==
/// ChunkID). Hash-sequence requests (which fan out to unknown children) are
/// refused outright — carapace only ever fetches single blobs by ChunkID.
///
/// Must be called from within a tokio runtime (spawns the event loop).
pub fn authorizing_event_sender<F>(authorize: F) -> EventSender
where
    F: Fn([u8; 32], [u8; 32]) -> bool + Send + Sync + 'static,
{
    // Intercept connections (to learn the node id) and get requests (to gate).
    let mask = EventMask {
        connected: ConnectMode::Intercept,
        get: RequestMode::Intercept,
        ..EventMask::DEFAULT
    };
    let (tx, mut rx) = EventSender::channel(64, mask);
    tokio::spawn(async move {
        // connection_id -> authenticated node id for that connection.
        let mut conns: HashMap<u64, [u8; 32]> = HashMap::new();
        while let Some(msg) = rx.recv().await {
            match msg {
                ProviderMessage::ClientConnected(msg) => {
                    // Accept the connection but remember its node id; the actual
                    // authorization happens per get-request below. A dialer with no
                    // endpoint id (should not happen on an authenticated QUIC
                    // connection) is left unrecorded and so refused every request.
                    if let Some(id) = msg.endpoint_id {
                        conns.insert(msg.connection_id, *id.as_bytes());
                    }
                    msg.tx.send(Ok(())).await.ok();
                }
                ProviderMessage::ConnectionClosed(msg) => {
                    conns.remove(&msg.connection_id);
                }
                ProviderMessage::GetRequestReceived(msg) => {
                    let allowed = msg.request.ranges.is_blob()
                        && conns
                            .get(&msg.connection_id)
                            .is_some_and(|node| authorize(*node, *msg.request.hash.as_bytes()));
                    let res = if allowed {
                        Ok(())
                    } else {
                        Err(AbortReason::Permission)
                    };
                    msg.tx.send(res).await.ok();
                }
                _ => {}
            }
        }
    });
    tx
}

impl ChunkStore for IrohBlobStore {
    fn put(&mut self, id: [u8; 32], data: Vec<u8>) -> Result<(), StoreError> {
        // Enforce the §5 self-verifying rule before storing.
        let got = *blake3::hash(&data).as_bytes();
        if got != id {
            return Err(StoreError::IdMismatch { expected: id, got });
        }
        let store = &self.store;
        let tag = self
            .handle
            .block_on(async move { store.add_slice(&data).await })
            .map_err(io_err)?;
        debug_assert_eq!(*tag.hash.as_bytes(), id);
        Ok(())
    }

    fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let store = &self.store;
        let id = *id;
        self.handle.block_on(async move {
            if !store.blobs().has(hash_of(id)).await.map_err(io_err)? {
                return Ok(None);
            }
            let bytes = store.get_bytes(hash_of(id)).await.map_err(io_err)?;
            Ok(Some(bytes.to_vec()))
        })
    }

    fn has(&self, id: &[u8; 32]) -> Result<bool, StoreError> {
        let store = &self.store;
        let id = *id;
        self.handle
            .block_on(async move { store.blobs().has(hash_of(id)).await })
            .map_err(io_err)
    }
}
