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
use iroh_blobs::api::Store;
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode,
};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::Hash;
use std::collections::HashMap;
use std::ops::Deref;
use std::path::Path;
use tokio::runtime::Handle;

/// Convert a carapace ChunkID into an iroh blob hash (identity mapping: both are
/// raw BLAKE3-256).
fn hash_of(id: [u8; 32]) -> Hash {
    Hash::from_bytes(id)
}

fn io_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

/// The backing iroh-blobs store: either in-memory (scratch / throwaway) or a
/// durable filesystem store (the daemon's served store, design §3.1). Both deref to
/// the same [`Store`] API, so every blob operation routes through [`Backing::store`].
#[derive(Debug, Clone)]
enum Backing {
    /// RAM-only. Used for the deliberate scratch stores (ingest, reconstruct/PoR
    /// re-serve) that must NOT persist third-party ciphertext to disk.
    Mem(MemStore),
    /// Durable, at `<state_dir>/blobs`. The daemon's served store: survives restart
    /// (design §3.1). Blobs are already ciphertext, so no extra sealing.
    Fs(FsStore),
}

impl Backing {
    /// The unified iroh-blobs [`Store`] API both variants deref to.
    fn store(&self) -> &Store {
        match self {
            Backing::Mem(m) => m.deref(),
            Backing::Fs(f) => f.deref(),
        }
    }
}

/// An iroh-blobs store presented as a carapace [`ChunkStore`].
///
/// Cloning shares the same underlying store and runtime handle (both are
/// cheap Arc-backed handles), so a clone serves and mutates the same blobs.
#[derive(Clone)]
pub struct IrohBlobStore {
    backing: Backing,
    handle: Handle,
}

impl IrohBlobStore {
    /// A fresh in-memory blob store (scratch / throwaway). Must be called from
    /// within a tokio runtime (captures the current runtime handle for the sync
    /// `ChunkStore` bridge). For the durable served store use [`IrohBlobStore::load`].
    pub fn new() -> Self {
        Self {
            backing: Backing::Mem(MemStore::new()),
            handle: Handle::current(),
        }
    }

    /// A durable filesystem-backed blob store rooted at `dir` (design §3.1). Creates
    /// `dir` (0700 on unix) if absent and loads/recovers any existing blobs, so the
    /// daemon's served store survives a restart. Must be called from within a tokio
    /// runtime.
    pub async fn load(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("create blobs dir {dir:?}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {dir:?}"))?;
        }
        let store = FsStore::load(dir)
            .await
            .with_context(|| format!("open FsStore at {dir:?}"))?;
        Ok(Self {
            backing: Backing::Fs(store),
            handle: Handle::current(),
        })
    }

    /// The underlying iroh-blobs store, e.g. for `BlobsProtocol::new(store.store(), None)`.
    pub fn store(&self) -> &Store {
        self.backing.store()
    }

    /// Add a blob, returning its hash (= ChunkID). Async; use from async code.
    pub async fn add(&self, data: &[u8]) -> Result<[u8; 32]> {
        let tag = self.store().add_slice(data).await.context("add_slice")?;
        Ok(*tag.hash.as_bytes())
    }

    /// Fetch the blob `id` from `conn`'s provider into this store. iroh-blobs
    /// verifies the BLAKE3 bao against `id` during transfer; we additionally
    /// assert the stored bytes re-hash to the requested ChunkID (§5, §6).
    pub async fn fetch(&self, conn: &Connection, id: [u8; 32]) -> Result<()> {
        self.store()
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

    /// Whether blob `id` is fully present in this store. Async; use from async
    /// code (the sync [`ChunkStore::has`] bridge is for blocking contexts).
    pub async fn has(&self, id: [u8; 32]) -> Result<bool> {
        self.store()
            .blobs()
            .has(hash_of(id))
            .await
            .context("blobs has")
    }

    /// Durability barrier: resolves only once every previously-acked write
    /// ([`add`](Self::add) / [`fetch`](Self::fetch)) is committed to disk.
    ///
    /// The iroh-blobs FsStore acks `add_slice` from INSIDE its open redb write
    /// batch, which commits up to ~1 s later (store/fs.rs module docs: writes
    /// "in the last seconds" are lost on an abrupt exit). `SyncDb` is a
    /// top-level command that cannot join a write batch, so its answer proves
    /// the prior batch committed — and redb commits at Immediate durability
    /// (fsync). Call this after a logical write group and BEFORE recording or
    /// acking those blobs anywhere durable; otherwise a prompt kill loses
    /// blobs that other state already claims exist. No-op on the Mem backing.
    pub async fn sync(&self) -> Result<()> {
        self.store().sync_db().await.context("sync_db")?;
        Ok(())
    }

    /// Read a present blob's bytes. Async; use from async code.
    pub async fn get_bytes(&self, id: [u8; 32]) -> Result<Vec<u8>> {
        let bytes = self
            .store()
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
        let store = self.store();
        let tag = self
            .handle
            .block_on(async move { store.add_slice(&data).await })
            .map_err(io_err)?;
        debug_assert_eq!(*tag.hash.as_bytes(), id);
        Ok(())
    }

    fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let store = self.store();
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
        let store = self.store();
        let id = *id;
        self.handle
            .block_on(async move { store.blobs().has(hash_of(id)).await })
            .map_err(io_err)
    }
}
