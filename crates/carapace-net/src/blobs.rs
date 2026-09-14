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
use iroh_blobs::protocol::{ChunkRanges, ChunkRangesExt, ChunkRangesSeq, GetRequest};
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode,
};
use iroh_blobs::store::fs::options::Options as FsOptions;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::store::{GcConfig, ProtectOutcome};
use iroh_blobs::Hash;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::runtime::Handle;

const GC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

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
    /// `None` makes the collector abort. `Some` is the last state-derived live set.
    protected: Arc<RwLock<Option<HashSet<Hash>>>>,
    /// Serializes durable writes through their caller's state commit against root publication
    /// and write-tag removal. Scratch stores do not need the guard.
    mutation: Arc<tokio::sync::Mutex<()>>,
}

impl IrohBlobStore {
    /// A fresh in-memory blob store (scratch / throwaway). Must be called from
    /// within a tokio runtime (captures the current runtime handle for the sync
    /// `ChunkStore` bridge). For the durable served store use [`IrohBlobStore::load`].
    pub fn new() -> Self {
        Self {
            backing: Backing::Mem(MemStore::new()),
            handle: Handle::current(),
            protected: Arc::new(RwLock::new(None)),
            mutation: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// A durable filesystem-backed blob store rooted at `dir` (design §3.1). Creates
    /// `dir` (0700 on unix) if absent and loads/recovers any existing blobs, so the
    /// daemon's served store survives a restart. Must be called from within a tokio
    /// runtime.
    pub async fn load(dir: &Path) -> Result<Self> {
        Self::load_with_gc_interval(dir, GC_INTERVAL).await
    }

    /// Load the filesystem store with a caller-selected collector interval.
    /// Production always calls [`Self::load`]; the short interval is only used by this
    /// module's physical-GC tests.
    async fn load_with_gc_interval(dir: &Path, gc_interval: std::time::Duration) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("create blobs dir {dir:?}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {dir:?}"))?;
        }
        let protected: Arc<RwLock<Option<HashSet<Hash>>>> = Arc::new(RwLock::new(None));
        let callback_roots = Arc::clone(&protected);
        let mut options = FsOptions::new(dir);
        options.gc = Some(GcConfig {
            interval: gc_interval,
            add_protected: Some(Arc::new(move |live| {
                let roots = callback_roots
                    .read()
                    .expect("blob GC protected-root lock")
                    .clone();
                Box::pin(async move {
                    match roots {
                        Some(roots) => {
                            live.extend(roots);
                            ProtectOutcome::Continue
                        }
                        None => ProtectOutcome::Abort,
                    }
                })
            })),
        });
        let store = FsStore::load_with_opts(dir.join("blobs.db"), options)
            .await
            .with_context(|| format!("open FsStore at {dir:?}"))?;
        Ok(Self {
            backing: Backing::Fs(store),
            handle: Handle::current(),
            protected,
            mutation: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// The underlying iroh-blobs store, e.g. for `BlobsProtocol::new(store.store(), None)`.
    pub fn store(&self) -> &Store {
        self.backing.store()
    }

    /// Hold this guard from before the first durable add or fetch until the state transaction
    /// that names every new hash commits. Garbage collection takes the same guard.
    pub async fn begin_durable_mutation(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.mutation).lock_owned().await
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

    /// Fetch and Bao-verify only the blocks that cover one requested byte range.
    pub async fn fetch_verified_range(
        &self,
        conn: &Connection,
        id: [u8; 32],
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        ensure!(len > 0, "verified range must not be empty");
        let end = offset.checked_add(len).context("verified range overflow")?;
        let ranges = ChunkRanges::bytes(offset..end);
        let request = GetRequest::new(hash_of(id), ChunkRangesSeq::from_ranges([ranges.clone()]));
        self.store()
            .remote()
            .execute_get(conn.clone(), request)
            .await
            .context("fetch verified Bao range")?;
        let selected = self
            .store()
            .blobs()
            .export_ranges(hash_of(id), offset..end)
            .concatenate()
            .await
            .context("read verified Bao range")?;
        let wanted = usize::try_from(len).context("range length")?;
        ensure!(selected.len() == wanted, "verified range was short");
        Ok(selected)
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

    /// Publish the last durable state-derived live set to the periodic collector.
    pub async fn garbage_collect(&self, retained: &HashSet<[u8; 32]>) -> Result<()> {
        let mutation = self.begin_durable_mutation().await;
        self.garbage_collect_during(retained, &mutation).await
    }

    /// Publish roots while the caller holds the mutation guard across its durable state read
    /// and transaction. This prevents a stale pre-add root snapshot from winning the lock.
    pub async fn garbage_collect_during(
        &self,
        retained: &HashSet<[u8; 32]>,
        _mutation: &tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<()> {
        let roots = retained.iter().copied().map(hash_of).collect();
        *self.protected.write().expect("blob GC protected-root lock") = Some(roots);
        // `add_slice` and remote fetches create public API tags that protect newly written
        // blobs until durable daemon state can name them. Once a complete durable root set is
        // published above, those write-time tags are redundant and would otherwise prevent the
        // physical collector from ever reclaiming stale ciphertext.
        self.store()
            .tags()
            .delete_all()
            .await
            .context("remove write-time blob tags")?;
        self.store()
            .sync_db()
            .await
            .context("sync blob tag removal")?;
        Ok(())
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

#[cfg(test)]
mod gc_tests {
    use super::*;

    const TEST_GC_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);
    const WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

    async fn wait_for_presence(store: &IrohBlobStore, id: [u8; 32], expected: bool, label: &str) {
        let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
        loop {
            let present = store.has(id).await.expect("query physical blob presence");
            if present == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out after {WAIT_LIMIT:?} waiting for {label} to become {} (hash {})",
                if expected { "present" } else { "absent" },
                hash_of(id),
            );
            tokio::time::sleep(TEST_GC_INTERVAL).await;
        }
    }

    #[tokio::test]
    async fn collector_aborts_until_durable_roots_are_published() {
        let store = IrohBlobStore::new();
        assert!(store.protected.read().expect("protected roots").is_none());

        let retained = HashSet::from([[0x41; 32], [0x42; 32]]);
        store
            .garbage_collect(&retained)
            .await
            .expect("publish roots");

        let roots = store.protected.read().expect("protected roots");
        let roots = roots.as_ref().expect("initialized roots");
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&hash_of([0x41; 32])));
        assert!(roots.contains(&hash_of([0x42; 32])));
    }

    #[tokio::test]
    async fn filesystem_collector_removes_only_unprotected_physical_blobs() {
        let dir = tempfile::tempdir().expect("temporary FsStore root");
        let store = IrohBlobStore::load_with_gc_interval(dir.path(), TEST_GC_INTERVAL)
            .await
            .expect("load real FsStore");
        let stale = store
            .add(b"stale ciphertext")
            .await
            .expect("add stale blob");
        let current = store
            .add(b"current vault ciphertext")
            .await
            .expect("add current blob");
        let disclosure = store
            .add(b"permanent disclosure ciphertext")
            .await
            .expect("add disclosure blob");
        store.sync().await.expect("durably store test blobs");

        // Several collector intervals pass with no durable root snapshot. The callback must
        // abort, not interpret an absent snapshot as an empty live set.
        tokio::time::sleep(TEST_GC_INTERVAL * 4).await;
        for (id, label) in [
            (stale, "pre-root stale blob"),
            (current, "pre-root current blob"),
            (disclosure, "pre-root disclosure blob"),
        ] {
            wait_for_presence(&store, id, true, label).await;
        }

        store
            .garbage_collect(&HashSet::from([current, disclosure]))
            .await
            .expect("publish complete durable roots");
        wait_for_presence(&store, stale, false, "unprotected stale blob").await;
        wait_for_presence(&store, current, true, "protected current blob").await;
        wait_for_presence(&store, disclosure, true, "protected disclosure blob").await;
        store.store().shutdown().await.expect("shutdown FsStore");
    }

    #[tokio::test]
    async fn restart_before_root_shrink_keeps_the_old_live_set_conservative() {
        let dir = tempfile::tempdir().expect("temporary FsStore root");
        let store = IrohBlobStore::load_with_gc_interval(dir.path(), TEST_GC_INTERVAL)
            .await
            .expect("load first FsStore");
        let stale = store
            .add(b"authorization was pruned")
            .await
            .expect("add stale blob");
        let current = store.add(b"still current").await.expect("add current blob");
        store.sync().await.expect("durably store restart blobs");
        store
            .garbage_collect(&HashSet::from([stale, current]))
            .await
            .expect("publish old conservative roots");
        store
            .store()
            .shutdown()
            .await
            .expect("shutdown first FsStore");
        drop(store);

        // Model a stop after durable authorization pruning but before publishing the smaller
        // physical-GC root set. A restarted collector starts with no roots and must abort.
        let restarted = IrohBlobStore::load_with_gc_interval(dir.path(), TEST_GC_INTERVAL)
            .await
            .expect("restart FsStore");
        tokio::time::sleep(TEST_GC_INTERVAL * 4).await;
        wait_for_presence(
            &restarted,
            stale,
            true,
            "conservatively retained stale blob",
        )
        .await;
        wait_for_presence(&restarted, current, true, "current blob after restart").await;

        restarted
            .garbage_collect(&HashSet::from([current]))
            .await
            .expect("publish post-restart smaller roots");
        wait_for_presence(&restarted, stale, false, "stale blob after root shrink").await;
        wait_for_presence(&restarted, current, true, "current blob after root shrink").await;
        restarted
            .store()
            .shutdown()
            .await
            .expect("shutdown restarted FsStore");
    }

    #[tokio::test]
    async fn concurrent_add_holds_gc_until_the_durable_root_commit() {
        let dir = tempfile::tempdir().expect("temporary FsStore root");
        let store = IrohBlobStore::load_with_gc_interval(dir.path(), TEST_GC_INTERVAL)
            .await
            .expect("load real FsStore");
        let durable_roots = Arc::new(RwLock::new(HashSet::<[u8; 32]>::new()));

        let mutation = store.begin_durable_mutation().await;
        let new_hash = store
            .add(b"concurrent publish ciphertext")
            .await
            .expect("add concurrent blob");
        store.sync().await.expect("sync concurrent blob");

        let gc_store = store.clone();
        let gc_roots = Arc::clone(&durable_roots);
        let collector = tokio::spawn(async move {
            let guard = gc_store.begin_durable_mutation().await;
            let roots = gc_roots.read().expect("durable roots").clone();
            gc_store.garbage_collect_during(&roots, &guard).await
        });
        tokio::time::sleep(TEST_GC_INTERVAL * 2).await;
        assert!(
            !collector.is_finished(),
            "collector passed the mutation guard before the state commit"
        );

        // This is the daemon's state transaction: name the hash before releasing the guard.
        durable_roots
            .write()
            .expect("durable roots")
            .insert(new_hash);
        drop(mutation);
        collector
            .await
            .expect("collector task")
            .expect("collector after commit");
        tokio::time::sleep(TEST_GC_INTERVAL * 3).await;
        wait_for_presence(&store, new_hash, true, "newly committed concurrent blob").await;

        // A later complete transaction removes the root. Physical collection can now delete it.
        durable_roots.write().expect("durable roots").clear();
        let empty_roots = durable_roots.read().expect("durable roots").clone();
        store
            .garbage_collect(&empty_roots)
            .await
            .expect("publish empty durable roots");
        wait_for_presence(&store, new_hash, false, "unrooted concurrent blob").await;
        store.store().shutdown().await.expect("shutdown FsStore");
    }
}
