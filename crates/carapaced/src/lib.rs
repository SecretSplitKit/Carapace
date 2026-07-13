//! carapaced: the Carapace daemon core (build-order step 1).
//!
//! A [`Daemon`] binds a carapace-net endpoint, serves its local iroh-blobs
//! store, holds one or more vaults, and runs the accept + anti-entropy loop.
//!
//! Two owner devices share the SAME user master key (`k_root`, hence the same
//! `K_manifest`/`K_content`/`K_disclose`) but hold DIFFERENT node keys, each
//! delegated by the user key (§4). Device A publishes a vault (ingest, seal
//! manifest, seal a per-chunk access grant, sign a [`VaultAnnounce`] +
//! [`FileGrant`]); device B discovers the announce over anti-entropy, fetches
//! the manifest envelope + every chunk by ChunkID, opens the grant, and
//! reconstructs the identical tree (§6, §7, §11).
//!
//! Chunk keys/nonces derive one-way from `K_content ‖ pt_hash`, so the wire
//! `Manifest` (only `{id, len}`) cannot re-derive them at reconstruct time. The
//! owner therefore ships them out of band: a det-CBOR [`GrantBody`] HPKE-sealed
//! to the user's disclosure key and carried in a signed [`FileGrant`] on the
//! control stream (the spec's §7.4 grant mechanism, reused here for the
//! same-user two-device case).

mod state;

pub use state::State;

use anyhow::{ensure, Context, Result};
use carapace_crypto::kdf::{self, INFO_DISCLOSE};
use carapace_crypto::seal::{self, HpkePrivateKey, HpkePublicKey};
use carapace_net::endpoint::ALPN;
use carapace_net::{read_frame_raw, read_msg, write_msg, CarapaceEndpoint, DocStore, IrohBlobStore};
use carapace_vault::{
    ingest_dir, new_vid, open_envelope, reconstruct, ChunkKeys, ChunkSecret, MemoryStore, VaultKeys,
};
use carapace_friend::{
    accept_friend_request, build_friend_request, build_ticket, friendship_core_bytes,
    verify_friend_accept, verify_friend_request, TicketBook,
};
use carapace_replica::{
    Health, Policy, RateLimiter, DEFAULT_GRACE_SECS, DEFAULT_QUOTA_BYTES, DEFAULT_RATE_CAPACITY,
    DEFAULT_RATE_REFILL_PER_SEC, MAX_REPLICA_BLOBS,
};
use carapace_wire::messages::Message;
use carapace_wire::{
    ContactCard, FileGrant, FriendAccept, FriendRequest, Friendship, GrantBody, GrantChunk,
    GrantFile, Hello, InviteTicket, Manifest, ManifestEnvelope, NodeEntry, Offers, ReplicaAccept,
    ReplicaInvite, Sealed, Signed, VaultAnnounce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::EndpointAddr;
use iroh_blobs::BlobsProtocol;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use zeroize::Zeroizing;

/// A far-future delegation expiry for the demo (2100-01-01Z, unix seconds).
const DELEG_NOT_AFTER: u64 = 4_102_444_800;

/// Tunable limits for the replica-store receive path (W1). Defaults come from the
/// replica crate: a 1 GiB default per-friend storage grant and a 256 MiB /
/// 64 MiB-per-s per-peer token bucket. Lower them (e.g. in tests) to exercise the
/// cut-offs.
#[derive(Clone, Copy, Debug)]
pub struct ReplicaLimits {
    /// Default per-friend replica-storage grant (bytes) recorded when this node
    /// ACCEPTS a friend request. Enforced later as that friend's replica quota;
    /// the initiating `befriend` path can agree a different amount explicitly.
    pub quota_bytes: u64,
    /// Per-peer rate-limit burst capacity in bytes.
    pub rate_capacity: u64,
    /// Per-peer rate-limit refill in bytes per second.
    pub rate_refill_per_sec: u64,
}

impl Default for ReplicaLimits {
    fn default() -> Self {
        Self {
            quota_bytes: DEFAULT_QUOTA_BYTES,
            rate_capacity: DEFAULT_RATE_CAPACITY,
            rate_refill_per_sec: DEFAULT_RATE_REFILL_PER_SEC,
        }
    }
}

/// A reconstructed vault, returned by [`Daemon::sync_from`].
pub struct Reconstructed {
    /// The vault id.
    pub vid: [u8; 32],
    /// The epoch that was reconstructed.
    pub epoch: u64,
    /// The directory the vault's files were written into.
    pub out_dir: std::path::PathBuf,
}

/// The blob source for one owned vault: the manifest-envelope digest and the
/// (unique) ChunkIDs, so the owner can push a full replica without re-ingesting.
#[derive(Clone)]
struct VaultBlobs {
    digest: [u8; 32],
    chunk_ids: Vec<[u8; 32]>,
}

/// The mutable document set the daemon advertises during anti-entropy, plus the
/// per-vault epoch counter and the friendship/replication state. Cloned (cheaply)
/// under a read lock at accept time; no lock is ever held across an `.await`.
#[derive(Default)]
struct Shared {
    cards: Vec<ContactCard>,
    announces: Vec<VaultAnnounce>,
    grants: Vec<FileGrant>,
    epochs: HashMap<[u8; 32], u64>,
    /// Established friendships, keyed by the *other* party's user pubkey.
    friendships: HashMap<[u8; 32], Friendship>,
    /// Each friend's newest verified `ContactCard`, keyed by user pubkey. This is
    /// the address book the control-stream gate consults (W5).
    friends: HashMap<[u8; 32], ContactCard>,
    /// Per-friend storage grant in bytes: how much replica storage THIS node
    /// grants THAT friend, keyed by the friend's user pubkey. Agreed at
    /// add-friend time (both the initiating `befriend` path and the accepting
    /// `serve_friend_accept` path) and enforced by `serve_replica_store` when the
    /// friend places a replica on us; defaults to `DEFAULT_QUOTA_BYTES` (1 GiB)
    /// when unspecified.
    ///
    /// This is LOCAL policy and is independent of what the friend advertises to
    /// us in their `ContactCard.offers.storage_bytes` (§9.1): the grant is what I
    /// enforce, the offer is what they claim to hold for me. A formal bilateral
    /// over-the-wire storage-agreement message is a possible future spec addition;
    /// the card-offer + local-grant model satisfies it for now (see spec-errata).
    ///
    /// ponytail: parallel map keyed like `friends`; there is no daemon unfriend
    /// path removing entries from `s.friends` yet, so the two cannot drift. Fold
    /// into a `FriendRecord { card, grant }` if `friends` ever gains a removal path.
    friend_grants: HashMap<[u8; 32], u64>,
    /// Tickets this daemon has issued and will honor exactly once (§6).
    tickets: TicketBook,
    /// Per-owned-vault blob source (digest + ChunkIDs) for replica placement.
    vault_blobs: HashMap<[u8; 32], VaultBlobs>,
    /// Owner-side replica membership: vid -> accepted replica node ids.
    members: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Owner-side replica invariant `r`, per vault.
    replica_target: HashMap<[u8; 32], usize>,
    /// Vids this daemon stores *as a replica* for some owner (blobs live in the
    /// iroh store; this records the relationship for read-serving/accounting).
    held: HashSet<[u8; 32]>,
    /// Owner-side deny-list of peer node ids this daemon refuses to place on (S4).
    replica_deny: HashSet<[u8; 32]>,
    /// Per-peer token buckets limiting how much a friend can push into our replica
    /// store per unit time (W1). Configured from [`ReplicaLimits`] at start.
    rate: RateLimiter,
}

/// The `carapace/1` control-stream handler. It authenticates the dialer against
/// the TLS-verified remote node id, then dispatches on the first frame:
///
/// - `ContactCard` (type 2): a document pull. The dialer presents its card; the
///   handler serves cards/announces/grants **only** if that card is validly
///   self-signed, its user is this daemon's own user or an established friend,
///   and it delegates the connection's authenticated remote node id (W5). Every
///   other dialer gets nothing beyond the `Hello`.
/// - `FriendRequest` (type 3): the acceptor half of the §9.2 handshake, gated by
///   a single-use ticket this daemon issued rather than by friendship.
/// - `ReplicaInvite` (type 10): the storage-peer half of §10.1 placement, gated
///   on the inviting owner being an established friend (or self).
#[derive(Clone)]
struct ControlHandler {
    hello: Hello,
    node_key: SigningKey,
    user_key: SigningKey,
    self_user: [u8; 32],
    blobs: IrohBlobStore,
    shared: Arc<RwLock<Shared>>,
    /// Default per-friend storage grant (bytes) recorded when this node ACCEPTS a
    /// friend request (`serve_friend_accept`). The per-friend grant is what
    /// `serve_replica_store` later enforces as that friend's replica quota (W1);
    /// the initiating `befriend` path can agree a different amount explicitly.
    default_grant_bytes: u64,
}

impl ControlHandler {
    async fn serve(&self, conn: Connection) -> Result<()> {
        let remote = *conn.remote_id().as_bytes();
        let (mut send, mut recv) = conn.accept_bi().await?;

        match read_frame_raw(&mut recv).await? {
            Some((ContactCard::TYPE, body)) => {
                let card = ContactCard::from_map(body)?;
                self.serve_docs(&card, &remote, &mut send).await?;
            }
            Some((FriendRequest::TYPE, body)) => {
                let req = FriendRequest::from_map(body)?;
                self.serve_friend_accept(req, &mut send, &mut recv).await?;
            }
            Some((ReplicaInvite::TYPE, body)) => {
                let inv = ReplicaInvite::from_map(body)?;
                self.serve_replica_store(inv, &remote, &mut send, &mut recv).await?;
            }
            // Unknown/legacy first frame (or a bare Hello): reveal only the Hello.
            _ => {
                write_msg(&mut send, &self.hello).await?;
                send.finish()?;
            }
        }
        conn.closed().await;
        Ok(())
    }

    /// Serve the document set iff the presented card authorizes the connection's
    /// authenticated remote node id (W5). Unauthorized dialers get only the Hello.
    async fn serve_docs(
        &self,
        card: &ContactCard,
        remote: &[u8; 32],
        send: &mut SendStream,
    ) -> Result<()> {
        write_msg(send, &self.hello).await?;

        let now = unix_now();
        let (authorized, cards, announces, grants) = {
            let s = self.shared.read().expect("shared lock");
            let ok = authorize_dialer(&s, &self.self_user, card, remote, now);
            if ok {
                (true, s.cards.clone(), s.announces.clone(), s.grants.clone())
            } else {
                (false, Vec::new(), Vec::new(), Vec::new())
            }
        };
        if !authorized {
            send.finish()?;
            return Ok(());
        }
        for card in &cards {
            write_msg(send, card).await?;
        }
        for ann in &announces {
            write_msg(send, ann).await?;
        }
        for grant in &grants {
            write_msg(send, grant).await?;
        }
        send.finish()?;
        Ok(())
    }

    /// Acceptor half of the friend handshake (§9.2). The requester drove the
    /// `FriendRequest`; here we pick `established`, run the interactive
    /// countersignature round-trip, redeem the ticket, and reply `FriendAccept`,
    /// persisting the dual-signed `Friendship` and the requester's card.
    async fn serve_friend_accept(
        &self,
        req: FriendRequest,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let now = unix_now();
        // W1: verify the request (outer node sig + embedded card + delegation).
        let requester_user = verify_friend_request(&req, now)
            .map_err(|e| anyhow::anyhow!("friend request rejected: {e}"))?;

        // Acceptor picks `established`; the requester must countersign the same
        // core over the wire (never the requester's private key locally).
        let established = now;
        write_u64(send, established).await?;
        let countersig = read_sig(recv).await?;

        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };

        // Redeem + assemble under the write lock (all synchronous, no await).
        let accept = {
            let mut s = self.shared.write().expect("shared lock");
            let (accept, friendship) = accept_friend_request(
                &req,
                &mut s.tickets,
                now,
                &self.node_key,
                &self.user_key,
                &own_card,
                established,
                |_core| countersig,
            )
            .map_err(|e| anyhow::anyhow!("friend accept failed: {e}"))?;
            s.friendships.insert(requester_user, friendship);
            s.friends.insert(requester_user, req.card.clone());
            // Agree a per-friend replica-storage grant at add-friend time. On the
            // accept path we grant this node's configured default; the initiating
            // `befriend` path can agree a different amount explicitly.
            s.friend_grants.insert(requester_user, self.default_grant_bytes);
            accept
        };

        write_msg(send, &accept).await?;
        send.finish()?;
        Ok(())
    }

    /// Storage-peer half of replica placement (§10.1). Verifies the owner's
    /// invite, requires the inviting owner to be an established friend (or self),
    /// consents per local policy, then receives the pushed envelope + chunks into
    /// the served blob store so this daemon can serve them to authorized peers.
    async fn serve_replica_store(
        &self,
        inv: ReplicaInvite,
        remote: &[u8; 32],
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let now = unix_now();
        inv.verify().map_err(|e| anyhow::anyhow!("replica invite bad sig: {e}"))?;

        // Authorize the inviting owner and rate-limit its push under one write
        // lock (all synchronous; the lock is released before any `.await`). The
        // invite signer must be an established friend (or our own device) AND the
        // connection's authenticated peer, and it must have rate-budget for the
        // advertised size (W1: a single friend cannot flood the store).
        let admitted = {
            let mut s = self.shared.write().expect("shared lock");
            let owner_ok = node_is_authorized(&s, &self.self_user, &inv.by, now);
            owner_ok && inv.by == *remote && s.rate.allow(*remote, now, inv.approx_bytes)
        };
        if !admitted {
            send.finish()?; // decline: no accept frame
            return Ok(());
        }

        // W1 + per-friend grant: the storage quota is the limit THIS node agreed to
        // grant the inviting friend at add-friend time (looked up by the friend's
        // user pubkey via the node that signed the invite), NOT a global default. A
        // placement larger than that friend's grant is declined outright. A node
        // with no friend record falls back to DEFAULT_QUOTA_BYTES defensively (S4
        // already gates placement on friendship, so this should not be reached).
        let grant = {
            let s = self.shared.read().expect("shared lock");
            friend_storage_grant(&s, &inv.by, now)
        };
        let Some(quota) = Policy::with_quota(grant).grant(inv.approx_bytes) else {
            send.finish()?;
            return Ok(());
        };
        let mut accept = ReplicaAccept { vid: inv.vid, quota_bytes: quota, by: [0; 32], sig: [0; 64] };
        accept.sign(&self.node_key);
        write_msg(send, &accept).await?;

        // Receive the pushed blobs: envelope first (verified), then each chunk.
        // W1: cap the blob count and track the running received-byte total for this
        // (peer, vid), aborting the moment it would exceed the advertised size
        // (which is <= the granted quota). The store never grows past the quota.
        let count = read_u64(recv).await?;
        ensure!(
            count <= MAX_REPLICA_BLOBS,
            "replica push declared {count} blobs, over the cap of {MAX_REPLICA_BLOBS}"
        );
        let mut received: u64 = 0;
        for i in 0..count {
            let bytes = read_blob(recv).await?;
            received = received.saturating_add(bytes.len() as u64);
            ensure!(
                received <= inv.approx_bytes,
                "replica push exceeded its advertised {} bytes",
                inv.approx_bytes
            );
            if i == 0 {
                let env = ManifestEnvelope::from_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("replica envelope decode: {e}"))?;
                env.verify().map_err(|e| anyhow::anyhow!("replica envelope bad sig: {e}"))?;
            }
            self.blobs.add(&bytes).await?;
        }
        self.shared.write().expect("shared lock").held.insert(inv.vid);
        // Ack: tell the owner storage is durable before it records membership.
        write_u64(send, count).await?;
        send.finish()?;
        Ok(())
    }
}

impl std::fmt::Debug for ControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlHandler").field("self_user", &hex32(&self.self_user)).finish()
    }
}

impl ProtocolHandler for ControlHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.serve(conn)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// A running Carapace daemon for one device.
pub struct Daemon {
    ep: CarapaceEndpoint,
    blobs: IrohBlobStore,
    shared: Arc<RwLock<Shared>>,
    node_key: SigningKey,
    user_key: SigningKey,
    k_root: Zeroizing<[u8; 32]>,
    /// Persistent per-signer document rollback state (cards by version, announces
    /// by epoch), kept across `sync_from` calls for the daemon's lifetime so a
    /// stale replica cannot roll an already-seen epoch back (W2). Held only for
    /// synchronous verification work; never locked across an `.await`.
    ///
    /// ponytail: in-memory, daemon-lifetime state. The blob store is also
    /// in-memory, so nothing survives a restart anyway; persist to disk here and
    /// in the blob store together if durable rollback across restarts is needed.
    docs: Arc<Mutex<DocStore>>,
    _router: Router,
}

impl Daemon {
    /// Bind the endpoint from `state`, start serving the blob store and the
    /// `carapace/1` control protocol, and publish this device's `ContactCard`
    /// (with a user-signed delegation of the node key). Uses the default
    /// [`ReplicaLimits`]; see [`Daemon::start_with_limits`] to tune them.
    pub async fn start(state: State) -> Result<Self> {
        Self::start_with_limits(state, ReplicaLimits::default()).await
    }

    /// Like [`Daemon::start`] but with explicit replica-store limits (W1). Tests
    /// use this to set a small quota or a tight rate limit and exercise the
    /// cut-offs without pushing gigabytes.
    pub async fn start_with_limits(state: State, limits: ReplicaLimits) -> Result<Self> {
        let node_key = state.node_key.clone();
        let user_key = state.user_key();
        let k_root = state.k_root.clone();

        let ep = CarapaceEndpoint::bind(&node_key).await?;
        let blobs = IrohBlobStore::new();
        let shared = Arc::new(RwLock::new(Shared::default()));

        // This device's ContactCard: one node entry, user-signed delegation.
        let card = build_card(&user_key, &node_key, &k_root);
        {
            let mut s = shared.write().expect("shared lock");
            s.cards.push(card);
            s.rate = RateLimiter::new(limits.rate_capacity, limits.rate_refill_per_sec);
        }

        let hello = Hello { protocol: 1, card_version: 1, roles: 1 };
        let handler = ControlHandler {
            hello,
            node_key: node_key.clone(),
            user_key: user_key.clone(),
            self_user: user_key.verifying_key().to_bytes(),
            blobs: blobs.clone(),
            shared: Arc::clone(&shared),
            default_grant_bytes: limits.quota_bytes,
        };
        // S5 (inherited design limitation, spec-errata E-blob-authz): the blob
        // store answers `iroh_blobs::ALPN` fetches from ANY dialer with no per-peer
        // read authorization. Confidentiality rests entirely on the AEAD sealing of
        // every chunk plus the unguessable ChunkIDs, which are revealed only inside
        // the W2/W5-gated manifest+grant on the `carapace/1` control stream. A peer
        // that never learns a ChunkID cannot ask for it, but anyone who does learn
        // one can fetch the (still-encrypted) bytes. A future per-peer blob-read
        // authz hook is owed here; this is not fixed in the current phase.
        let router = Router::builder(ep.endpoint().clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(blobs.mem(), None))
            .accept(ALPN, handler)
            .spawn();

        let docs = Arc::new(Mutex::new(DocStore::new()));
        Ok(Self { ep, blobs, shared, node_key, user_key, k_root, docs, _router: router })
    }

    /// This device's node id (= iroh endpoint id).
    pub fn node_id(&self) -> [u8; 32] {
        self.ep.node_id()
    }

    /// A directly dialable address for this daemon (localhost).
    pub fn addr(&self) -> Result<EndpointAddr> {
        self.ep.direct_addr()
    }

    /// Mint a new vault id for this user (persist the returned nonce out of band
    /// if you need to re-derive the vid later).
    pub fn new_vid(&self) -> ([u8; 32], [u8; 16]) {
        new_vid(&self.user_key.verifying_key().to_bytes())
    }

    /// Ingest `src` into vault `vid`: (re-)chunk + seal every file, load the
    /// ciphertext + manifest envelope into the served blob store, seal a
    /// per-chunk access grant, and publish a freshly signed `VaultAnnounce` +
    /// `FileGrant`. Bumps the vault's epoch on each call, so calling it again
    /// after a local change republishes at a higher epoch. Returns the epoch.
    ///
    /// ponytail: no filesystem watcher; the caller triggers re-ingest on change.
    /// ponytail: ingest + reconstruct run inline on the async worker (fine for a
    /// demo); a production daemon would `spawn_blocking` the heavy CPU/IO path.
    /// ponytail (S10): the epoch counter is bumped under one lock and committed
    /// under another, so two *concurrent* publishes of the same vid could commit
    /// out of counter order. The Phase 1 path is single-caller; hold a per-vid
    /// lock across the whole publish if concurrent publishing ever becomes real.
    pub async fn publish_vault(&self, src: &Path, vid: [u8; 32]) -> Result<u64> {
        let vkeys = VaultKeys::derive(&*self.k_root, vid);
        let epoch = {
            let mut s = self.shared.write().expect("shared lock");
            let e = s.epochs.entry(vid).or_insert(0);
            *e += 1;
            *e
        };

        // Ingest into a plain in-memory store, then mirror blobs into iroh.
        let mut mem = MemoryStore::new();
        let ingest = ingest_dir(src, &self.node_key, &vkeys, epoch, &mut mem)?;

        let env_digest = self.blobs.add(&ingest.envelope.to_bytes()).await?;
        ensure!(env_digest == ingest.digest, "envelope blob hash != manifestDigest");
        for f in &ingest.manifest.files {
            for (id, _len) in &f.chunks {
                let ct = carapace_vault::ChunkStore::get(&mem, id)?
                    .with_context(|| "chunk missing from source store")?;
                let h = self.blobs.add(&ct).await?;
                ensure!(&h == id, "iroh blob hash != carapace ChunkID");
            }
        }

        // Seal the per-chunk access grant to the user's disclosure key.
        let grant = self.build_file_grant(&ingest.manifest, &ingest.keys, vid, epoch)?;

        // Record the blob source (digest + unique ChunkIDs) so replica placement
        // can push a full copy later without re-ingesting.
        let mut seen = HashSet::new();
        let mut chunk_ids = Vec::new();
        for f in &ingest.manifest.files {
            for (id, _len) in &f.chunks {
                if seen.insert(*id) {
                    chunk_ids.push(*id);
                }
            }
        }

        let mut s = self.shared.write().expect("shared lock");
        s.vault_blobs.insert(vid, VaultBlobs { digest: ingest.digest, chunk_ids });
        let replicas = replica_list(self.node_id(), s.members.get(&vid));
        let mut ann =
            VaultAnnounce { vid, epoch, replicas, digest: ingest.digest, by: [0; 32], sig: [0; 64] };
        ann.sign(&self.node_key);
        // Replace any older announce/grant for this vid (monotonic epoch).
        s.announces.retain(|a| a.vid != vid);
        s.announces.push(ann);
        s.grants.retain(|g| g.vid != vid);
        s.grants.push(grant);
        Ok(epoch)
    }

    /// Test-only: advertise a node-signed (hence delegation-passing) announce +
    /// grant for `vid` at `epoch` whose manifest digest is not backed by any
    /// blob, so a peer that selects it will fail to fetch it. Used to prove one
    /// poison vault does not abort reconstruction of the others (W3).
    #[doc(hidden)]
    pub fn advertise_unfetchable_for_test(&self, vid: [u8; 32], epoch: u64) {
        let mut ann = VaultAnnounce {
            vid,
            epoch,
            replicas: vec![self.node_id()],
            digest: [0xAB; 32],
            by: [0; 32],
            sig: [0; 64],
        };
        ann.sign(&self.node_key);
        let mut grant = FileGrant {
            grant_id: [0; 16],
            vid,
            epoch,
            audience: vec![],
            sealed: vec![],
            by: [0; 32],
            sig: [0; 64],
        };
        grant.sign(&self.node_key);
        let mut s = self.shared.write().expect("shared lock");
        s.announces.retain(|a| a.vid != vid);
        s.announces.push(ann);
        s.grants.retain(|g| g.vid != vid);
        s.grants.push(grant);
    }

    /// Run anti-entropy against `peer`, then reconstruct every vault for which we
    /// received both an announce and an openable grant. Each vault is written to
    /// `out_root/<hex vid>/`. Returns the vaults reconstructed. Blobs are fetched
    /// from the same `peer` that served the documents.
    pub async fn sync_from(&self, peer: EndpointAddr, out_root: &Path) -> Result<Vec<Reconstructed>> {
        self.sync_impl(peer.clone(), peer, out_root).await
    }

    /// Like [`Daemon::sync_from`], but pull documents (announce + grant) from
    /// `doc_peer` while fetching the ciphertext blobs from `blob_peer` (a replica
    /// that holds them). This is how a delegated device reconstructs from a
    /// surviving replica after the owner device goes away (§10.1).
    pub async fn reconstruct_from_replica(
        &self,
        doc_peer: EndpointAddr,
        blob_peer: EndpointAddr,
        out_root: &Path,
    ) -> Result<Vec<Reconstructed>> {
        self.sync_impl(doc_peer, blob_peer, out_root).await
    }

    async fn sync_impl(
        &self,
        doc_peer: EndpointAddr,
        blob_peer: EndpointAddr,
        out_root: &Path,
    ) -> Result<Vec<Reconstructed>> {
        // ---- anti-entropy pull over the control stream ----
        // Drain the whole stream into buffers first; the verification pass below
        // runs synchronously so we never hold the doc lock across an `.await`.
        let conn = self.ep.connect(doc_peer.clone(), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        // Present our own card so the peer can authorize this pull (W5). The peer
        // serves documents only if our card's user is itself or a friend and the
        // card delegates our (TLS-authenticated) node id.
        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        write_msg(&mut send, &own_card).await?;

        let mut recv_cards: Vec<ContactCard> = Vec::new();
        let mut recv_announces: Vec<VaultAnnounce> = Vec::new();
        let mut grants: HashMap<[u8; 32], FileGrant> = HashMap::new();
        while let Some((ty, body)) = read_frame_raw(&mut recv).await? {
            match ty {
                ContactCard::TYPE => recv_cards.push(ContactCard::from_map(body)?),
                VaultAnnounce::TYPE => recv_announces.push(VaultAnnounce::from_map(body)?),
                FileGrant::TYPE => {
                    let g = FileGrant::from_map(body)?;
                    // Keep the highest-epoch grant per vid within this batch.
                    match grants.get(&g.vid) {
                        Some(prev) if g.epoch <= prev.epoch => {}
                        _ => {
                            grants.insert(g.vid, g);
                        }
                    }
                }
                _ => {}
            }
        }
        send.finish()?;

        // ---- verify (C1 delegation) + rollback (W2), under the doc lock ----
        let now = unix_now();
        let self_user = self.user_key.verifying_key().to_bytes();
        let (targets, newer_cards) = {
            let mut docs = self.docs.lock().expect("docs lock");
            // Admit cards with their own version-rollback rule; a stale/duplicate
            // card is ignored, not fatal. Collect the ones that were genuinely
            // newer so the friend address book can be refreshed (W2).
            let mut newer_cards = Vec::new();
            for card in &recv_cards {
                if matches!(docs.offer_card(card), Ok(true)) {
                    newer_cards.push(card.clone());
                }
            }
            let targets = select_targets(&mut docs, &self_user, &recv_announces, &grants, now);
            (targets, newer_cards)
        };

        // W2: refresh `s.friends` with rollback-guarded newer cards so a friend
        // that publishes a card dropping a device actually revokes it. The update
        // is monotonic on the friend's own stored version, so a first-seen older
        // card (accepted by the empty DocStore) cannot roll the address book back.
        if !newer_cards.is_empty() {
            let mut s = self.shared.write().expect("shared lock");
            for card in &newer_cards {
                if let Some(existing) = s.friends.get(&card.user) {
                    if card.version > existing.version {
                        s.friends.insert(card.user, card.clone());
                    }
                }
            }
        }

        // ---- per-vault: fetch, open, reconstruct ----
        // W3: one poisoned/unfetchable vault must not abort the others; collect
        // the error and move on.
        let (disclose_priv, _disclose_pub) = self.disclose_keypair();
        let mut out = Vec::new();
        for (vid, ann, grant) in &targets {
            match self
                .reconstruct_one(&blob_peer, vid, ann, grant, &disclose_priv, out_root)
                .await
            {
                Ok(r) => out.push(r),
                Err(e) => eprintln!("carapaced: skipping vault {}: {e:#}", hex32(vid)),
            }
        }
        Ok(out)
    }

    /// Fetch, open, and reconstruct a single accepted-and-delegated vault from
    /// `blob_peer` (owner or a replica). Any failure here is contained to this
    /// vault (see `sync_impl`'s loop).
    async fn reconstruct_one(
        &self,
        blob_peer: &EndpointAddr,
        vid: &[u8; 32],
        ann: &VaultAnnounce,
        grant: &FileGrant,
        disclose_priv: &HpkePrivateKey,
        out_root: &Path,
    ) -> Result<Reconstructed> {
        let vkeys = VaultKeys::derive(&*self.k_root, *vid);

        // Manifest envelope by digest.
        let bconn = self.ep.connect(blob_peer.clone(), iroh_blobs::ALPN).await?;
        self.blobs.fetch(&bconn, ann.digest).await?;
        let env_bytes = self.blobs.get_bytes(ann.digest).await?;
        let envelope = ManifestEnvelope::from_bytes(&env_bytes)?;
        let manifest = open_envelope(&envelope, &vkeys.k_manifest)?;
        ensure!(&manifest.vid == vid, "envelope vid mismatch");
        // S6: the AEAD aad already binds env.epoch to the manifest; also bind the
        // independently-signed announce epoch so a higher advertised epoch cannot
        // point at a lower-epoch envelope.
        ensure!(manifest.epoch == ann.epoch, "manifest epoch != announce epoch");

        // Open the grant -> per-chunk secrets.
        let keys = self.open_file_grant(grant, disclose_priv, *vid)?;

        // Fetch every chunk into a plain store keyed by ChunkID.
        let mut store = MemoryStore::new();
        for f in &manifest.files {
            if f.deleted {
                continue;
            }
            for (id, _len) in &f.chunks {
                self.blobs.fetch(&bconn, *id).await?;
                let ct = self.blobs.get_bytes(*id).await?;
                carapace_vault::ChunkStore::put(&mut store, *id, ct)?;
            }
        }

        let out_dir = out_root.join(hex32(vid));
        reconstruct(&manifest, &store, &keys, &out_dir)?;
        Ok(Reconstructed { vid: *vid, epoch: ann.epoch, out_dir })
    }

    // ---- friendship (§9.2) ---------------------------------------------

    /// This daemon's user id (shared across the user's devices).
    pub fn user_id(&self) -> [u8; 32] {
        self.user_key.verifying_key().to_bytes()
    }

    /// Whether an established friendship exists with `user`.
    pub fn is_friend(&self, user: &[u8; 32]) -> bool {
        self.shared.read().expect("shared lock").friendships.contains_key(user)
    }

    /// The stored dual-signed friendship with `user`, if any.
    pub fn friendship_with(&self, user: &[u8; 32]) -> Option<Friendship> {
        self.shared.read().expect("shared lock").friendships.get(user).cloned()
    }

    /// Test/diagnostic helper: perform a document pull against `peer` and return
    /// the counts of `(cards, announces, grants)` frames the peer actually served.
    /// A peer that refuses this dialer (W5) serves only its `Hello`, so all three
    /// counts are zero; an authorized dialer sees the peer's document set.
    #[doc(hidden)]
    pub async fn pull_doc_counts(&self, peer: EndpointAddr) -> Result<(usize, usize, usize)> {
        let conn = self.ep.connect(peer, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        write_msg(&mut send, &own_card).await?;
        let (mut cards, mut announces, mut grants) = (0, 0, 0);
        while let Some((ty, _body)) = read_frame_raw(&mut recv).await? {
            match ty {
                ContactCard::TYPE => cards += 1,
                VaultAnnounce::TYPE => announces += 1,
                FileGrant::TYPE => grants += 1,
                _ => {}
            }
        }
        send.finish()?;
        Ok((cards, announces, grants))
    }

    /// Issue a single-use invite ticket (§6). The ticket is signed by this user's
    /// key and names this device; hand it to a prospective friend out of band. The
    /// daemon records it and will honor exactly one matching `FriendRequest`.
    pub fn issue_ticket(&self) -> Result<InviteTicket> {
        let now = unix_now();
        let ticket = build_ticket(&self.user_key, self.node_id(), vec![], vec![], now + 3600)
            .map_err(|e| anyhow::anyhow!("build ticket: {e}"))?;
        {
            let mut s = self.shared.write().expect("shared lock");
            s.tickets.prune(now); // S7: drop expired tokens before recording a new one.
            s.tickets.issue(&ticket);
        }
        Ok(ticket)
    }

    /// Drive the requester side of the §9.2 handshake against the ticket issuer at
    /// `peer`: send a `FriendRequest`, countersign the friendship core the acceptor
    /// chooses, and on a valid `FriendAccept` persist the dual-signed `Friendship`
    /// plus the acceptor's card. Returns the completed friendship.
    ///
    /// `grant_bytes` is the per-friend replica-storage limit THIS node agrees to
    /// grant the new friend (enforced later by `serve_replica_store` when they
    /// place a replica on us); `None` uses `DEFAULT_QUOTA_BYTES` (1 GiB). This is
    /// local policy, independent of the friend's advertised `offers.storage_bytes`.
    pub async fn befriend(
        &self,
        peer: EndpointAddr,
        ticket: &InviteTicket,
        grant_bytes: Option<u64>,
    ) -> Result<Friendship> {
        let now = unix_now();
        let self_user = self.user_key.verifying_key().to_bytes();
        let acceptor_user = ticket.user;
        ensure!(acceptor_user != self_user, "cannot befriend yourself");

        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        let req = build_friend_request(&self.node_key, own_card, ticket.token);

        let conn = self.ep.connect(peer, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, &req).await?;

        // The acceptor picks `established`; countersign the identical core.
        let established = read_u64(&mut recv).await?;
        let (a, b) = if self_user <= acceptor_user {
            (self_user, acceptor_user)
        } else {
            (acceptor_user, self_user)
        };
        let core = friendship_core_bytes((a, b), established);
        let countersig = self.user_key.sign(&core).to_bytes();
        write_sig(&mut send, &countersig).await?;

        let accept = read_msg::<FriendAccept>(&mut recv).await?;
        send.finish()?;

        let friendship = verify_friend_accept(&accept, now, &self_user)
            .map_err(|e| anyhow::anyhow!("friend accept invalid: {e}"))?;
        // S3: the accept must actually come from the ticket's issuer, and the
        // resulting friendship must bind that same party - defense in depth against
        // a redirected/substituted acceptor.
        ensure!(
            accept_binds_ticket(&accept, &ticket.user, &friendship),
            "friend accept does not match the ticket issuer"
        );
        {
            let mut s = self.shared.write().expect("shared lock");
            s.friendships.insert(acceptor_user, friendship.clone());
            s.friends.insert(acceptor_user, accept.card.clone());
            // Agree the per-friend replica-storage grant at add-friend time.
            s.friend_grants.insert(acceptor_user, grant_bytes.unwrap_or(DEFAULT_QUOTA_BYTES));
        }
        drop(conn);
        Ok(friendship)
    }

    // ---- replica placement + repair (§10.1) ----------------------------

    /// Whether this daemon currently stores `vid` as a replica for some owner.
    pub fn holds_replica(&self, vid: &[u8; 32]) -> bool {
        self.shared.read().expect("shared lock").held.contains(vid)
    }

    /// Add `node` to the owner-side replica deny-list: this daemon will never place
    /// a replica on it, even if it is an established friend (S4).
    pub fn deny_replica_peer(&self, node: [u8; 32]) {
        self.shared.write().expect("shared lock").replica_deny.insert(node);
    }

    /// S4 owner-side placement gate: a candidate node may be invited only if it is
    /// a trusted device (an established friend's, or one of ours) AND not on the
    /// owner deny-list.
    fn replica_candidate_ok(&self, node: &[u8; 32], self_user: &[u8; 32], now: u64) -> bool {
        let s = self.shared.read().expect("shared lock");
        !s.replica_deny.contains(node) && node_is_authorized(&s, self_user, node, now)
    }

    /// The current owner-side replica member set for `vid` (accepted peer nodes).
    pub fn replica_members(&self, vid: &[u8; 32]) -> Vec<[u8; 32]> {
        self.shared
            .read()
            .expect("shared lock")
            .members
            .get(vid)
            .cloned()
            .unwrap_or_default()
    }

    /// Invite each friend in `peers` to store a replica of `vid`, targeting
    /// invariant `r`. Each accepting peer is pushed the manifest envelope plus
    /// every ciphertext chunk and recorded as a member; the announce is re-signed
    /// to reflect the new set. Returns the node ids that accepted.
    pub async fn place_replicas(
        &self,
        vid: [u8; 32],
        peers: &[EndpointAddr],
        r: usize,
    ) -> Result<Vec<[u8; 32]>> {
        let (vb, epoch) = {
            let s = self.shared.read().expect("shared lock");
            let vb = s.vault_blobs.get(&vid).cloned().context("vault not published")?;
            let epoch = *s.epochs.get(&vid).context("vault has no epoch")?;
            (vb, epoch)
        };
        let blobs = self.gather_blob_bytes(&vb).await?;
        let total: u64 = blobs.iter().map(|b| b.len() as u64).sum();

        let now = unix_now();
        let self_user = self.user_id();
        let mut placed = Vec::new();
        for peer in peers {
            let node = *peer.id.as_bytes();
            // S4: only invite an established friend (or our own device) that is not
            // on the owner deny-list.
            if !self.replica_candidate_ok(&node, &self_user, now) {
                continue;
            }
            if let Some(node) = self.invite_and_push(peer, vid, epoch, total, &blobs).await? {
                placed.push(node);
            }
        }
        {
            let mut s = self.shared.write().expect("shared lock");
            let members = s.members.entry(vid).or_default();
            for n in &placed {
                if !members.contains(n) {
                    members.push(*n);
                }
            }
            s.replica_target.insert(vid, r);
            reannounce(&mut s, vid, self.node_id(), &self.node_key);
        }
        Ok(placed)
    }

    /// Run the §10.1 repair loop for `vid`: drop members confirmed lost by the
    /// injected `healths` (unfriended, or unreachable past the 24 h grace), then
    /// re-replicate from `candidates` up to the invariant `r`, re-announcing the
    /// new set. Returns `true` if the member set changed.
    ///
    /// ponytail: the re-announce reuses the content epoch rather than bumping it,
    /// because `announce.epoch` is bound to the sealed manifest here (reconstruct
    /// checks `manifest.epoch == announce.epoch`). A fresh puller therefore always
    /// sees the current set; a peer that already cached the announce would not pick
    /// up a set change until the next content epoch. Decouple the replica-set
    /// version from the content epoch if in-place set propagation is required.
    pub async fn repair_vault(
        &self,
        vid: [u8; 32],
        healths: &HashMap<[u8; 32], Health>,
        candidates: &[EndpointAddr],
    ) -> Result<bool> {
        let now = unix_now();
        let (before, r, vb, epoch) = {
            let s = self.shared.read().expect("shared lock");
            let before = s.members.get(&vid).cloned().unwrap_or_default();
            let r = *s.replica_target.get(&vid).unwrap_or(&before.len());
            let vb = s.vault_blobs.get(&vid).cloned().context("vault not published")?;
            let epoch = *s.epochs.get(&vid).context("vault has no epoch")?;
            (before, r, vb, epoch)
        };

        let mut members = before.clone();
        members.retain(|m| !healths.get(m).is_some_and(|h| h.is_lost(now, DEFAULT_GRACE_SECS)));

        if members.len() < r {
            let blobs = self.gather_blob_bytes(&vb).await?;
            let total: u64 = blobs.iter().map(|b| b.len() as u64).sum();
            let self_user = self.user_id();
            for peer in candidates {
                if members.len() >= r {
                    break;
                }
                let node = *peer.id.as_bytes();
                if members.contains(&node) {
                    continue;
                }
                // S4: skip non-friends and owner-denied peers before inviting.
                if !self.replica_candidate_ok(&node, &self_user, now) {
                    continue;
                }
                if let Some(n) = self.invite_and_push(peer, vid, epoch, total, &blobs).await? {
                    members.push(n);
                }
            }
        }

        if members == before {
            return Ok(false);
        }
        {
            // S7: merge rather than blindly overwrite, so a concurrent placement
            // that added a member while we were pushing is not clobbered. Drop the
            // members we confirmed lost, then union in the repaired set.
            let mut s = self.shared.write().expect("shared lock");
            let cur = s.members.entry(vid).or_default();
            cur.retain(|m| !healths.get(m).is_some_and(|h| h.is_lost(now, DEFAULT_GRACE_SECS)));
            for n in &members {
                if !cur.contains(n) {
                    cur.push(*n);
                }
            }
            reannounce(&mut s, vid, self.node_id(), &self.node_key);
        }
        Ok(true)
    }

    /// Fetch the envelope (index 0) plus every unique chunk from this daemon's
    /// blob store, in the order a replica expects them pushed.
    async fn gather_blob_bytes(&self, vb: &VaultBlobs) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(1 + vb.chunk_ids.len());
        out.push(self.blobs.get_bytes(vb.digest).await?);
        for id in &vb.chunk_ids {
            out.push(self.blobs.get_bytes(*id).await?);
        }
        Ok(out)
    }

    /// Dial `peer`'s control stream, send a `ReplicaInvite`, and on a valid
    /// `ReplicaAccept` push the envelope + chunks. Returns the peer node id if it
    /// accepted and stored, or `None` if it declined.
    async fn invite_and_push(
        &self,
        peer: &EndpointAddr,
        vid: [u8; 32],
        epoch: u64,
        total: u64,
        blobs: &[Vec<u8>],
    ) -> Result<Option<[u8; 32]>> {
        let node = *peer.id.as_bytes();
        let conn = self.ep.connect(peer.clone(), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        let mut inv =
            ReplicaInvite { vid, epoch, approx_bytes: total, by: [0; 32], sig: [0; 64] };
        inv.sign(&self.node_key);
        write_msg(&mut send, &inv).await?;

        // A declining peer finishes its stream without an accept frame.
        let accept = match read_frame_raw(&mut recv).await? {
            Some((ReplicaAccept::TYPE, body)) => ReplicaAccept::from_map(body)?,
            _ => return Ok(None),
        };
        accept.verify().map_err(|e| anyhow::anyhow!("replica accept bad sig: {e}"))?;
        ensure!(accept.vid == vid, "replica accept named a different vault");
        ensure!(accept.by == node, "replica accept signer is not this peer");
        ensure!(total <= accept.quota_bytes, "placement exceeds granted quota");

        write_u64(&mut send, blobs.len() as u64).await?;
        for b in blobs {
            write_blob(&mut send, b).await?;
        }
        send.finish()?;
        // Wait for the replica's ack so membership only records durable storage.
        let acked = read_u64(&mut recv).await?;
        ensure!(acked == blobs.len() as u64, "replica acked {acked} of {} blobs", blobs.len());
        Ok(Some(node))
    }

    /// Gracefully close the endpoint.
    pub async fn shutdown(self) {
        self.ep.close().await;
    }

    // ---- grant sealing -------------------------------------------------

    fn disclose_keypair(&self) -> (HpkePrivateKey, HpkePublicKey) {
        seal::derive_keypair(&*kdf::k_disclose(&*self.k_root))
    }

    fn build_file_grant(
        &self,
        manifest: &Manifest,
        keys: &ChunkKeys,
        vid: [u8; 32],
        epoch: u64,
    ) -> Result<FileGrant> {
        let body = grant_body(manifest, keys);
        let (_priv, disclose_pub) = self.disclose_keypair();
        let user_pub = self.user_key.verifying_key().to_bytes();

        // Prefix the encapsulated key onto the HPKE ciphertext (Sealed carries no
        // separate encap field); split it back off on open. S7: the serialized
        // body holds every chunk key in the clear, so scrub it after sealing.
        let body_bytes = Zeroizing::new(body.to_bytes());
        let (enc, ct) = seal::seal(&disclose_pub, INFO_DISCLOSE, &vid, &body_bytes)
            .map_err(|e| anyhow::anyhow!("grant seal: {e}"))?;
        let mut sealed_ct = enc;
        sealed_ct.extend_from_slice(&ct);

        let mut grant_id = [0u8; 16];
        getrandom::getrandom(&mut grant_id).map_err(|e| anyhow::anyhow!("grant id: {e}"))?;
        let mut fg = FileGrant {
            grant_id,
            vid,
            epoch,
            audience: vec![user_pub],
            sealed: vec![Sealed { to: user_pub, ct: sealed_ct }],
            by: [0; 32],
            sig: [0; 64],
        };
        fg.sign(&self.node_key);
        Ok(fg)
    }

    fn open_file_grant(
        &self,
        grant: &FileGrant,
        disclose_priv: &HpkePrivateKey,
        vid: [u8; 32],
    ) -> Result<ChunkKeys> {
        let user_pub = self.user_key.verifying_key().to_bytes();
        let sealed = grant
            .sealed
            .iter()
            .find(|s| s.to == user_pub)
            .context("grant has no sealed body for this user")?;
        ensure!(sealed.ct.len() >= 32, "sealed grant too short for encap key");
        let (enc, ct) = sealed.ct.split_at(32);
        // S7: the opened plaintext carries every chunk key; scrub it on drop.
        let pt = Zeroizing::new(
            seal::open(disclose_priv, enc, INFO_DISCLOSE, &vid, ct)
                .map_err(|e| anyhow::anyhow!("grant open: {e}"))?,
        );
        let body = GrantBody::from_bytes(&pt)?;
        Ok(keys_from_grant(&body))
    }
}

/// Choose which vaults to reconstruct from a pulled document batch, applying the
/// two §6 MUSTs: (C1) the announce/grant signer node must be delegated by the
/// vault-owning user in that user's newest verified `ContactCard`, and (W2) the
/// announce epoch must exceed the highest ever seen from that signer for the vid.
///
/// Phase 1 is same-user two-device sync, so the vault owner is bound to *our own*
/// user key: an announce signed by a node not delegated by our user is refused.
fn select_targets(
    docs: &mut DocStore,
    self_user: &[u8; 32],
    announces: &[VaultAnnounce],
    grants: &HashMap<[u8; 32], FileGrant>,
    now: u64,
) -> Vec<([u8; 32], VaultAnnounce, FileGrant)> {
    // The set of node ids our user currently delegates (per its newest card).
    // Built once so the rollback offer below can borrow `docs` mutably.
    let delegated: HashSet<[u8; 32]> = match docs.card(self_user) {
        Some(card) => card
            .nodes
            .iter()
            .filter(|n| card_delegates_node(card, &n.node_id, now))
            .map(|n| n.node_id)
            .collect(),
        None => HashSet::new(),
    };

    let mut out = Vec::new();
    for ann in announces {
        // C1: the announce signer must be a delegated node of the vault owner.
        if !delegated.contains(&ann.by) {
            continue;
        }
        // A matching-epoch grant from a delegated node is required to open it.
        let grant = match grants.get(&ann.vid) {
            Some(g) if g.epoch == ann.epoch && delegated.contains(&g.by) => g,
            _ => continue,
        };
        // W2: persistent rollback — accept only an epoch strictly newer than the
        // highest ever seen from this signer for this vid (also re-verifies sig).
        if matches!(docs.offer_announce(ann), Ok(true)) {
            out.push((ann.vid, ann.clone(), grant.clone()));
        }
    }
    out
}

/// True iff `card` (self-signature valid) carries a `NodeEntry` for `node_id`
/// whose user->node delegation verifies and has not expired at `now` (§4).
fn card_delegates_node(card: &ContactCard, node_id: &[u8; 32], now: u64) -> bool {
    if card.verify().is_err() {
        return false;
    }
    let Ok(user) = VerifyingKey::from_bytes(&card.user) else {
        return false;
    };
    for n in &card.nodes {
        if &n.node_id == node_id {
            let Ok(node) = VerifyingKey::from_bytes(&n.node_id) else {
                return false;
            };
            let sig = Signature::from_bytes(&n.deleg);
            return carapace_crypto::identity::verify_delegation(
                &user,
                &node,
                n.not_after,
                &sig,
                Some(now),
            )
            .is_ok();
        }
    }
    false
}

/// W5/W2 gate for a document pull: authorize the connection's authenticated remote
/// node id. The presented `card` must be validly self-signed and name this
/// daemon's own user or an established friend. Delegation is then checked as
/// follows:
///
/// - Self branch (`card.user == self_user`): the presented own-user card's
///   delegations are trusted. ponytail (own-device limitation): we do not keep a
///   rollback-guarded newest self-card here, so a removed own device presenting an
///   old self-card still authorizes until the self-card store is versioned like
///   `s.friends`. Friend-device revocation (the W2 target) is handled below.
/// - Friend branch (W2): authorization uses the STORED newest friend card
///   (`s.friends`), never the delegations in the card the dialer presents. Once a
///   friend publishes a newer card dropping a device, a dialer presenting an old
///   card that still delegates that device is refused.
fn authorize_dialer(
    s: &Shared,
    self_user: &[u8; 32],
    card: &ContactCard,
    remote: &[u8; 32],
    now: u64,
) -> bool {
    if card.verify().is_err() {
        return false;
    }
    if card.user == *self_user {
        return card_delegates_node(card, remote, now);
    }
    match s.friends.get(&card.user) {
        Some(stored) => card_delegates_node(stored, remote, now),
        None => false,
    }
}

/// S3: whether a `FriendAccept` genuinely comes from the issuer of the ticket the
/// requester redeemed. The accept's embedded card must name `ticket_user`, and the
/// completed friendship must bind that same party. Signature validity is proven
/// separately by `verify_friend_accept`; this binds identity to the ticket.
fn accept_binds_ticket(accept: &FriendAccept, ticket_user: &[u8; 32], fr: &Friendship) -> bool {
    accept.card.user == *ticket_user && (fr.a == *ticket_user || fr.b == *ticket_user)
}

/// Whether `node` is a device this daemon trusts: one of our own devices (per our
/// own card) or a device delegated by an established friend's newest card. Used to
/// gate the replica-invite path on the inviting owner being a friend (or self).
fn node_is_authorized(s: &Shared, self_user: &[u8; 32], node: &[u8; 32], now: u64) -> bool {
    if s.cards.iter().any(|c| c.user == *self_user && card_delegates_node(c, node, now)) {
        return true;
    }
    s.friends.values().any(|c| card_delegates_node(c, node, now))
}

/// The per-friend replica-storage grant to enforce for a placement signed by
/// `node`: the byte limit agreed with the friend whose newest card delegates
/// `node`, or `DEFAULT_QUOTA_BYTES` if no grant is recorded (defensive default -
/// S4 already requires an established friendship to place at all). This is the
/// receive-side quota the storing node grants that specific friend (W1); it is
/// looked up by the placing friend, never a global constant.
fn friend_storage_grant(s: &Shared, node: &[u8; 32], now: u64) -> u64 {
    for (user, card) in &s.friends {
        if card_delegates_node(card, node, now) {
            return s.friend_grants.get(user).copied().unwrap_or(DEFAULT_QUOTA_BYTES);
        }
    }
    DEFAULT_QUOTA_BYTES
}

/// The announce `replicas` list: this device first, then the accepted members.
fn replica_list(self_node: [u8; 32], members: Option<&Vec<[u8; 32]>>) -> Vec<[u8; 32]> {
    let mut v = vec![self_node];
    if let Some(m) = members {
        for n in m {
            if !v.contains(n) {
                v.push(*n);
            }
        }
    }
    v
}

/// Re-sign the announce for `vid` reflecting the current member set (same content
/// epoch + digest). Replaces any prior announce for the vid.
fn reannounce(s: &mut Shared, vid: [u8; 32], self_node: [u8; 32], node_key: &SigningKey) {
    let Some(vb) = s.vault_blobs.get(&vid).cloned() else {
        return;
    };
    let epoch = *s.epochs.get(&vid).unwrap_or(&0);
    let replicas = replica_list(self_node, s.members.get(&vid));
    let mut ann =
        VaultAnnounce { vid, epoch, replicas, digest: vb.digest, by: [0; 32], sig: [0; 64] };
    ann.sign(node_key);
    s.announces.retain(|a| a.vid != vid);
    s.announces.push(ann);
}

/// Cap on a single pushed replica blob (envelope or ciphertext chunk): the vault
/// max chunk is 4 MiB plus sealing overhead, so 16 MiB is a generous ceiling that
/// still bounds a hostile length prefix.
const MAX_REPLICA_BLOB: usize = 16 * 1024 * 1024;

async fn write_u64(send: &mut SendStream, v: u64) -> Result<()> {
    send.write_all(&v.to_be_bytes()).await?;
    Ok(())
}

async fn read_u64(recv: &mut RecvStream) -> Result<u64> {
    let mut b = [0u8; 8];
    recv.read_exact(&mut b).await.map_err(|e| anyhow::anyhow!("read u64: {e}"))?;
    Ok(u64::from_be_bytes(b))
}

async fn write_sig(send: &mut SendStream, sig: &[u8; 64]) -> Result<()> {
    send.write_all(sig).await?;
    Ok(())
}

async fn read_sig(recv: &mut RecvStream) -> Result<[u8; 64]> {
    let mut b = [0u8; 64];
    recv.read_exact(&mut b).await.map_err(|e| anyhow::anyhow!("read sig: {e}"))?;
    Ok(b)
}

async fn write_blob(send: &mut SendStream, data: &[u8]) -> Result<()> {
    write_u64(send, data.len() as u64).await?;
    send.write_all(data).await?;
    Ok(())
}

async fn read_blob(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let len = read_u64(recv).await? as usize;
    ensure!(len <= MAX_REPLICA_BLOB, "replica blob length {len} exceeds cap");
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| anyhow::anyhow!("read blob: {e}"))?;
    Ok(buf)
}

/// Current unix time in seconds (for delegation-expiry checks).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a `GrantBody` carrying every non-deleted chunk's secret.
fn grant_body(manifest: &Manifest, keys: &ChunkKeys) -> GrantBody {
    let files = manifest
        .files
        .iter()
        .filter(|f| !f.deleted)
        .map(|f| {
            let chunks = f
                .chunks
                .iter()
                .map(|(id, len)| {
                    let s = &keys[id];
                    GrantChunk { chunk_id: *id, chunk_key: *s.chunk_key, nonce: *s.nonce, len: *len }
                })
                .collect();
            GrantFile { path: f.path.clone(), file_hash: f.file_hash, size: f.size, chunks }
        })
        .collect();
    GrantBody { files }
}

/// Rebuild the `ChunkKeys` map from an opened `GrantBody`.
fn keys_from_grant(body: &GrantBody) -> ChunkKeys {
    let mut m = HashMap::new();
    for f in &body.files {
        for c in &f.chunks {
            m.insert(
                c.chunk_id,
                ChunkSecret {
                    chunk_key: Zeroizing::new(c.chunk_key),
                    nonce: Zeroizing::new(c.nonce),
                },
            );
        }
    }
    m
}

/// This device's ContactCard: display name, disclosure enc key, and a single
/// node entry whose delegation is user-signed (§4).
fn build_card(user_key: &SigningKey, node_key: &SigningKey, k_root: &[u8; 32]) -> ContactCard {
    let (_priv, disclose_pub) = seal::derive_keypair(&*kdf::k_disclose(k_root));
    let enc_pub: [u8; 32] = disclose_pub
        .to_bytes()
        .try_into()
        .expect("X25519 pubkey is 32 bytes");
    let node_pub = node_key.verifying_key();
    let deleg =
        carapace_crypto::identity::sign_delegation(user_key, &node_pub, DELEG_NOT_AFTER).to_bytes();

    let mut card = ContactCard {
        user: user_key.verifying_key().to_bytes(),
        display: "carapace-device".into(),
        enc_pub,
        nodes: vec![NodeEntry {
            node_id: node_pub.to_bytes(),
            deleg,
            not_after: DELEG_NOT_AFTER,
            addrs: vec![],
            relay_url: None,
        }],
        offers: Offers { storage_bytes: 0, relay: false, trustee: false },
        version: 1,
        by: [0; 32],
        sig: [0; 64],
    };
    card.sign(user_key);
    card
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000; // well before DELEG_NOT_AFTER

    fn kp(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn announce(node: &SigningKey, vid: [u8; 32], epoch: u64) -> VaultAnnounce {
        let mut a =
            VaultAnnounce { vid, epoch, replicas: vec![], digest: [7; 32], by: [0; 32], sig: [0; 64] };
        a.sign(node);
        a
    }

    fn grant(node: &SigningKey, vid: [u8; 32], epoch: u64) -> FileGrant {
        let mut g = FileGrant {
            grant_id: [0; 16],
            vid,
            epoch,
            audience: vec![],
            sealed: vec![],
            by: [0; 32],
            sig: [0; 64],
        };
        g.sign(node);
        g
    }

    fn one_grant(node: &SigningKey, vid: [u8; 32], epoch: u64) -> HashMap<[u8; 32], FileGrant> {
        let mut m = HashMap::new();
        m.insert(vid, grant(node, vid, epoch));
        m
    }

    // C1: an announce is honored only if its signer node is delegated by the
    // vault-owning user's newest card; a rogue/undelegated node is refused.
    #[test]
    fn c1_only_delegated_signer_is_accepted() {
        let user = kp(1);
        let node = kp(3);
        let card = build_card(&user, &node, &[9; 32]);
        let self_user = user.verifying_key().to_bytes();
        let vid = [0x55; 32];

        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[announce(&node, vid, 1)],
            &one_grant(&node, vid, 1),
            NOW,
        );
        assert_eq!(targets.len(), 1, "delegated signer must be accepted");

        // A rogue node, not present in the user's card, is refused even though it
        // self-signs a valid announce + grant.
        let rogue = kp(0x42);
        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[announce(&rogue, vid, 1)],
            &one_grant(&rogue, vid, 1),
            NOW,
        );
        assert!(targets.is_empty(), "undelegated signer must be refused (C1)");
    }

    // C1: a valid announce survives even when a poison undelegated announce is in
    // the same batch (this is also the selection half of W3's isolation).
    #[test]
    fn c1_poison_announce_does_not_starve_valid_vault() {
        let user = kp(1);
        let node = kp(3);
        let rogue = kp(0x42);
        let card = build_card(&user, &node, &[9; 32]);
        let self_user = user.verifying_key().to_bytes();
        let good = [0x11; 32];
        let bad = [0x22; 32];

        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();
        let mut grants = one_grant(&node, good, 1);
        grants.insert(bad, grant(&rogue, bad, 1));
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[announce(&rogue, bad, 1), announce(&node, good, 1)],
            &grants,
            NOW,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, good);
    }

    #[test]
    fn c1_expired_or_unknown_delegation_refused() {
        let user = kp(1);
        let node = kp(3);
        let card = build_card(&user, &node, &[9; 32]);
        let node_id = node.verifying_key().to_bytes();
        assert!(card_delegates_node(&card, &node_id, NOW));
        assert!(!card_delegates_node(&card, &node_id, DELEG_NOT_AFTER + 1), "expired");
        assert!(!card_delegates_node(&card, &[0x42; 32], NOW), "unknown node id");
    }

    /// A self-signed card for `user` delegating exactly `node`, at `version`.
    fn card_with(user: &SigningKey, node: &SigningKey, version: u64) -> ContactCard {
        let node_pub = node.verifying_key();
        let deleg = carapace_crypto::identity::sign_delegation(user, &node_pub, DELEG_NOT_AFTER)
            .to_bytes();
        let mut card = ContactCard {
            user: user.verifying_key().to_bytes(),
            display: "x".into(),
            enc_pub: [0; 32],
            nodes: vec![NodeEntry {
                node_id: node_pub.to_bytes(),
                deleg,
                not_after: DELEG_NOT_AFTER,
                addrs: vec![],
                relay_url: None,
            }],
            offers: Offers { storage_bytes: 0, relay: false, trustee: false },
            version,
            by: [0; 32],
            sig: [0; 64],
        };
        card.sign(user);
        card
    }

    // W2: friend-device revocation takes effect. A friend delegates node N in card
    // v1, then publishes v2 dropping N. Once v2 is the stored newest card, a dialer
    // presenting the old v1 card for node N is refused - authorization uses the
    // stored card, not the presented one.
    #[test]
    fn w2_friend_revocation_refused_after_newer_card() {
        let friend_user = kp(0x50);
        let node_n = kp(0x51);
        let node_m = kp(0x52);
        let friend = friend_user.verifying_key().to_bytes();
        let n_id = node_n.verifying_key().to_bytes();
        let self_user = kp(0x01).verifying_key().to_bytes();

        let v1 = card_with(&friend_user, &node_n, 1); // delegates N
        let v2 = card_with(&friend_user, &node_m, 2); // drops N, delegates M

        let mut s = Shared::default();
        s.friends.insert(friend, v1.clone());
        // While v1 is newest, a dialer presenting v1 for node N is authorized.
        assert!(authorize_dialer(&s, &self_user, &v1, &n_id, NOW));

        // Friend publishes v2 (drops N). A dialer still presenting v1 for N loses.
        s.friends.insert(friend, v2);
        assert!(
            !authorize_dialer(&s, &self_user, &v1, &n_id, NOW),
            "node N is revoked once the newer card dropping it is known (W2)"
        );
    }

    // S3: a friend accept is bound to the ticket's issuer - both the accept's card
    // user and the friendship's parties must match the ticket user.
    #[test]
    fn s3_accept_must_bind_ticket_issuer() {
        let issuer_key = kp(0x60);
        let issuer = issuer_key.verifying_key().to_bytes();
        let me = kp(0x62).verifying_key().to_bytes();
        let stranger = kp(0x64).verifying_key().to_bytes();

        let friendship = |x: [u8; 32], y: [u8; 32]| {
            let (a, b) = if x <= y { (x, y) } else { (y, x) };
            Friendship { a, b, established: 1, sig_a: [0; 64], sig_b: [0; 64] }
        };
        let accept = FriendAccept {
            card: card_with(&issuer_key, &kp(0x63), 1),
            friendship: friendship(issuer, me),
            by: [0; 32],
            sig: [0; 64],
        };

        // Correct issuer: card user and friendship party both match.
        assert!(accept_binds_ticket(&accept, &issuer, &accept.friendship));
        // Wrong ticket issuer: the card names someone else.
        assert!(!accept_binds_ticket(&accept, &stranger, &accept.friendship));
        // Card matches the ticket but the friendship binds a different pair.
        let mismatched = friendship(stranger, me);
        assert!(!accept_binds_ticket(&accept, &issuer, &mismatched));
    }

    // W2: the highest-seen epoch persists across sync calls (shared DocStore), so
    // a genuinely-signed but older/equal announce is refused on a later sync.
    #[test]
    fn w2_rollback_persists_across_syncs() {
        let user = kp(1);
        let node = kp(3);
        let card = build_card(&user, &node, &[9; 32]);
        let self_user = user.verifying_key().to_bytes();
        let vid = [0x55; 32];

        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();

        // sync 1: accept epoch 2
        let t = select_targets(
            &mut docs,
            &self_user,
            &[announce(&node, vid, 2)],
            &one_grant(&node, vid, 2),
            NOW,
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].1.epoch, 2);

        // sync 2: a real, signed epoch-1 announce (stale replica) is refused
        let t = select_targets(
            &mut docs,
            &self_user,
            &[announce(&node, vid, 1)],
            &one_grant(&node, vid, 1),
            NOW,
        );
        assert!(t.is_empty(), "epoch-1 rollback refused after epoch 2 (W2)");

        // equal epoch is not newer either
        let t = select_targets(
            &mut docs,
            &self_user,
            &[announce(&node, vid, 2)],
            &one_grant(&node, vid, 2),
            NOW,
        );
        assert!(t.is_empty(), "equal epoch is refused");
    }
}
