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
use carapace_net::{read_frame_raw, write_msg, CarapaceEndpoint, DocStore, IrohBlobStore};
use carapace_vault::{
    ingest_dir, new_vid, open_envelope, reconstruct, ChunkKeys, ChunkSecret, MemoryStore, VaultKeys,
};
use carapace_wire::messages::Message;
use carapace_wire::{
    ContactCard, FileGrant, GrantBody, GrantChunk, GrantFile, Hello, Manifest, ManifestEnvelope,
    NodeEntry, Offers, Sealed, Signed, VaultAnnounce,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::EndpointAddr;
use iroh_blobs::BlobsProtocol;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use zeroize::Zeroizing;

/// A far-future delegation expiry for the demo (2100-01-01Z, unix seconds).
const DELEG_NOT_AFTER: u64 = 4_102_444_800;

/// A reconstructed vault, returned by [`Daemon::sync_from`].
pub struct Reconstructed {
    /// The vault id.
    pub vid: [u8; 32],
    /// The epoch that was reconstructed.
    pub epoch: u64,
    /// The directory the vault's files were written into.
    pub out_dir: std::path::PathBuf,
}

/// The mutable document set the daemon advertises during anti-entropy, plus the
/// per-vault epoch counter. Cloned (cheaply) under a read lock at accept time;
/// no lock is ever held across an `.await`.
#[derive(Debug, Default)]
struct Shared {
    cards: Vec<ContactCard>,
    announces: Vec<VaultAnnounce>,
    grants: Vec<FileGrant>,
    epochs: HashMap<[u8; 32], u64>,
}

/// The `carapace/1` control-stream handler: exchange `Hello`, then push the
/// daemon's current cards, announces, and file grants. The peer applies its own
/// verification + rollback rule on receipt.
///
/// W5 (known Phase 1 limitation): this pushes the document set to *any* dialer;
/// the remote node id is not yet checked against a friend set. Spec §6 requires
/// "documents flow only across friendship edges." Grant bodies stay HPKE-sealed,
/// so no key material leaks, but social-graph/placement metadata is exposed.
/// Gate this on an established `Friendship` (or allowlist) once that layer lands.
#[derive(Clone, Debug)]
struct ControlHandler {
    hello: Hello,
    shared: Arc<RwLock<Shared>>,
}

impl ControlHandler {
    async fn serve(&self, conn: Connection) -> Result<()> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        // Hello: read the peer's, then send ours.
        let _ = read_frame_raw(&mut recv).await?;
        write_msg(&mut send, &self.hello).await?;

        // Snapshot the advertised set without holding the lock across awaits.
        let (cards, announces, grants) = {
            let s = self.shared.read().expect("shared lock");
            (s.cards.clone(), s.announces.clone(), s.grants.clone())
        };
        for card in &cards {
            write_msg(&mut send, card).await?;
        }
        for ann in &announces {
            write_msg(&mut send, ann).await?;
        }
        for grant in &grants {
            write_msg(&mut send, grant).await?;
        }
        send.finish()?;
        conn.closed().await;
        Ok(())
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
    /// (with a user-signed delegation of the node key).
    pub async fn start(state: State) -> Result<Self> {
        let node_key = state.node_key.clone();
        let user_key = state.user_key();
        let k_root = state.k_root.clone();

        let ep = CarapaceEndpoint::bind(&node_key).await?;
        let blobs = IrohBlobStore::new();
        let shared = Arc::new(RwLock::new(Shared::default()));

        // This device's ContactCard: one node entry, user-signed delegation.
        let card = build_card(&user_key, &node_key, &k_root);
        shared.write().expect("shared lock").cards.push(card);

        let hello = Hello { protocol: 1, card_version: 1, roles: 1 };
        let handler = ControlHandler { hello, shared: Arc::clone(&shared) };
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

        let announce = {
            let mut ann = VaultAnnounce {
                vid,
                epoch,
                replicas: vec![self.node_id()],
                digest: ingest.digest,
                by: [0; 32],
                sig: [0; 64],
            };
            ann.sign(&self.node_key);
            ann
        };

        let mut s = self.shared.write().expect("shared lock");
        // Replace any older announce/grant for this vid (monotonic epoch).
        s.announces.retain(|a| a.vid != vid);
        s.announces.push(announce);
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
    /// `out_root/<hex vid>/`. Returns the vaults reconstructed.
    pub async fn sync_from(&self, peer: EndpointAddr, out_root: &Path) -> Result<Vec<Reconstructed>> {
        // ---- anti-entropy pull over the control stream ----
        // Drain the whole stream into buffers first; the verification pass below
        // runs synchronously so we never hold the doc lock across an `.await`.
        let conn = self.ep.connect(peer.clone(), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let hello = Hello { protocol: 1, card_version: 0, roles: 0 };
        write_msg(&mut send, &hello).await?;
        let _peer_hello = read_frame_raw(&mut recv).await?;

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
        let targets = {
            let mut docs = self.docs.lock().expect("docs lock");
            // Admit cards with their own version-rollback rule; a stale/duplicate
            // card is ignored, not fatal.
            for card in &recv_cards {
                let _ = docs.offer_card(card);
            }
            select_targets(&mut docs, &self_user, &recv_announces, &grants, now)
        };

        // ---- per-vault: fetch, open, reconstruct ----
        // W3: one poisoned/unfetchable vault must not abort the others; collect
        // the error and move on.
        let (disclose_priv, _disclose_pub) = self.disclose_keypair();
        let mut out = Vec::new();
        for (vid, ann, grant) in &targets {
            match self
                .reconstruct_one(&peer, vid, ann, grant, &disclose_priv, out_root)
                .await
            {
                Ok(r) => out.push(r),
                Err(e) => eprintln!("carapaced: skipping vault {}: {e:#}", hex32(vid)),
            }
        }
        Ok(out)
    }

    /// Fetch, open, and reconstruct a single accepted-and-delegated vault. Any
    /// failure here is contained to this vault (see `sync_from`'s loop).
    async fn reconstruct_one(
        &self,
        peer: &EndpointAddr,
        vid: &[u8; 32],
        ann: &VaultAnnounce,
        grant: &FileGrant,
        disclose_priv: &HpkePrivateKey,
        out_root: &Path,
    ) -> Result<Reconstructed> {
        let vkeys = VaultKeys::derive(&*self.k_root, *vid);

        // Manifest envelope by digest.
        let bconn = self.ep.connect(peer.clone(), iroh_blobs::ALPN).await?;
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
