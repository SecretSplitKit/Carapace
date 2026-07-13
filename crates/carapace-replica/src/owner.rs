//! Owner-side replica management (§10.1): maintain invariant `r`, place with
//! consent, track membership and health against an injected clock, repair on
//! confirmed loss, and re-announce.
//!
//! The owner holds the plaintext [`Manifest`] (to enumerate chunks) and the
//! signed [`ManifestEnvelope`] (the opaque blob peers store). Placement pushes
//! the envelope plus every referenced ciphertext chunk to an accepting peer and
//! records it in the replica set. [`ReplicaSet::announce`] emits the current,
//! owner-signed [`VaultAnnounce`]; a repair that changes the set bumps the
//! announce epoch so the §6 rollback rule admits the new list.

use std::collections::{HashMap, HashSet};

use carapace_crypto::content::chunk_id;
use carapace_vault::ChunkStore;
use carapace_wire::{Manifest, ManifestEnvelope, ReplicaInvite, Signed, VaultAnnounce};
use ed25519_dalek::SigningKey;

use crate::peer::ReplicaPeer;
use crate::policy::{Health, Policy};
use crate::{ReplicaError, DEFAULT_GRACE_SECS, DEFAULT_R};

/// One ciphertext chunk to place: its ChunkID and bytes.
type Chunk = ([u8; 32], Vec<u8>);

/// The source data for a placement: the owner's chunk store, the plaintext
/// manifest (to enumerate chunks), and the signed envelope peers store. Bundled
/// so placement and repair take one context instead of three parameters.
pub struct PlacementCtx<'a, S: ChunkStore> {
    /// The owner's local chunk store.
    pub store: &'a S,
    /// The plaintext manifest (names every chunk).
    pub manifest: &'a Manifest,
    /// The owner-signed manifest envelope (the opaque blob peers hold).
    pub env: &'a ManifestEnvelope,
}

impl<'a, S: ChunkStore> PlacementCtx<'a, S> {
    /// Bundle placement source data.
    pub fn new(store: &'a S, manifest: &'a Manifest, env: &'a ManifestEnvelope) -> Self {
        Self { store, manifest, env }
    }
}

/// The owner's view of one vault's replication: the target `r`, the accepted
/// replica node ids (in placement order), the current announce epoch, and the
/// manifest digest peers are expected to hold.
pub struct ReplicaSet {
    vid: [u8; 32],
    owner_node: SigningKey,
    r: usize,
    epoch: u64,
    digest: [u8; 32],
    members: Vec<[u8; 32]>,
    policy: Policy,
}

impl ReplicaSet {
    /// A new replica set for `manifest`/`env`, targeting invariant `r`. The
    /// announce epoch starts at the envelope's epoch and the digest is the
    /// envelope's ChunkID (its "iroh blob hash"). `policy` is the owner's local
    /// deny-list of peers it will not place on.
    pub fn new(
        owner_node: SigningKey,
        r: usize,
        policy: Policy,
        manifest: &Manifest,
        env: &ManifestEnvelope,
    ) -> Self {
        Self {
            vid: manifest.vid,
            owner_node,
            r,
            epoch: env.epoch,
            digest: chunk_id(&env.to_bytes()),
            members: Vec::new(),
            policy,
        }
    }

    /// Target replica invariant.
    pub fn target(&self) -> usize {
        self.r
    }

    /// Current accepted replica node ids, in placement order.
    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }

    /// Current announce epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether the invariant is currently met (`members >= r`).
    pub fn satisfied(&self) -> bool {
        self.members.len() >= self.r
    }

    /// Build a signed [`ReplicaInvite`] for the current vault/epoch sized for the
    /// full placement in `src`. Exposed for driving the handshake directly;
    /// [`ReplicaSet::add_replica`] uses it internally.
    pub fn make_invite<S: ChunkStore>(&self, src: &PlacementCtx<'_, S>) -> ReplicaInvite {
        let mut inv = ReplicaInvite {
            vid: self.vid,
            epoch: self.epoch,
            approx_bytes: placement_bytes(src.manifest, src.env),
            by: [0; 32],
            sig: [0; 64],
        };
        inv.sign(&self.owner_node);
        inv
    }

    /// Run the full consent handshake with `peer` and, if it accepts, place the
    /// envelope plus every chunk and record membership. Returns `Ok(true)` if the
    /// peer is now a member (freshly placed or already held), `Ok(false)` if the
    /// owner's own policy denies this peer or the peer declined.
    ///
    /// This does not bump the announce epoch; call [`ReplicaSet::announce`] once
    /// after a batch of initial placements. [`ReplicaSet::repair`] bumps it.
    pub fn add_replica<S: ChunkStore>(
        &mut self,
        peer: &mut ReplicaPeer,
        src: &PlacementCtx<'_, S>,
    ) -> Result<bool, ReplicaError> {
        let id = peer.node_id();
        if self.members.contains(&id) {
            return Ok(true);
        }
        // Owner-side consent: refuse to place on a deny-listed peer.
        if self.policy.denies_peer(&id) {
            return Ok(false);
        }
        let inv = self.make_invite(src);
        let Some(accept) = peer.consider(&inv)? else {
            return Ok(false);
        };
        // Peer-side accept must verify, name this vault, and be signed by this
        // peer; the placement must fit the quota the peer granted.
        accept.verify()?;
        if accept.vid != self.vid {
            return Err(ReplicaError::WrongVault);
        }
        if accept.by != id {
            return Err(ReplicaError::PeerMismatch);
        }
        let chunks = gather_chunks(src.store, src.manifest)?;
        let needed = src.env.to_bytes().len() as u64
            + chunks.iter().map(|(_, d)| d.len() as u64).sum::<u64>();
        if needed > accept.quota_bytes {
            return Err(ReplicaError::QuotaExceeded { quota: accept.quota_bytes, needed });
        }
        peer.receive(src.env, chunks)?;
        self.members.push(id);
        Ok(true)
    }

    /// Emit the current owner-signed [`VaultAnnounce`] reflecting the live member
    /// list, epoch, and digest.
    pub fn announce(&self) -> VaultAnnounce {
        let mut a = VaultAnnounce {
            vid: self.vid,
            epoch: self.epoch,
            replicas: self.members.clone(),
            digest: self.digest,
            by: [0; 32],
            sig: [0; 64],
        };
        a.sign(&self.owner_node);
        a
    }

    /// Whether reads can currently be served: the owner device is reachable, or
    /// at least one current member is reachable (§10.1). A member with no health
    /// signal is treated as present-and-serving (offline is not failure); a
    /// member known unreachable or unfriended does not serve.
    pub fn readable(&self, healths: &HashMap<[u8; 32], Health>, owner_reachable: bool) -> bool {
        owner_reachable
            || self
                .members
                .iter()
                .any(|m| healths.get(m).is_none_or(Health::serves_reads))
    }

    /// The repair loop (§10.1). Drops members that are confirmed lost at `now`
    /// (unfriended, or unreachable past `grace`); a member with no signal is
    /// kept. Then re-replicates from `candidates` - skipping current members and
    /// deny-listed peers - until the invariant `r` is met or candidates run out.
    /// If the member set changed, bumps the epoch and returns the new
    /// [`VaultAnnounce`]; otherwise returns `Ok(None)`.
    pub fn repair<S: ChunkStore>(
        &mut self,
        healths: &HashMap<[u8; 32], Health>,
        now: u64,
        grace: u64,
        src: &PlacementCtx<'_, S>,
        candidates: &mut [ReplicaPeer],
    ) -> Result<Option<VaultAnnounce>, ReplicaError> {
        let before = self.members.clone();

        // 1. Drop confirmed-lost members.
        self.members
            .retain(|m| !healths.get(m).is_some_and(|h| h.is_lost(now, grace)));

        // 2. Re-replicate up to r from fresh accepting friends.
        for cand in candidates.iter_mut() {
            if self.members.len() >= self.r {
                break;
            }
            // add_replica already skips current members and owner-denied peers.
            self.add_replica(cand, src)?;
        }

        if self.members == before {
            return Ok(None);
        }
        self.epoch += 1;
        Ok(Some(self.announce()))
    }

    /// Convenience repair with the default `r` grace window (24 h).
    pub fn repair_default_grace<S: ChunkStore>(
        &mut self,
        healths: &HashMap<[u8; 32], Health>,
        now: u64,
        src: &PlacementCtx<'_, S>,
        candidates: &mut [ReplicaPeer],
    ) -> Result<Option<VaultAnnounce>, ReplicaError> {
        self.repair(healths, now, DEFAULT_GRACE_SECS, src, candidates)
    }
}

impl ReplicaSet {
    /// A replica set targeting the default invariant `r` (3).
    pub fn with_default_r(
        owner_node: SigningKey,
        policy: Policy,
        manifest: &Manifest,
        env: &ManifestEnvelope,
    ) -> Self {
        Self::new(owner_node, DEFAULT_R, policy, manifest, env)
    }
}

/// Total bytes a full placement of `manifest`/`env` needs: the envelope plus
/// every unique referenced chunk length. Used as the invite's `approx_bytes`.
fn placement_bytes(manifest: &Manifest, env: &ManifestEnvelope) -> u64 {
    let mut seen = HashSet::new();
    let mut total = env.to_bytes().len() as u64;
    for f in &manifest.files {
        for (id, len) in &f.chunks {
            if seen.insert(*id) {
                total += *len;
            }
        }
    }
    total
}

/// Fetch every unique chunk the manifest references from the owner's store,
/// erroring if one is missing locally.
fn gather_chunks(
    store: &impl ChunkStore,
    manifest: &Manifest,
) -> Result<Vec<Chunk>, ReplicaError> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for f in &manifest.files {
        for (id, _) in &f.chunks {
            if seen.insert(*id) {
                let data = store.get(id)?.ok_or(ReplicaError::MissingChunk(*id))?;
                out.push((*id, data));
            }
        }
    }
    Ok(out)
}
