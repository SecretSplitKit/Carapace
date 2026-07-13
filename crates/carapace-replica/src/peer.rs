//! A friend acting as a storage peer (§10.1). [`ReplicaPeer`] owns its consent
//! decision and its blob store: it verifies an owner's [`ReplicaInvite`], applies
//! its own [`Policy`] (owner deny-list, vault deny-list, quota), and either signs
//! a [`ReplicaAccept`] or declines. On placement it verifies the envelope's node
//! signature and admits chunks through the content-addressed [`MemoryStore`],
//! which rejects any blob whose hash disagrees with its ChunkID.

use carapace_vault::{ChunkStore, MemoryStore};
use carapace_wire::{ManifestEnvelope, ReplicaAccept, ReplicaInvite, Signed};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;

use crate::policy::Policy;
use crate::{ReplicaError, MAX_REPLICA_BLOBS};

/// A friend's storage node: its node key, its local [`Policy`], the ciphertext
/// chunks it holds, the [`ManifestEnvelope`] per vault it replicates, and the
/// running received-byte total per vault used to enforce the quota on receive.
pub struct ReplicaPeer {
    node_key: SigningKey,
    policy: Policy,
    store: MemoryStore,
    envelopes: HashMap<[u8; 32], ManifestEnvelope>,
    /// Cumulative bytes admitted per vault (W1 receive-side quota accounting).
    received: HashMap<[u8; 32], u64>,
}

impl ReplicaPeer {
    /// A fresh storage peer with the given node key and policy.
    pub fn new(node_key: SigningKey, policy: Policy) -> Self {
        Self {
            node_key,
            policy,
            store: MemoryStore::new(),
            envelopes: HashMap::new(),
            received: HashMap::new(),
        }
    }

    /// This peer's node public key (its identity in a replica set / announce).
    pub fn node_id(&self) -> [u8; 32] {
        self.node_key.verifying_key().to_bytes()
    }

    /// Consider an owner's [`ReplicaInvite`]. Verifies the owner's node
    /// signature, then applies local policy: returns `Ok(Some(accept))` with a
    /// signed [`ReplicaAccept`] if this peer consents, or `Ok(None)` if it
    /// declines (owner or vault deny-listed, or the placement exceeds quota).
    pub fn consider(&self, inv: &ReplicaInvite) -> Result<Option<ReplicaAccept>, ReplicaError> {
        inv.verify()?;
        if self.policy.denies_peer(&inv.by) || self.policy.denies_vid(&inv.vid) {
            return Ok(None);
        }
        let Some(quota) = self.policy.grant(inv.approx_bytes) else {
            return Ok(None);
        };
        let mut accept = ReplicaAccept {
            vid: inv.vid,
            quota_bytes: quota,
            by: [0; 32],
            sig: [0; 64],
        };
        accept.sign(&self.node_key);
        Ok(Some(accept))
    }

    /// Admit a placement: verify the envelope's node signature and store every
    /// chunk plus the envelope. Each chunk passes through the content-addressed
    /// store, which rejects a blob whose hash is not its declared ChunkID.
    ///
    /// W1: enforces the granted storage quota on the RECEIVE side, not just in the
    /// accept. The blob count is capped at [`MAX_REPLICA_BLOBS`], and the running
    /// received-byte total for this vault must stay within the peer's quota
    /// ([`Policy::quota`]); a push that would breach either is rejected (no
    /// partial mutation) so an accepted friend cannot OOM the replica by streaming
    /// unbounded blobs.
    pub fn receive(
        &mut self,
        env: &ManifestEnvelope,
        chunks: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), ReplicaError> {
        env.verify()?;
        if chunks.len() as u64 > MAX_REPLICA_BLOBS {
            return Err(ReplicaError::TooManyBlobs {
                count: chunks.len() as u64,
                max: MAX_REPLICA_BLOBS,
            });
        }
        let incoming: u64 =
            env.to_bytes().len() as u64 + chunks.iter().map(|(_, d)| d.len() as u64).sum::<u64>();
        let quota = self.policy.quota();
        let already = self.received.get(&env.vid).copied().unwrap_or(0);
        let running = already.saturating_add(incoming);
        if running > quota {
            return Err(ReplicaError::QuotaExceeded {
                quota,
                needed: running,
            });
        }
        // Only mutate state once the whole push is known to fit.
        for (id, data) in chunks {
            self.store.put(id, data)?;
        }
        self.received.insert(env.vid, running);
        self.envelopes.insert(env.vid, env.clone());
        Ok(())
    }

    /// Whether this peer currently holds a replica of `vid` (has its envelope).
    pub fn holds(&self, vid: &[u8; 32]) -> bool {
        self.envelopes.contains_key(vid)
    }

    /// The stored envelope for `vid`, if held.
    pub fn envelope(&self, vid: &[u8; 32]) -> Option<&ManifestEnvelope> {
        self.envelopes.get(vid)
    }

    /// Serve a chunk this peer holds, or `None` if absent.
    pub fn chunk(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.store.get(id).ok().flatten()
    }

    /// Number of ciphertext blobs held (across all vaults).
    pub fn blob_count(&self) -> usize {
        self.store.len()
    }

    /// Drop everything this peer holds for `vid` metadata-wise (the envelope).
    /// Used after an unfriend/delete. Chunk blobs are content-addressed and may
    /// be shared, so only the vault's envelope is removed here.
    pub fn drop_vault(&mut self, vid: &[u8; 32]) {
        self.envelopes.remove(vid);
    }
}
