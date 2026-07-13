//! carapace-replica: consent-based replica placement and repair (protocol §10.1).
//!
//! Per vault the owner maintains invariant `r` (default 3) accepted storage
//! peers, each holding the current [`carapace_wire::ManifestEnvelope`] plus every
//! ciphertext chunk. Placement is consent-based **both directions**: the owner
//! selects a friend and sends a [`carapace_wire::ReplicaInvite`]; the friend
//! either signs a [`carapace_wire::ReplicaAccept`] or declines. Local private
//! policies and deny-lists gate the decision on both sides ([`Policy`]).
//!
//! - [`peer`]: [`ReplicaPeer`], a friend's storage node - its consent decision
//!   ([`ReplicaPeer::consider`]) and blob intake ([`ReplicaPeer::receive`]).
//! - [`owner`]: [`ReplicaSet`], the owner-side manager - place, track membership,
//!   evaluate replica health against an injected clock, repair on confirmed loss
//!   (unfriended, or unreachable past the grace window), and re-announce
//!   ([`carapace_wire::VaultAnnounce`]).
//! - [`policy`]: [`Policy`] (deny-lists + quota) and [`Health`] signals.
//!
//! Offline is not failure: a replica that is merely unreachable inside the grace
//! window (default 24 h) is kept. Only confirmed loss triggers re-replication to
//! a fresh accepting friend and a new announce reflecting the updated set. Reads
//! succeed while at least one current replica or the owner device is reachable.

pub mod owner;
pub mod peer;
pub mod policy;
pub mod por;

pub use owner::{PlacementCtx, ReplicaSet};
pub use peer::ReplicaPeer;
pub use policy::{
    Health, Policy, RateLimiter, DEFAULT_QUOTA_BYTES, DEFAULT_RATE_CAPACITY,
    DEFAULT_RATE_REFILL_PER_SEC,
};
pub use por::{
    build_audit, build_audit_n, build_wide_audit, run_audit, signed_audit_notice,
    verify_audit_response, Audit, AuditAction, AuditFailure, AuditOutcome, AuditResponder,
    AuditSample, AuditTracker, AUDIT_CODE_RETENTION_LOST, DEFAULT_POR_FAIL_LIMIT,
    DEFAULT_POR_INTERVAL_SECS, DEFAULT_SAMPLES_PER_ROUND, DEFAULT_WIDE_EVERY,
};

/// Default replica invariant `r` (§10.1).
pub const DEFAULT_R: usize = 3;
/// Default repair grace window in seconds (24 h, §10.1).
pub const DEFAULT_GRACE_SECS: u64 = 24 * 60 * 60;

/// Hard cap on the number of blobs (envelope + chunks) accepted in a single
/// replica push (W1). The running-byte quota is the real bound on volume; this
/// caps the loop count so a peer cannot force unbounded iterations with a huge
/// declared count (e.g. a flood of zero-length blobs).
///
/// ponytail: fixed ceiling. A 1 GiB quota of tiny chunks stays well under this;
/// scale it with the quota if very large quotas ever hold many small chunks.
pub const MAX_REPLICA_BLOBS: u64 = 1 << 20;

/// Every failure mode of the replica layer.
#[derive(Debug)]
pub enum ReplicaError {
    /// A wire-layer encode/decode or signature-verification error.
    Wire(carapace_wire::Error),
    /// A chunk-store error while reading or writing a blob.
    Store(carapace_vault::StoreError),
    /// The owner's local store is missing a chunk the manifest references.
    MissingChunk([u8; 32]),
    /// A [`carapace_wire::ReplicaAccept`] named a different vault than the invite.
    WrongVault,
    /// A [`carapace_wire::ReplicaAccept`]'s signer did not match the peer it came
    /// from - the accept cannot be attributed to this storage node.
    PeerMismatch,
    /// The placement would exceed the quota the peer granted in its accept.
    QuotaExceeded {
        /// Bytes the peer agreed to store.
        quota: u64,
        /// Bytes the placement actually needs.
        needed: u64,
    },
    /// A push declared more blobs than [`MAX_REPLICA_BLOBS`] (W1).
    TooManyBlobs {
        /// Blob count the push declared.
        count: u64,
        /// The cap that was exceeded.
        max: u64,
    },
}

impl core::fmt::Display for ReplicaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "wire error: {e}"),
            Self::Store(e) => write!(f, "chunk store error: {e}"),
            Self::MissingChunk(id) => write!(f, "owner store missing chunk {}", hex::encode(id)),
            Self::WrongVault => f.write_str("replica accept named a different vault"),
            Self::PeerMismatch => f.write_str("replica accept signer is not this peer"),
            Self::QuotaExceeded { quota, needed } => {
                write!(
                    f,
                    "placement needs {needed} bytes but peer granted only {quota}"
                )
            }
            Self::TooManyBlobs { count, max } => {
                write!(
                    f,
                    "replica push declared {count} blobs, over the cap of {max}"
                )
            }
        }
    }
}

impl std::error::Error for ReplicaError {}

impl From<carapace_wire::Error> for ReplicaError {
    fn from(e: carapace_wire::Error) -> Self {
        Self::Wire(e)
    }
}

impl From<carapace_vault::StoreError> for ReplicaError {
    fn from(e: carapace_vault::StoreError) -> Self {
        Self::Store(e)
    }
}
