//! Local private policies and health signals (§10.1).
//!
//! [`Policy`] is the deny-list-plus-quota gate consulted on both sides of a
//! placement: the owner uses it to refuse placing on a peer; the peer uses it to
//! refuse storing for an owner (or a vault), or to bound how much it will hold.
//! [`Health`] is the per-replica signal an owner feeds the repair loop.

use std::collections::HashMap;
use std::collections::HashSet;

/// Default per-replica storage quota granted by an otherwise-open policy (W1):
/// **1 GiB**. A peer that accepts with an open policy grants at most this much for
/// a placement, so a single friend cannot stream unbounded blobs into the store.
/// Use [`Policy::with_quota`] to raise or lower it explicitly.
pub const DEFAULT_QUOTA_BYTES: u64 = 1024 * 1024 * 1024;

/// A node's local placement policy. All fields are private preferences: an owner
/// consults its own `Policy` before inviting a peer; a peer consults its own
/// before accepting. Deny entries are keyed by node public key; `deny_vids`
/// blocks specific vaults; `max_store` bounds accepted bytes (`None` = no bound).
#[derive(Clone, Debug, Default)]
pub struct Policy {
    deny_peers: HashSet<[u8; 32]>,
    deny_vids: HashSet<[u8; 32]>,
    max_store: Option<u64>,
}

impl Policy {
    /// An open policy: no deny-list, and the bounded default storage quota
    /// ([`DEFAULT_QUOTA_BYTES`], 1 GiB). "Open" means no peer/vault is refused, not
    /// that storage is unbounded (W1) - an unbounded grant would let any accepted
    /// friend OOM the replica.
    pub fn open() -> Self {
        Self::with_quota(DEFAULT_QUOTA_BYTES)
    }

    /// A policy that will store at most `bytes` for any one placement.
    pub fn with_quota(bytes: u64) -> Self {
        Self { max_store: Some(bytes), ..Self::default() }
    }

    /// Add a node public key to the counterparty deny-list.
    pub fn deny_peer(mut self, node: [u8; 32]) -> Self {
        self.deny_peers.insert(node);
        self
    }

    /// Add a vault id to the deny-list (peer refuses to hold this vault).
    pub fn deny_vid(mut self, vid: [u8; 32]) -> Self {
        self.deny_vids.insert(vid);
        self
    }

    /// Whether `node` is on the counterparty deny-list.
    pub fn denies_peer(&self, node: &[u8; 32]) -> bool {
        self.deny_peers.contains(node)
    }

    /// Whether `vid` is on the vault deny-list.
    pub fn denies_vid(&self, vid: &[u8; 32]) -> bool {
        self.deny_vids.contains(vid)
    }

    /// The quota this policy will grant for a placement of `approx_bytes`, or
    /// `None` to decline (the placement is larger than the storage bound). A policy
    /// with no explicit bound (only [`Policy::default`]) grants `u64::MAX`;
    /// [`Policy::open`] carries the 1 GiB default instead.
    pub fn grant(&self, approx_bytes: u64) -> Option<u64> {
        match self.max_store {
            Some(max) if approx_bytes > max => None,
            Some(max) => Some(max),
            None => Some(u64::MAX),
        }
    }

    /// The effective storage cap this policy enforces on the receive side: the
    /// explicit bound, or `u64::MAX` for an unbounded [`Policy::default`]. Used by
    /// [`crate::ReplicaPeer::receive`] to abort a push once cumulative received
    /// bytes for a vault would exceed what the peer granted (W1).
    pub fn quota(&self) -> u64 {
        self.max_store.unwrap_or(u64::MAX)
    }
}

/// Default per-peer burst capacity for the replica-store rate limit (W1): 256 MiB.
/// A peer may push up to this many bytes before its bucket must refill.
pub const DEFAULT_RATE_CAPACITY: u64 = 256 * 1024 * 1024;
/// Default per-peer refill rate for the replica-store rate limit (W1): 64 MiB/s.
pub const DEFAULT_RATE_REFILL_PER_SEC: u64 = 64 * 1024 * 1024;

/// A per-peer byte token bucket that rate-limits how much a single authenticated
/// friend can push into a replica store per unit time (W1). Each peer key gets a
/// bucket of `capacity` bytes that refills at `refill_per_sec`; a push of `n`
/// bytes is admitted (and debited) only if the bucket currently holds `>= n`.
/// The clock is injected (unix seconds) so behavior is deterministic and testable.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    capacity: u64,
    refill_per_sec: u64,
    /// peer -> (tokens, last-refill second).
    buckets: HashMap<[u8; 32], (u64, u64)>,
}

impl RateLimiter {
    /// A limiter with the given burst `capacity` and `refill_per_sec` (bytes).
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        Self { capacity, refill_per_sec, buckets: HashMap::new() }
    }

    /// Try to admit `n` bytes for `peer` at wall-clock `now` (unix seconds).
    /// Refills the bucket for elapsed time (capped at `capacity`), then debits `n`
    /// and returns `true` iff enough tokens remained. A rejected request debits
    /// nothing, so a later, smaller push can still succeed.
    pub fn allow(&mut self, peer: [u8; 32], now: u64, n: u64) -> bool {
        let cap = self.capacity;
        let refill = self.refill_per_sec;
        let bucket = self.buckets.entry(peer).or_insert((cap, now));
        let elapsed = now.saturating_sub(bucket.1);
        bucket.0 = cap.min(bucket.0.saturating_add(elapsed.saturating_mul(refill)));
        bucket.1 = now;
        if bucket.0 >= n {
            bucket.0 -= n;
            true
        } else {
            false
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RATE_CAPACITY, DEFAULT_RATE_REFILL_PER_SEC)
    }
}

/// A per-replica health signal fed to the owner's repair loop, evaluated against
/// an injected clock. Absence of a signal for a member means "no news" - offline
/// is not failure, so an un-signalled member is left in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// The replica answered recently.
    Reachable,
    /// The replica has been unreachable since this wall-clock second. It is only
    /// lost once `now - since >= grace` (default 24 h).
    UnreachableSince(u64),
    /// The friendship ended: confirmed loss, repair immediately.
    Unfriended,
}

impl Health {
    /// Whether this signal means the replica is confirmed lost at `now` given the
    /// `grace` window (§10.1): unfriended is immediate, unreachable only past
    /// grace, reachable never.
    pub fn is_lost(&self, now: u64, grace: u64) -> bool {
        match self {
            Health::Reachable => false,
            Health::Unfriended => true,
            Health::UnreachableSince(since) => now.saturating_sub(*since) >= grace,
        }
    }

    /// Whether this replica can currently serve reads: reachable serves,
    /// anything else (unreachable or unfriended) does not.
    pub fn serves_reads(&self) -> bool {
        matches!(self, Health::Reachable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // W1: an "open" policy is bounded, not unlimited - it grants the 1 GiB default
    // and declines a placement larger than that.
    #[test]
    fn open_policy_is_bounded_to_default_quota() {
        let p = Policy::open();
        assert_eq!(p.quota(), DEFAULT_QUOTA_BYTES);
        assert_eq!(p.grant(1), Some(DEFAULT_QUOTA_BYTES));
        assert_eq!(p.grant(DEFAULT_QUOTA_BYTES + 1), None, "over 1 GiB is declined");
    }

    // W1: the token bucket admits within capacity, refuses over it, and refills
    // over time. A refused request debits nothing.
    #[test]
    fn rate_limiter_admits_within_capacity_and_refills() {
        let peer = [1u8; 32];
        let mut rl = RateLimiter::new(1000, 100); // 1000 B burst, 100 B/s refill

        assert!(rl.allow(peer, 0, 600));
        assert!(rl.allow(peer, 0, 400)); // exactly drains the bucket
        assert!(!rl.allow(peer, 0, 1), "empty bucket refuses even 1 byte");

        // 5 s later, 500 B have refilled: a 500 B push fits, a 501 B one does not.
        assert!(!rl.allow(peer, 5, 501));
        assert!(rl.allow(peer, 5, 500));

        // A different peer has its own independent full bucket.
        assert!(rl.allow([2u8; 32], 5, 1000));
    }
}
