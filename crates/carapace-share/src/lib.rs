//! carapace-share: share-health cadence (protocol §10.2).
//!
//! The recovery layer ([`carapace_recovery`]) owns the attestation *primitives* -
//! building/answering/verifying [`carapace_wire::ShareAttestChallenge`] /
//! [`carapace_wire::ShareAttestation`], CRC self-validation, the extend/re-split
//! mechanics, and the raw `attested live >= M + slack` predicate. This crate owns
//! the *cadence and decision* on top of them, mapping directly to §10.2:
//!
//! - [`trustee`]: a trustee's continuous local self-validation loop. On a fixed
//!   interval it runs [`carapace_recovery::self_validate_share`] (a single share
//!   validates alone via the CRC over its words, SPEC §4.6) to catch bit-rot, and
//!   surfaces a [`trustee::ShareHealth`].
//! - [`owner`]: the owner's attestation loop. It drives daily challenge rounds,
//!   folds verified attestations into a per-recovery-set attested-live count under
//!   a freshness window (a trustee silent past the window is not counted live),
//!   and turns drift toward `M` into a [`owner::ShareAction`] the daemon acts on:
//!   `Extend` to replace lost shares, or `ResplitLargerM` when the §8.3 issued-count
//!   cap is the blocker. The extend/re-split itself is
//!   [`carapace_recovery`]'s job - this crate DECIDES and signals.
//!
//! All cadence and freshness logic runs against an injected unix-seconds clock via
//! [`Cadence`], so nothing here sleeps and every schedule is deterministic in tests.

mod owner;
mod trustee;

pub use owner::{
    AttestTracker, ShareAction, DEFAULT_ATTEST_INTERVAL_SECS, DEFAULT_FRESHNESS_SECS, DEFAULT_SLACK,
};
pub use trustee::{ShareHealth, ShareMonitor, DEFAULT_SELF_VALIDATE_SECS};

// Re-export the recovery-side primitives a daemon needs to actually run a round,
// so callers depend on one crate for the whole share-health flow (§10.2).
pub use carapace_recovery::{
    answer_attest_challenge, attestation_live, build_attest_challenge, self_validate_share,
    soft_cap, verify_attestation, RecoveryError, Share,
};

/// A fixed-interval "is it time yet?" gate against an injected unix-seconds clock.
///
/// Both the trustee self-validation loop and the owner attestation loop are
/// periodic actions with no other state, so they share this one helper rather than
/// each hand-rolling last-run bookkeeping. `due(now)` is true before the first run
/// and once `interval` seconds have elapsed since the last [`Cadence::mark`].
#[derive(Clone, Copy, Debug)]
pub struct Cadence {
    interval: u64,
    last: Option<u64>,
}

impl Cadence {
    /// A cadence that fires every `interval` seconds (and immediately, before any
    /// first run).
    #[must_use]
    pub fn new(interval: u64) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    /// Whether the action is due at `now`: true if it has never run, or if at least
    /// `interval` seconds have elapsed since the last [`Cadence::mark`].
    #[must_use]
    pub fn due(&self, now: u64) -> bool {
        self.last
            .is_none_or(|last| now.saturating_sub(last) >= self.interval)
    }

    /// Record that the action ran at `now` (resets the interval).
    pub fn mark(&mut self, now: u64) {
        self.last = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_fires_first_then_on_interval() {
        let mut c = Cadence::new(100);
        assert!(c.due(0), "never-run cadence is due immediately");
        c.mark(0);
        assert!(!c.due(50), "not due before the interval elapses");
        assert!(!c.due(99));
        assert!(c.due(100), "due exactly at the interval");
        c.mark(100);
        assert!(!c.due(150));
    }
}
