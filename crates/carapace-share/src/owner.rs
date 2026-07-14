//! Owner-side attestation cadence and drift decision (protocol §10.2).
//!
//! The owner periodically challenges every trustee, folds each verified
//! [`carapace_wire::ShareAttestation`] into a per-recovery-set attested-live count
//! under a freshness window, and turns drift toward `M` into a [`ShareAction`]. All
//! against an injected clock; the actual extend / re-split is
//! [`carapace_recovery`]'s job.

use std::collections::HashMap;

use carapace_wire::{ShareAttestChallenge, ShareAttestation};

use carapace_recovery::{attestation_live, soft_cap, verify_attestation, RecoveryError};

use crate::Cadence;

/// Default interval between attestation rounds: daily (§12 "daily attestation").
pub const DEFAULT_ATTEST_INTERVAL_SECS: u64 = 24 * 3600;

/// Default freshness window for counting a trustee's attestation "live": three
/// missed daily rounds. A trustee silent longer than this is dropped from the live
/// count, so a couple of missed rounds (offline, not lost) does not trip a repair
/// while a genuinely departed trustee still ages out.
pub const DEFAULT_FRESHNESS_SECS: u64 = 3 * DEFAULT_ATTEST_INTERVAL_SECS;

/// Default liveness slack above `M` (§8.3: initial issuance SHOULD be `N₀ ≥ M + 1`,
/// i.e. at least one share of slack). The owner may raise it.
pub const DEFAULT_SLACK: u8 = 1;

/// The recommended action from a drift evaluation (§10.2). The daemon acts on it;
/// this crate only decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareAction {
    /// Attested-live count is at or above `M + slack`: the invariant holds, do
    /// nothing.
    Healthy,
    /// Live count has drifted below `M + slack` and the §8.3 issued-count cap has
    /// room: extend to replace `needed` lost shares (§8.1) to restore the slack.
    Extend {
        /// How many replacement shares to issue to get back to `M + slack`.
        needed: usize,
    },
    /// Live count has drifted below `M + slack` but extending by the needed amount
    /// would push lifetime issuance past the `3·M − 1` soft cap (§8.3), so extension
    /// is not the answer: re-split with a larger `M` instead. Reaching the cap via
    /// replacements is itself a re-split signal (§8.3).
    ResplitLargerM,
}

/// The owner's attestation-cadence and drift tracker for one recovery set (§10.2).
///
/// It knows the set's threshold `M`, the desired `slack`, and the lifetime
/// issued-share count (every share ever put on the polynomial, including lost and
/// replaced ones - the quantity the §8.3 cap bounds). Feed it verified attestations
/// as they arrive; ask it for the live count, invariant, or recommended action at
/// any `now`. The round [`Cadence`] tells the daemon when to fire the next
/// challenge round.
#[derive(Clone, Debug)]
pub struct AttestTracker {
    m: u8,
    slack: u8,
    issued: usize,
    freshness_secs: u64,
    round: Cadence,
    /// Enrolled roster (W1): trustee signing-key -> the `card_number` (share `x`) it
    /// was issued. An attestation counts toward liveness only if its signer is in
    /// this map and it echoes that signer's own card number, so a non-enrolled or
    /// cross-set signer cannot inflate the count and no trustee can claim a share
    /// that is not its own.
    roster: HashMap<[u8; 32], u64>,
    /// card_number (share `x`) -> unix second of its most recent verified attestation.
    /// Keyed by the claimed share, not the signer, so duplicate answers for the same
    /// share collapse to one live entry: the count is distinct live shares (§10.2).
    last_seen: HashMap<u64, u64>,
}

impl AttestTracker {
    /// A tracker for a set of threshold `m` with `issued` lifetime shares and the
    /// enrolled `roster` (trustee signing-key -> its issued `card_number`), using
    /// the default slack, freshness window, and daily round interval.
    #[must_use]
    pub fn new(m: u8, issued: usize, roster: HashMap<[u8; 32], u64>) -> Self {
        Self::with_params(
            m,
            DEFAULT_SLACK,
            issued,
            DEFAULT_FRESHNESS_SECS,
            DEFAULT_ATTEST_INTERVAL_SECS,
            roster,
        )
    }

    /// A tracker with explicit slack, freshness window (seconds), round interval
    /// (seconds), and enrolled `roster`.
    #[must_use]
    pub fn with_params(
        m: u8,
        slack: u8,
        issued: usize,
        freshness_secs: u64,
        round_interval_secs: u64,
        roster: HashMap<[u8; 32], u64>,
    ) -> Self {
        Self {
            // S3: a recovery set has threshold >= 1; guard so downstream cap math
            // (`soft_cap`) and the live-target never underflow on a bogus m=0.
            m: m.max(1),
            slack,
            issued,
            freshness_secs,
            round: Cadence::new(round_interval_secs),
            roster,
            last_seen: HashMap::new(),
        }
    }

    /// Whether an attestation round is due at `now`. The daemon builds one
    /// [`ShareAttestChallenge`] per round (fresh nonce) and sends it to every
    /// trustee.
    #[must_use]
    pub fn round_due(&self, now: u64) -> bool {
        self.round.due(now)
    }

    /// Record that a challenge round was issued at `now` (resets the round cadence).
    pub fn mark_round(&mut self, now: u64) {
        self.round.mark(now);
    }

    /// Verify `att` against the `challenge` it answers (signature + echoed
    /// subject/rsid/nonce, via [`carapace_recovery::verify_attestation`]), bind it to
    /// the enrolled roster (W1), and on success mark its claimed share live as of
    /// `now`. Rejections change nothing counted:
    ///
    /// - a signer not on the roster is [`RecoveryError::NotATrustee`] - an outsider
    ///   or a trustee answering with an unexpected key cannot pad the live count;
    /// - a signer whose echoed `card_number` is not its own enrolled share is
    ///   [`RecoveryError::ChallengeMismatch`] - a trustee cannot claim liveness for a
    ///   share it was not issued.
    ///
    /// Liveness is keyed by the (validated) `card_number`, so this proves "distinct
    /// enrolled shares whose holder cooperated and self-validated," not merely
    /// "distinct online signers." It still cannot prove possession over the
    /// label-only channel (§10.2): an enrolled trustee that discarded its words but
    /// stays online is caught only by its own failing `answer_attest_challenge`
    /// (silent non-answer -> ages out), never here. Never touches the words.
    pub fn record_attestation(
        &mut self,
        att: &ShareAttestation,
        challenge: &ShareAttestChallenge,
        now: u64,
    ) -> Result<(), RecoveryError> {
        verify_attestation(att, challenge)?;
        let expected = self.roster.get(&att.by).ok_or(RecoveryError::NotATrustee)?;
        if att.card_number != *expected {
            return Err(RecoveryError::ChallengeMismatch);
        }
        self.last_seen.insert(att.card_number, now);
        Ok(())
    }

    /// The enrolled trustee signing-keys (= their dialable node ids) the owner
    /// challenges each round (§10.2). The daemon's maintenance loop resolves these to
    /// addresses to run [`crate::AttestTracker`]-driven attestation rounds.
    #[must_use]
    pub fn trustees(&self) -> Vec<[u8; 32]> {
        self.roster.keys().copied().collect()
    }

    /// The `M + slack` attested-live target the §10.2 invariant requires. Surfaced on
    /// the status API alongside [`AttestTracker::live_count`] so the operator sees the
    /// margin, not just the pass/fail verdict.
    #[must_use]
    pub fn target(&self) -> usize {
        usize::from(self.m) + usize::from(self.slack)
    }

    /// The number of distinct enrolled shares whose most recent verified attestation
    /// is within the freshness window at `now`. A share silent longer than the window
    /// (or never heard from) is not counted live (§10.2).
    #[must_use]
    pub fn live_count(&self, now: u64) -> usize {
        self.last_seen
            .values()
            .filter(|&&seen| now.saturating_sub(seen) <= self.freshness_secs)
            .count()
    }

    /// Whether the §10.2 invariant `attested live ≥ M + slack` holds at `now`.
    #[must_use]
    pub fn is_healthy(&self, now: u64) -> bool {
        attestation_live(self.live_count(now), self.m, self.slack)
    }

    /// The lifetime issued-share count this tracker is holding (§8.3).
    #[must_use]
    pub fn issued(&self) -> usize {
        self.issued
    }

    /// Update the lifetime issued-share count after the owner has extended or
    /// re-split, so the next decision uses the new cap headroom.
    pub fn set_issued(&mut self, issued: usize) {
        self.issued = issued;
    }

    /// Evaluate drift at `now` and recommend an action (§10.2):
    ///
    /// - at or above `M + slack` -> [`ShareAction::Healthy`];
    /// - below it, with cap headroom -> [`ShareAction::Extend`] by the shortfall;
    /// - below it, where extending by the shortfall would breach the `3·M − 1`
    ///   soft cap (§8.3) -> [`ShareAction::ResplitLargerM`].
    #[must_use]
    pub fn decide(&self, now: u64) -> ShareAction {
        let live = self.live_count(now);
        let target = usize::from(self.m) + usize::from(self.slack);
        if live >= target {
            return ShareAction::Healthy;
        }
        let needed = target - live;
        if self.issued + needed > soft_cap(self.m) {
            ShareAction::ResplitLargerM
        } else {
            ShareAction::Extend { needed }
        }
    }
}
