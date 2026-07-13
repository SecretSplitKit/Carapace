//! Trustee-side continuous local self-validation (protocol §10.2).
//!
//! A trustee holds one share and must catch bit-rot before an owner's challenge
//! does. On a fixed cadence it runs the CRC over its stored words (a single share
//! validates alone, SPEC §4.6) and surfaces the latest [`ShareHealth`].

use carapace_recovery::{self_validate_share, Share};

use crate::Cadence;

/// Default interval between local CRC self-validations. The spec calls share-health
/// CRC "continuous" (§12) without a fixed period; hourly is a cheap default that
/// still catches rot long before the daily attestation round would. Tune via
/// [`ShareMonitor::with_interval`].
pub const DEFAULT_SELF_VALIDATE_SECS: u64 = 3600;

/// The health of a locally stored share, from its last self-validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareHealth {
    /// Never self-validated yet (fresh monitor).
    Unknown,
    /// The last CRC check passed - the words decode cleanly.
    Valid,
    /// The last CRC check failed - the stored words are corrupt (bit-rot or
    /// tampering). The trustee should re-fetch its grant or alert the owner; a
    /// corrupt share will also fail to answer any attestation challenge.
    Corrupt,
}

/// A trustee's local self-validation loop for one stored share, driven by an
/// injected unix-seconds clock (no sleeping). Poll it periodically; it self-checks
/// on its cadence and remembers the latest verdict.
#[derive(Clone, Copy, Debug)]
pub struct ShareMonitor {
    cadence: Cadence,
    status: ShareHealth,
}

impl ShareMonitor {
    /// A monitor at the default self-validation interval
    /// ([`DEFAULT_SELF_VALIDATE_SECS`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_interval(DEFAULT_SELF_VALIDATE_SECS)
    }

    /// A monitor that self-validates every `interval_secs`.
    #[must_use]
    pub fn with_interval(interval_secs: u64) -> Self {
        Self {
            cadence: Cadence::new(interval_secs),
            status: ShareHealth::Unknown,
        }
    }

    /// The most recent verdict without running a new check.
    #[must_use]
    pub fn status(&self) -> ShareHealth {
        self.status
    }

    /// Whether a self-validation is due at `now`.
    #[must_use]
    pub fn due(&self, now: u64) -> bool {
        self.cadence.due(now)
    }

    /// Run a self-validation of `share` if one is due at `now`, updating and
    /// returning the current [`ShareHealth`]. When nothing is due this is a no-op
    /// that returns the stored status, so it is cheap to call every tick. Use
    /// [`ShareMonitor::check_now`] to force a check regardless of cadence.
    pub fn poll(&mut self, share: &Share, now: u64) -> ShareHealth {
        if self.cadence.due(now) {
            self.check_now(share, now);
        }
        self.status
    }

    /// Force a self-validation of `share` now, ignoring the cadence, and return the
    /// verdict. Marks the cadence so the next scheduled check is measured from here.
    pub fn check_now(&mut self, share: &Share, now: u64) -> ShareHealth {
        self.status = match self_validate_share(share) {
            Ok(()) => ShareHealth::Valid,
            Err(_) => ShareHealth::Corrupt,
        };
        self.cadence.mark(now);
        self.status
    }
}

impl Default for ShareMonitor {
    fn default() -> Self {
        Self::new()
    }
}
