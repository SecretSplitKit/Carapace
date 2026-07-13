//! The recovery ceremony (protocol §8.5, normative). A testable state machine plus the message
//! builders/verifiers. No protocol can cryptographically prove a key-less claimant is the owner,
//! so the ceremony structures human verification and makes silent takeover loud and slow:
//! only a trustee may open, the subject's own key can abort unforgeably, and no share moves before
//! both the delay elapses and `M` trustees approve. Wall-clock time is injected as a `now`
//! parameter so tests never sleep.

use carapace_crypto::seal::{open, seal, HpkePrivateKey, HpkePublicKey};
use carapace_wire::{
    CeremonyAbort, CeremonyApprove, CeremonyShare, RecoveryOpen, ShareGrant, Signed,
};
use ed25519_dalek::SigningKey;

use crate::grant::verify_share_grant;
use crate::RecoveryError;

/// Chela's `recovery_set_id` is an 11-bit value; a wire `rsid` above this cannot name a real set.
const MAX_RSID: u64 = 0x7FF;

/// HPKE `info` context for a sealed ceremony share (protocol §8.5).
pub const CEREMONY_SHARE_INFO: &[u8] = b"carapace/v1/ceremony-share";

/// The observable phase of a ceremony at a given wall-clock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyPhase {
    /// Collecting approvals and/or waiting out the delay.
    Open,
    /// `≥ M` approvals AND the delay has elapsed: approving trustees may release their shares.
    ReadyToRelease,
    /// A valid subject-signed abort was seen: permanently cancelled, flagged as attempted takeover.
    Aborted,
}

/// Per-subject rate limiter for `RecoveryOpen` (protocol §8.5: "rate-limited per subject").
/// A sliding window of recent opens; opens beyond `max_per_window` inside `window_secs` are refused.
pub struct RecoveryRateLimiter {
    window_secs: u64,
    max_per_window: usize,
    events: Vec<([u8; 32], u64)>,
}

impl RecoveryRateLimiter {
    /// A limiter allowing `max_per_window` opens per subject within any `window_secs` window.
    #[must_use]
    pub fn new(window_secs: u64, max_per_window: usize) -> Self {
        Self {
            window_secs,
            max_per_window,
            events: Vec::new(),
        }
    }

    /// Record an open for `subject` at `now`, or refuse with [`RecoveryError::RateLimited`] if the
    /// window is already full. Prunes events older than the window on each call.
    pub fn check_and_record(&mut self, subject: [u8; 32], now: u64) -> Result<(), RecoveryError> {
        self.events
            .retain(|(_, t)| now.saturating_sub(*t) < self.window_secs);
        let count = self.events.iter().filter(|(s, _)| *s == subject).count();
        if count >= self.max_per_window {
            return Err(RecoveryError::RateLimited);
        }
        self.events.push((subject, now));
        Ok(())
    }
}

/// Build and sign a [`RecoveryOpen`] (protocol §8.5 step 1). Signed by the sponsor's *trustee*
/// key; `verify_recovery_open` enforces that the signer is in the roster.
#[allow(clippy::too_many_arguments)]
pub fn open_recovery(
    sponsor: &SigningKey,
    ceremony_id: [u8; 16],
    subject: [u8; 32],
    rsid: u64,
    claimant_display: String,
    ceremony_enc: [u8; 32],
    new_node: [u8; 32],
    reason: String,
    opened_at: u64,
) -> RecoveryOpen {
    let mut open = RecoveryOpen {
        ceremony_id,
        subject,
        rsid,
        claimant_display,
        ceremony_enc,
        new_node,
        reason,
        opened_at,
        by: [0; 32],
        sig: [0; 64],
    };
    open.sign(sponsor);
    open
}

/// Verify a [`RecoveryOpen`]: valid signature AND the signer is a trustee of the subject's
/// recovery set (protocol §8.5 step 1 - strangers cannot open). `roster` is the co-trustee user
/// pubkeys for the set.
pub fn verify_recovery_open(open: &RecoveryOpen, roster: &[[u8; 32]]) -> Result<(), RecoveryError> {
    // The wire `rsid` is a u64, but Chela's `recovery_set_id` is 11-bit; a larger value cannot
    // reference a real set, so reject it on ingest rather than carrying it inward.
    if open.rsid > MAX_RSID {
        return Err(RecoveryError::RsidOutOfRange);
    }
    open.verify()?;
    if !roster.contains(&open.by) {
        return Err(RecoveryError::NotATrustee);
    }
    Ok(())
}

/// A ceremony as tracked by any party observing it (a trustee, the sponsor). Records approvals and
/// aborts; `can_release` / `phase` gate share release on `M` approvals AND the delay.
pub struct CeremonyState {
    /// The ceremony id, echoed by every message in this ceremony.
    pub ceremony_id: [u8; 16],
    /// The subject user pubkey (only its key can abort).
    pub subject: [u8; 32],
    /// The recovery-set id.
    pub rsid: u64,
    /// The claimant's fresh X25519 pubkey; approving trustees seal their shares to it.
    pub ceremony_enc: [u8; 32],
    /// The recovery delay in seconds (from the `ShareGrant`, default 72 h).
    pub recovery_delay: u64,
    /// The sponsor's claimed open time (from the signed `RecoveryOpen`). Advisory only: the release
    /// gate uses `max(opened_at, first_seen)` so a sponsor cannot backdate it (see `can_release`).
    pub opened_at: u64,
    /// This observer's own first-observation time, captured when it began tracking the ceremony.
    /// The delay clock is anchored here, not to the sponsor-controlled `opened_at`.
    pub first_seen: u64,
    /// The reconstruction threshold `M`.
    pub m: u8,
    roster: Vec<[u8; 32]>,
    approvals: Vec<[u8; 32]>,
    aborted: bool,
}

impl CeremonyState {
    /// Begin tracking a ceremony from a verified [`RecoveryOpen`]. Verifies the open against the
    /// roster (only a trustee may open). `recovery_delay` and `m` come from the `ShareGrant`. `now`
    /// is this observer's wall clock at ingest and anchors the delay (see [`Self::can_release`]).
    ///
    /// Prefer [`Self::open_from_grant`], which binds the open to a verified grant, derives the
    /// roster / `m` / `recovery_delay` from it, and applies the per-subject rate limit. This
    /// lower-level form trusts the caller to pair the correct roster with the open.
    pub fn open(
        open: &RecoveryOpen,
        roster: Vec<[u8; 32]>,
        m: u8,
        recovery_delay: u64,
        now: u64,
    ) -> Result<Self, RecoveryError> {
        verify_recovery_open(open, &roster)?;
        Ok(Self::track(open, roster, m, recovery_delay, now))
    }

    /// Begin tracking a ceremony bound to the [`ShareGrant`] that gates it. This is the front door
    /// for an inbound [`RecoveryOpen`] and closes the composition gaps of the raw [`Self::open`]:
    ///
    /// - verifies the grant's signature and decodes its share;
    /// - requires `open.subject == grant.subject` and `open.rsid == share.recovery_set_id`
    ///   (an open cannot be gated on a grant for a different subject or set);
    /// - derives the roster (`grant.by` plus every `grant.cotrustees[i].user`), threshold `M`
    ///   (the share's), and `recovery_delay` from the grant rather than trusting loose arguments;
    /// - verifies the open against that derived roster (only a trustee may sponsor);
    /// - charges the per-subject rate limit (protocol §8.5: "rate-limited per subject").
    ///
    /// `limiter` is the daemon's long-lived [`RecoveryRateLimiter`]; `now` anchors the delay.
    pub fn open_from_grant(
        open: &RecoveryOpen,
        grant: &ShareGrant,
        limiter: &mut RecoveryRateLimiter,
        now: u64,
    ) -> Result<Self, RecoveryError> {
        let share = verify_share_grant(grant)?;
        if open.subject != grant.subject || open.rsid != u64::from(share.recovery_set_id) {
            return Err(RecoveryError::GrantMismatch);
        }
        let mut roster = Vec::with_capacity(1 + grant.cotrustees.len());
        roster.push(grant.by);
        roster.extend(grant.cotrustees.iter().map(|c| c.user));
        // Authenticate the sponsor before charging the subject's budget, so forged opens cannot
        // exhaust an honest subject's rate limit.
        verify_recovery_open(open, &roster)?;
        limiter.check_and_record(open.subject, now)?;
        Ok(Self::track(
            open,
            roster,
            share.threshold,
            grant.recovery_delay,
            now,
        ))
    }

    /// Construct the tracking state from already-verified parts. Callers MUST have verified the
    /// open against `roster` first (both [`Self::open`] and [`Self::open_from_grant`] do).
    fn track(
        open: &RecoveryOpen,
        roster: Vec<[u8; 32]>,
        m: u8,
        recovery_delay: u64,
        now: u64,
    ) -> Self {
        Self {
            ceremony_id: open.ceremony_id,
            subject: open.subject,
            rsid: open.rsid,
            ceremony_enc: open.ceremony_enc,
            recovery_delay,
            opened_at: open.opened_at,
            first_seen: now,
            m,
            roster,
            approvals: Vec::new(),
            aborted: false,
        }
    }

    /// Apply a [`CeremonyApprove`] (protocol §8.5 step 4): verify the signature, the ceremony id,
    /// and that the approver is a roster trustee; record a distinct approval.
    pub fn approve(&mut self, ap: &CeremonyApprove) -> Result<(), RecoveryError> {
        ap.verify()?;
        if ap.ceremony_id != self.ceremony_id {
            return Err(RecoveryError::CeremonyMismatch);
        }
        let who = ap.by;
        if !self.roster.contains(&who) {
            return Err(RecoveryError::NotATrustee);
        }
        if !self.approvals.contains(&who) {
            self.approvals.push(who);
        }
        Ok(())
    }

    /// Apply a [`CeremonyAbort`] (protocol §8.5 step 3). Authoritative and unforgeable: it must be
    /// signed by the subject's *user* key. A valid abort cancels the ceremony permanently.
    pub fn abort(&mut self, ab: &CeremonyAbort) -> Result<(), RecoveryError> {
        ab.verify()?;
        if ab.ceremony_id != self.ceremony_id {
            return Err(RecoveryError::CeremonyMismatch);
        }
        if ab.by != self.subject {
            return Err(RecoveryError::NotSubject);
        }
        self.aborted = true;
        Ok(())
    }

    /// Distinct approvals recorded so far.
    #[must_use]
    pub fn approvals_count(&self) -> usize {
        self.approvals.len()
    }

    /// Whether a valid subject-signed abort has cancelled this ceremony.
    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    /// Whether shares may be released at `now`: not aborted, `≥ M` approvals, AND the delay has
    /// elapsed (protocol §8.5 step 5). Both conditions are required.
    ///
    /// The delay is anchored to `max(opened_at, first_seen)`, not to the sponsor-controlled
    /// `opened_at` alone. A malicious sponsor who backdates `opened_at` (e.g. to 0) cannot collapse
    /// the abort window: each honest observer still waits `recovery_delay` from its own first
    /// observation. A future-dated `opened_at` only pushes release later. See spec-errata E4.
    #[must_use]
    pub fn can_release(&self, now: u64) -> bool {
        let release_at = self
            .opened_at
            .max(self.first_seen)
            .saturating_add(self.recovery_delay);
        !self.aborted && self.approvals.len() >= usize::from(self.m) && now >= release_at
    }

    /// The observable phase at `now`.
    #[must_use]
    pub fn phase(&self, now: u64) -> CeremonyPhase {
        if self.aborted {
            CeremonyPhase::Aborted
        } else if self.can_release(now) {
            CeremonyPhase::ReadyToRelease
        } else {
            CeremonyPhase::Open
        }
    }
}

/// Build a [`CeremonyShare`] (protocol §8.5 step 5): HPKE-seal the trustee's `chela.share` JSON to
/// the claimant's `ceremony_enc` pubkey, then sign the message with the trustee key. The sealed
/// bytes are `encapped_key(32) ‖ ciphertext`; the ceremony id is bound as AEAD associated data.
/// No trustee ever sees another's share.
pub fn build_ceremony_share(
    trustee: &SigningKey,
    ceremony_id: [u8; 16],
    ceremony_enc: &[u8; 32],
    share_json: &str,
) -> Result<CeremonyShare, RecoveryError> {
    let recipient = HpkePublicKey::from_bytes(ceremony_enc)?;
    let (encapped, ct) = seal(
        &recipient,
        CEREMONY_SHARE_INFO,
        &ceremony_id,
        share_json.as_bytes(),
    )?;
    let mut sealed = encapped; // X25519 encapped key is 32 bytes
    sealed.extend_from_slice(&ct);

    let mut cs = CeremonyShare {
        ceremony_id,
        sealed,
        by: [0; 32],
        sig: [0; 64],
    };
    cs.sign(trustee);
    Ok(cs)
}

/// Open a [`CeremonyShare`] with the claimant's ceremony private key, returning the recovered
/// `chela.share` JSON. Authenticates the sender first - the trustee signature must verify AND
/// `cs.by` must be in `roster` - before decrypting, so a party who merely observed the (semi-public)
/// `ceremony_enc` cannot feed the claimant a bogus share. Then splits the leading 32-byte encapped
/// key from the ciphertext and binds the ceremony id as associated data.
pub fn open_ceremony_share(
    recipient: &HpkePrivateKey,
    cs: &CeremonyShare,
    roster: &[[u8; 32]],
) -> Result<String, RecoveryError> {
    cs.verify()?;
    if !roster.contains(&cs.by) {
        return Err(RecoveryError::NotATrustee);
    }
    if cs.sealed.len() < 32 {
        return Err(RecoveryError::Open);
    }
    let (encapped, ct) = cs.sealed.split_at(32);
    let plaintext = open(
        recipient,
        encapped,
        CEREMONY_SHARE_INFO,
        &cs.ceremony_id,
        ct,
    )?;
    String::from_utf8(plaintext).map_err(|_| RecoveryError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{build_share_grant, share_from_json};
    use crate::split::{recover_key_from_shares, split_root};
    use carapace_crypto::seal::derive_keypair;
    use carapace_wire::CoTrustee;
    use chela_engine::Share;
    use ed25519_dalek::SigningKey;

    const K_ROOT: [u8; 32] = [0x11u8; 32];
    const DELAY: u64 = 72 * 3600;
    const T0: u64 = 1_800_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    struct Setup {
        shares: Vec<Share>,
        trustees: Vec<SigningKey>,
        roster: Vec<[u8; 32]>,
        subject_key: SigningKey,
        subject: [u8; 32],
    }

    /// 3-of-5 split of K_root with five trustee identities.
    fn setup() -> Setup {
        let (shares, _state, _w) = split_root(&K_ROOT, 3, 5, false).unwrap();
        let trustees: Vec<SigningKey> = (0..5).map(|i| key(0x40 + i)).collect();
        let roster: Vec<[u8; 32]> = trustees
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect();
        let subject_key = key(0x09);
        let subject = subject_key.verifying_key().to_bytes();
        Setup {
            shares,
            trustees,
            roster,
            subject_key,
            subject,
        }
    }

    /// A `ShareGrant` signed by trustee `signer_idx` that carries the full roster in `cotrustees`
    /// (every other trustee's user pubkey), so `open_from_grant` derives the same 5-trustee roster.
    fn grant_with_roster(s: &Setup, signer_idx: usize) -> ShareGrant {
        let cotrustees = s
            .roster
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != signer_idx)
            .map(|(_, user)| CoTrustee {
                user: *user,
                node: [0; 32],
                relay_url: None,
            })
            .collect();
        build_share_grant(
            &s.trustees[signer_idx],
            s.subject,
            &s.shares[signer_idx],
            DELAY,
            cotrustees,
            vec![],
        )
    }

    /// A `RecoveryOpen` sponsored by trustee 0 for this subject at the given `rsid`/`opened_at`.
    fn an_open(s: &Setup, rsid: u64, opened_at: u64) -> RecoveryOpen {
        open_recovery(
            &s.trustees[0],
            [0xCE; 16],
            s.subject,
            rsid,
            "heir".into(),
            [0x01; 32],
            [0x77; 32],
            "r".into(),
            opened_at,
        )
    }

    #[test]
    fn full_ceremony_releases_and_recovers() {
        let s = setup();

        // Claimant's fresh ceremony HPKE keypair (new device).
        let mut ikm = [0u8; 32];
        getrandom::getrandom(&mut ikm).unwrap();
        let (ceremony_sk, ceremony_pk) = derive_keypair(&ikm);
        let ceremony_enc: [u8; 32] = ceremony_pk.to_bytes().try_into().unwrap();

        // ShareGrants for each trustee (carry the delay and the share JSON).
        let grants: Vec<_> = s
            .shares
            .iter()
            .enumerate()
            .map(|(i, share)| {
                build_share_grant(&s.trustees[i], s.subject, share, DELAY, vec![], vec![])
            })
            .collect();

        // Sponsor (trustee 0) opens the ceremony.
        let open = open_recovery(
            &s.trustees[0],
            [0xCE; 16],
            s.subject,
            0x321,
            "heir".into(),
            ceremony_enc,
            [0x77; 32],
            "lost all devices".into(),
            T0,
        );
        let mut cer = CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0).unwrap();
        assert_eq!(cer.phase(T0), CeremonyPhase::Open);

        // Three trustees approve.
        for t in s.trustees.iter().take(3) {
            let mut ap = CeremonyApprove {
                ceremony_id: [0xCE; 16],
                ts: T0 + 10,
                by: [0; 32],
                sig: [0; 64],
            };
            ap.sign(t);
            cer.approve(&ap).unwrap();
        }
        assert_eq!(cer.approvals_count(), 3);

        // Before the delay: not releasable even with M approvals.
        assert!(!cer.can_release(T0 + 10));
        assert_eq!(cer.phase(T0 + 10), CeremonyPhase::Open);
        // After the delay: releasable.
        let after = T0 + DELAY;
        assert!(cer.can_release(after));
        assert_eq!(cer.phase(after), CeremonyPhase::ReadyToRelease);

        // The three approving trustees each seal their share to ceremony_enc.
        let mut recovered_jsons = Vec::new();
        for (i, t) in s.trustees.iter().take(3).enumerate() {
            let cs =
                build_ceremony_share(t, [0xCE; 16], &ceremony_enc, &grants[i].share_json).unwrap();
            // Claimant authenticates the sender (sig + roster) and opens in one step.
            let json = open_ceremony_share(&ceremony_sk, &cs, &s.roster).unwrap();
            recovered_jsons.push(json);
        }

        // Claimant parses the M shares and recovers K_root.
        let shares: Vec<Share> = recovered_jsons
            .iter()
            .map(|j| share_from_json(j).unwrap())
            .collect();
        let recovered = recover_key_from_shares(&shares).unwrap();
        assert_eq!(recovered.as_slice(), &K_ROOT);
    }

    #[test]
    fn abort_cancels_permanently() {
        let s = setup();
        let open = open_recovery(
            &s.trustees[0],
            [0xCE; 16],
            s.subject,
            1,
            "x".into(),
            [0x01; 32],
            [0x02; 32],
            "r".into(),
            T0,
        );
        let mut cer = CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0).unwrap();
        for t in s.trustees.iter().take(3) {
            let mut ap = CeremonyApprove {
                ceremony_id: [0xCE; 16],
                ts: T0,
                by: [0; 32],
                sig: [0; 64],
            };
            ap.sign(t);
            cer.approve(&ap).unwrap();
        }

        // Subject aborts.
        let mut abort = CeremonyAbort {
            ceremony_id: [0xCE; 16],
            by: [0; 32],
            sig: [0; 64],
        };
        abort.sign(&s.subject_key);
        cer.abort(&abort).unwrap();

        assert!(cer.is_aborted());
        // Even past the delay with M approvals, an aborted ceremony never releases.
        assert!(!cer.can_release(T0 + DELAY));
        assert_eq!(cer.phase(T0 + DELAY), CeremonyPhase::Aborted);
    }

    #[test]
    fn impostor_cannot_abort() {
        let s = setup();
        let open = open_recovery(
            &s.trustees[0],
            [0xCE; 16],
            s.subject,
            1,
            "x".into(),
            [0x01; 32],
            [0x02; 32],
            "r".into(),
            T0,
        );
        let mut cer = CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0).unwrap();
        // A validly self-signed abort by someone who is not the subject is rejected.
        let impostor = key(0xEE);
        let mut abort = CeremonyAbort {
            ceremony_id: [0xCE; 16],
            by: [0; 32],
            sig: [0; 64],
        };
        abort.sign(&impostor);
        assert!(matches!(cer.abort(&abort), Err(RecoveryError::NotSubject)));
        assert!(!cer.is_aborted());
    }

    #[test]
    fn sub_m_never_releases() {
        let s = setup();
        let open = open_recovery(
            &s.trustees[0],
            [0xCE; 16],
            s.subject,
            1,
            "x".into(),
            [0x01; 32],
            [0x02; 32],
            "r".into(),
            T0,
        );
        let mut cer = CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0).unwrap();
        // Only two approvals for a 3-of-5.
        for t in s.trustees.iter().take(2) {
            let mut ap = CeremonyApprove {
                ceremony_id: [0xCE; 16],
                ts: T0,
                by: [0; 32],
                sig: [0; 64],
            };
            ap.sign(t);
            cer.approve(&ap).unwrap();
        }
        assert!(!cer.can_release(T0 + DELAY + 999_999));
    }

    #[test]
    fn non_sponsor_cannot_open() {
        let s = setup();
        // A stranger not in the roster signs a RecoveryOpen.
        let stranger = key(0xAB);
        let open = open_recovery(
            &stranger,
            [0xCE; 16],
            s.subject,
            1,
            "x".into(),
            [0x01; 32],
            [0x02; 32],
            "r".into(),
            T0,
        );
        assert!(matches!(
            verify_recovery_open(&open, &s.roster),
            Err(RecoveryError::NotATrustee)
        ));
        assert!(matches!(
            CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0),
            Err(RecoveryError::NotATrustee)
        ));
    }

    #[test]
    fn duplicate_approvals_count_once() {
        let s = setup();
        let open = open_recovery(
            &s.trustees[0],
            [0xCE; 16],
            s.subject,
            1,
            "x".into(),
            [0x01; 32],
            [0x02; 32],
            "r".into(),
            T0,
        );
        let mut cer = CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0).unwrap();
        for _ in 0..3 {
            let mut ap = CeremonyApprove {
                ceremony_id: [0xCE; 16],
                ts: T0,
                by: [0; 32],
                sig: [0; 64],
            };
            ap.sign(&s.trustees[0]);
            cer.approve(&ap).unwrap();
        }
        assert_eq!(cer.approvals_count(), 1);
    }

    #[test]
    fn rate_limiter_caps_opens_per_subject() {
        let mut rl = RecoveryRateLimiter::new(3600, 2);
        let subject = [0x09; 32];
        rl.check_and_record(subject, 100).unwrap();
        rl.check_and_record(subject, 200).unwrap();
        assert!(matches!(
            rl.check_and_record(subject, 300),
            Err(RecoveryError::RateLimited)
        ));
        // A different subject is independent.
        rl.check_and_record([0x0A; 32], 300).unwrap();
        // After the window slides, the subject is allowed again.
        rl.check_and_record(subject, 100 + 3600).unwrap();
    }

    #[test]
    fn wrong_ceremony_id_rejected() {
        let s = setup();
        let open = open_recovery(
            &s.trustees[0],
            [0xCE; 16],
            s.subject,
            1,
            "x".into(),
            [0x01; 32],
            [0x02; 32],
            "r".into(),
            T0,
        );
        let mut cer = CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0).unwrap();
        let mut ap = CeremonyApprove {
            ceremony_id: [0xFF; 16],
            ts: T0,
            by: [0; 32],
            sig: [0; 64],
        };
        ap.sign(&s.trustees[0]);
        assert!(matches!(
            cer.approve(&ap),
            Err(RecoveryError::CeremonyMismatch)
        ));
    }

    /// C1: a malicious sponsor who backdates `opened_at` cannot skip the delay. The clock is
    /// anchored to the observer's own `first_seen`, so with `opened_at = 0` and M approvals the
    /// ceremony is still not releasable until `first_seen + recovery_delay`.
    #[test]
    fn delay_anchored_to_first_seen_not_sponsor_opened_at() {
        let s = setup();
        let rsid = u64::from(s.shares[0].recovery_set_id);
        let open = an_open(&s, rsid, 0); // sponsor claims opened_at = 0
        let mut cer = CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0).unwrap();
        for t in s.trustees.iter().take(3) {
            let mut ap = CeremonyApprove {
                ceremony_id: [0xCE; 16],
                ts: T0,
                by: [0; 32],
                sig: [0; 64],
            };
            ap.sign(t);
            cer.approve(&ap).unwrap();
        }
        // If the gate trusted opened_at = 0, this (now = DELAY + 10 >= 0 + DELAY) would release.
        assert!(!cer.can_release(DELAY + 10));
        // The delay runs from first_seen (T0), not the sponsor's opened_at.
        assert!(!cer.can_release(T0 + DELAY - 1));
        assert!(cer.can_release(T0 + DELAY));
    }

    /// W1: `open_from_grant` binds the open to the grant - a mismatched subject is refused.
    #[test]
    fn open_from_grant_rejects_subject_mismatch() {
        let s = setup();
        let grant = grant_with_roster(&s, 0);
        let rsid = u64::from(s.shares[0].recovery_set_id);
        let mut open = an_open(&s, rsid, T0);
        open.subject = [0xAB; 32];
        open.sign(&s.trustees[0]); // validly signed, but the subject no longer matches the grant
        let mut rl = RecoveryRateLimiter::new(3600, 5);
        assert!(matches!(
            CeremonyState::open_from_grant(&open, &grant, &mut rl, T0),
            Err(RecoveryError::GrantMismatch)
        ));
    }

    /// W1: a mismatched `rsid` (a different, in-range set) is refused.
    #[test]
    fn open_from_grant_rejects_rsid_mismatch() {
        let s = setup();
        let grant = grant_with_roster(&s, 0);
        let real = u64::from(s.shares[0].recovery_set_id);
        let wrong = (real + 1) & MAX_RSID; // still in range, but not this grant's set
        let open = an_open(&s, wrong, T0);
        let mut rl = RecoveryRateLimiter::new(3600, 5);
        assert!(matches!(
            CeremonyState::open_from_grant(&open, &grant, &mut rl, T0),
            Err(RecoveryError::GrantMismatch)
        ));
    }

    /// W1: `open_from_grant` derives the roster, threshold, and delay from the grant, not from
    /// loose arguments - a cotrustee named only in the grant can then approve.
    #[test]
    fn open_from_grant_derives_roster_and_delay() {
        let s = setup();
        let grant = grant_with_roster(&s, 0);
        let rsid = u64::from(s.shares[0].recovery_set_id);
        let open = an_open(&s, rsid, T0);
        let mut rl = RecoveryRateLimiter::new(3600, 5);
        let mut cer = CeremonyState::open_from_grant(&open, &grant, &mut rl, T0).unwrap();
        assert_eq!(cer.m, 3);
        assert_eq!(cer.recovery_delay, DELAY);
        let mut ap = CeremonyApprove {
            ceremony_id: [0xCE; 16],
            ts: T0,
            by: [0; 32],
            sig: [0; 64],
        };
        ap.sign(&s.trustees[3]); // a cotrustee from the derived roster
        cer.approve(&ap).unwrap();
        assert_eq!(cer.approvals_count(), 1);
    }

    /// W3: the per-subject rate limit is enforced inside the verified open path.
    #[test]
    fn open_from_grant_is_rate_limited_per_subject() {
        let s = setup();
        let grant = grant_with_roster(&s, 0);
        let rsid = u64::from(s.shares[0].recovery_set_id);
        let open = an_open(&s, rsid, T0);
        let mut rl = RecoveryRateLimiter::new(3600, 1);
        CeremonyState::open_from_grant(&open, &grant, &mut rl, T0).unwrap();
        assert!(matches!(
            CeremonyState::open_from_grant(&open, &grant, &mut rl, T0 + 1),
            Err(RecoveryError::RateLimited)
        ));
    }

    /// W3: a forged open (sponsor not in the roster) is refused *before* the rate limit is charged,
    /// so it cannot be used to exhaust an honest subject's budget.
    #[test]
    fn forged_open_does_not_consume_rate_budget() {
        let s = setup();
        let grant = grant_with_roster(&s, 0);
        let rsid = u64::from(s.shares[0].recovery_set_id);
        let stranger = key(0xAB);
        let mut forged = an_open(&s, rsid, T0);
        forged.sign(&stranger); // signer is not in the roster
        let mut rl = RecoveryRateLimiter::new(3600, 1);
        assert!(matches!(
            CeremonyState::open_from_grant(&forged, &grant, &mut rl, T0),
            Err(RecoveryError::NotATrustee)
        ));
        // Budget was not spent: a legitimate open still fits under the limit of 1.
        let open = an_open(&s, rsid, T0);
        CeremonyState::open_from_grant(&open, &grant, &mut rl, T0).unwrap();
    }

    /// W2: `open_ceremony_share` refuses a share sealed by a non-roster sender.
    #[test]
    fn open_ceremony_share_rejects_nonroster_sender() {
        let s = setup();
        let mut ikm = [0u8; 32];
        getrandom::getrandom(&mut ikm).unwrap();
        let (ceremony_sk, ceremony_pk) = derive_keypair(&ikm);
        let ceremony_enc: [u8; 32] = ceremony_pk.to_bytes().try_into().unwrap();

        let attacker = key(0xAB); // knows the semi-public ceremony_enc, but is not a trustee
        let grant = build_share_grant(
            &s.trustees[0],
            s.subject,
            &s.shares[0],
            DELAY,
            vec![],
            vec![],
        );
        let cs =
            build_ceremony_share(&attacker, [0xCE; 16], &ceremony_enc, &grant.share_json).unwrap();
        assert!(matches!(
            open_ceremony_share(&ceremony_sk, &cs, &s.roster),
            Err(RecoveryError::NotATrustee)
        ));
    }

    /// W2: a tampered signature on a `CeremonyShare` is rejected before decryption.
    #[test]
    fn open_ceremony_share_rejects_tampered_signature() {
        let s = setup();
        let mut ikm = [0u8; 32];
        getrandom::getrandom(&mut ikm).unwrap();
        let (ceremony_sk, ceremony_pk) = derive_keypair(&ikm);
        let ceremony_enc: [u8; 32] = ceremony_pk.to_bytes().try_into().unwrap();
        let grant = build_share_grant(
            &s.trustees[0],
            s.subject,
            &s.shares[0],
            DELAY,
            vec![],
            vec![],
        );
        let mut cs =
            build_ceremony_share(&s.trustees[0], [0xCE; 16], &ceremony_enc, &grant.share_json)
                .unwrap();
        cs.sig[0] ^= 1;
        assert!(matches!(
            open_ceremony_share(&ceremony_sk, &cs, &s.roster),
            Err(RecoveryError::Wire(carapace_wire::Error::Signature))
        ));
    }

    /// S3: a `RecoveryOpen` naming an `rsid` above Chela's 11-bit range is refused on ingest.
    #[test]
    fn recovery_open_rejects_out_of_range_rsid() {
        let s = setup();
        let open = an_open(&s, MAX_RSID + 1, T0);
        assert!(matches!(
            verify_recovery_open(&open, &s.roster),
            Err(RecoveryError::RsidOutOfRange)
        ));
        assert!(matches!(
            CeremonyState::open(&open, s.roster.clone(), 3, DELAY, T0),
            Err(RecoveryError::RsidOutOfRange)
        ));
    }
}
