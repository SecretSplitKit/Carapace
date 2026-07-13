//! §10.2 share-health cadence: trustee self-validation, owner attestation freshness,
//! and the drift decision (extend vs re-split under the §8.3 cap).

use std::collections::HashMap;

use carapace_recovery::{answer_attest_challenge, build_attest_challenge, split_root, Share};
use carapace_share::{
    AttestTracker, ShareAction, ShareHealth, ShareMonitor, DEFAULT_FRESHNESS_SECS,
};
use ed25519_dalek::SigningKey;

const K_ROOT: [u8; 32] = [0x11u8; 32];

fn trustee_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Split `K_ROOT` into `n` shares (threshold `m`), pairing each with a distinct
/// trustee signing key.
fn shares_with_trustees(m: u8, n: u8) -> Vec<(SigningKey, Share)> {
    let (shares, _state, _warn) = split_root(&K_ROOT, m, n, false).unwrap();
    shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| (trustee_key(100 + i as u8), s))
        .collect()
}

/// The enrolled roster (W1) for a set of `(trustee key, share)` pairs: each
/// trustee's signing-key -> its issued card_number (share `x`).
fn roster_of(trustees: &[(SigningKey, Share)]) -> HashMap<[u8; 32], u64> {
    trustees
        .iter()
        .map(|(k, s)| (k.verifying_key().to_bytes(), u64::from(s.x)))
        .collect()
}

/// Run one attestation round: the owner issues one challenge (fixed nonce) and each
/// listed trustee answers with its share. Returns the challenge and answers so a
/// test can feed a chosen subset into the tracker.
fn round(
    owner: &SigningKey,
    nonce: [u8; 16],
    trustees: &[(SigningKey, Share)],
) -> (
    carapace_wire::ShareAttestChallenge,
    Vec<carapace_wire::ShareAttestation>,
) {
    let subject = owner.verifying_key().to_bytes();
    let rsid = u64::from(trustees[0].1.recovery_set_id);
    let challenge = build_attest_challenge(owner, subject, rsid, nonce);
    let atts = trustees
        .iter()
        .map(|(k, s)| answer_attest_challenge(k, &challenge, s).unwrap())
        .collect();
    (challenge, atts)
}

// All trustees attesting in the current round => invariant holds and the live count
// equals N.
#[test]
fn all_trustees_attesting_is_healthy_count_n() {
    let owner = trustee_key(3);
    let trustees = shares_with_trustees(3, 5);
    let mut tracker = AttestTracker::new(3, trustees.len(), roster_of(&trustees));

    let (challenge, atts) = round(&owner, [0x01; 16], &trustees);
    for att in &atts {
        tracker.record_attestation(att, &challenge, 0).unwrap();
    }

    assert_eq!(tracker.live_count(0), 5);
    assert!(tracker.is_healthy(0));
    assert_eq!(tracker.decide(0), ShareAction::Healthy);
}

// Trustees silent past the freshness window drop out of the live count; a fresh
// re-attestation from the rest keeps them live.
#[test]
fn silence_past_window_drops_live_count() {
    let owner = trustee_key(3);
    let trustees = shares_with_trustees(3, 5);
    let mut tracker = AttestTracker::new(3, trustees.len(), roster_of(&trustees));

    // Round 1 at t=0: everyone attests.
    let (c0, a0) = round(&owner, [0x01; 16], &trustees);
    for att in &a0 {
        tracker.record_attestation(att, &c0, 0).unwrap();
    }
    assert_eq!(tracker.live_count(0), 5);

    // Later, only the first three re-attest. The other two go silent.
    let later = DEFAULT_FRESHNESS_SECS + 1;
    let (c1, a1) = round(&owner, [0x02; 16], &trustees[..3]);
    for att in &a1 {
        tracker.record_attestation(att, &c1, later).unwrap();
    }

    // At `later`, the two silent trustees are past the window (last seen at t=0),
    // the three fresh ones remain live.
    assert_eq!(tracker.live_count(later), 3);
    // At exactly the window edge from t=0 the silent ones are still counted.
    assert_eq!(tracker.live_count(DEFAULT_FRESHNESS_SECS), 5);
}

// Live count crossing below `M + slack` with cap headroom => extend by the
// shortfall.
#[test]
fn drift_below_threshold_recommends_extend() {
    let owner = trustee_key(3);
    let trustees = shares_with_trustees(3, 5); // M=3, slack default 1 => target 4
    let mut tracker = AttestTracker::new(3, trustees.len(), roster_of(&trustees));

    // Only three trustees attest => live 3 < target 4.
    let (c, a) = round(&owner, [0x01; 16], &trustees[..3]);
    for att in &a {
        tracker.record_attestation(att, &c, 0).unwrap();
    }

    assert_eq!(tracker.live_count(0), 3);
    assert!(!tracker.is_healthy(0));
    // issued 5, need 1 more to reach 4 live-target => projected 6 <= soft_cap(3)=8.
    assert_eq!(tracker.decide(0), ShareAction::Extend { needed: 1 });
}

// Same drift, but lifetime issuance already sits at the cap => extending is blocked
// and the recommendation flips to re-split with a larger M (§8.3).
#[test]
fn cap_reached_recommends_resplit_not_extend() {
    let owner = trustee_key(3);
    let trustees = shares_with_trustees(3, 5);
    // M=3 => soft cap 3*3-1 = 8. Start already at the cap.
    let mut tracker = AttestTracker::new(3, carapace_share::soft_cap(3), roster_of(&trustees));
    assert_eq!(tracker.issued(), 8);

    let (c, a) = round(&owner, [0x01; 16], &trustees[..3]);
    for att in &a {
        tracker.record_attestation(att, &c, 0).unwrap();
    }

    assert!(!tracker.is_healthy(0));
    // needed 1 => projected 9 > cap 8 => must re-split, not extend.
    assert_eq!(tracker.decide(0), ShareAction::ResplitLargerM);
}

// W1: an attestation from a signer not on the enrolled roster does not count, and
// an enrolled trustee echoing a card_number that is not its own is rejected too - so
// an outsider or a cross-claim cannot pad the attested-live count.
#[test]
fn off_roster_and_wrong_card_attestations_are_not_counted() {
    use carapace_recovery::RecoveryError;
    use carapace_wire::{ShareAttestation, Signed};

    let owner = trustee_key(3);
    let trustees = shares_with_trustees(3, 5);
    let mut tracker = AttestTracker::new(3, trustees.len(), roster_of(&trustees));

    let (challenge, atts) = round(&owner, [0x01; 16], &trustees);

    // A stranger self-signs an attestation echoing this challenge's public fields
    // (the exact forgery W1 warns about - no share possession needed). It is a
    // valid signature over matching subject/rsid/nonce, but its signer is not on the
    // roster -> refused, so it cannot pad the live count.
    let stranger = trustee_key(200);
    let mut outsider = ShareAttestation {
        subject: challenge.subject,
        rsid: challenge.rsid,
        card_number: u64::from(trustees[0].1.x),
        nonce: challenge.nonce,
        by: [0; 32],
        sig: [0; 64],
    };
    outsider.sign(&stranger);
    assert!(matches!(
        tracker.record_attestation(&outsider, &challenge, 0),
        Err(RecoveryError::NotATrustee)
    ));

    // An enrolled trustee whose attestation claims a different card_number than the
    // one it was issued is refused (cannot claim a share it does not hold).
    let mut forged = atts[0].clone();
    forged.card_number = u64::from(trustees[1].1.x); // a co-trustee's share number
                                                     // Re-sign so the signature is valid but the card_number binding is wrong.
    forged.sign(&trustees[0].0);
    assert!(matches!(
        tracker.record_attestation(&forged, &challenge, 0),
        Err(RecoveryError::ChallengeMismatch)
    ));

    // Neither bad attestation was counted; the honest set is still what drives live.
    for att in &atts {
        tracker.record_attestation(att, &challenge, 0).unwrap();
    }
    assert_eq!(
        tracker.live_count(0),
        5,
        "only the 5 enrolled shares count live"
    );
}

// Trustee-side continuous CRC self-validation flags a corrupted share.
#[test]
fn self_validation_flags_corrupt_share() {
    let (mut shares, _s, _w) = split_root(&K_ROOT, 3, 5, false).unwrap();
    let mut share = shares.pop().unwrap();

    let mut monitor = ShareMonitor::with_interval(3600);
    assert_eq!(monitor.status(), ShareHealth::Unknown);

    // First poll at t=0 runs a check: a real share is Valid.
    assert_eq!(monitor.poll(&share, 0), ShareHealth::Valid);
    // Within the interval, poll is a no-op (still Valid) even if the share rots.
    assert!(!monitor.due(3599));
    assert_eq!(monitor.poll(&share, 3599), ShareHealth::Valid);

    // Corrupt a word; at the next due check the CRC fails.
    share.word_indices[2] ^= 1;
    assert!(monitor.due(3600));
    assert_eq!(monitor.poll(&share, 3600), ShareHealth::Corrupt);

    // check_now forces a check regardless of cadence.
    share.word_indices[2] ^= 1; // restore
    assert_eq!(monitor.check_now(&share, 3601), ShareHealth::Valid);
}
