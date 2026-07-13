//! `ShareGrant` (wire type 12) and the attestation cycle (protocol §8, §10.2). A grant wraps the
//! `chela.share` JSON carrier verbatim together with the co-trustee roster, recovery delay, and
//! latest announce refs a quorum needs to act. Attestation proves a stored share is still live
//! using label fields only - never the words.

use carapace_wire::{
    AnnounceRef, CoTrustee, ShareAttestChallenge, ShareAttestation, ShareGrant, Signed,
};
use chela_engine::Share;
use chela_share::BackupMeta;
use ed25519_dalek::SigningKey;

use crate::RecoveryError;

/// Build and sign a [`ShareGrant`] for `subject`. The share is serialized to its canonical
/// `chela.share` JSON carrier (SPEC §6.2) and stored verbatim; the roster, recovery delay, and
/// announce refs are what a quorum needs to run the ceremony when the owner is gone (§8).
///
/// `recovery_delay` is the owner's own abort window (§8.5, default 72 h). A very small value
/// collapses that window to "M approvals"; owners SHOULD keep a floor (see spec-errata E5). It is
/// accepted verbatim here because the spec makes it the owner's choice.
pub fn build_share_grant(
    signer: &SigningKey,
    subject: [u8; 32],
    share: &Share,
    recovery_delay: u64,
    cotrustees: Vec<CoTrustee>,
    refs: Vec<AnnounceRef>,
) -> ShareGrant {
    let share_json = chela_share::render_share_json(share, &BackupMeta::default());
    let mut grant = ShareGrant {
        subject,
        share_json,
        recovery_delay,
        cotrustees,
        refs,
        by: [0; 32],
        sig: [0; 64],
    };
    grant.sign(signer);
    grant
}

/// Verify a [`ShareGrant`]'s signature, then parse and self-validate its embedded share (the
/// words' CRC must pass - SPEC §4.6). Returns the decoded [`Share`], the authoritative object the
/// words carry. A grant that carries other than exactly one share is [`RecoveryError::ShareCount`].
pub fn verify_share_grant(grant: &ShareGrant) -> Result<Share, RecoveryError> {
    grant.verify()?;
    share_from_json(&grant.share_json)
}

/// Parse a single share from a `chela.share` JSON document, self-validating its words' CRC. The
/// carrier must hold exactly one share ([`RecoveryError::ShareCount`] otherwise).
pub fn share_from_json(share_json: &str) -> Result<Share, RecoveryError> {
    let mut shares = chela_share::extract_shares_from_json(share_json)?;
    if shares.len() != 1 {
        return Err(RecoveryError::ShareCount);
    }
    // `extract_shares_from_json` already ran the words through the Chela decoder (CRC check).
    Ok(shares.pop().expect("len == 1")?)
}

/// Self-validate a stored share with the Chela decoder: a single share validates alone via the
/// CRC over its words (SPEC §4.6). Trustee daemons run this periodically to catch bit-rot (§10.2).
pub fn self_validate_share(share: &Share) -> Result<(), RecoveryError> {
    chela_engine::decode_share_words(&share.word_indices)?;
    Ok(())
}

/// Build and sign a [`ShareAttestChallenge`] for a stored share (protocol §10.2).
pub fn build_attest_challenge(
    signer: &SigningKey,
    subject: [u8; 32],
    rsid: u64,
    nonce: [u8; 16],
) -> ShareAttestChallenge {
    let mut c = ShareAttestChallenge {
        subject,
        rsid,
        nonce,
        by: [0; 32],
        sig: [0; 64],
    };
    c.sign(signer);
    c
}

/// Answer a challenge with a signed [`ShareAttestation`] (protocol §10.2). The share is first
/// self-validated (a corrupt share is [`RecoveryError::Engine`]); the attestation echoes only the
/// label fields (`card_number` = the share's `x`) and the challenge nonce - never the words.
///
/// S6: the answered share MUST belong to the recovery set the challenge names
/// (`share.recovery_set_id == challenge.rsid`). Without this pin a trustee could
/// answer a new-set liveness challenge with a valid share from *any* set it holds,
/// so the attested-live count would not bind the actual new-set share (§10.2).
pub fn answer_attest_challenge(
    signer: &SigningKey,
    challenge: &ShareAttestChallenge,
    share: &Share,
) -> Result<ShareAttestation, RecoveryError> {
    challenge.verify()?;
    if u64::from(share.recovery_set_id) != challenge.rsid {
        return Err(RecoveryError::ChallengeMismatch);
    }
    self_validate_share(share)?;
    let mut att = ShareAttestation {
        subject: challenge.subject,
        rsid: challenge.rsid,
        card_number: u64::from(share.x),
        nonce: challenge.nonce,
        by: [0; 32],
        sig: [0; 64],
    };
    att.sign(signer);
    Ok(att)
}

/// Verify an attestation against the challenge it answers: the signature must be valid and the
/// echoed subject / rsid / nonce must match the challenge ([`RecoveryError::ChallengeMismatch`]).
pub fn verify_attestation(
    att: &ShareAttestation,
    challenge: &ShareAttestChallenge,
) -> Result<(), RecoveryError> {
    att.verify()?;
    if att.subject != challenge.subject || att.rsid != challenge.rsid || att.nonce != challenge.nonce
    {
        return Err(RecoveryError::ChallengeMismatch);
    }
    Ok(())
}

/// The §10.2 liveness invariant: `attested live shares ≥ M + slack`. Owners track the attested
/// count per set and extend / re-split before it drifts toward `M`.
#[must_use]
pub fn attestation_live(attested_live: usize, m: u8, slack: u8) -> bool {
    attested_live >= usize::from(m) + usize::from(slack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::split_root;
    use ed25519_dalek::SigningKey;

    const K_ROOT: [u8; 32] = [0x11u8; 32];

    fn trustee_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn a_share() -> Share {
        let (shares, _s, _w) = split_root(&K_ROOT, 3, 5, false).unwrap();
        shares.into_iter().next().unwrap()
    }

    #[test]
    fn grant_round_trips_and_verifies() {
        let signer = trustee_key(7);
        let subject = trustee_key(9).verifying_key().to_bytes();
        let share = a_share();
        let cotrustees = vec![CoTrustee {
            user: [0xAA; 32],
            node: [0xBB; 32],
            relay_url: Some("relay.example".into()),
        }];
        let refs = vec![AnnounceRef {
            vid: [0xC0; 32],
            epoch: 4,
            digest: [0xDD; 32],
        }];
        let grant = build_share_grant(&signer, subject, &share, 72 * 3600, cotrustees, refs);

        // Signature verifies and the embedded share decodes back to the original.
        let decoded = verify_share_grant(&grant).unwrap();
        assert_eq!(decoded.x, share.x);
        assert_eq!(decoded.recovery_set_id, share.recovery_set_id);
        assert_eq!(decoded.threshold, share.threshold);
        assert_eq!(decoded.word_indices, share.word_indices);
        assert_eq!(grant.recovery_delay, 72 * 3600);
    }

    #[test]
    fn tampered_grant_signature_rejected() {
        let signer = trustee_key(7);
        let share = a_share();
        let mut grant = build_share_grant(&signer, [1; 32], &share, 100, vec![], vec![]);
        grant.recovery_delay = 999; // change signed content without re-signing
        assert!(matches!(
            verify_share_grant(&grant),
            Err(RecoveryError::Wire(carapace_wire::Error::Signature))
        ));
    }

    #[test]
    fn self_validate_accepts_real_share_rejects_corrupt() {
        let mut share = a_share();
        self_validate_share(&share).unwrap();
        share.word_indices[2] ^= 1; // flip one word -> CRC fails
        assert!(self_validate_share(&share).is_err());
    }

    #[test]
    fn attestation_cycle() {
        let trustee = trustee_key(7);
        let owner = trustee_key(3);
        let subject = owner.verifying_key().to_bytes();
        let share = a_share();
        let rsid = u64::from(share.recovery_set_id);

        let challenge = build_attest_challenge(&owner, subject, rsid, [0x5A; 16]);
        let att = answer_attest_challenge(&trustee, &challenge, &share).unwrap();
        // Label fields only: card_number is the share x, nonce echoes the challenge.
        assert_eq!(att.card_number, u64::from(share.x));
        assert_eq!(att.nonce, challenge.nonce);
        verify_attestation(&att, &challenge).unwrap();
    }

    #[test]
    fn attestation_wrong_nonce_rejected() {
        let trustee = trustee_key(7);
        let owner = trustee_key(3);
        let share = a_share();
        let rsid = u64::from(share.recovery_set_id);
        let challenge = build_attest_challenge(&owner, [4; 32], rsid, [0x11; 16]);
        let mut att = answer_attest_challenge(&trustee, &challenge, &share).unwrap();
        att.nonce = [0x22; 16];
        att.sign(&trustee); // re-sign so the signature is valid but the echo is wrong
        assert!(matches!(
            verify_attestation(&att, &challenge),
            Err(RecoveryError::ChallengeMismatch)
        ));
    }

    #[test]
    fn attestation_of_corrupt_share_refused() {
        let trustee = trustee_key(7);
        let owner = trustee_key(3);
        let mut share = a_share();
        let rsid = u64::from(share.recovery_set_id);
        share.word_indices[2] ^= 1;
        let challenge = build_attest_challenge(&owner, [4; 32], rsid, [0x11; 16]);
        assert!(answer_attest_challenge(&trustee, &challenge, &share).is_err());
    }

    // S6: a share that belongs to a *different* recovery set cannot answer a
    // challenge naming this set - liveness must bind the actual set's share.
    #[test]
    fn attestation_of_share_from_other_set_refused() {
        let trustee = trustee_key(7);
        let owner = trustee_key(3);
        let share = a_share();
        let real = u64::from(share.recovery_set_id);
        // Challenge some other set id the trustee's share is not part of.
        let challenge = build_attest_challenge(&owner, [4; 32], real ^ 1, [0x11; 16]);
        assert!(matches!(
            answer_attest_challenge(&trustee, &challenge, &share),
            Err(RecoveryError::ChallengeMismatch)
        ));
    }

    #[test]
    fn liveness_invariant() {
        assert!(attestation_live(5, 3, 2));
        assert!(!attestation_live(4, 3, 2));
    }
}
