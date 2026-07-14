//! Re-split on unfriend (protocol §9.3 step 3, §10.2). When an unfriended party
//! was a trustee their share cannot be revoked and **extension cannot remove it**;
//! only a full re-split neutralizes it, and only indirectly. This module drives
//! the completion sequence and refuses to skip a step:
//!
//! - **(a)** stand up a NEW recovery set (fresh `recovery_set_id`) via
//!   [`carapace_recovery::split_root`] and hand each new trustee a
//!   [`carapace_wire::ShareGrant`];
//! - **(b)** collect attestations until the new set is live (`>= M + slack`,
//!   the §10.2 invariant);
//! - **(c)** ONLY THEN instruct the remaining honest old-set trustees to destroy
//!   their shares (`ShareDestroy` -> signed `ShareDestroyAck`).
//!
//! The ex-friend's retained old share is stranded because the honest holders
//! destroyed theirs: the old set can no longer reach `M` anywhere. During (a)-(c)
//! both sets briefly coexist - two doors, each still requiring its own full quorum
//! - and [`Resplit::progress`] reports where the sequence stands.

use carapace_recovery::{
    attestation_live, build_share_grant, verify_attestation, Share, SplitState,
};
use carapace_wire::{
    ShareAttestChallenge, ShareAttestation, ShareDestroy, ShareDestroyAck, ShareGrant, Signed,
};
use ed25519_dalek::SigningKey;

use crate::FriendError;

/// Where the re-split completion sequence stands (§9.3 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResplitPhase {
    /// (a)+(b): grants delivered, still collecting attestations. Old shares MUST
    /// NOT be destroyed yet.
    AwaitingNewSet,
    /// The new set is live (`>= M + slack` attested); (c) may proceed - old-set
    /// trustees can be told to destroy.
    ReadyToDestroy,
    /// Every remaining honest old-set trustee has destroy-acked. The old door is
    /// closed; the ex-friend's share is stranded below `M`.
    Complete,
}

/// A snapshot of re-split progress for display (§9.3 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResplitProgress {
    /// Current phase.
    pub phase: ResplitPhase,
    /// New-set trustees total.
    pub new_total: usize,
    /// New-set trustees that have attested a live share.
    pub new_attested: usize,
    /// Old-set honest trustees total (the ones asked to destroy).
    pub old_total: usize,
    /// Old-set trustees that have destroy-acked.
    pub old_destroyed: usize,
    /// Whether the new set has reached `>= M + slack` attestations.
    pub new_live: bool,
}

struct NewTrustee {
    user: [u8; 32],
    /// The card number (`share.x`) of the new-set share this trustee was granted.
    /// An attestation must echo exactly this, so a trustee cannot count toward
    /// liveness with some other new-set share (S6).
    card_number: u64,
    attested: bool,
}

struct OldTrustee {
    user: [u8; 32],
    destroyed: bool,
}

/// The re-split completion state machine (§9.3 step 3). Build one with
/// [`Resplit::begin`], feed it attestations and destroy-acks, and it gates the
/// destroy step until the new set is live.
pub struct Resplit {
    subject: [u8; 32],
    m: u8,
    slack: u8,
    new_rsid: u64,
    old_rsid: u64,
    new_set: Vec<NewTrustee>,
    old_set: Vec<OldTrustee>,
    phase: ResplitPhase,
}

impl Resplit {
    /// Start a re-split (§9.3 step 3a): generate a fresh split of `k_root`
    /// (`m`-of-`n`, new `recovery_set_id`) and a signed [`ShareGrant`] for each new
    /// trustee. `old_remaining` is the set of honest old-set trustees still holding
    /// a share (the ex-friend is deliberately excluded - they will never destroy).
    ///
    /// Returns the machine, the fresh shares (to deliver, one per new trustee, in
    /// order), the grants, and the open [`SplitState`] of the fresh split (so the owner
    /// can register the new set as the active one for extend/bookkeeping once the
    /// re-split completes, §9.3 step 4). `new_trustees` and the produced shares are
    /// paired by index, so their counts must match `n`.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        owner_signer: &SigningKey,
        k_root: &[u8; 32],
        subject: [u8; 32],
        m: u8,
        n: u8,
        slack: u8,
        allow_over_cap: bool,
        old_rsid: u64,
        old_remaining: Vec<[u8; 32]>,
        new_trustees: Vec<[u8; 32]>,
        recovery_delay: u64,
    ) -> Result<(Self, Vec<Share>, Vec<ShareGrant>, SplitState), FriendError> {
        if new_trustees.len() != usize::from(n) {
            return Err(FriendError::WrongSet);
        }
        let (shares, state, _warnings) =
            carapace_recovery::split_root(k_root, m, Some(n), allow_over_cap)?;
        // Every share of one split shares the polynomial's recovery_set_id.
        let new_rsid = u64::from(shares[0].recovery_set_id);

        let grants = new_trustees
            .iter()
            .zip(shares.iter())
            .map(|(_t, s)| {
                build_share_grant(owner_signer, subject, s, recovery_delay, vec![], vec![])
            })
            .collect();

        // Pair each new trustee with the card number of the share it was granted,
        // so its later attestation must echo that exact share (S6).
        let new_set = new_trustees
            .into_iter()
            .zip(shares.iter())
            .map(|(user, s)| NewTrustee {
                user,
                card_number: u64::from(s.x),
                attested: false,
            })
            .collect();

        let machine = Self {
            subject,
            m,
            slack,
            new_rsid,
            old_rsid,
            new_set,
            old_set: old_remaining
                .into_iter()
                .map(|user| OldTrustee {
                    user,
                    destroyed: false,
                })
                .collect(),
            phase: ResplitPhase::AwaitingNewSet,
        };
        Ok((machine, shares, grants, state))
    }

    /// Record a new-set trustee's [`ShareAttestation`] (§9.3 step 3b). Verifies the
    /// attestation against its challenge, checks it is for this subject + new set,
    /// and marks the trustee live. When `>= M + slack` trustees have attested the
    /// phase advances to [`ResplitPhase::ReadyToDestroy`].
    pub fn record_attestation(
        &mut self,
        att: &ShareAttestation,
        challenge: &ShareAttestChallenge,
    ) -> Result<(), FriendError> {
        verify_attestation(att, challenge)?;
        if att.subject != self.subject || att.rsid != self.new_rsid {
            return Err(FriendError::WrongSet);
        }
        let t = self
            .new_set
            .iter_mut()
            .find(|t| t.user == att.by)
            .ok_or(FriendError::UnknownTrustee)?;
        // S6: the attestation must name the exact new-set share this trustee was
        // granted, not just any share of the set.
        if att.card_number != t.card_number {
            return Err(FriendError::WrongSet);
        }
        t.attested = true;
        if self.phase == ResplitPhase::AwaitingNewSet && self.new_set_live() {
            self.phase = ResplitPhase::ReadyToDestroy;
        }
        Ok(())
    }

    /// Whether the new set has reached the §10.2 liveness invariant
    /// (`attested >= M + slack`).
    #[must_use]
    pub fn new_set_live(&self) -> bool {
        let attested = self.new_set.iter().filter(|t| t.attested).count();
        attestation_live(attested, self.m, self.slack)
    }

    /// Build the signed [`ShareDestroy`] instruction for the OLD set (§9.3 step 3c).
    /// **Refuses with [`FriendError::NewSetNotLive`] until the new set is live** -
    /// this is the completion-sequence guard: the old shares are only destroyed
    /// once the new door is provably open. Deliver it to each still-pending old
    /// trustee (see [`Resplit::pending_old`]).
    pub fn share_destroy(&self, owner_signer: &SigningKey) -> Result<ShareDestroy, FriendError> {
        if self.phase == ResplitPhase::AwaitingNewSet {
            return Err(FriendError::NewSetNotLive);
        }
        let mut d = ShareDestroy {
            subject: self.subject,
            rsid: self.old_rsid,
            by: [0; 32],
            sig: [0; 64],
        };
        d.sign(owner_signer);
        Ok(d)
    }

    /// Record an old-set trustee's signed [`ShareDestroyAck`] (§9.3 step 3c). Only
    /// valid once destruction has been authorized (phase past `AwaitingNewSet`).
    /// When every remaining old trustee has acked the phase advances to
    /// [`ResplitPhase::Complete`].
    pub fn record_destroy_ack(&mut self, ack: &ShareDestroyAck) -> Result<(), FriendError> {
        if self.phase == ResplitPhase::AwaitingNewSet {
            return Err(FriendError::NewSetNotLive);
        }
        ack.verify()?;
        if ack.subject != self.subject || ack.rsid != self.old_rsid {
            return Err(FriendError::WrongSet);
        }
        let t = self
            .old_set
            .iter_mut()
            .find(|t| t.user == ack.by)
            .ok_or(FriendError::UnknownTrustee)?;
        t.destroyed = true;
        if self.old_set.iter().all(|t| t.destroyed) {
            self.phase = ResplitPhase::Complete;
        }
        Ok(())
    }

    /// The current phase.
    #[must_use]
    pub fn phase(&self) -> ResplitPhase {
        self.phase
    }

    /// The new set's `recovery_set_id`.
    #[must_use]
    pub fn new_rsid(&self) -> u64 {
        self.new_rsid
    }

    /// New-set trustees that have not yet attested a live share.
    pub fn pending_new(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.new_set.iter().filter(|t| !t.attested).map(|t| &t.user)
    }

    /// Old-set trustees that have not yet destroy-acked (destroy still queued).
    pub fn pending_old(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.old_set
            .iter()
            .filter(|t| !t.destroyed)
            .map(|t| &t.user)
    }

    /// A snapshot for display (§9.3 step 4).
    #[must_use]
    pub fn progress(&self) -> ResplitProgress {
        ResplitProgress {
            phase: self.phase,
            new_total: self.new_set.len(),
            new_attested: self.new_set.iter().filter(|t| t.attested).count(),
            old_total: self.old_set.len(),
            old_destroyed: self.old_set.iter().filter(|t| t.destroyed).count(),
            new_live: self.new_set_live(),
        }
    }
}

/// Build a signed [`ShareDestroyAck`] (a trustee's reply to a [`ShareDestroy`],
/// §9.3 step 3c). Bookkeeping: it records the honest holder destroyed its share.
pub fn build_share_destroy_ack(
    node_key: &SigningKey,
    subject: [u8; 32],
    rsid: u64,
    ts: u64,
) -> ShareDestroyAck {
    let mut ack = ShareDestroyAck {
        subject,
        rsid,
        ts,
        by: [0; 32],
        sig: [0; 64],
    };
    ack.sign(node_key);
    ack
}

#[cfg(test)]
mod tests {
    use super::*;
    use carapace_recovery::{
        answer_attest_challenge, build_attest_challenge, recover_key_from_shares,
        verify_share_grant,
    };
    use ed25519_dalek::SigningKey;

    const K_ROOT: [u8; 32] = [0x11u8; 32];
    const M: u8 = 3;
    const N: u8 = 5;
    const SLACK: u8 = 1;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn pk(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    #[test]
    fn resplit_strands_old_set_and_stands_up_new_set() {
        let owner = key(3); // owner node key: signs grants, challenges, destroys
        let subject = pk(&key(5)); // the owner user being re-split

        // --- OLD recovery set: a real 3-of-5 split already out in the world. ---
        let (old_shares, _s, _w) =
            carapace_recovery::split_root(&K_ROOT, M, Some(N), false).unwrap();
        let old_rsid = u64::from(old_shares[0].recovery_set_id);
        // Ex-friend (unfriended trustee) keeps share 0 forever; four honest
        // trustees hold shares 1..5.
        let ex_friend_share = old_shares[0].clone();
        let old_honest: Vec<SigningKey> = (0..4).map(|i| key(10 + i)).collect();

        // --- (a) begin the re-split: fresh split + grants to a NEW trustee set. ---
        let new_trustee_keys: Vec<SigningKey> = (0..N).map(|i| key(20 + i)).collect();
        let new_trustees: Vec<[u8; 32]> = new_trustee_keys.iter().map(pk).collect();
        let old_remaining: Vec<[u8; 32]> = old_honest.iter().map(pk).collect();

        let (mut rs, new_shares, grants, _state) = Resplit::begin(
            &owner,
            &K_ROOT,
            subject,
            M,
            N,
            SLACK,
            false,
            old_rsid,
            old_remaining,
            new_trustees,
            72 * 3600,
        )
        .unwrap();
        assert_eq!(grants.len(), usize::from(N));
        assert_eq!(rs.phase(), ResplitPhase::AwaitingNewSet);
        // Each grant verifies and carries a real share the trustee can hold.
        for g in &grants {
            verify_share_grant(g).unwrap();
        }

        // GUARD: destroying old shares before the new set is live is refused.
        assert!(matches!(
            rs.share_destroy(&owner),
            Err(FriendError::NewSetNotLive)
        ));

        // --- (b) collect attestations until the new set is live (>= M+slack=4). ---
        for (i, tk) in new_trustee_keys.iter().enumerate() {
            let nonce = [i as u8; 16];
            let challenge = build_attest_challenge(&owner, subject, rs.new_rsid(), nonce);
            let att = answer_attest_challenge(tk, &challenge, &new_shares[i]).unwrap();
            rs.record_attestation(&att, &challenge).unwrap();
            let want_live = i + 1 >= usize::from(M + SLACK);
            assert_eq!(rs.new_set_live(), want_live);
        }
        assert_eq!(rs.phase(), ResplitPhase::ReadyToDestroy);

        // --- (c) now the old honest trustees are told to destroy, and ack. ---
        let destroy = rs.share_destroy(&owner).unwrap();
        destroy.verify().unwrap();
        assert_eq!(destroy.rsid, old_rsid);
        for tk in &old_honest {
            let ack = build_share_destroy_ack(tk, subject, old_rsid, 1_700_000_000);
            rs.record_destroy_ack(&ack).unwrap();
        }
        assert_eq!(rs.phase(), ResplitPhase::Complete);
        assert_eq!(rs.pending_old().count(), 0);

        // --- The point of the whole dance -------------------------------------
        // OLD set is provably below M: the only surviving old share is the
        // ex-friend's one, and one share of a 3-of-5 cannot recover anything.
        assert!(recover_key_from_shares(&[ex_friend_share]).is_err());
        // NEW set CAN recover K_root from any M of its fresh shares.
        let recovered = recover_key_from_shares(&new_shares[0..usize::from(M)]).unwrap();
        assert_eq!(recovered.as_slice(), &K_ROOT);
    }

    #[test]
    fn wrong_trustee_count_rejected() {
        let owner = key(3);
        let subject = pk(&key(5));
        let res = Resplit::begin(
            &owner,
            &K_ROOT,
            subject,
            M,
            N,
            SLACK,
            false,
            1,
            vec![],
            vec![[1; 32], [2; 32]], // only 2, not N=5
            100,
        );
        assert!(matches!(res, Err(FriendError::WrongSet)));
    }

    #[test]
    fn attestation_from_stranger_rejected() {
        let owner = key(3);
        let subject = pk(&key(5));
        let new_trustee_keys: Vec<SigningKey> = (0..N).map(|i| key(20 + i)).collect();
        let new_trustees: Vec<[u8; 32]> = new_trustee_keys.iter().map(pk).collect();
        let (mut rs, new_shares, _g, _state) = Resplit::begin(
            &owner,
            &K_ROOT,
            subject,
            M,
            N,
            SLACK,
            false,
            1,
            vec![],
            new_trustees,
            100,
        )
        .unwrap();

        // A stranger (not in the new set) answers a valid challenge with a real
        // share: the signature and echo verify, but they are not a set member.
        let stranger = key(99);
        let challenge = build_attest_challenge(&owner, subject, rs.new_rsid(), [0; 16]);
        let att = answer_attest_challenge(&stranger, &challenge, &new_shares[0]).unwrap();
        assert!(matches!(
            rs.record_attestation(&att, &challenge),
            Err(FriendError::UnknownTrustee)
        ));
    }

    // S6: a new-set trustee that answers with a *different* new-set share (wrong
    // card number) does not count toward liveness, even though the share is a
    // genuine member of the set and the rsid matches.
    #[test]
    fn attestation_with_wrong_card_number_rejected() {
        let owner = key(3);
        let subject = pk(&key(5));
        let new_trustee_keys: Vec<SigningKey> = (0..N).map(|i| key(20 + i)).collect();
        let new_trustees: Vec<[u8; 32]> = new_trustee_keys.iter().map(pk).collect();
        let (mut rs, new_shares, _g, _state) = Resplit::begin(
            &owner,
            &K_ROOT,
            subject,
            M,
            N,
            SLACK,
            false,
            1,
            vec![],
            new_trustees,
            100,
        )
        .unwrap();

        // Trustee 0 answers with trustee 1's share: same set, valid signature and
        // echo, but the card number does not match trustee 0's granted share.
        let challenge = build_attest_challenge(&owner, subject, rs.new_rsid(), [0; 16]);
        let att =
            answer_attest_challenge(&new_trustee_keys[0], &challenge, &new_shares[1]).unwrap();
        assert!(matches!(
            rs.record_attestation(&att, &challenge),
            Err(FriendError::WrongSet)
        ));
    }

    #[test]
    fn destroy_ack_before_live_rejected() {
        let owner = key(3);
        let subject = pk(&key(5));
        let honest = key(10);
        let new_trustee_keys: Vec<SigningKey> = (0..N).map(|i| key(20 + i)).collect();
        let new_trustees: Vec<[u8; 32]> = new_trustee_keys.iter().map(pk).collect();
        let (mut rs, _shares, _g, _state) = Resplit::begin(
            &owner,
            &K_ROOT,
            subject,
            M,
            N,
            SLACK,
            false,
            7,
            vec![pk(&honest)],
            new_trustees,
            100,
        )
        .unwrap();
        // No attestations yet -> destruction is not authorized.
        let ack = build_share_destroy_ack(&honest, subject, 7, 1);
        assert!(matches!(
            rs.record_destroy_ack(&ack),
            Err(FriendError::NewSetNotLive)
        ));
    }
}
