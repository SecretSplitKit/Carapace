//! Split orchestration (protocol §8.1-§8.3, §10.2). Split `K_root` (inner circle) and scoped
//! vault keys; extend to add a trustee or replace a lost share; enforce the issuance cap; and
//! round-trip-verify a fresh split before trusting it.

use zeroize::Zeroizing;

use chela_engine::{
    extend, recover_secret, split_extendable, OutputMode, RecoveredSecret, Share, SplitInput,
    SplitState,
};

use crate::state_seal::{open_split_state, seal_split_state, SealedSplitState};
use crate::{key_to_mnemonic, mnemonic_to_key, RecoveryError};

/// The soft cap on lifetime issuance for a threshold: `3·M − 1` shares (protocol §8.3). Beyond
/// it a recovering coalition would need at most ⅓ of outstanding shares.
#[must_use]
pub fn soft_cap(m: u8) -> usize {
    // S3: saturating so a bogus m=0 (thresholds are >= 2 in practice) yields 0
    // rather than underflowing/panicking; `3*M - 1` for every real threshold.
    usize::from(m).saturating_mul(3).saturating_sub(1)
}

/// A non-fatal issuance-policy note (protocol §8.3). Advisory: surfaced to the owner, never a
/// silent block. The hard cap is an [`RecoveryError::OverSoftCap`] unless overridden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyWarning {
    /// `N₀ = M`: zero slack. One lost share ends recoverability before it is noticed (§8.3).
    ZeroSlack,
    /// Lifetime issuance passed the `3·M − 1` soft cap; `allow_over_cap` was set (§8.3).
    OverSoftCap,
}

/// Check an issuance of `n` shares at threshold `m` against the §8.3 rules. Returns advisory
/// warnings, or [`RecoveryError::InvalidThreshold`] / [`RecoveryError::OverSoftCap`] when the
/// issuance is disallowed. `already_issued` is the count already on the polynomial (0 for an
/// initial split), so extension is checked on projected lifetime issuance.
pub fn check_initial_issuance(
    m: u8,
    n: u8,
    allow_over_cap: bool,
) -> Result<Vec<PolicyWarning>, RecoveryError> {
    check_issuance(m, 0, n, allow_over_cap)
}

/// Shared cap check for both initial split and extension. `projected = already_issued + count`.
fn check_issuance(
    m: u8,
    already_issued: usize,
    count: u8,
    allow_over_cap: bool,
) -> Result<Vec<PolicyWarning>, RecoveryError> {
    if !(2..=32).contains(&m) {
        return Err(RecoveryError::InvalidThreshold);
    }
    let projected = already_issued + usize::from(count);
    if projected > 32 || projected < usize::from(m) {
        return Err(RecoveryError::InvalidThreshold);
    }

    let mut warnings = Vec::new();
    // Zero-slack only applies to the initial issuance (`N₀ = M`).
    if already_issued == 0 && count == m {
        warnings.push(PolicyWarning::ZeroSlack);
    }
    if projected > soft_cap(m) {
        if !allow_over_cap {
            return Err(RecoveryError::OverSoftCap);
        }
        warnings.push(PolicyWarning::OverSoftCap);
    }
    Ok(warnings)
}

/// Split a 32-byte key into `n` shares with threshold `m`, returning the shares, the retained
/// (secret-equivalent) split-state, and any policy warnings. The split is round-trip-verified
/// against `key` before returning (§10.2); a verification failure is [`RecoveryError::RoundTripFailed`].
fn split_key(
    key: &[u8; 32],
    m: u8,
    n: u8,
    allow_over_cap: bool,
) -> Result<(Vec<Share>, SplitState, Vec<PolicyWarning>), RecoveryError> {
    let warnings = check_initial_issuance(m, n, allow_over_cap)?;
    let mnemonic = key_to_mnemonic(key)?;
    let input = SplitInput::Bip39 {
        mnemonic: &mnemonic,
        passphrase: "",
    };
    let (shares, state) = split_extendable(&input, m, n, OutputMode::Bip39Wordlist)?;
    verify_split_roundtrip(&shares, key)?;
    Ok((shares, state, warnings))
}

/// Split `K_root` for the inner circle (protocol §8.1/§8.2). Every split of `K_root` is a full
/// door to the identity, so this SHOULD be done exactly once.
pub fn split_root(
    k_root: &[u8; 32],
    m: u8,
    n: u8,
    allow_over_cap: bool,
) -> Result<(Vec<Share>, SplitState, Vec<PolicyWarning>), RecoveryError> {
    split_key(k_root, m, n, allow_over_cap)
}

/// Split `K_vaultroot(vid)` for an additional / outer-circle trustee set (scoped split, §8.2). A
/// quorum recovers *that vault only*, never the identity. The state is still sealed under
/// `K_root` (see [`seal_split_state`]); only the split *secret* is the vault key.
pub fn split_vault(
    k_root: &[u8; 32],
    vid: &[u8; 32],
    m: u8,
    n: u8,
    allow_over_cap: bool,
) -> Result<(Vec<Share>, SplitState, Vec<PolicyWarning>), RecoveryError> {
    let k_vaultroot = carapace_crypto::kdf::k_vaultroot(k_root, vid);
    split_key(&k_vaultroot, m, n, allow_over_cap)
}

/// Recover the split secret from at least `M` shares and decode it back to its 32-byte key.
/// Chela guarantees recovery never silently yields a wrong secret (integrity tag + CRC).
pub fn recover_key_from_shares(shares: &[Share]) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    let recovered = recover_secret(shares)?;
    match &recovered {
        RecoveredSecret::Bip39 { mnemonic, .. } => mnemonic_to_key(mnemonic),
        // A Carapace key split is always the 24-word kind; a text payload means wrong shares.
        RecoveredSecret::Text { .. } => Err(RecoveryError::RoundTripFailed),
    }
}

/// Owner-side verification (protocol §10.2): recover from a sample of `M`-subsets and confirm each
/// reproduces `key`. Covers every share via sliding windows of `M` consecutive shares, so any
/// single bad share is caught. Returns [`RecoveryError::RoundTripFailed`] on any mismatch.
pub fn verify_split_roundtrip(shares: &[Share], key: &[u8; 32]) -> Result<(), RecoveryError> {
    if shares.is_empty() {
        return Err(RecoveryError::RoundTripFailed);
    }
    let m = usize::from(shares[0].threshold);
    if shares.len() < m {
        return Err(RecoveryError::RoundTripFailed);
    }
    for window in shares.windows(m) {
        let recovered = recover_key_from_shares(window)?;
        if recovered.as_slice() != key.as_slice() {
            return Err(RecoveryError::RoundTripFailed);
        }
    }
    Ok(())
}

/// Issue `count` further shares on an open split-state at fresh unused x-coordinates (§8.1).
/// `secret_key` is the same 32-byte key the split was made from - Chela recomputes the body and
/// rejects a wrong secret/state pairing. The §8.3 cap is enforced here in addition to Chela's own
/// (Chela's soft cap is projected issuance; this surfaces the friendly [`RecoveryError::OverSoftCap`]).
pub fn extend_split(
    state: &mut SplitState,
    secret_key: &[u8; 32],
    count: u8,
    allow_over_cap: bool,
) -> Result<Vec<Share>, RecoveryError> {
    check_issuance(
        state.threshold(),
        state.issued_count(),
        count,
        allow_over_cap,
    )?;
    let mnemonic = key_to_mnemonic(secret_key)?;
    let input = SplitInput::Bip39 {
        mnemonic: &mnemonic,
        passphrase: "",
    };
    Ok(extend(
        state,
        &input,
        count,
        allow_over_cap,
        OutputMode::Bip39Wordlist,
    )?)
}

/// Add a trustee (protocol §8.1): unseal the split-state, issue one new share at a fresh unused
/// x-coordinate on the same polynomial, and re-seal. Existing shareholders are untouched. Returns
/// the new share and the re-sealed state (the old sealed blob should be replaced with it).
///
/// # Concurrency
///
/// This is a read-modify-write on the sealed blob (open -> extend -> reseal) and is NOT safe to run
/// concurrently against the same recovery set. Two overlapping runs each draw a fresh x against the
/// same `issued_count`, and last-writer-wins on the re-sealed blob drops one run's issuance record;
/// no key leaks (a re-issued coordinate on the same polynomial is a byte-identical share), but the
/// §8.3 soft-cap accounting drifts. Callers MUST serialize seal->open->extend->reseal per set.
pub fn add_trustee(
    k_root: &[u8; 32],
    secret_key: &[u8; 32],
    sealed: &SealedSplitState,
    allow_over_cap: bool,
) -> Result<(Share, SealedSplitState), RecoveryError> {
    let mut state = open_split_state(k_root, sealed)?;
    let mut shares = extend_split(&mut state, secret_key, 1, allow_over_cap)?;
    let resealed = seal_split_state(k_root, &state)?;
    // `count = 1` always yields exactly one share.
    let share = shares.pop().ok_or(RecoveryError::ShareCount)?;
    Ok((share, resealed))
}

/// Replace a lost share (protocol §8.1). Identical operation to [`add_trustee`]: the lost share
/// stays *valid-if-found* and remains in the issued-count, so this is a new share, not a revocation.
pub fn replace_lost_share(
    k_root: &[u8; 32],
    secret_key: &[u8; 32],
    sealed: &SealedSplitState,
    allow_over_cap: bool,
) -> Result<(Share, SealedSplitState), RecoveryError> {
    add_trustee(k_root, secret_key, sealed, allow_over_cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K_ROOT: [u8; 32] = [0x11u8; 32];

    #[test]
    fn split_root_recovers_from_m_shares() {
        let (shares, _state, warnings) = split_root(&K_ROOT, 3, 5, false).unwrap();
        assert_eq!(shares.len(), 5);
        assert!(warnings.is_empty());
        // Any 3 shares reproduce K_root.
        let subset = [shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_key_from_shares(&subset).unwrap();
        assert_eq!(recovered.as_slice(), &K_ROOT);
    }

    #[test]
    fn sub_m_shares_do_not_recover() {
        let (shares, _state, _w) = split_root(&K_ROOT, 3, 5, false).unwrap();
        let subset = [shares[0].clone(), shares[1].clone()];
        // Two of a 3-of-5 is below threshold: recovery must error, never yield a key.
        assert!(recover_key_from_shares(&subset).is_err());
    }

    #[test]
    fn split_vault_scopes_to_vault_key_not_root() {
        let vid = [0xC0u8; 32];
        let (shares, _state, _w) = split_vault(&K_ROOT, &vid, 2, 3, false).unwrap();
        let recovered = recover_key_from_shares(&[shares[0].clone(), shares[1].clone()]).unwrap();
        let expected = carapace_crypto::kdf::k_vaultroot(&K_ROOT, &vid);
        assert_eq!(recovered.as_slice(), &*expected);
        // The vault key is NOT K_root.
        assert_ne!(recovered.as_slice(), &K_ROOT);
    }

    #[test]
    fn add_trustee_then_recover_from_mixed_set() {
        let (mut shares, state, _w) = split_root(&K_ROOT, 3, 5, false).unwrap();
        let sealed = seal_split_state(&K_ROOT, &state).unwrap();
        let (new_share, _resealed) = add_trustee(&K_ROOT, &K_ROOT, &sealed, false).unwrap();
        // New share is on the same polynomial (same rsid + M) at a fresh x.
        assert_eq!(new_share.recovery_set_id, shares[0].recovery_set_id);
        assert_eq!(new_share.threshold, shares[0].threshold);
        assert!(shares.iter().all(|s| s.x != new_share.x));

        // Recover from a mix of two originals plus the new share.
        let mixed = [shares[0].clone(), shares[3].clone(), new_share.clone()];
        let recovered = recover_key_from_shares(&mixed).unwrap();
        assert_eq!(recovered.as_slice(), &K_ROOT);
        shares.push(new_share);
    }

    #[test]
    fn extend_rejects_wrong_secret() {
        let (_shares, mut state, _w) = split_root(&K_ROOT, 3, 5, false).unwrap();
        // Extending with the wrong key must be a clean WrongSecret, not incompatible shares.
        let err = extend_split(&mut state, &[0x22u8; 32], 1, false).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::Extend(chela_engine::ExtendError::WrongSecret)
        ));
    }

    #[test]
    fn zero_slack_warns_but_succeeds() {
        // N0 = M is allowed but flagged.
        let (_shares, _state, warnings) = split_root(&K_ROOT, 3, 3, false).unwrap();
        assert_eq!(warnings, vec![PolicyWarning::ZeroSlack]);
    }

    #[test]
    fn over_soft_cap_blocks_without_override() {
        // M=2 -> cap 5. N=6 exceeds it.
        assert!(matches!(
            split_root(&K_ROOT, 2, 6, false),
            Err(RecoveryError::OverSoftCap)
        ));
        // With override it succeeds and reports the warning.
        let (shares, _state, warnings) = split_root(&K_ROOT, 2, 6, true).unwrap();
        assert_eq!(shares.len(), 6);
        assert!(warnings.contains(&PolicyWarning::OverSoftCap));
    }

    #[test]
    fn extend_over_cap_needs_override() {
        // M=2, N0=5 (= cap). One more extension projects to 6 > cap.
        let (_shares, state, _w) = split_root(&K_ROOT, 2, 5, false).unwrap();
        let sealed = seal_split_state(&K_ROOT, &state).unwrap();
        assert!(matches!(
            add_trustee(&K_ROOT, &K_ROOT, &sealed, false),
            Err(RecoveryError::OverSoftCap)
        ));
        // Override proceeds.
        let (_new, _resealed) = add_trustee(&K_ROOT, &K_ROOT, &sealed, true).unwrap();
    }

    #[test]
    fn invalid_thresholds_rejected() {
        assert!(matches!(
            split_root(&K_ROOT, 1, 3, false),
            Err(RecoveryError::InvalidThreshold)
        ));
        assert!(matches!(
            split_root(&K_ROOT, 4, 3, false),
            Err(RecoveryError::InvalidThreshold)
        ));
    }

    #[test]
    fn every_m_subset_round_trips_after_extension() {
        let (shares, state, _w) = split_root(&K_ROOT, 3, 5, false).unwrap();
        let sealed = seal_split_state(&K_ROOT, &state).unwrap();
        let (new_share, _r) = add_trustee(&K_ROOT, &K_ROOT, &sealed, false).unwrap();
        let mut all = shares;
        all.push(new_share);
        // verify_split_roundtrip covers sliding windows; do a full-set check.
        verify_split_roundtrip(&all, &K_ROOT).unwrap();
    }
}
