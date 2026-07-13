//! carapace-recovery: recovery-via-Chela orchestration (protocol §8).
//!
//! Carapace consumes Chela's extendable-split profile through five concerns, one module each:
//!
//! - [`state_seal`]: AEAD-seal a [`SplitState`] under `HKDF(K_root, "carapace/v1/split-state")`
//!   (§8.1). A leaked sealed blob reveals nothing without `K_root`.
//! - [`split`]: split `K_root` (inner circle) and `K_vaultroot(vid)` (scoped, §8.2); extend to
//!   add a trustee / replace a lost share; the §8.3 issuance cap; owner-side round-trip
//!   verification (§10.2).
//! - [`grant`]: build/verify [`carapace_wire::ShareGrant`] (wire type 12) and the attestation
//!   cycle (§10.2).
//! - [`ceremony`]: the normative recovery ceremony state machine (§8.5).
//!
//! `K_root` and vault keys are 32-byte secrets; Chela splits a *secret*, so each is carried as
//! its 24-word BIP-39 (`kind 0x05`) mnemonic and split as [`chela_engine::SplitInput::Bip39`].

use zeroize::Zeroizing;

pub mod ceremony;
pub mod grant;
pub mod split;
pub mod state_seal;

pub use chela_engine::{Share, SplitState};
pub use ceremony::{
    build_ceremony_share, open_ceremony_share, open_recovery, verify_recovery_open, CeremonyPhase,
    CeremonyState, RecoveryRateLimiter, CEREMONY_SHARE_INFO,
};
pub use grant::{
    answer_attest_challenge, attestation_live, build_attest_challenge, build_share_grant,
    self_validate_share, share_from_json, verify_attestation, verify_share_grant,
};
pub use split::{
    add_trustee, check_initial_issuance, extend_split, recover_key_from_shares, replace_lost_share,
    soft_cap, split_root, split_vault, verify_split_roundtrip, PolicyWarning,
};
pub use state_seal::{open_split_state, seal_split_state, SealedSplitState};

/// Every failure mode of the recovery layer. Each wrapped error keeps its source so a caller
/// can distinguish a bad signature from a wrong-secret from an AEAD failure.
#[derive(Debug)]
pub enum RecoveryError {
    /// A wire-layer encode/decode or signature-verification error.
    Wire(carapace_wire::Error),
    /// An HPKE seal/open error (ceremony share sealing).
    Hpke(carapace_crypto::seal::HpkeError),
    /// A Chela engine error (split, recover, bundling).
    Engine(chela_engine::EngineError),
    /// A Chela `extend` error (wrong secret, exhausted, over-cap).
    Extend(chela_engine::ExtendError),
    /// A Chela split-state parse error.
    State(chela_engine::StateError),
    /// A Chela share-import (`chela.share` JSON) error.
    Import(chela_share::ImportError),
    /// A BIP-39 entropy<->mnemonic conversion error.
    Bip39(chela_bip39::Bip39Error),
    /// Split-state AEAD seal failed.
    Seal,
    /// Split-state AEAD open failed (wrong `K_root`, tampered blob, or tampered `rsid`/`M`).
    Open,
    /// A key was not exactly 32 bytes.
    BadKeyLength,
    /// `M < 2`, `N < M`, or `N > 32`.
    InvalidThreshold,
    /// Issuance would exceed the soft cap of `3·M − 1` and `allow_over_cap` was not set (§8.3).
    OverSoftCap,
    /// The opener/approver is not in the recovery-set roster (only a trustee may sponsor/approve).
    NotATrustee,
    /// A `CeremonyAbort` was not signed by the subject user key.
    NotSubject,
    /// A ceremony message referenced a different `ceremony_id` than this ceremony.
    CeremonyMismatch,
    /// The per-subject open rate limit was exceeded.
    RateLimited,
    /// A `ShareGrant`/carrier held other than exactly one share.
    ShareCount,
    /// Owner-side round-trip verification of a fresh split failed - do not trust the split.
    RoundTripFailed,
    /// An attestation did not echo its challenge (subject/rsid/nonce mismatch).
    ChallengeMismatch,
    /// A `RecoveryOpen` referenced an `rsid` outside Chela's 11-bit range (`> 0x7FF`).
    RsidOutOfRange,
    /// A `RecoveryOpen`'s subject/rsid did not match the `ShareGrant` it is gated on.
    GrantMismatch,
}

impl core::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "wire error: {e}"),
            Self::Hpke(e) => write!(f, "hpke error: {e}"),
            Self::Engine(e) => write!(f, "chela engine error: {e}"),
            Self::Extend(e) => write!(f, "chela extend error: {e}"),
            Self::State(e) => write!(f, "chela split-state error: {e}"),
            Self::Import(e) => write!(f, "chela share import error: {e}"),
            Self::Bip39(e) => write!(f, "bip39 error: {e}"),
            Self::Seal => f.write_str("split-state seal failed"),
            Self::Open => f.write_str("split-state open failed (wrong K_root or tampered blob)"),
            Self::BadKeyLength => f.write_str("key must be exactly 32 bytes"),
            Self::InvalidThreshold => f.write_str("invalid threshold/total: require 2 <= M <= N <= 32"),
            Self::OverSoftCap => f.write_str(
                "issuance would exceed the recommended cap of 3*M-1 shares; set allow_over_cap to proceed",
            ),
            Self::NotATrustee => f.write_str("signer is not a trustee of this recovery set"),
            Self::NotSubject => f.write_str("abort was not signed by the subject user key"),
            Self::CeremonyMismatch => f.write_str("message references a different ceremony"),
            Self::RateLimited => f.write_str("too many recovery opens for this subject; rate limited"),
            Self::ShareCount => f.write_str("carrier did not hold exactly one share"),
            Self::RoundTripFailed => f.write_str("split failed owner-side round-trip verification"),
            Self::ChallengeMismatch => f.write_str("attestation does not match its challenge"),
            Self::RsidOutOfRange => f.write_str("recovery-set id is out of range (must be <= 0x7FF)"),
            Self::GrantMismatch => {
                f.write_str("recovery open does not match the share grant (subject/rsid)")
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<carapace_wire::Error> for RecoveryError {
    fn from(e: carapace_wire::Error) -> Self {
        Self::Wire(e)
    }
}
impl From<carapace_crypto::seal::HpkeError> for RecoveryError {
    fn from(e: carapace_crypto::seal::HpkeError) -> Self {
        Self::Hpke(e)
    }
}
impl From<chela_engine::EngineError> for RecoveryError {
    fn from(e: chela_engine::EngineError) -> Self {
        Self::Engine(e)
    }
}
impl From<chela_engine::ExtendError> for RecoveryError {
    fn from(e: chela_engine::ExtendError) -> Self {
        Self::Extend(e)
    }
}
impl From<chela_engine::StateError> for RecoveryError {
    fn from(e: chela_engine::StateError) -> Self {
        Self::State(e)
    }
}
impl From<chela_share::ImportError> for RecoveryError {
    fn from(e: chela_share::ImportError) -> Self {
        Self::Import(e)
    }
}
impl From<chela_bip39::Bip39Error> for RecoveryError {
    fn from(e: chela_bip39::Bip39Error) -> Self {
        Self::Bip39(e)
    }
}

/// Encode a 32-byte key as its canonical 24-word BIP-39 mnemonic (`kind 0x05`, no passphrase).
/// The returned string self-zeroizes on drop; it is secret-equivalent to the key.
pub(crate) fn key_to_mnemonic(key: &[u8; 32]) -> Result<Zeroizing<String>, RecoveryError> {
    let mut idx = [0u16; 24];
    let n = chela_bip39::encode_entropy_to_indices(key, &mut idx)?;
    let mut out = String::with_capacity(24 * 9);
    for (i, &w) in idx[..n].iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        // `w` came from the encoder, so it is always a valid wordlist index.
        out.push_str(chela_bip39::index_to_word(w).ok_or(RecoveryError::BadKeyLength)?);
    }
    Ok(Zeroizing::new(out))
}

/// Decode a BIP-39 mnemonic back into its 32-byte key (verifying the BIP-39 checksum). Rejects
/// any mnemonic that does not decode to exactly 32 bytes. The result self-zeroizes on drop.
pub(crate) fn mnemonic_to_key(mnemonic: &str) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    let mut idx: Vec<u16> = Vec::with_capacity(24);
    for w in mnemonic.split_whitespace() {
        idx.push(chela_bip39::word_to_index(w).ok_or(RecoveryError::Bip39(
            chela_bip39::Bip39Error::UnknownWord,
        ))?);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    let n = chela_bip39::decode_indices_to_entropy(&idx, out.as_mut_slice())?;
    if n != 32 {
        return Err(RecoveryError::BadKeyLength);
    }
    Ok(out)
}
