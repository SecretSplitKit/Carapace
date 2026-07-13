//! Split-state sealing (protocol §8.1). Carapace AEAD-encrypts `SplitState::to_bytes()` under
//! `HKDF(K_root, "carapace/v1/split-state")` with XChaCha20-Poly1305, binding `rsid ‖ M` as
//! associated data. The split-state is secret-equivalent (its polynomial constant terms *are*
//! the secret body), so a leaked sealed blob must reveal nothing without `K_root`.

use carapace_crypto::kdf;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chela_engine::SplitState;

use crate::RecoveryError;

const NONCE_LEN: usize = 24;

/// A sealed split-state. `rsid` and `M` are public (a random nonce and the threshold) and are
/// kept in the clear so `open` can reconstruct the AEAD associated data; the AEAD binds them, so
/// swapping either fails to open. `ct` is the XChaCha20-Poly1305 ciphertext of the state bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSplitState {
    /// The 11-bit recovery-set id (Chela's per-split nonce), bound as associated data.
    pub rsid: u16,
    /// The reconstruction threshold `M`, bound as associated data.
    pub m: u8,
    /// Fresh random AEAD nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext of `SplitState::to_bytes()`.
    pub ct: Vec<u8>,
}

/// `aad = rsid.to_be_bytes() ‖ [M]` (protocol §8.1).
fn aad(rsid: u16, m: u8) -> [u8; 3] {
    let r = rsid.to_be_bytes();
    [r[0], r[1], m]
}

/// Seal `state` under `K_root`. Serializes the state (a self-zeroizing buffer), encrypts it, and
/// drops the plaintext immediately. The nonce is drawn fresh from the OS CSPRNG.
pub fn seal_split_state(
    k_root: &[u8; 32],
    state: &SplitState,
) -> Result<SealedSplitState, RecoveryError> {
    let rsid = state.recovery_set_id();
    let m = state.threshold();

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| RecoveryError::Seal)?;

    let key = kdf::k_split_state(k_root);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));

    // `to_bytes()` returns a `Zeroizing<Vec<u8>>`: the plaintext wipes when `plaintext` drops at
    // the end of this function, i.e. right after it has been encrypted.
    let plaintext = state.to_bytes();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(rsid, m),
            },
        )
        .map_err(|_| RecoveryError::Seal)?;

    Ok(SealedSplitState { rsid, m, nonce, ct })
}

/// Open a sealed split-state with `K_root`. The associated data is reconstructed from the blob's
/// public `rsid`/`M`; a wrong `K_root`, tampered ciphertext, or tampered `rsid`/`M` all fail the
/// AEAD tag. The recovered plaintext is parsed by Chela's fuzz-robust `from_bytes`.
pub fn open_split_state(
    k_root: &[u8; 32],
    sealed: &SealedSplitState,
) -> Result<SplitState, RecoveryError> {
    let key = kdf::k_split_state(k_root);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: &aad(sealed.rsid, sealed.m),
            },
        )
        .map_err(|_| RecoveryError::Open)?;
    // `plaintext` is secret-equivalent; wipe it after parsing regardless of outcome.
    let plaintext = zeroize::Zeroizing::new(plaintext);
    SplitState::from_bytes(&plaintext).map_err(RecoveryError::State)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::split_root;

    fn fresh_split() -> SplitState {
        let (_shares, state, _w) = split_root(&[0x11u8; 32], 3, 5, false).unwrap();
        state
    }

    #[test]
    fn seal_open_roundtrip() {
        let k_root = [0x11u8; 32];
        let state = fresh_split();
        let (rsid, m, issued) = (
            state.recovery_set_id(),
            state.threshold(),
            state.issued_count(),
        );

        let sealed = seal_split_state(&k_root, &state).unwrap();
        assert_eq!(sealed.rsid, rsid);
        assert_eq!(sealed.m, m);

        let opened = open_split_state(&k_root, &sealed).unwrap();
        assert_eq!(opened.recovery_set_id(), rsid);
        assert_eq!(opened.threshold(), m);
        assert_eq!(opened.issued_count(), issued);
        // Functional equivalence: the re-parsed state serializes identically.
        assert_eq!(&*opened.to_bytes(), &*state.to_bytes());
    }

    #[test]
    fn wrong_k_root_fails() {
        let state = fresh_split();
        let sealed = seal_split_state(&[0x11u8; 32], &state).unwrap();
        assert!(matches!(
            open_split_state(&[0x22u8; 32], &sealed),
            Err(RecoveryError::Open)
        ));
    }

    #[test]
    fn tampered_aad_fails() {
        let k_root = [0x11u8; 32];
        let state = fresh_split();
        let mut sealed = seal_split_state(&k_root, &state).unwrap();
        // Flip the public rsid header: the AEAD binds it, so open must fail (not silently mask).
        sealed.rsid ^= 1;
        assert!(matches!(
            open_split_state(&k_root, &sealed),
            Err(RecoveryError::Open)
        ));

        // Flip M instead.
        let mut sealed = seal_split_state(&k_root, &state).unwrap();
        sealed.m = sealed.m.wrapping_add(1);
        assert!(matches!(
            open_split_state(&k_root, &sealed),
            Err(RecoveryError::Open)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k_root = [0x11u8; 32];
        let state = fresh_split();
        let mut sealed = seal_split_state(&k_root, &state).unwrap();
        sealed.ct[0] ^= 0xFF;
        assert!(matches!(
            open_split_state(&k_root, &sealed),
            Err(RecoveryError::Open)
        ));
    }

    #[test]
    fn fresh_nonce_per_seal() {
        let k_root = [0x11u8; 32];
        let state = fresh_split();
        let a = seal_split_state(&k_root, &state).unwrap();
        let b = seal_split_state(&k_root, &state).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ct, b.ct);
    }
}
