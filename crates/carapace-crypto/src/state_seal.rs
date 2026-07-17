//! Durable runtime-state row sealing (design §3.4).
//!
//! The daemon persists its runtime state to `state.redb`. Secret rows (Shamir shares,
//! Chela split polynomials, share grants) are AEAD-sealed first, under
//! `HKDF(K_root, "carapace/v1/state-seal")` with XChaCha20-Poly1305. This is a generic
//! byte sealer: the caller serializes a value to bytes, seals it, and stores the sealed
//! blob as the redb row value.
//!
//! Design invariants (all load-bearing):
//! - **Fresh random 24-byte nonce on EVERY seal and every re-seal.** Counter nonces are
//!   forbidden: restoring an older `state.redb` backup would rewind a counter into
//!   catastrophic nonce reuse under one HKDF key. XChaCha's 192-bit nonce makes random
//!   selection collision-safe.
//! - `aad = FORMAT_VERSION ‖ table_name ‖ canonical_redb_key_bytes`. This binds each row
//!   to its exact location, so a relocated / cross-table / cross-key swap fails to open.
//!   The version byte enables a future aad-layout migration.
//! - Decrypted plaintext is returned in a `Zeroizing` buffer (wiped on drop).
//! - **Fail loud:** a wrong key, tampered ciphertext, tampered aad, or truncated blob all
//!   return an error rather than a partial/garbage result. The caller MUST abort startup
//!   on an open failure, never skip-and-continue (that silently loses a share).
//!
//! Distinct key from `carapace-recovery::state_seal` (`"carapace/v1/split-state"`): the
//! two seal mechanisms use independent HKDF labels.

use crate::kdf;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;

/// aad format version (design §3.4). Bump to migrate the sealed-row aad layout.
pub const FORMAT_VERSION: u8 = 1;

/// A failure sealing or opening a state row. Opaque by design: an open failure never
/// discloses whether the key, ciphertext, or aad was wrong.
#[derive(Debug, PartialEq, Eq)]
pub enum StateSealError {
    /// Encryption failed (or the OS CSPRNG failed to produce a nonce).
    Seal,
    /// Decryption/authentication failed, or the sealed blob was malformed.
    Open,
}

impl std::fmt::Display for StateSealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateSealError::Seal => write!(f, "state-seal encryption failed"),
            StateSealError::Open => write!(f, "state-seal open failed (auth/decrypt)"),
        }
    }
}

impl std::error::Error for StateSealError {}

/// `aad = FORMAT_VERSION ‖ table_name ‖ canonical_redb_key_bytes` (design §3.4).
fn aad(table: &[u8], key: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(1 + table.len() + key.len());
    a.push(FORMAT_VERSION);
    a.extend_from_slice(table);
    a.extend_from_slice(key);
    a
}

/// Seal `plaintext` for the row `(table, key)` under `K_root`. Returns
/// `nonce(24) ‖ ciphertext`, the blob to store as the redb row value. A fresh random
/// nonce is drawn on every call (including re-seals of an existing row).
///
/// The caller owns the plaintext buffer's zeroization (pass a `Zeroizing` slice for
/// secret material); this function does not copy it beyond the AEAD's internal handling.
pub fn seal(
    k_root: &[u8; 32],
    table: &[u8],
    key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, StateSealError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| StateSealError::Seal)?;

    let sk = kdf::k_state_seal(k_root);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*sk));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad(table, key),
            },
        )
        .map_err(|_| StateSealError::Seal)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `nonce(24) ‖ ciphertext` blob produced by [`seal`] for the row `(table, key)`.
/// A wrong `K_root`, tampered ciphertext, tampered `table`/`key` (aad), or a truncated
/// blob all fail loudly. The recovered plaintext is returned `Zeroizing`.
pub fn open(
    k_root: &[u8; 32],
    table: &[u8],
    key: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StateSealError> {
    if sealed.len() < NONCE_LEN {
        return Err(StateSealError::Open);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);

    let sk = kdf::k_state_seal(k_root);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*sk));
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad(table, key),
            },
        )
        .map_err(|_| StateSealError::Open)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 32] = [0x11u8; 32];
    const TABLE: &[u8] = b"held_shares";
    const KEY: &[u8] = &[0xAAu8; 8];
    const SECRET: &[u8] = b"a Shamir share polynomial constant term";

    #[test]
    fn roundtrip() {
        let sealed = seal(&K, TABLE, KEY, SECRET).unwrap();
        let opened = open(&K, TABLE, KEY, &sealed).unwrap();
        assert_eq!(&*opened, SECRET);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&K, TABLE, KEY, SECRET).unwrap();
        assert_eq!(
            open(&[0x22u8; 32], TABLE, KEY, &sealed),
            Err(StateSealError::Open)
        );
    }

    #[test]
    fn aad_table_mismatch_fails() {
        let sealed = seal(&K, TABLE, KEY, SECRET).unwrap();
        assert_eq!(
            open(&K, b"held_grants", KEY, &sealed),
            Err(StateSealError::Open)
        );
    }

    #[test]
    fn aad_key_mismatch_fails() {
        // Row relocation: same table, different key bytes -> must not open.
        let sealed = seal(&K, TABLE, KEY, SECRET).unwrap();
        assert_eq!(
            open(&K, TABLE, &[0xBBu8; 8], &sealed),
            Err(StateSealError::Open)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(&K, TABLE, KEY, SECRET).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert_eq!(open(&K, TABLE, KEY, &sealed), Err(StateSealError::Open));
    }

    #[test]
    fn tampered_nonce_fails() {
        let mut sealed = seal(&K, TABLE, KEY, SECRET).unwrap();
        sealed[0] ^= 0xFF;
        assert_eq!(open(&K, TABLE, KEY, &sealed), Err(StateSealError::Open));
    }

    #[test]
    fn truncated_blob_fails() {
        assert_eq!(open(&K, TABLE, KEY, &[0u8; 10]), Err(StateSealError::Open));
        assert_eq!(open(&K, TABLE, KEY, &[]), Err(StateSealError::Open));
    }

    #[test]
    fn fresh_nonce_and_ct_per_seal() {
        let a = seal(&K, TABLE, KEY, SECRET).unwrap();
        let b = seal(&K, TABLE, KEY, SECRET).unwrap();
        // nonce prefix differs, so the whole blob differs (no counter reuse).
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn secret_never_appears_in_ciphertext() {
        let sealed = seal(&K, TABLE, KEY, SECRET).unwrap();
        assert!(
            !sealed
                .windows(SECRET.len())
                .any(|w| w == SECRET),
            "plaintext secret must not appear in the sealed blob"
        );
    }
}
