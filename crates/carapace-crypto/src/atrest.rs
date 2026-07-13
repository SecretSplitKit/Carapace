//! Argon2id at-rest sealing (protocol §2 "Root-at-rest KDF"): local-only sealing
//! of a secret (e.g. `K_root`) under a passphrase. Argon2id stretches the
//! passphrase into a 32-byte key; XChaCha20-Poly1305 then seals the secret.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Argon2id cost parameters used for new blobs. Pinned explicitly (rather than
/// `Argon2::default()`) and recorded in each blob so a future change to the
/// crate's defaults can never leave existing blobs un-openable.
const ARGON2_M_COST: u32 = 19_456; // KiB
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// A sealed-at-rest blob. Self-describing: carries the Argon2 salt, cost
/// parameters, and AEAD nonce so `open_at_rest` needs only the passphrase and
/// derives with the exact parameters the blob was sealed under.
pub struct AtRestBlob {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// Argon2id memory cost (KiB) used to derive this blob's key.
    pub m_cost: u32,
    /// Argon2id time cost (iterations).
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u32,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AtRestError {
    Kdf,
    Seal,
    Open,
    Rng,
}

impl std::fmt::Display for AtRestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AtRestError::Kdf => write!(f, "Argon2id key derivation failed"),
            AtRestError::Seal => write!(f, "at-rest seal failed"),
            AtRestError::Open => write!(f, "at-rest open failed (wrong passphrase or tampered)"),
            AtRestError::Rng => write!(f, "system RNG failed"),
        }
    }
}

impl std::error::Error for AtRestError {}

/// Argon2id(passphrase, salt) -> 32-byte key, using the given explicit cost
/// parameters (never `Argon2::default()`, so derivation is stable across crate
/// versions).
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, AtRestError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|_| AtRestError::Kdf)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|_| AtRestError::Kdf)?;
    Ok(key)
}

/// Seal `secret` under `passphrase`. Generates a fresh random salt and nonce,
/// and records the Argon2id cost parameters in the blob.
pub fn seal_at_rest(passphrase: &[u8], secret: &[u8]) -> Result<AtRestBlob, AtRestError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| AtRestError::Rng)?;
    getrandom::getrandom(&mut nonce).map_err(|_| AtRestError::Rng)?;

    let key = derive_key(passphrase, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: secret, aad: b"carapace/v1/at-rest" })
        .map_err(|_| AtRestError::Seal)?;
    Ok(AtRestBlob {
        salt,
        nonce,
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
        ciphertext,
    })
}

/// Open an at-rest blob with the passphrase. Returns the recovered secret,
/// zeroized on drop. Derives the key with the blob's recorded parameters.
pub fn open_at_rest(passphrase: &[u8], blob: &AtRestBlob) -> Result<Zeroizing<Vec<u8>>, AtRestError> {
    let key = derive_key(passphrase, &blob.salt, blob.m_cost, blob.t_cost, blob.p_cost)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));
    cipher
        .decrypt(
            XNonce::from_slice(&blob.nonce),
            Payload { msg: &blob.ciphertext, aad: b"carapace/v1/at-rest" },
        )
        .map(Zeroizing::new)
        .map_err(|_| AtRestError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_rest_roundtrip() {
        let pass = b"correct horse battery staple";
        let secret = [0x42u8; 32]; // stand-in for K_root

        let blob = seal_at_rest(pass, &secret).unwrap();
        let opened = open_at_rest(pass, &blob).unwrap();
        assert_eq!(&opened[..], &secret[..]);

        // wrong passphrase fails to open
        assert_eq!(open_at_rest(b"tr0ub4dor&3", &blob), Err(AtRestError::Open));
        // fresh salt/nonce each seal
        let blob2 = seal_at_rest(pass, &secret).unwrap();
        assert_ne!(blob.salt, blob2.salt);
        assert_ne!(blob.nonce, blob2.nonce);
    }

    // S1: the blob records its Argon2id params, and `open` derives with those
    // recorded params (not a fixed default) — proven by the fact that altering
    // a recorded param changes the derived key and the open fails.
    #[test]
    fn open_honors_recorded_params() {
        let pass = b"correct horse battery staple";
        let secret = [0x42u8; 32];
        let mut blob = seal_at_rest(pass, &secret).unwrap();

        assert_eq!(
            (blob.m_cost, blob.t_cost, blob.p_cost),
            (ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST),
            "blob must persist the params it was sealed under"
        );

        blob.t_cost += 1;
        assert_eq!(open_at_rest(pass, &blob), Err(AtRestError::Open));
    }
}
