//! HPKE sealed disclosure (protocol §2, §7.4), RFC 9180 single-shot.
//!
//! KEM = DHKEM(X25519, HKDF-SHA256), KDF = HKDF-SHA256.
//!
//! Spec asks for the AEAD to be XChaCha20-Poly1305, but RFC 9180 registers no
//! XChaCha20 AEAD and the `hpke` crate offers none; we use the registered
//! ChaCha20-Poly1305 (AEAD id 0x0003). This is the only spec deviation in the
//! crate and is called out in the crate report. HPKE ciphertext is opaque at
//! the framing layer (Appendix B uses a 0xEE placeholder), so no golden vector
//! is affected.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{
    single_shot_open, single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS,
    Serializable,
};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

/// A CSPRNG for HPKE's `single_shot_seal`, backed by `getrandom`. `hpke 0.13`
/// takes the sealing RNG as an argument (unlike `0.14`); this bridges the OS
/// CSPRNG into hpke's `rand_core` traits without adding a `rand` dependency.
struct OsCsprng;
impl RngCore for OsCsprng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("CSPRNG");
    }
}
impl CryptoRng for OsCsprng {}

/// The recipient's private HPKE key (X25519). Wraps the `hpke` private key so
/// callers never touch the trait soup. The inner key material is an
/// `x25519-dalek` `StaticSecret`, which is `ZeroizeOnDrop`, so this wrapper's
/// `Drop` scrubs the secret without extra handling.
pub struct HpkePrivateKey(<Kem as KemTrait>::PrivateKey);

/// The recipient's public HPKE key (X25519).
#[derive(Clone)]
pub struct HpkePublicKey(<Kem as KemTrait>::PublicKey);

impl HpkePublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        <Kem as KemTrait>::PublicKey::from_bytes(bytes)
            .map(HpkePublicKey)
            .map_err(|_| HpkeError::BadKey)
    }
}

/// Deterministically derive an HPKE keypair from input keying material, e.g. the
/// 32-byte `K_disclose` seed (RFC 9180 DeriveKeyPair).
pub fn derive_keypair(ikm: &[u8]) -> (HpkePrivateKey, HpkePublicKey) {
    let (sk, pk) = <Kem as KemTrait>::derive_keypair(ikm);
    (HpkePrivateKey(sk), HpkePublicKey(pk))
}

/// Seal `plaintext` to `recipient` in HPKE base mode. Returns the serialized
/// encapsulated key and the ciphertext.
pub fn seal(
    recipient: &HpkePublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let (encapped, ciphertext) = single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &recipient.0,
        info,
        plaintext,
        aad,
        &mut OsCsprng,
    )
    .map_err(|_| HpkeError::Seal)?;
    Ok((encapped.to_bytes().to_vec(), ciphertext))
}

/// Open an HPKE base-mode ciphertext with the recipient's private key.
pub fn open(
    recipient: &HpkePrivateKey,
    encapped_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(encapped_key)
        .map_err(|_| HpkeError::BadKey)?;
    single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient.0,
        &encapped,
        info,
        ciphertext,
        aad,
    )
    .map_err(|_| HpkeError::Open)
}

#[derive(Debug, PartialEq, Eq)]
pub enum HpkeError {
    BadKey,
    Seal,
    Open,
}

impl std::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HpkeError::BadKey => write!(f, "invalid HPKE key/encapsulation bytes"),
            HpkeError::Seal => write!(f, "HPKE seal failed"),
            HpkeError::Open => write!(f, "HPKE open failed (auth/decrypt)"),
        }
    }
}

impl std::error::Error for HpkeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_roundtrip() {
        let (sk, pk) = derive_keypair(&[0x05u8; 32]);
        let info = b"carapace/v1/disclosure";
        let aad = b"vid-c0";
        let pt = b"a sealed Chela share";

        let (enc, ct) = seal(&pk, info, aad, pt).unwrap();
        let opened = open(&sk, &enc, info, aad, &ct).unwrap();
        assert_eq!(opened, pt);

        // wrong aad is rejected
        assert_eq!(open(&sk, &enc, info, b"wrong", &ct), Err(HpkeError::Open));
        // wrong recipient is rejected
        let (sk2, _) = derive_keypair(&[0x06u8; 32]);
        assert_eq!(open(&sk2, &enc, info, aad, &ct), Err(HpkeError::Open));
    }

    #[test]
    fn pubkey_serialization_roundtrips() {
        let (_, pk) = derive_keypair(&[0x05u8; 32]);
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 32);
        let pk2 = HpkePublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk2.to_bytes(), bytes);
    }
}
