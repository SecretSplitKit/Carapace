//! carapace-crypto: cryptographic suite `0x01` (Carapace protocol §2) behind
//! clean, unit-testable interfaces.
//!
//! - [`kdf`]: HKDF-SHA-256 derivation tree with the exact §4 info strings.
//! - [`identity`]: Ed25519 user/node keys and device-delegation chains.
//! - [`content`]: FastCDC chunking + XChaCha20-Poly1305 convergent seal +
//!   BLAKE3-256 ChunkID (§5).
//! - [`seal`]: HPKE (RFC 9180, X25519 + ChaCha20-Poly1305) sealed disclosure.
//! - [`atrest`]: Argon2id at-rest sealing of a local secret.
//!
//! Hand-rolls nothing cryptographic; every primitive routes through a vetted
//! RustCrypto / established crate.

pub mod atrest;
pub mod content;
pub mod identity;
pub mod kdf;
pub mod seal;

pub use ed25519_dalek;

#[cfg(test)]
mod appendix_b_pins {
    //! Cross-pins against the normative Appendix B material. These must match
    //! byte-for-byte; if they drift, the crate no longer conforms.

    use crate::content;
    use crate::identity;
    use ed25519_dalek::SigningKey;

    /// (a) The device delegation embedded in the B.8.3 ContactCard vector:
    /// `Ed25519(USER_A, "carapace/v1/deleg" ‖ NODE_A1_pub ‖ (T0+1y).be8)`.
    /// Bytes taken verbatim from B.8.3 / the reference `cbor_vectors.py`.
    const B83_DELEGATION: &str = "485ff570b5fc2c8d68074e514d98c04e9312363ae19b6ac6c90b3c163f0323b9\
                                  1a3301cc6a6883979931bf5a11fad8252fe46c32994ce48c50a588c64bbda504";
    const T0: u64 = 1_767_225_600;

    #[test]
    fn pin_b83_delegation_bytes() {
        let user_a = SigningKey::from_bytes(&[0x01; 32]); // USER_A seed 01×32
        let node_a1 = SigningKey::from_bytes(&[0x03; 32]); // NODE_A1 seed 03×32
        let not_after = T0 + 31_536_000; // T0 + 1 year

        let sig = identity::sign_delegation(&user_a, &node_a1.verifying_key(), not_after);
        assert_eq!(
            hex::encode(sig.to_bytes()),
            B83_DELEGATION.replace(char::is_whitespace, ""),
            "delegation must reproduce the B.8.3 ContactCard vector"
        );

        // and it verifies as a chain
        assert!(identity::verify_delegation(
            &user_a.verifying_key(),
            &node_a1.verifying_key(),
            not_after,
            &sig,
            Some(T0),
        )
        .is_ok());
    }

    /// (b) Seal a chunk, recompute its ChunkID, and decrypt it back.
    #[test]
    fn pin_chunk_seal_roundtrip() {
        let k_content = [0x22u8; 32];
        let vid = [0xC0u8; 32]; // vid c0×32 per B.7
        let plaintext = b"carapace chunk seal cross-pin".repeat(1000);

        let sealed = content::seal_chunk(&k_content, &vid, &plaintext).unwrap();
        assert_eq!(sealed.chunk_id, content::chunk_id(&sealed.ciphertext));
        let opened =
            content::open_chunk(&sealed.chunk_key, &sealed.nonce, &sealed.ciphertext, &vid).unwrap();
        assert_eq!(opened, plaintext);
    }
}
