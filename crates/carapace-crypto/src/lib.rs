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
pub mod state_seal;

pub use ed25519_dalek;

#[cfg(test)]
mod appendix_b_pins {
    //! Cross-pins against the normative Appendix B material. These must match
    //! byte-for-byte; if they drift, the crate no longer conforms.

    use crate::content;
    use crate::identity;
    use crate::kdf;
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
            content::open_chunk(&sealed.chunk_key, &sealed.nonce, &sealed.ciphertext, &vid)
                .unwrap();
        assert_eq!(opened, plaintext);
    }

    /// BLAKE3 extendable output — the cross-language deterministic buffer fill
    /// used by the §B.10 vectors (any BLAKE3 impl reproduces it byte-for-byte).
    fn blake3_xof(seed: &[u8], n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        blake3::Hasher::new()
            .update(seed)
            .finalize_xof()
            .fill(&mut out);
        out
    }

    /// (c) §B.10.1 KDF tree vector — pins the empty-salt HKDF-SHA-256 §4 tree
    /// from `K_root = 00×32`, `vid = c0×32`.
    #[test]
    fn pin_b10_1_kdf_tree() {
        let k_root = [0x00u8; 32];
        let vid = [0xC0u8; 32];
        let vr = kdf::k_vaultroot(&k_root, &vid);
        assert_eq!(
            hex::encode(*vr),
            "92d90be86652064e1c52a1749cbdaccd6a94d24e9cccdb0dcfec38e7165517c6"
        );
        assert_eq!(
            hex::encode(*kdf::k_content(&*vr)),
            "f545200aa775f683c955d9123468b87e5405b962ffd69c7ac3bfe87279172192"
        );
        assert_eq!(
            hex::encode(*kdf::k_manifest(&*vr)),
            "6bfe69d0e457994892e0e95919947398aa80427f09abae3caf02700c5b4fe775"
        );
        assert_eq!(
            hex::encode(*kdf::k_audit(&*vr)),
            "6f05d55b61a919442b9e8551e2cbd37f37634a1047c47bd5e62b77a6648d0689"
        );
        assert_eq!(
            hex::encode(*kdf::k_userid(&k_root)),
            "956dc4696762c4c1aa2d3bfd5e7fcb3b384c6bec47e43dafa73e11e2170f235c"
        );
        assert_eq!(
            hex::encode(*kdf::k_disclose(&k_root)),
            "a6bf0efac0cbf63b32c00cb9f5e2ac601a259a95ced890192b082cd8dcc802c0"
        );
    }

    /// (d) §B.10.2 chunk-boundary vector — pins FastCDC v2016 / Gear / Norm.
    /// Level 1 cut points on an 8 MiB BLAKE3-XOF buffer. A second chunker MUST
    /// reproduce this offset/length list exactly.
    #[test]
    fn pin_b10_2_chunk_boundaries() {
        let buf = blake3_xof(b"carapace/v1/fastcdc-test-vector", 8 * 1024 * 1024);
        let ranges = content::chunk_ranges(&buf);
        let expected: &[(usize, usize)] = &[
            (0, 2017596),
            (2017596, 415201),
            (2432797, 1562602),
            (3995399, 1116653),
            (5112052, 769948),
            (5882000, 1032702),
            (6914702, 818610),
            (7733312, 655296),
        ];
        assert_eq!(ranges, expected, "FastCDC cut points must match §B.10.2");
        // sanity: contiguous and total
        assert_eq!(ranges.last().map(|(o, l)| o + l), Some(buf.len()));
    }

    /// (e) §B.10.3 convergent-seal vector — pins the whole §5 seal pipeline from
    /// `K_content = 11×32`, `vid = c0×32`, `plaintext = 0x00..0x3F`.
    #[test]
    fn pin_b10_3_convergent_seal() {
        let k_content = [0x11u8; 32];
        let vid = [0xC0u8; 32];
        let mut plaintext = [0u8; 64];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sealed = content::seal_chunk(&k_content, &vid, &plaintext).unwrap();
        assert_eq!(
            hex::encode(sealed.pt_hash),
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"
        );
        assert_eq!(
            hex::encode(*sealed.chunk_key),
            "d5518b9b9091ba13696dee33fe2d10054b3cbf414847c9b9efe5d7645745c4c1"
        );
        assert_eq!(
            hex::encode(*sealed.nonce),
            "24043a8b48396741746260c1c4d02dc6a8380e3dac02488a"
        );
        assert_eq!(
            hex::encode(&sealed.ciphertext),
            "a3760f56f5ef0ff11e8c630e96c9968ec9cf7d86f4f9ab93e9c5bcd680c15f7e\
             af4f9e7626aa467153d9e93420ebcab39d3fc67e4eb8786d452677073145415555\
             b00319b262a208310acfafe7f396c1"
        );
        assert_eq!(
            hex::encode(sealed.chunk_id),
            "344368f7a16c3a40a851be8917f174f84b362c8376c998b9bd1eec87b88db7e1"
        );
        // ChunkID = BLAKE3(ciphertext), and the seal opens back to plaintext.
        assert_eq!(sealed.chunk_id, content::chunk_id(&sealed.ciphertext));
        assert_eq!(
            content::open_chunk(&sealed.chunk_key, &sealed.nonce, &sealed.ciphertext, &vid)
                .unwrap(),
            plaintext
        );
    }
}
