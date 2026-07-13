//! Content addressing (protocol §5): FastCDC chunking, per-chunk convergent
//! seal, and BLAKE3-256 ChunkID.

use crate::kdf;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// FastCDC parameters, normative for cross-client dedup (protocol §5).
pub const MIN_SIZE: usize = 256 * 1024;
pub const AVG_SIZE: usize = 1024 * 1024;
pub const MAX_SIZE: usize = 4 * 1024 * 1024;

/// Split `data` into content-defined chunks (FastCDC, standard Gear hash).
/// Returns `(offset, length)` cut points in order; concatenation reproduces the
/// input exactly.
pub fn chunk_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    fastcdc::v2016::FastCDC::new(data, MIN_SIZE, AVG_SIZE, MAX_SIZE)
        .map(|c| (c.offset, c.length))
        .collect()
}

/// A sealed chunk plus everything a manifest needs to recover it. `chunk_key`
/// and `nonce` are stored per-chunk in the (separately sealed) manifest, so the
/// owner never needs the plaintext again to open the blob.
pub struct SealedChunk {
    /// `BLAKE3-256(C)` — the iroh blob hash.
    pub chunk_id: [u8; 32],
    /// `C = XChaCha20-Poly1305(chunk_key, nonce, P, aad = vid)`.
    pub ciphertext: Vec<u8>,
    /// `BLAKE3(P)` — the convergence tag the key/nonce are bound to.
    pub pt_hash: [u8; 32],
    pub chunk_key: Zeroizing<[u8; 32]>,
    pub nonce: Zeroizing<[u8; 24]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChunkError {
    Seal,
    Open,
}

impl std::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkError::Seal => write!(f, "chunk seal (AEAD encrypt) failed"),
            ChunkError::Open => write!(f, "chunk open (AEAD decrypt/verify) failed"),
        }
    }
}

impl std::error::Error for ChunkError {}

/// Seal one plaintext chunk under vault-scoped convergent encryption (§5):
/// `pt_hash = BLAKE3(P)`, key/nonce = HKDF(K_content, …‖pt_hash),
/// `C = XChaCha20-Poly1305(key, nonce, P, aad = vid)`, `ChunkID = BLAKE3(C)`.
pub fn seal_chunk(k_content: &[u8], vid: &[u8], plaintext: &[u8]) -> Result<SealedChunk, ChunkError> {
    let pt_hash: [u8; 32] = *blake3::hash(plaintext).as_bytes();
    let chunk_key = kdf::chunk_key(k_content, &pt_hash);
    let nonce = kdf::chunk_nonce(k_content, &pt_hash);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*chunk_key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&*nonce), Payload { msg: plaintext, aad: vid })
        .map_err(|_| ChunkError::Seal)?;

    let chunk_id: [u8; 32] = *blake3::hash(&ciphertext).as_bytes();
    Ok(SealedChunk { chunk_id, ciphertext, pt_hash, chunk_key, nonce })
}

/// Recompute the ChunkID (iroh blob hash) of a sealed ciphertext.
pub fn chunk_id(ciphertext: &[u8]) -> [u8; 32] {
    *blake3::hash(ciphertext).as_bytes()
}

/// Open a sealed chunk given the manifest-stored key and nonce.
pub fn open_chunk(
    chunk_key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    vid: &[u8],
) -> Result<Vec<u8>, ChunkError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(chunk_key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: vid })
        .map_err(|_| ChunkError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_ranges_cover_input_contiguously() {
        // 10 MiB of pseudo-random-ish data so FastCDC actually cuts.
        let mut data = vec![0u8; 10 * 1024 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i.wrapping_mul(2654435761) >> 13) as u8;
        }
        let ranges = chunk_ranges(&data);
        assert!(ranges.len() > 1, "large input should produce multiple chunks");
        let mut pos = 0;
        for (off, len) in &ranges {
            assert_eq!(*off, pos, "chunks must be contiguous");
            assert!(*len >= MIN_SIZE || *off + *len == data.len(), "min-size honored except last");
            assert!(*len <= MAX_SIZE, "max-size honored");
            pos += len;
        }
        assert_eq!(pos, data.len(), "chunks must cover the whole input");
    }

    #[test]
    fn seal_roundtrip_and_chunkid() {
        let k_content = [0x22u8; 32];
        let vid = [0xC0u8; 32];
        let plaintext = b"the mitochondria is the powerhouse of the cell".repeat(50);

        let sealed = seal_chunk(&k_content, &vid, &plaintext).unwrap();
        // (b) recompute ChunkID from the ciphertext, byte-for-byte.
        assert_eq!(sealed.chunk_id, chunk_id(&sealed.ciphertext));
        // decrypt round-trips
        let opened = open_chunk(&sealed.chunk_key, &sealed.nonce, &sealed.ciphertext, &vid).unwrap();
        assert_eq!(opened, plaintext);

        // convergence: same plaintext+vid -> identical ciphertext and ChunkID.
        let again = seal_chunk(&k_content, &vid, &plaintext).unwrap();
        assert_eq!(again.ciphertext, sealed.ciphertext);
        assert_eq!(again.chunk_id, sealed.chunk_id);

        // vault scoping: aad=vid is authenticated, so a wrong vid fails to open.
        let wrong_vid = [0xC1u8; 32];
        assert_eq!(
            open_chunk(&sealed.chunk_key, &sealed.nonce, &sealed.ciphertext, &wrong_vid),
            Err(ChunkError::Open)
        );
    }
}
