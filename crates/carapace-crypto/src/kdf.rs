//! HKDF-SHA-256 derivation tree (protocol §4). Every `info` string here is
//! byte-for-byte normative; do not "clean up" the spellings.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Prefix for the per-vault root: `info = VAULT_PREFIX ‖ vid`.
pub const VAULT_PREFIX: &[u8] = b"carapace/v1/vault/";
pub const INFO_CONTENT: &[u8] = b"content";
pub const INFO_MANIFEST: &[u8] = b"manifest";
pub const INFO_AUDIT: &[u8] = b"por";
pub const INFO_USERID: &[u8] = b"carapace/v1/user-identity";
pub const INFO_DISCLOSE: &[u8] = b"carapace/v1/disclosure";
/// Split-state sealing key (protocol §8.1): AEAD key for the Chela extendable-split state.
pub const INFO_SPLIT_STATE: &[u8] = b"carapace/v1/split-state";

/// Per-chunk key/nonce info prefixes: `info = PREFIX ‖ pt_hash` (protocol §5).
pub const CHUNK_KEY_PREFIX: &[u8] = b"chunk-key";
pub const CHUNK_NONCE_PREFIX: &[u8] = b"chunk-nonce";

/// A 32-byte derived key that zeroes itself on drop.
pub type Key32 = Zeroizing<[u8; 32]>;

/// HKDF-SHA-256 with an empty salt: extract over `ikm`, expand `info` into `out`.
/// This is the single primitive every named derivation below routes through.
fn hkdf_expand(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    // expand only fails when out is absurdly long (> 255*32); ours never is.
    hk.expand(info, out)
        .expect("HKDF output length within one hash block budget");
}

/// Derive a fresh 32-byte key: `HKDF(parent, info)`.
fn derive32(parent: &[u8], info: &[u8]) -> Key32 {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_expand(parent, info, out.as_mut_slice());
    out
}

/// `K_vaultroot(vid) = HKDF(K_root, "carapace/v1/vault/" ‖ vid)`.
pub fn k_vaultroot(k_root: &[u8], vid: &[u8]) -> Key32 {
    let mut info = Vec::with_capacity(VAULT_PREFIX.len() + vid.len());
    info.extend_from_slice(VAULT_PREFIX);
    info.extend_from_slice(vid);
    derive32(k_root, &info)
}

/// `K_content(vid) = HKDF(K_vaultroot(vid), "content")`.
pub fn k_content(k_vaultroot: &[u8]) -> Key32 {
    derive32(k_vaultroot, INFO_CONTENT)
}

/// `K_manifest(vid) = HKDF(K_vaultroot(vid), "manifest")`.
pub fn k_manifest(k_vaultroot: &[u8]) -> Key32 {
    derive32(k_vaultroot, INFO_MANIFEST)
}

/// `K_audit(vid) = HKDF(K_vaultroot(vid), "por")`.
pub fn k_audit(k_vaultroot: &[u8]) -> Key32 {
    derive32(k_vaultroot, INFO_AUDIT)
}

/// `K_userid = HKDF(K_root, "carapace/v1/user-identity")` (Ed25519 seed).
pub fn k_userid(k_root: &[u8]) -> Key32 {
    derive32(k_root, INFO_USERID)
}

/// `K_disclose = HKDF(K_root, "carapace/v1/disclosure")` (X25519/HPKE seed).
pub fn k_disclose(k_root: &[u8]) -> Key32 {
    derive32(k_root, INFO_DISCLOSE)
}

/// `K_splitstate = HKDF(K_root, "carapace/v1/split-state")` (protocol §8.1). The AEAD key
/// under which the daemon seals a Chela split-state before persisting it.
pub fn k_split_state(k_root: &[u8]) -> Key32 {
    derive32(k_root, INFO_SPLIT_STATE)
}

/// `chunk_key = HKDF(K_content, "chunk-key" ‖ pt_hash)`.
pub fn chunk_key(k_content: &[u8], pt_hash: &[u8]) -> Key32 {
    let mut info = Vec::with_capacity(CHUNK_KEY_PREFIX.len() + pt_hash.len());
    info.extend_from_slice(CHUNK_KEY_PREFIX);
    info.extend_from_slice(pt_hash);
    derive32(k_content, &info)
}

/// `chunk_nonce = HKDF(K_content, "chunk-nonce" ‖ pt_hash)[0:24]`. HKDF-Expand is
/// prefix-stable, so expanding exactly 24 bytes equals the first 24 of any longer
/// expansion.
pub fn chunk_nonce(k_content: &[u8], pt_hash: &[u8]) -> Zeroizing<[u8; 24]> {
    let mut info = Vec::with_capacity(CHUNK_NONCE_PREFIX.len() + pt_hash.len());
    info.extend_from_slice(CHUNK_NONCE_PREFIX);
    info.extend_from_slice(pt_hash);
    let mut out = Zeroizing::new([0u8; 24]);
    hkdf_expand(k_content, &info, out.as_mut_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_is_deterministic_and_distinct() {
        let root = [0x11u8; 32];
        let vid = [0xC0u8; 32];
        let vr = k_vaultroot(&root, &vid);
        assert_eq!(*vr, *k_vaultroot(&root, &vid), "derivation must be stable");

        let content = k_content(&*vr);
        let manifest = k_manifest(&*vr);
        let audit = k_audit(&*vr);
        // Distinct info strings must yield distinct keys.
        assert_ne!(*content, *manifest);
        assert_ne!(*content, *audit);
        assert_ne!(*manifest, *audit);
        assert_ne!(*k_userid(&root), *k_disclose(&root));
        // Vault scoping: a different vid diverges.
        let vid2 = [0xC1u8; 32];
        assert_ne!(*vr, *k_vaultroot(&root, &vid2));
    }

    #[test]
    fn chunk_key_and_nonce_bind_to_pt_hash() {
        let content = [0x22u8; 32];
        let h1 = [0xAAu8; 32];
        let h2 = [0xABu8; 32];
        assert_eq!(*chunk_key(&content, &h1), *chunk_key(&content, &h1));
        assert_ne!(*chunk_key(&content, &h1), *chunk_key(&content, &h2));
        assert_ne!(*chunk_nonce(&content, &h1), *chunk_nonce(&content, &h2));
        // key and nonce derivations are independent even for the same pt_hash.
        assert_ne!(
            &chunk_key(&content, &h1)[..24],
            &chunk_nonce(&content, &h1)[..]
        );
    }
}
