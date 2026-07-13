//! End-to-end vault round-trip: ingest a directory (including a file that spans
//! multiple FastCDC chunks) into a manifest + chunk store, then reconstruct and
//! assert byte-identity, ChunkID integrity, and envelope seal/open/verify.

use carapace_vault::{
    ingest_dir, new_vid, open_envelope, reconstruct, ChunkStore, FsStore, MemoryStore, VaultKeys,
};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;

/// A throwaway unique directory under the system temp dir.
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let mut n = [0u8; 8];
        getrandom::getrandom(&mut n).unwrap();
        let dir = std::env::temp_dir().join(format!("carapace-vault-{tag}-{}", u64::from_le_bytes(n)));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Pseudo-random-ish bytes so FastCDC actually finds cut points.
fn varied(len: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; len];
    let mut x = seed | 1;
    for b in v.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    v
}

fn write_tree(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let big = varied(3 * 1024 * 1024, 0xDEAD_BEEF); // > 256 KiB => multiple chunks
    let files: Vec<(String, Vec<u8>)> = vec![
        ("a.txt".to_string(), b"hello vault".to_vec()),
        ("sub/big.bin".to_string(), big),
        ("sub/nested/c.dat".to_string(), b"small nested file".to_vec()),
        ("empty".to_string(), Vec::new()),
    ];
    for (rel, data) in &files {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
    }
    files
}

fn setup() -> (VaultKeys, SigningKey) {
    let k_root = [0x11u8; 32];
    let node_key = SigningKey::from_bytes(&[0x07u8; 32]);
    let user_pub = [0x42u8; 32];
    let (vid, _nonce) = new_vid(&user_pub);
    (VaultKeys::derive(&k_root, vid), node_key)
}

#[test]
fn full_roundtrip_memory_store() {
    let src = TempDir::new("src");
    let out = TempDir::new("out");
    let originals = write_tree(src.path());

    let (keys, node_key) = setup();
    let mut store = MemoryStore::new();
    let ingest = ingest_dir(src.path(), &node_key, &keys, 1, &mut store).unwrap();

    // The big file must have been cut into more than one chunk.
    let big = ingest
        .manifest
        .files
        .iter()
        .find(|f| f.path == "sub/big.bin")
        .expect("big file present");
    assert!(big.chunks.len() > 1, "big file should span multiple FastCDC chunks");
    assert!(!store.is_empty());

    // (b) each stored ciphertext's BLAKE3 == its ChunkID == the chunk ref id.
    for file in &ingest.manifest.files {
        for (id, _len) in &file.chunks {
            let ct = store.get(id).unwrap().expect("chunk stored");
            assert_eq!(*blake3::hash(&ct).as_bytes(), *id, "ChunkID = BLAKE3(ciphertext)");
        }
    }

    // Reconstruct from the (opened) manifest and assert byte-identity.
    let manifest = open_envelope(&ingest.envelope, &keys.k_manifest).unwrap();
    assert_eq!(manifest, ingest.manifest, "opened manifest matches sealed input");
    reconstruct(&manifest, &store, &ingest.keys, out.path()).unwrap();

    for (rel, data) in &originals {
        let got = fs::read(out.path().join(rel)).unwrap();
        assert_eq!(&got, data, "reconstructed {rel} must be byte-identical");
    }
}

#[test]
fn envelope_seal_open_verify_and_digest() {
    let src = TempDir::new("src");
    write_tree(src.path());
    let (keys, node_key) = setup();
    let mut store = MemoryStore::new();
    let ingest = ingest_dir(src.path(), &node_key, &keys, 7, &mut store).unwrap();

    // Node signature verifies and digest is BLAKE3 of the envelope bytes.
    assert!(ingest.envelope.verify().is_ok());
    assert_eq!(*blake3::hash(&ingest.envelope.to_bytes()).as_bytes(), ingest.digest);

    // Wrong manifest key fails to open (aad/key bound).
    let wrong = [0u8; 32];
    assert!(open_envelope(&ingest.envelope, &wrong).is_err());

    // Tampered signature fails verification.
    let mut tampered = ingest.envelope.clone();
    tampered.sig[0] ^= 0xff;
    assert!(open_envelope(&tampered, &keys.k_manifest).is_err());

    // Tampered epoch breaks the aad and fails to decrypt.
    let mut wrong_epoch = ingest.envelope.clone();
    wrong_epoch.epoch = 8;
    assert!(open_envelope(&wrong_epoch, &keys.k_manifest).is_err());
}

#[test]
fn full_roundtrip_fs_store() {
    let src = TempDir::new("src");
    let out = TempDir::new("out");
    let blobs = TempDir::new("blobs");
    let originals = write_tree(src.path());

    let (keys, node_key) = setup();
    let mut store = FsStore::open(blobs.path()).unwrap();
    let ingest = ingest_dir(src.path(), &node_key, &keys, 1, &mut store).unwrap();

    reconstruct(&ingest.manifest, &store, &ingest.keys, out.path()).unwrap();
    for (rel, data) in &originals {
        assert_eq!(&fs::read(out.path().join(rel)).unwrap(), data);
    }
}
