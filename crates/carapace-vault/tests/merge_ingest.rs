//! End-to-end §11 checks over real ingest: per-file version-vector bump on
//! change/new/delete, and a two-device concurrent-edit merge that keeps both
//! copies instead of silently overwriting.

use carapace_vault::{
    concurrent, dominates, ingest_dir, merge_manifests, new_vid, ChunkStore, MemoryStore, VaultKeys,
};
use carapace_wire::{FileEntry, Manifest, Vv};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::{Path, PathBuf};

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let mut n = [0u8; 8];
        getrandom::getrandom(&mut n).unwrap();
        let dir =
            std::env::temp_dir().join(format!("carapace-merge-{tag}-{}", u64::from_le_bytes(n)));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn keys() -> VaultKeys {
    let (vid, _n) = new_vid(&[0x42u8; 32]);
    VaultKeys::derive(&[0x11u8; 32], vid)
}

fn find<'a>(m: &'a Manifest, path: &str) -> &'a FileEntry {
    m.files.iter().find(|f| f.path == path).expect("entry")
}

/// A device's per-file vector after ingest is keyed by that device's pubkey and
/// counts real changes: new = 1, unchanged carries forward, changed bumps,
/// delete tombstones with a bump.
#[test]
fn ingest_bumps_vv_on_change_new_and_delete() {
    let k = keys();
    let node = SigningKey::from_bytes(&[0x07u8; 32]);
    let np = node.verifying_key().to_bytes();
    let src = TempDir::new("src");
    let mut store = MemoryStore::new();

    fs::write(src.path().join("keep.txt"), b"stable").unwrap();
    fs::write(src.path().join("edit.txt"), b"v1").unwrap();
    let m1 = ingest_dir(src.path(), &node, &k, 1, None, &mut store)
        .unwrap()
        .manifest;

    let want1: Vv = vec![(np, 1)];
    assert_eq!(find(&m1, "keep.txt").version, want1);
    assert_eq!(find(&m1, "edit.txt").version, want1);

    // Round 2: edit one, keep one unchanged, add one, delete none.
    fs::write(src.path().join("edit.txt"), b"v2 changed").unwrap();
    fs::write(src.path().join("new.txt"), b"fresh").unwrap();
    let m2 = ingest_dir(src.path(), &node, &k, 2, Some(&m1), &mut store)
        .unwrap()
        .manifest;

    assert_eq!(
        find(&m2, "keep.txt").version,
        want1,
        "unchanged file keeps its vector"
    );
    assert_eq!(
        find(&m2, "edit.txt").version,
        vec![(np, 2)],
        "changed file bumps this node's component"
    );
    assert_eq!(find(&m2, "new.txt").version, vec![(np, 1)], "new = 1");

    // Round 3: delete edit.txt -> tombstone with a further bump.
    fs::remove_file(src.path().join("edit.txt")).unwrap();
    let m3 = ingest_dir(src.path(), &node, &k, 3, Some(&m2), &mut store)
        .unwrap()
        .manifest;
    let tomb = find(&m3, "edit.txt");
    assert!(tomb.deleted, "deleted file becomes a tombstone");
    assert_eq!(tomb.version, vec![(np, 3)], "tombstone bumps this node");
    assert!(dominates(&tomb.version, &vec![(np, 2)]));
}

/// Two owner devices independently editing the same file from a common state
/// produce concurrent vectors; the merge keeps BOTH (winner at the path, loser
/// renamed) rather than one silently clobbering the other.
#[test]
fn two_device_concurrent_edit_keeps_both() {
    let k = keys();
    let node_a = SigningKey::from_bytes(&[0x0Au8; 32]);
    let node_b = SigningKey::from_bytes(&[0x0Bu8; 32]);

    // Common ancestor: A ingests f.txt.
    let src_a = TempDir::new("a");
    let mut store = MemoryStore::new();
    fs::write(src_a.path().join("f.txt"), b"base").unwrap();
    let m0 = ingest_dir(src_a.path(), &node_a, &k, 1, None, &mut store)
        .unwrap()
        .manifest;

    // Device B fetches m0, edits f.txt, re-ingests from m0.
    let src_b = TempDir::new("b");
    fs::write(src_b.path().join("f.txt"), b"B's edit").unwrap();
    let mb = ingest_dir(src_b.path(), &node_b, &k, 2, Some(&m0), &mut store)
        .unwrap()
        .manifest;

    // Device A concurrently edits f.txt, re-ingests from m0 (never saw B).
    fs::write(src_a.path().join("f.txt"), b"A's own edit is longer").unwrap();
    let ma = ingest_dir(src_a.path(), &node_a, &k, 2, Some(&m0), &mut store)
        .unwrap()
        .manifest;

    // The two vectors must be genuinely concurrent.
    assert!(concurrent(
        &find(&ma, "f.txt").version,
        &find(&mb, "f.txt").version
    ));

    let merged = merge_manifests(&ma, &mb);
    // Both survive: one at f.txt, one renamed to a sync-conflict copy.
    assert_eq!(merged.files.len(), 2, "concurrent edit keeps both");
    assert!(merged.files.iter().any(|e| e.path == "f.txt"));
    assert!(merged
        .files
        .iter()
        .any(|e| e.path.contains(".sync-conflict-") && e.path.ends_with(".txt")));

    // Commutative in the resulting file set.
    let merged_rev = merge_manifests(&mb, &ma);
    let paths = |m: &carapace_vault::MergedManifest| {
        let mut v: Vec<_> = m.files.iter().map(|e| e.path.clone()).collect();
        v.sort();
        v
    };
    assert_eq!(paths(&merged), paths(&merged_rev));

    // The kept copies must be reconstructable from the store (winner keeps its
    // own chunks; the renamed loser keeps its content, just under a new path).
    for e in &merged.files {
        for (id, _pt, _len) in &e.chunks {
            assert!(store.has(id).unwrap(), "chunk for surviving copy present");
        }
    }
}
