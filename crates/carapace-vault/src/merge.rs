//! §11 live-sync conflict resolution: version-vector algebra and per-file /
//! per-manifest merge. Pure logic, network-independent.
//!
//! A version vector ([`Vv`]) maps a device pubkey to a per-file change counter.
//! Each local edit bumps that device's component ([`bump`]); comparing two
//! vectors classifies the relationship as one dominating the other (a
//! fast-forward) or the two being *concurrent* (a genuine conflict). §11:
//!
//! - **Dominance** -> take the dominant entry (live or tombstone).
//! - **Concurrent (or equal-VV) with DISTINCT content** -> BOTH kept: the winner
//!   by `(mtime, content-hash)` keeps the path, the loser is renamed
//!   `path.sync-conflict-<ts>-<h>.<ext>`. Both the winner tie-break and the loser
//!   filename derive from order-independent, content-intrinsic data (mtime +
//!   `file_hash`), never the post-merge joined VV, so 3+ devices converge on an
//!   identical file set regardless of the order they fold manifests in. Identical
//!   content collapses to one survivor (no pointless duplicate).
//! - **Concurrent, delete-vs-edit** -> the edit survives at the path (a
//!   concurrent delete does not resurrect-block a live edit).
//! - **Concurrent, delete-vs-delete** -> the file stays deleted.
//!
//! [`merge_manifests`] applies the per-file rule across the union of paths and
//! is deterministic, commutative (equal resulting file set for `merge(a,b)` and
//! `merge(b,a)`), and idempotent (`merge(a,a) == a`).

use carapace_wire::{FileEntry, Manifest, Vv};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

// ---------------- version-vector algebra --------------------------------

/// A device's counter in `vv`. A missing component is `0`.
fn vv_get(vv: &Vv, dev: &[u8; 32]) -> u64 {
    vv.iter()
        .filter(|(d, _)| d == dev)
        .map(|(_, c)| *c)
        .max()
        .unwrap_or(0)
}

/// Canonical form: entries sorted bytewise by device key, zero-valued
/// components dropped, duplicate keys collapsed to their max. Two vectors that
/// are equal as maps have identical canonical forms, which makes [`FileEntry`]
/// equality (a `Vec` compare) order-insensitive and merge output deterministic.
pub fn canon_vv(vv: &Vv) -> Vv {
    let mut m: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for (d, c) in vv {
        if *c == 0 {
            continue;
        }
        let e = m.entry(*d).or_insert(0);
        *e = (*e).max(*c);
    }
    m.into_iter().collect()
}

/// The relationship between two version vectors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rel {
    /// Equal on every device.
    Equal,
    /// `a >= b` componentwise and `a != b`.
    ADominates,
    /// `b >= a` componentwise and `a != b`.
    BDominates,
    /// Neither dominates: some device where `a > b` and some where `b > a`.
    Concurrent,
}

fn devices(a: &Vv, b: &Vv) -> BTreeSet<[u8; 32]> {
    let mut s = BTreeSet::new();
    for (d, _) in a {
        s.insert(*d);
    }
    for (d, _) in b {
        s.insert(*d);
    }
    s
}

fn classify(a: &Vv, b: &Vv) -> Rel {
    let mut a_gt = false;
    let mut b_gt = false;
    for d in devices(a, b) {
        match vv_get(a, &d).cmp(&vv_get(b, &d)) {
            Ordering::Greater => a_gt = true,
            Ordering::Less => b_gt = true,
            Ordering::Equal => {}
        }
    }
    match (a_gt, b_gt) {
        (false, false) => Rel::Equal,
        (true, false) => Rel::ADominates,
        (false, true) => Rel::BDominates,
        (true, true) => Rel::Concurrent,
    }
}

/// `true` when `a >= b` componentwise AND `a != b` (a strict fast-forward of
/// `b`). Missing components count as `0`.
pub fn dominates(a: &Vv, b: &Vv) -> bool {
    classify(a, b) == Rel::ADominates
}

/// `true` when neither vector dominates and they are not equal (a genuine
/// concurrent conflict).
pub fn concurrent(a: &Vv, b: &Vv) -> bool {
    classify(a, b) == Rel::Concurrent
}

/// `true` when the two vectors are equal on every device (missing = `0`).
pub fn vv_equal(a: &Vv, b: &Vv) -> bool {
    classify(a, b) == Rel::Equal
}

/// Componentwise maximum of two version vectors, in canonical form.
pub fn merge_vv(a: &Vv, b: &Vv) -> Vv {
    let mut m: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for (d, c) in a.iter().chain(b.iter()) {
        if *c == 0 {
            continue;
        }
        let e = m.entry(*d).or_insert(0);
        *e = (*e).max(*c);
    }
    m.into_iter().collect()
}

/// Increment `dev`'s component, recording one local change. Returns the new
/// canonical vector.
pub fn bump(vv: &Vv, dev: &[u8; 32]) -> Vv {
    let mut m: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for (d, c) in vv {
        if *c == 0 {
            continue;
        }
        let e = m.entry(*d).or_insert(0);
        *e = (*e).max(*c);
    }
    *m.entry(*dev).or_insert(0) += 1;
    m.into_iter().collect()
}

// ---------------- per-file merge (§11) ----------------------------------

/// A deterministic, argument-order-independent total key over a file's
/// content-intrinsic identity: `(mtime, file_hash, size)`. Used both to pick the
/// `(mtime, deviceID)`-style path winner on a genuine conflict and to pick a
/// single survivor for otherwise-identical entries. It is intrinsic to the entry
/// (never the post-merge joined VV), so it is IDENTICAL regardless of pairwise
/// fold order across any number of devices (§11, MAJOR 3): `mtime` is primary
/// (the spec's winner rule) and a tie falls to the content hash rather than an
/// order-dependent device attribution.
///
/// ponytail: a `mode`-only difference between two byte-identical, same-mtime
/// entries is not disambiguated here; that corner only picks between two
/// content-identical survivors, so it is cosmetic. Add `mode` to the key if
/// mode-exact convergence is ever required.
fn entry_key(e: &FileEntry) -> (u64, [u8; 32], u64) {
    (e.mtime, e.file_hash, e.size)
}

fn hex_short(bytes: &[u8; 32]) -> String {
    // First 4 bytes -> 8 lowercase hex chars, enough to disambiguate the loser's
    // content in a conflict filename while staying short.
    let mut s = String::with_capacity(8);
    for b in &bytes[..4] {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        s.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
    }
    s
}

/// Build the loser's conflict path: `<dir>/<stem>.sync-conflict-<ts>-<h>.<ext>`,
/// preserving the last extension (`report.txt` -> `report.sync-conflict-….txt`;
/// `archive.tar.gz` -> `archive.tar.sync-conflict-….gz`; `README` and
/// `.gitignore` keep no extension). `ts` is the loser's mtime in unix seconds and
/// `h` is the short (first-4-byte) hex of the loser's `file_hash`.
///
/// Both inputs are content-intrinsic to the losing entry (§11, MAJOR 3): they do
/// not depend on the post-merge joined version vector, so every device names the
/// same losing content the same way regardless of the order it folded manifests
/// in. Termination of the manifest fold still holds because a rename strictly
/// lengthens the stem (a re-collision nests a second `.sync-conflict-` segment
/// rather than reproducing the same path).
fn conflict_path(path: &str, ts: u64, file_hash: &[u8; 32]) -> String {
    let h = hex_short(file_hash);
    let (dir, base) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    // A leading-dot basename (`.gitignore`) has no extension.
    match base.rfind('.') {
        Some(i) if i > 0 => {
            let (stem, ext) = (&base[..i], &base[i + 1..]);
            format!("{dir}{stem}.sync-conflict-{ts}-{h}.{ext}")
        }
        _ => format!("{dir}{base}.sync-conflict-{ts}-{h}"),
    }
}

/// Merge two entries for the *same path* from two devices per §11. Returns one
/// entry (dominance, identical content, delete-vs-edit resolved to the edit, or
/// both deleted) or two (a concurrent edit-vs-edit conflict over DISTINCT
/// content: winner at the path, loser renamed). Every surviving entry carries the
/// merged version vector.
///
/// Conflict identity (winner + loser filename) is derived from order-independent,
/// content-intrinsic data ([`entry_key`], `file_hash`), never the mutated joined
/// VV, so 3+ devices converge on an identical file set no matter what pairwise
/// order they fold in (MAJOR 3). Equal-VV-but-distinct-content is treated as a
/// conflict, never a silent drop (MAJOR 2).
pub fn merge_entries(a: &FileEntry, b: &FileEntry) -> Vec<FileEntry> {
    debug_assert_eq!(a.path, b.path, "merge_entries requires equal paths");
    let mvv = merge_vv(&a.version, &b.version);

    // A clean fast-forward: take the dominant entry (live or tombstone) as-is.
    match classify(&a.version, &b.version) {
        Rel::ADominates => {
            let mut e = a.clone();
            e.version = mvv;
            return vec![e];
        }
        Rel::BDominates => {
            let mut e = b.clone();
            e.version = mvv;
            return vec![e];
        }
        // Equal or Concurrent: resolve by delete-state and content below. Equal is
        // NOT assumed to mean identical content (MAJOR 2) - the hashes are compared.
        Rel::Equal | Rel::Concurrent => {}
    }

    match (a.deleted, b.deleted) {
        // delete-vs-delete: the file stays deleted (single tombstone).
        (true, true) => {
            let mut e = if entry_key(a) >= entry_key(b) {
                a.clone()
            } else {
                b.clone()
            };
            e.version = mvv;
            e.deleted = true;
            vec![e]
        }
        (false, false) => {
            if a.file_hash == b.file_hash {
                // Identical content: one survivor, merged VV. No point keeping two
                // byte-identical copies, and this keeps the fold terminating.
                let mut e = if entry_key(a) >= entry_key(b) {
                    a.clone()
                } else {
                    b.clone()
                };
                e.version = mvv;
                vec![e]
            } else {
                // Distinct concurrent (or equal-VV) content: keep BOTH. Winner by
                // (mtime, content) keeps the path; loser renamed by ITS OWN intrinsic
                // (mtime, file_hash) so every device agrees on the name (MAJOR 2/3).
                let (win, lose) = if entry_key(a) >= entry_key(b) {
                    (a, b)
                } else {
                    (b, a)
                };
                let mut w = win.clone();
                w.version = mvv.clone();
                let mut l = lose.clone();
                l.version = mvv;
                l.path = conflict_path(&lose.path, lose.mtime, &lose.file_hash);
                vec![w, l]
            }
        }
        // delete-vs-edit: the edit survives at the path; the delete is discarded
        // (it does not resurrect-block the live edit).
        _ => {
            let live = if a.deleted { b } else { a };
            let mut e = live.clone();
            e.version = mvv;
            vec![e]
        }
    }
}

// ---------------- manifest merge ----------------------------------------

/// The result of [`merge_manifests`]: the reconciled file set (sorted by path,
/// canonical version vectors, including any `sync-conflict`-renamed copies) and
/// the merged manifest-level version vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedManifest {
    /// Reconciled entries, sorted by path.
    pub files: Vec<FileEntry>,
    /// Merged manifest-level version vector (componentwise max).
    pub vv: Vv,
}

/// Merge two manifests of the same vault per §11, applying [`merge_entries`]
/// across the union of paths (a path present on only one side passes through).
/// Deterministic, commutative in the resulting file set, and idempotent.
pub fn merge_manifests(local: &Manifest, incoming: &Manifest) -> MergedManifest {
    // Fold every entry into a path-keyed map, merging on collision. A
    // concurrent edit-vs-edit conflict re-queues its two outputs (winner at the
    // original path, loser at a renamed path).
    //
    // ponytail: worst-case O(n) re-queues; terminates because a conflict rename
    // strictly lengthens the path stem, so a renamed loser cannot re-collide
    // with the finite set of original paths.
    let mut out: HashMap<String, FileEntry> = HashMap::new();
    let mut work: Vec<FileEntry> = Vec::with_capacity(local.files.len() + incoming.files.len());
    work.extend(local.files.iter().cloned());
    work.extend(incoming.files.iter().cloned());

    while let Some(e) = work.pop() {
        match out.remove(&e.path) {
            None => {
                out.insert(e.path.clone(), e);
            }
            Some(prev) => work.extend(merge_entries(&prev, &e)),
        }
    }

    let mut files: Vec<FileEntry> = out
        .into_values()
        .map(|mut e| {
            e.version = canon_vv(&e.version);
            e
        })
        .collect();
    files.sort_by(|x, y| x.path.cmp(&y.path));

    MergedManifest {
        files,
        vv: merge_vv(&local.vv, &incoming.vv),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn vv(items: &[(u8, u64)]) -> Vv {
        items.iter().map(|(d, c)| (dev(*d), *c)).collect()
    }

    /// A file entry whose content identity (`file_hash`) is tagged by `content`,
    /// so two "different edits" of the same path get DIFFERENT hashes (as real
    /// distinct bytes would) and the same edit gets the same hash. A tombstone has
    /// the all-zero hash.
    fn entry_h(path: &str, mtime: u64, version: Vv, deleted: bool, content: u64) -> FileEntry {
        let file_hash = if deleted {
            [0; 32]
        } else {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&content.to_le_bytes());
            h
        };
        FileEntry {
            path: path.to_string(),
            mode: 0o644,
            mtime,
            size: if deleted { 0 } else { 1 },
            chunks: vec![],
            file_hash,
            version,
            deleted,
        }
    }

    /// Default content: distinct per `mtime`, matching the common test pattern of
    /// using a bumped mtime to stand in for a distinct edit.
    fn entry(path: &str, mtime: u64, version: Vv, deleted: bool) -> FileEntry {
        entry_h(path, mtime, version, deleted, mtime)
    }

    fn manifest(files: Vec<FileEntry>, mvv: Vv) -> Manifest {
        Manifest {
            vid: [0xC0; 32],
            epoch: 1,
            authors: vec![],
            files,
            vv: mvv,
        }
    }

    // ---- vv algebra ----

    #[test]
    fn missing_component_is_zero_and_equality() {
        assert!(vv_equal(&vv(&[(1, 3)]), &vv(&[(1, 3), (2, 0)])));
        assert!(vv_equal(&vv(&[]), &vv(&[(9, 0)])));
        assert!(!vv_equal(&vv(&[(1, 3)]), &vv(&[(1, 4)])));
        assert_eq!(vv_get(&vv(&[(1, 3)]), &dev(2)), 0);
    }

    #[test]
    fn dominance_and_concurrency() {
        // {A:2} dominates {A:1}
        assert!(dominates(&vv(&[(1, 2)]), &vv(&[(1, 1)])));
        assert!(!dominates(&vv(&[(1, 1)]), &vv(&[(1, 2)])));
        // {A:1,B:1} dominates {A:1}
        assert!(dominates(&vv(&[(1, 1), (2, 1)]), &vv(&[(1, 1)])));
        // equal is not dominance
        assert!(!dominates(&vv(&[(1, 1)]), &vv(&[(1, 1)])));
        // {A:2} vs {A:1,B:1} concurrent
        assert!(concurrent(&vv(&[(1, 2)]), &vv(&[(1, 1), (2, 1)])));
        assert!(concurrent(&vv(&[(1, 1), (2, 1)]), &vv(&[(1, 2)])));
        // {A:1} vs {B:1} concurrent
        assert!(concurrent(&vv(&[(1, 1)]), &vv(&[(2, 1)])));
        assert!(!concurrent(&vv(&[(1, 2)]), &vv(&[(1, 1)])));
    }

    #[test]
    fn merge_and_bump() {
        assert_eq!(
            merge_vv(&vv(&[(1, 2)]), &vv(&[(1, 1), (2, 5)])),
            vv(&[(1, 2), (2, 5)])
        );
        // bump increments only the named device
        assert_eq!(bump(&vv(&[]), &dev(1)), vv(&[(1, 1)]));
        assert_eq!(bump(&vv(&[(1, 1), (2, 3)]), &dev(1)), vv(&[(1, 2), (2, 3)]));
        // canonical: sorted, zeros dropped
        assert_eq!(
            canon_vv(&vv(&[(2, 1), (1, 0), (1, 2)])),
            vv(&[(1, 2), (2, 1)])
        );
        // merged dominates each input
        let m = merge_vv(&vv(&[(1, 2)]), &vv(&[(2, 1)]));
        assert!(dominates(&m, &vv(&[(1, 2)])));
        assert!(dominates(&m, &vv(&[(2, 1)])));
    }

    // ---- per-file merge ----

    #[test]
    fn fast_forward_takes_dominant_no_conflict() {
        // B is a strict fast-forward of A: single survivor, no rename.
        let a = entry("f.txt", 100, vv(&[(1, 1)]), false);
        let b = entry("f.txt", 200, vv(&[(1, 1), (2, 1)]), false);
        let out = merge_entries(&a, &b);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "f.txt");
        assert_eq!(out[0].mtime, 200, "dominant (B) entry survives");
        assert_eq!(out[0].version, vv(&[(1, 1), (2, 1)]));
    }

    #[test]
    fn concurrent_edit_keeps_both_winner_by_mtime() {
        // Concurrent; B has the higher mtime, so B keeps the path and A (dev 1)
        // is renamed, extension preserved.
        let a = entry("docs/report.txt", 100, vv(&[(1, 2)]), false); // from ancestor {A:1}
        let b = entry("docs/report.txt", 200, vv(&[(1, 1), (2, 1)]), false);
        let out = merge_entries(&a, &b);
        assert_eq!(out.len(), 2, "both kept");
        let winner = out.iter().find(|e| e.path == "docs/report.txt").unwrap();
        assert_eq!(winner.mtime, 200, "higher mtime wins the path");
        let loser = out.iter().find(|e| e.path != "docs/report.txt").unwrap();
        // Loser renamed by ITS OWN mtime + content hash (order-independent), with
        // the extension preserved.
        assert_eq!(
            loser.path,
            conflict_path("docs/report.txt", 100, &a.file_hash),
            "loser renamed with preserved extension + loser mtime + content hash"
        );
        assert!(
            loser.path.starts_with("docs/report.sync-conflict-100-")
                && loser.path.ends_with(".txt")
        );
        // both carry the merged vv
        let mvv = vv(&[(1, 2), (2, 1)]);
        assert_eq!(winner.version, mvv);
        assert_eq!(loser.version, mvv);
    }

    #[test]
    fn concurrent_edit_mtime_tie_broken_by_content_hash() {
        // Equal mtime, distinct content -> the higher (bytewise) file_hash wins the
        // path; the tie-break is content-intrinsic and order-independent, NOT the
        // post-merge device attribution. Content 0x22 > 0x11, so B wins.
        let a = entry_h("x", 500, vv(&[(1, 1)]), false, 0x11);
        let b = entry_h("x", 500, vv(&[(2, 1)]), false, 0x22);
        let ab = merge_entries(&a, &b);
        let ba = merge_entries(&b, &a);
        assert_eq!(ab.len(), 2);
        // Order-independent: same winner + same loser name whichever way we fold.
        assert_eq!(
            ab[0].file_hash,
            ba.iter().find(|e| e.path == "x").unwrap().file_hash
        );
        let winner = ab.iter().find(|e| e.path == "x").unwrap();
        assert_eq!(
            winner.file_hash, b.file_hash,
            "higher content hash wins the tie"
        );
        let loser = ab.iter().find(|e| e.path != "x").unwrap();
        assert_eq!(
            loser.path,
            conflict_path("x", 500, &a.file_hash),
            "loser is A, no extension, named by its own content hash"
        );
    }

    #[test]
    fn equal_vv_distinct_content_becomes_conflict_not_silent_drop() {
        // MAJOR 2: two entries with the SAME version vector but DIFFERENT content
        // must both survive (a conflict copy), never a silent discard of one body.
        let a = entry_h("f.txt", 100, vv(&[(1, 1)]), false, 0xAA);
        let b = entry_h("f.txt", 200, vv(&[(1, 1)]), false, 0xBB);
        assert!(vv_equal(&a.version, &b.version), "same VV precondition");
        let out = merge_entries(&a, &b);
        assert_eq!(out.len(), 2, "both distinct bodies kept, none dropped");
        let hashes: BTreeSet<[u8; 32]> = out.iter().map(|e| e.file_hash).collect();
        assert!(hashes.contains(&a.file_hash) && hashes.contains(&b.file_hash));
        // Same VV, same content -> a single survivor (no spurious conflict copy).
        let c = entry_h("f.txt", 100, vv(&[(1, 1)]), false, 0xCC);
        let d = entry_h("f.txt", 200, vv(&[(1, 1)]), false, 0xCC);
        assert_eq!(
            merge_entries(&c, &d).len(),
            1,
            "identical content -> one survivor"
        );
    }

    #[test]
    fn conflict_name_preserves_last_extension_variants() {
        // multi-dot: only the last extension is preserved
        let a = entry("a/archive.tar.gz", 10, vv(&[(1, 2)]), false);
        let b = entry("a/archive.tar.gz", 20, vv(&[(1, 1), (2, 1)]), false);
        let loser = merge_entries(&a, &b)
            .into_iter()
            .find(|e| e.path != "a/archive.tar.gz")
            .unwrap();
        assert_eq!(
            loser.path,
            conflict_path("a/archive.tar.gz", 10, &a.file_hash)
        );
        assert!(
            loser.path.starts_with("a/archive.tar.sync-conflict-10-")
                && loser.path.ends_with(".gz")
        );

        // dotfile has no extension
        let c = entry(".gitignore", 10, vv(&[(1, 2)]), false);
        let d = entry(".gitignore", 20, vv(&[(1, 1), (2, 1)]), false);
        let loser = merge_entries(&c, &d)
            .into_iter()
            .find(|e| e.path != ".gitignore")
            .unwrap();
        assert_eq!(loser.path, conflict_path(".gitignore", 10, &c.file_hash));
        assert!(
            loser.path.starts_with(".gitignore.sync-conflict-10-")
                && !loser.path.ends_with(".gitignore")
        );
    }

    #[test]
    fn delete_vs_edit_concurrent_edit_survives() {
        // A deletes (tombstone), B edits, concurrent -> the edit survives.
        let tomb = entry("f", 300, vv(&[(1, 2)]), true); // ancestor {A:1}, A deleted
        let edit = entry("f", 400, vv(&[(1, 1), (2, 1)]), false); // B edited
        let out = merge_entries(&tomb, &edit);
        assert_eq!(out.len(), 1, "single survivor");
        assert!(!out[0].deleted, "edit survives");
        assert_eq!(out[0].path, "f");
        assert_eq!(out[0].version, vv(&[(1, 2), (2, 1)]));
    }

    #[test]
    fn delete_dominates_edit_file_deleted() {
        // Tombstone that dominates the edit -> file is deleted.
        let edit = entry("f", 100, vv(&[(1, 1)]), false);
        let tomb = entry("f", 200, vv(&[(1, 2)]), true);
        let out = merge_entries(&edit, &tomb);
        assert_eq!(out.len(), 1);
        assert!(out[0].deleted, "dominant tombstone -> deleted");
    }

    #[test]
    fn edit_dominates_delete_edit_survives() {
        let tomb = entry("f", 100, vv(&[(1, 1)]), true);
        let edit = entry("f", 200, vv(&[(1, 2)]), false);
        let out = merge_entries(&tomb, &edit);
        assert_eq!(out.len(), 1);
        assert!(!out[0].deleted, "dominant edit -> live");
    }

    #[test]
    fn concurrent_delete_vs_delete_stays_deleted() {
        let ta = entry("f", 100, vv(&[(1, 2)]), true);
        let tb = entry("f", 200, vv(&[(2, 1)]), true);
        let out = merge_entries(&ta, &tb);
        assert_eq!(out.len(), 1);
        assert!(out[0].deleted);
        assert_eq!(out[0].version, vv(&[(1, 2), (2, 1)]));
    }

    // ---- manifest merge: commutativity, idempotence, convergence ----

    fn path_set(m: &MergedManifest) -> Vec<String> {
        let mut v: Vec<String> = m.files.iter().map(|e| e.path.clone()).collect();
        v.sort();
        v
    }

    #[test]
    fn passthrough_union_of_disjoint_paths() {
        let la = manifest(vec![entry("a", 1, vv(&[(1, 1)]), false)], vv(&[(1, 1)]));
        let lb = manifest(vec![entry("b", 1, vv(&[(2, 1)]), false)], vv(&[(2, 1)]));
        let m = merge_manifests(&la, &lb);
        assert_eq!(path_set(&m), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(m.vv, vv(&[(1, 1), (2, 1)]));
    }

    #[test]
    fn merge_is_commutative_in_file_set() {
        let a = manifest(
            vec![
                entry("shared.txt", 100, vv(&[(1, 2)]), false),
                entry("only_a", 1, vv(&[(1, 1)]), false),
            ],
            vv(&[(1, 2)]),
        );
        let b = manifest(
            vec![
                entry("shared.txt", 200, vv(&[(1, 1), (2, 1)]), false),
                entry("only_b", 1, vv(&[(2, 1)]), false),
            ],
            vv(&[(1, 1), (2, 1)]),
        );
        let ab = merge_manifests(&a, &b);
        let ba = merge_manifests(&b, &a);
        assert_eq!(path_set(&ab), path_set(&ba));
        assert_eq!(ab.files, ba.files, "full entry set order-independent");
        assert_eq!(ab.vv, ba.vv);
        // the shared concurrent edit produced a conflict copy
        assert!(ab.files.iter().any(|e| e.path == "shared.txt"));
        assert!(ab.files.iter().any(|e| e.path.contains("sync-conflict")));
    }

    #[test]
    fn merge_is_idempotent() {
        let a = manifest(
            vec![
                entry("a", 100, vv(&[(1, 2)]), false),
                entry("gone", 50, vv(&[(1, 1)]), true),
            ],
            vv(&[(1, 2)]),
        );
        let once = merge_manifests(&a, &a);
        // input vvs are already canonical, so merge(a,a) reproduces a
        assert_eq!(once.files, a.files);
        assert_eq!(once.vv, canon_vv(&a.vv));
    }

    #[test]
    fn three_way_convergence() {
        // Common ancestor {A:1}; A, B, C each edit "f" concurrently.
        let anc = vv(&[(1, 1)]);
        let ea = entry("f", 100, bump(&anc, &dev(1)), false); // {A:2}
        let eb = entry("f", 200, bump(&anc, &dev(2)), false); // {A:1,B:1}
        let ec = entry("f", 300, bump(&anc, &dev(3)), false); // {A:1,C:1}
        let ma = manifest(vec![ea.clone()], vv(&[(1, 2)]));
        let mb = manifest(vec![eb.clone()], vv(&[(1, 1), (2, 1)]));
        let mc = manifest(vec![ec.clone()], vv(&[(1, 1), (3, 1)]));

        // Two different merge orders must reach the same set of paths.
        let ab_c = {
            let ab = merge_manifests(&ma, &mb);
            merge_manifests(&mm(&ab), &mc)
        };
        let bc_a = {
            let bc = merge_manifests(&mb, &mc);
            merge_manifests(&mm(&bc), &ma)
        };
        assert_eq!(path_set(&ab_c), path_set(&bc_a), "path set converges");
        // C has the highest mtime, so C keeps the original path in both orders.
        let keep_ab = ab_c.files.iter().find(|e| e.path == "f").unwrap();
        let keep_bc = bc_a.files.iter().find(|e| e.path == "f").unwrap();
        assert_eq!(keep_ab.mtime, 300);
        assert_eq!(keep_bc.mtime, 300);
        // Exactly three entries: the winner + two conflict copies.
        assert_eq!(ab_c.files.len(), 3);
        assert_eq!(bc_a.files.len(), 3);

        // A second reconciliation of the two orders converges VVs fully.
        let round2 = merge_manifests(&mm(&ab_c), &mm(&bc_a));
        let round2b = merge_manifests(&mm(&bc_a), &mm(&ab_c));
        assert_eq!(round2.files, round2b.files, "fully converged and stable");
    }

    /// Rebuild a `Manifest` from a `MergedManifest` for chained merges.
    fn mm(m: &MergedManifest) -> Manifest {
        manifest(m.files.clone(), m.vv.clone())
    }
}
