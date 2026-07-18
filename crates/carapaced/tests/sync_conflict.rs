//! §11 multi-device conflict reconciliation between two owner daemons sharing one `k_root`
//! but distinct node keys. Both publish a concurrent change to the same path (neither VV
//! dominates), then reconcile over bounded rounds. Proves: no loss on edit-vs-edit (winner at
//! the path, loser at `path.sync-conflict-*.ext`), edit wins delete-vs-edit, and convergence
//! (a fixed point well within the cap; a per-call timeout fails a ping-pong regression fast).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Result};
use carapaced::{Daemon, Reconstructed, State};
use iroh::EndpointAddr;

/// Shared user master key: same user, two devices.
const K_ROOT: [u8; 32] = [0x44; 32];

/// Hard ceiling on reconcile rounds. Both scenarios converge in ~3; this is pure
/// anti-hang headroom. Reaching it is a test failure (non-convergence).
const MAX_ROUNDS: usize = 10;

/// Per-call wall-clock bound. A single small-vault sync completes in well under a
/// second; exceeding this means a deadlock, not slowness.
const CALL_TIMEOUT: Duration = Duration::from_secs(25);

/// One anti-entropy pull, bounded so a deadlock surfaces as a failed assertion
/// rather than a hung test process.
async fn pull(d: &Daemon, peer: EndpointAddr, out: &Path) -> Result<Vec<Reconstructed>> {
    match tokio::time::timeout(CALL_TIMEOUT, d.sync_from(peer, out)).await {
        Ok(res) => res,
        Err(_) => bail!("sync_from did not finish within {CALL_TIMEOUT:?}: possible deadlock/hang"),
    }
}

/// Drive `b <- a` then `a <- b` for up to [`MAX_ROUNDS`], stopping the instant a
/// full round reconstructs nothing new for `vid` on either side (the fixed
/// point). Returns the two devices' on-disk vault directories. Panics via
/// assertion if it fails to converge inside the cap.
async fn reconcile(
    daemon_a: &Daemon,
    daemon_b: &Daemon,
    vid: [u8; 32],
    out_a: &Path,
    out_b: &Path,
) -> Result<(PathBuf, PathBuf)> {
    let addr_a = daemon_a.addr()?;
    let addr_b = daemon_b.addr()?;
    let mut a_dir: Option<PathBuf> = None;
    let mut b_dir: Option<PathBuf> = None;

    let mut converged = false;
    let mut rounds = 0;
    while rounds < MAX_ROUNDS {
        rounds += 1;
        let b_got = pull(daemon_b, addr_a.clone(), out_b).await?;
        let a_got = pull(daemon_a, addr_b.clone(), out_a).await?;

        if let Some(r) = b_got.iter().find(|r| r.vid == vid) {
            b_dir = Some(r.out_dir.clone());
        }
        if let Some(r) = a_got.iter().find(|r| r.vid == vid) {
            a_dir = Some(r.out_dir.clone());
        }

        // A round that pulls nothing newer in EITHER direction is the fixed point: the
        // idempotent merge stopped republishing, so every further pull is a no-op.
        let touched = a_got.iter().any(|r| r.vid == vid) || b_got.iter().any(|r| r.vid == vid);
        if !touched {
            converged = true;
            break;
        }
    }

    assert!(
        converged,
        "sync did not converge within {MAX_ROUNDS} rounds - re-publish ping-pong regression"
    );
    Ok((
        a_dir.expect("device A never reconstructed the vault"),
        b_dir.expect("device B never reconstructed the vault"),
    ))
}

/// Flat directory listing: file name -> bytes. Both scenarios use top-level
/// paths only (conflict renames never introduce a `/`), so no recursion needed.
fn dir_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(dir).expect("read vault out dir") {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            out.insert(name, std::fs::read(entry.path()).unwrap());
        }
    }
    out
}

/// Concurrent edit-vs-edit on the same path (no shared ancestry, neither VV dominates): after
/// a bounded reconcile BOTH devices hold BOTH bodies - winner at `notes.txt`, loser at
/// `notes.sync-conflict-*.txt` with the extension preserved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_edit_same_path_keeps_both_no_loss() -> Result<()> {
    const ALPHA: &[u8] = b"device A wrote these notes first";
    const BRAVO: &[u8] = b"device B wrote entirely different notes";

    let daemon_a = Daemon::start(State::from_seeds([0x51; 32], K_ROOT)).await?;
    let daemon_b = Daemon::start(State::from_seeds([0x5b; 32], K_ROOT)).await?;
    assert_ne!(daemon_a.node_id(), daemon_b.node_id());

    // Same vid on both devices; each publishes its own concurrent body.
    let (vid, _n) = daemon_a.new_vid();
    let src_a = tempfile::tempdir()?;
    let src_b = tempfile::tempdir()?;
    std::fs::write(src_a.path().join("notes.txt"), ALPHA)?;
    std::fs::write(src_b.path().join("notes.txt"), BRAVO)?;
    assert_eq!(daemon_a.publish_vault(src_a.path(), vid).await?, 1);
    assert_eq!(daemon_b.publish_vault(src_b.path(), vid).await?, 1);

    let out_a = tempfile::tempdir()?;
    let out_b = tempfile::tempdir()?;
    let (a_dir, b_dir) = reconcile(&daemon_a, &daemon_b, vid, out_a.path(), out_b.path()).await?;

    // Both devices must agree on the same reconciled tree, and it must contain
    // both edits: winner at the path, loser renamed, extension preserved.
    for (who, dir) in [("A", &a_dir), ("B", &b_dir)] {
        let files = dir_files(dir);
        assert_eq!(
            files.len(),
            2,
            "device {who}: expected winner + one conflict copy, got {:?}",
            files.keys().collect::<Vec<_>>()
        );

        let winner = files
            .get("notes.txt")
            .unwrap_or_else(|| panic!("device {who}: winner must keep notes.txt"));

        let (cname, loser) = files
            .iter()
            .find(|(n, _)| n.contains("sync-conflict"))
            .unwrap_or_else(|| panic!("device {who}: loser must be renamed"));
        assert!(
            cname.starts_with("notes.sync-conflict-") && cname.ends_with(".txt"),
            "device {who}: conflict name must preserve stem+ext, got {cname}"
        );

        let bodies: BTreeSet<&[u8]> = [winner.as_slice(), loser.as_slice()].into_iter().collect();
        assert_eq!(
            bodies,
            [ALPHA, BRAVO].into_iter().collect::<BTreeSet<_>>(),
            "device {who}: both edits must survive, none lost"
        );
    }

    // Cross-device agreement: identical file set on both ends.
    assert_eq!(
        dir_files(&a_dir).keys().collect::<Vec<_>>(),
        dir_files(&b_dir).keys().collect::<Vec<_>>(),
        "both devices must converge on the same file names"
    );

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;
    Ok(())
}

/// Delete-vs-edit: A deletes `data.txt` while B concurrently edits it. §11 resolves to the
/// edit surviving; after a bounded reconcile BOTH devices hold the edit, no tombstone/conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_vs_edit_edit_survives_on_both() -> Result<()> {
    const ORIG: &[u8] = b"the original body on device A";
    const EDIT: &[u8] = b"device B kept editing this file";

    let daemon_a = Daemon::start(State::from_seeds([0x61; 32], K_ROOT)).await?;
    let daemon_b = Daemon::start(State::from_seeds([0x6b; 32], K_ROOT)).await?;

    let (vid, _n) = daemon_a.new_vid();

    // Device A: publish, then delete and republish -> a tombstone carrying A's bumped VV.
    let src_a = tempfile::tempdir()?;
    std::fs::write(src_a.path().join("data.txt"), ORIG)?;
    assert_eq!(daemon_a.publish_vault(src_a.path(), vid).await?, 1);
    std::fs::remove_file(src_a.path().join("data.txt"))?;
    assert_eq!(
        daemon_a.publish_vault(src_a.path(), vid).await?,
        2,
        "the delete republishes a tombstone at a bumped epoch"
    );

    // Device B: concurrently publish an independent edit; B's {b:1} is concurrent with A's tombstone.
    let src_b = tempfile::tempdir()?;
    std::fs::write(src_b.path().join("data.txt"), EDIT)?;
    assert_eq!(daemon_b.publish_vault(src_b.path(), vid).await?, 1);

    let out_a = tempfile::tempdir()?;
    let out_b = tempfile::tempdir()?;
    let (a_dir, b_dir) = reconcile(&daemon_a, &daemon_b, vid, out_a.path(), out_b.path()).await?;

    for (who, dir) in [("A", &a_dir), ("B", &b_dir)] {
        let files = dir_files(dir);
        assert_eq!(
            files.len(),
            1,
            "device {who}: only the surviving edit, no tombstone/conflict artifact, got {:?}",
            files.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            files.get("data.txt").map(Vec::as_slice),
            Some(EDIT),
            "device {who}: the concurrent edit must survive the delete"
        );
    }

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;
    Ok(())
}
