//! BLOCKER 1 regression: a filesystem watcher on a vault's working directory must
//! not tombstone files that a sync merged INTO that directory.
//!
//! Two owner daemons share one `k_root`. Device A watches its working dir. The two
//! reconcile a vault whose merge yields (a) a file that exists only on B (a pure
//! union, synced INTO A's working dir) and (b) a `sync-conflict-*` copy from a
//! concurrent edit. A watcher tick then fires (a genuine local change). The bug
//! was: the watcher re-ingested a directory that the sync had written to a
//! DIFFERENT location, saw the synced-in file "absent from disk", and minted a
//! dominating tombstone that deleted it on every device (silent data loss).
//!
//! With the unified working-directory model the sync reconstructs into the watched
//! tree, so the re-ingest sees the full merged set and mints NO tombstone. The test
//! proves it by advancing past a watcher re-ingest and then confirming both the
//! synced-in file AND the conflict copy still round-trip to a peer - i.e. neither
//! was tombstoned. Every wait is hard-bounded, so a regression fails fast.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use carapaced::{Daemon, Reconstructed, State};
use iroh::EndpointAddr;

const K_ROOT: [u8; 32] = [0x9c; 32];
/// Per-`sync_from` wall-clock bound: a small-vault sync is sub-second, so this only
/// ever trips on a deadlock.
const CALL_TIMEOUT: Duration = Duration::from_secs(25);
/// Anti-hang ceiling on reconcile rounds; convergence takes ~3.
const MAX_ROUNDS: usize = 12;
/// Bound on how long we wait for the watcher to observe a change and re-ingest.
const WATCH_DEADLINE: Duration = Duration::from_secs(15);

async fn pull(d: &Daemon, peer: EndpointAddr, out: &Path) -> Result<Vec<Reconstructed>> {
    match tokio::time::timeout(CALL_TIMEOUT, d.sync_from(peer, out)).await {
        Ok(res) => res,
        Err(_) => bail!("sync_from did not finish within {CALL_TIMEOUT:?}: deadlock/hang"),
    }
}

/// Reconcile `a` and `b` for `vid` until a full round pulls nothing new in either
/// direction (the fixed point). `out_a`/`out_b` are the fallback out-roots; owned
/// vaults reconstruct into their recorded working dirs regardless.
async fn reconcile(
    a: &Daemon,
    b: &Daemon,
    vid: [u8; 32],
    out_a: &Path,
    out_b: &Path,
) -> Result<()> {
    let addr_a = a.addr()?;
    let addr_b = b.addr()?;
    for _ in 0..MAX_ROUNDS {
        let b_got = pull(b, addr_a.clone(), out_b).await?;
        let a_got = pull(a, addr_b.clone(), out_a).await?;
        let touched = a_got.iter().any(|r| r.vid == vid) || b_got.iter().any(|r| r.vid == vid);
        if !touched {
            return Ok(());
        }
    }
    bail!("did not converge within {MAX_ROUNDS} rounds");
}

/// File-name set of a directory (flat; conflict renames never add a `/`).
fn names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

fn epoch_of(d: &Daemon, vid: [u8; 32]) -> u64 {
    d.published_vaults()
        .into_iter()
        .find(|(v, _)| *v == vid)
        .map(|(_, e)| e)
        .unwrap_or(0)
}

/// Poll until `vid`'s epoch on `d` exceeds `from`, or fail at the deadline.
async fn wait_epoch_above(d: &Daemon, vid: [u8; 32], from: u64) -> Result<u64> {
    let poll = async {
        loop {
            let e = epoch_of(d, vid);
            if e > from {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    match tokio::time::timeout(WATCH_DEADLINE, poll).await {
        Ok(e) => Ok(e),
        Err(_) => bail!("watcher did not re-ingest within {WATCH_DEADLINE:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watcher_does_not_tombstone_synced_in_files() -> Result<()> {
    const A_NOTES: &[u8] = b"device A concurrent notes";
    const B_NOTES: &[u8] = b"device B concurrent notes (different)";
    const A_ONLY: &[u8] = b"exists only on A";
    const B_ONLY: &[u8] = b"exists only on B - this is the synced-in file";

    let daemon_a = Arc::new(Daemon::start(State::from_seeds([0xa1; 32], K_ROOT)).await?);
    let daemon_b = Daemon::start(State::from_seeds([0xb1; 32], K_ROOT)).await?;

    let (vid, _n) = daemon_a.new_vid();

    // A's working dir (which A will WATCH) and B's working dir.
    let src_a = tempfile::tempdir()?;
    let src_b = tempfile::tempdir()?;
    std::fs::write(src_a.path().join("notes.txt"), A_NOTES)?; // concurrent w/ B
    std::fs::write(src_a.path().join("a_only.txt"), A_ONLY)?;
    std::fs::write(src_b.path().join("notes.txt"), B_NOTES)?; // concurrent w/ A
    std::fs::write(src_b.path().join("b_only.txt"), B_ONLY)?;

    daemon_a.publish_vault(src_a.path(), vid).await?;
    daemon_b.publish_vault(src_b.path(), vid).await?;

    // Arm the watcher on A's working dir BEFORE reconciling, so the sync's writes
    // into it (the synced-in b_only.txt and the conflict copy) actually fire the
    // watcher - the exact condition that used to trigger the tombstone bug.
    let watcher = Arc::clone(&daemon_a).watch_vault(vid, src_a.path().to_path_buf())?;

    let out_a = tempfile::tempdir()?;
    let out_b = tempfile::tempdir()?;
    reconcile(&daemon_a, &daemon_b, vid, out_a.path(), out_b.path()).await?;

    // After reconcile, A's WATCHED working dir must hold the full merged set: its own
    // file, the synced-in B-only file, the conflict winner, and the conflict loser.
    let a_names = names(src_a.path());
    let conflict = a_names
        .iter()
        .find(|n| n.contains("sync-conflict"))
        .cloned()
        .expect("a conflict copy must exist from the concurrent edit");
    let expected: BTreeSet<String> = ["notes.txt", "a_only.txt", "b_only.txt", conflict.as_str()]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(
        a_names, expected,
        "A's watched working dir must contain the synced-in file + conflict copy"
    );

    // Force an observable watcher re-ingest with a genuine local change. If the bug
    // were present, this re-ingest of A's working dir would tombstone b_only.txt and
    // the conflict copy (seen as "absent" because the sync had written them
    // elsewhere), and the tombstone would then propagate and delete them on B.
    let e0 = epoch_of(&daemon_a, vid);
    tokio::time::sleep(Duration::from_millis(100)).await; // let the watcher settle
    std::fs::write(src_a.path().join("trigger.txt"), b"local change")?;
    wait_epoch_above(&daemon_a, vid, e0).await?;

    // Propagate the re-ingested state to B and quiesce.
    reconcile(&daemon_a, &daemon_b, vid, out_a.path(), out_b.path()).await?;

    // The decisive assertion: NOTHING was tombstoned. Both devices hold every file -
    // A's own, B's own (synced in), the conflict winner + loser, and the trigger.
    let final_expected: BTreeSet<String> = [
        "notes.txt",
        "a_only.txt",
        "b_only.txt",
        "trigger.txt",
        conflict.as_str(),
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        names(src_a.path()),
        final_expected,
        "A lost a file after its own watcher re-ingested the working dir"
    );
    assert_eq!(
        names(src_b.path()),
        final_expected,
        "B lost the synced-in file or conflict copy (a tombstone leaked across)"
    );

    // And the bytes survived, not just the names: B still has A-only and its own body.
    assert_eq!(std::fs::read(src_b.path().join("a_only.txt"))?, A_ONLY);
    assert_eq!(std::fs::read(src_a.path().join("b_only.txt"))?, B_ONLY);

    drop(watcher);
    let daemon_a = Arc::try_unwrap(daemon_a)
        .map_err(|_| anyhow::anyhow!("watcher still holds a strong daemon ref"))?;
    daemon_a.shutdown().await;
    daemon_b.shutdown().await;
    Ok(())
}
