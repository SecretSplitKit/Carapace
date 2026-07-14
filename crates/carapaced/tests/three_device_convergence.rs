//! MAJOR 3 regression: 3+ device convergence on a concurrent edit must be
//! order-independent.
//!
//! Three owner daemons share one `k_root` and each publishes a DIFFERENT body for
//! the same path in the same vault, with no shared ancestry, so all three edits are
//! mutually concurrent. The bug: the winner tie-break and the `sync-conflict-<dev>`
//! filename were derived from the POST-MERGE joined version vector, so different
//! pairwise fold orders on different devices produced different winners / conflict
//! names - the devices ended up with DIFFERENT file sets (permanent divergence).
//!
//! The fix derives both the winner and the conflict name from order-independent,
//! content-intrinsic data (mtime + file_hash). This test reconciles the three
//! devices to a fixed point and asserts they converge on an IDENTICAL file set -
//! same winner path, same two conflict-copy names - with all three bodies present
//! (nothing dropped). Bounded and self-terminating.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use carapaced::{Daemon, Reconstructed, State};
use iroh::EndpointAddr;

const K_ROOT: [u8; 32] = [0x3d; 32];
const CALL_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_ROUNDS: usize = 20;

async fn pull(d: &Daemon, peer: EndpointAddr, out: &Path) -> Result<Vec<Reconstructed>> {
    match tokio::time::timeout(CALL_TIMEOUT, d.sync_from(peer, out)).await {
        Ok(res) => res,
        Err(_) => bail!("sync_from did not finish within {CALL_TIMEOUT:?}: deadlock/hang"),
    }
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

/// Bodies present anywhere in a directory (order-independent content check).
fn bodies(dir: &Path) -> BTreeSet<Vec<u8>> {
    std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| std::fs::read(e.path()).expect("read file"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_device_concurrent_edit_converges_identically() -> Result<()> {
    const A: &[u8] = b"body from device A";
    const B: &[u8] = b"body from device B - different length here";
    const C: &[u8] = b"body from device C";

    let da = Daemon::start(State::from_seeds([0x0a; 32], K_ROOT)).await?;
    let db = Daemon::start(State::from_seeds([0x0b; 32], K_ROOT)).await?;
    let dc = Daemon::start(State::from_seeds([0x0c; 32], K_ROOT)).await?;

    let (vid, _n) = da.new_vid();

    let src_a = tempfile::tempdir()?;
    let src_b = tempfile::tempdir()?;
    let src_c = tempfile::tempdir()?;
    std::fs::write(src_a.path().join("doc.txt"), A)?;
    std::fs::write(src_b.path().join("doc.txt"), B)?;
    std::fs::write(src_c.path().join("doc.txt"), C)?;

    // All three publish epoch 1 with no shared ancestry -> mutually concurrent.
    da.publish_vault(src_a.path(), vid).await?;
    db.publish_vault(src_b.path(), vid).await?;
    dc.publish_vault(src_c.path(), vid).await?;

    let out_a = tempfile::tempdir()?;
    let out_b = tempfile::tempdir()?;
    let out_c = tempfile::tempdir()?;

    // Round-robin reconcile: every device pulls from the other two each round until
    // a full round reconstructs nothing new anywhere (the fixed point).
    let daemons: [(&Daemon, &Path); 3] = [
        (&da, out_a.path()),
        (&db, out_b.path()),
        (&dc, out_c.path()),
    ];
    let addrs = [da.addr()?, db.addr()?, dc.addr()?];

    let mut converged = false;
    for _ in 0..MAX_ROUNDS {
        let mut touched = false;
        for (i, (d, out)) in daemons.iter().enumerate() {
            for (j, peer) in addrs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let got = pull(d, peer.clone(), out).await?;
                touched |= got.iter().any(|r| r.vid == vid);
            }
        }
        if !touched {
            converged = true;
            break;
        }
    }
    assert!(
        converged,
        "3-device reconcile did not converge within {MAX_ROUNDS} rounds"
    );

    // All three working dirs must be byte-for-byte the same reconciled tree.
    let na = names(src_a.path());
    let nb = names(src_b.path());
    let nc = names(src_c.path());
    assert_eq!(
        na, nb,
        "A and B diverged on file set (order-dependent conflict identity)"
    );
    assert_eq!(
        nb, nc,
        "B and C diverged on file set (order-dependent conflict identity)"
    );

    // Exactly the winner + two conflict copies, and all three bodies survived.
    assert_eq!(
        na.len(),
        3,
        "expected winner + 2 conflict copies, got {na:?}"
    );
    assert!(
        na.contains("doc.txt"),
        "the winner must keep the original path"
    );
    assert_eq!(
        na.iter().filter(|n| n.contains("sync-conflict")).count(),
        2,
        "two losers must be renamed to conflict copies"
    );
    let expected_bodies: BTreeSet<Vec<u8>> =
        [A.to_vec(), B.to_vec(), C.to_vec()].into_iter().collect();
    for (who, dir) in [
        ("A", src_a.path()),
        ("B", src_b.path()),
        ("C", src_c.path()),
    ] {
        assert_eq!(
            bodies(dir),
            expected_bodies,
            "device {who}: all three edits must survive, none dropped"
        );
    }

    da.shutdown().await;
    db.shutdown().await;
    dc.shutdown().await;
    Ok(())
}
