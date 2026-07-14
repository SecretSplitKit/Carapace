//! §11 / W12 filesystem watcher: a local change under a published vault's source
//! directory re-ingests the vault (epoch++), so replicas and other owner devices
//! pick it up "like Dropbox".
//!
//! Bounded and non-flaky: the watcher runs against a REAL `notify` backend, but
//! every wait is capped by `tokio::time::timeout`, so a regression that stops the
//! watcher from firing FAILS fast instead of hanging.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use carapaced::{Daemon, State};

/// Hard ceiling on how long we wait for the watcher to observe a change and
/// re-publish. Generous (fs event latency + debounce + a full re-ingest) yet
/// finite: exceeding it means the watcher never fired, which is the failure we
/// are guarding against.
const REINGEST_DEADLINE: Duration = Duration::from_secs(15);

/// Current epoch this daemon has published for `vid`, or 0 if none.
fn epoch_of(d: &Daemon, vid: [u8; 32]) -> u64 {
    d.published_vaults()
        .into_iter()
        .find(|(v, _)| *v == vid)
        .map(|(_, e)| e)
        .unwrap_or(0)
}

/// Poll `published_vaults` until `vid`'s epoch exceeds `from`, or fail at the
/// deadline. Polls (rather than sleeps a fixed time) so the test returns the
/// instant the watcher fires.
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
    match tokio::time::timeout(REINGEST_DEADLINE, poll).await {
        Ok(e) => Ok(e),
        Err(_) => bail!("watcher did not re-ingest within {REINGEST_DEADLINE:?}"),
    }
}

#[tokio::test]
async fn w12_local_change_triggers_reingest() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let src = dir.path();
    std::fs::write(src.join("note.txt"), b"first version")?;

    let daemon = Arc::new(Daemon::start(State::from_seeds([0x71; 32], [0x77; 32])).await?);
    let vid = daemon.new_vid().0;

    // Initial one-shot publish, then start watching the same directory.
    let e0 = daemon.publish_vault(src, vid).await?;
    let watcher = Arc::clone(&daemon).watch_vault(vid, src.to_path_buf())?;

    // Modify a file: the watcher should debounce, then re-ingest at a higher epoch.
    modify_after_settle(src.join("note.txt").as_path(), b"second version").await?;
    let e1 = wait_epoch_above(&daemon, vid, e0).await?;
    assert!(e1 > e0, "epoch must advance on modify: {e0} -> {e1}");

    // A second, independent change (a NEW file) must also be picked up: proves the
    // watcher keeps running, not a one-shot.
    modify_after_settle(src.join("added.txt").as_path(), b"brand new file").await?;
    let e2 = wait_epoch_above(&daemon, vid, e1).await?;
    assert!(e2 > e1, "epoch must advance on create: {e1} -> {e2}");

    // Clean shutdown: dropping the watcher stops it, and the daemon Arc is now the
    // sole strong ref (the watcher held only a Weak), so we can reclaim + close it.
    drop(watcher);
    let daemon = Arc::try_unwrap(daemon)
        .map_err(|_| anyhow::anyhow!("watcher still holds a strong daemon ref"))?;
    daemon.shutdown().await;
    Ok(())
}

/// Give the freshly-armed watcher a beat to settle before writing, so the write
/// lands as a distinct, observed event (avoids racing setup on slow CI), then
/// write atomically-ish via a single `fs::write`.
async fn modify_after_settle(path: &Path, contents: &[u8]) -> Result<()> {
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(path, contents)?;
    Ok(())
}
