//! Durability under NON-graceful loss (kill -9, power cut): a published vault's blobs must
//! be on disk by the time `publish_vault` returns. The FsStore acks each add from an open
//! redb write batch that commits up to ~1 s later, so without the `sync()` barrier a prompt
//! kill loses the envelope + chunks that state.redb already names.
//!
//! Kill simulation: copy the whole state dir while the daemon still runs (exactly the disk
//! image an abrupt kill leaves), probe its FsStore, then boot a full daemon from it.
//!
//! Unix-only: copying redb's live db files needs no mandatory byte-range lock (Windows fails
//! with os error 33). The guarantee is redb-level and platform-independent, and the
//! `reboot_survival` tests cover the committed-state-survives-restart path everywhere.
#![cfg(unix)]

use anyhow::{Context, Result};
use carapace_net::IrohBlobStore;
use carapaced::{Daemon, State};
use std::path::Path;

/// Recursive plain-file dir copy (the state dir holds only files + dirs).
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from).with_context(|| format!("read_dir {from:?}"))? {
        let entry = entry?;
        let dst = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &dst)?;
        } else {
            std::fs::copy(entry.path(), &dst)
                .with_context(|| format!("copy {:?} -> {dst:?}", entry.path()))?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_survives_immediate_kill() -> Result<()> {
    let state_a = tempfile::tempdir()?;
    let src = tempfile::tempdir()?;
    // One tiny file (inline in redb) + one large file (file-backed blob) to cover both
    // iroh-blobs storage paths.
    std::fs::write(src.path().join("small.txt"), b"must survive kill -9")?;
    std::fs::create_dir_all(src.path().join("nested"))?;
    let big: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(src.path().join("nested/big.bin"), &big)?;

    let node_seed = [0x61u8; 32];
    let k_root = [0x62u8; 32];
    let d = Daemon::start(State::from_seeds_in(state_a.path(), node_seed, k_root)).await?;
    let (vid, _nonce) = d.new_vid();
    let epoch = d.publish_vault(src.path(), vid).await?;
    assert_eq!(epoch, 1, "first publish is epoch 1");
    let (digest, chunks) = d
        .vault_blob_ids(&vid)
        .expect("published vault has a blob source");
    assert!(!chunks.is_empty(), "published vault has chunks");

    // "Kill -9": snapshot the on-disk state now, while the daemon still runs.
    let state_b = tempfile::tempdir()?;
    copy_tree(state_a.path(), state_b.path())?;
    d.shutdown().await;

    // The kill image's FsStore must already hold every published blob.
    let probe = IrohBlobStore::load(&state_b.path().join("blobs")).await?;
    assert!(
        probe.has(digest).await?,
        "manifest envelope must be durable by the time publish_vault returns"
    );
    for (i, id) in chunks.iter().enumerate() {
        assert!(
            probe.has(*id).await?,
            "chunk {i} must be durable by the time publish_vault returns"
        );
    }
    // Release the probe's redb lock before booting a daemon on the same dir.
    probe.store().shutdown().await?;
    drop(probe);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Full reboot from the kill image: the vault is listed and its manifest
    // re-derives from the surviving envelope.
    let d2 = Daemon::start(State::from_seeds_in(state_b.path(), node_seed, k_root)).await?;
    assert_eq!(
        d2.published_vaults(),
        vec![(vid, 1)],
        "vault survives a reboot from the kill image"
    );
    assert!(
        d2.blob_present(digest).await,
        "envelope present after reboot"
    );
    for id in &chunks {
        assert!(d2.blob_present(*id).await, "chunk present after reboot");
    }
    d2.shutdown().await;
    Ok(())
}
