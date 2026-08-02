#![cfg(unix)]

//! Phase 1 acceptance: two localhost daemons sharing one `k_root` but distinct node keys.
//! Device A publishes a vault; device B runs anti-entropy, fetches the envelope + chunks, and
//! reconstructs the tree byte-for-byte against A's source.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use carapaced::{Daemon, State};

/// Shared user master key for both devices (same user, two devices).
const K_ROOT: [u8; 32] = [0x33; 32];

/// A mix of files: a multi-chunk 3 MiB file, a nested file, an empty file, and a
/// small text file.
fn make_tree() -> (tempfile::TempDir, BTreeMap<String, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut expected = BTreeMap::new();

    let big: Vec<u8> = (0..(3 * 1024 * 1024u32))
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("readme.txt", b"hello carapace".to_vec()),
        ("empty.bin", Vec::new()),
        ("nested/deep/data.bin", big),
        ("nested/note.md", b"# note\nsome text\n".repeat(50)),
    ];
    for (rel, bytes) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        expected.insert(rel.replace('\\', "/"), bytes);
    }
    (dir, expected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_device_sync() -> Result<()> {
    // Same k_root, distinct node seeds.
    let device_a = State::from_seeds([0x09; 32], K_ROOT);
    let device_b = State::from_seeds([0x0b; 32], K_ROOT);

    // Same user identity derived from the shared k_root, but different nodes.
    let user_a = device_a.user_key().verifying_key().to_bytes();
    let user_b = device_b.user_key().verifying_key().to_bytes();
    assert_eq!(user_a, user_b, "both devices must share one user identity");

    let daemon_a = Daemon::start(device_a).await?;
    let daemon_b = Daemon::start(device_b).await?;
    assert_ne!(
        daemon_a.node_id(),
        daemon_b.node_id(),
        "devices must hold distinct node keys"
    );

    // ---- device A: create a vault and announce it ----
    let (src, expected) = make_tree();
    let (vid, _nonce) = daemon_a.new_vid();
    let epoch = daemon_a.publish_vault(src.path(), vid).await?;
    assert_eq!(epoch, 1, "first publish is epoch 1");

    // ---- device B: discover + fetch + reconstruct ----
    let out = tempfile::tempdir()?;
    let addr_a = daemon_a.addr()?;
    let reconstructed = daemon_b.sync_from(addr_a, out.path()).await?;

    let got = reconstructed
        .iter()
        .find(|r| r.vid == vid)
        .context("device B did not reconstruct the announced vault")?;
    assert_eq!(got.epoch, epoch);

    // Byte-identity against A's source.
    for (rel, bytes) in &expected {
        let path = got.out_dir.join(rel);
        let recovered =
            std::fs::read(&path).with_context(|| format!("reconstructed file missing: {rel}"))?;
        assert_eq!(&recovered, bytes, "content mismatch for {rel}");
    }
    // No extra files leaked in.
    assert_eq!(
        count_files(&got.out_dir),
        expected.len(),
        "unexpected extra files"
    );

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;
    Ok(())
}

/// Re-publishing after a local change bumps the epoch; a fresh device B sync
/// reconstructs the newer content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn republish_bumps_epoch_and_syncs_update() -> Result<()> {
    let daemon_a = Daemon::start(State::from_seeds([0x21; 32], K_ROOT)).await?;
    let daemon_b = Daemon::start(State::from_seeds([0x23; 32], K_ROOT)).await?;

    let src = tempfile::tempdir()?;
    std::fs::write(src.path().join("f.txt"), b"v1 contents")?;
    let (vid, _n) = daemon_a.new_vid();
    assert_eq!(daemon_a.publish_vault(src.path(), vid).await?, 1);

    // Local change -> republish.
    std::fs::write(src.path().join("f.txt"), b"v2 contents are longer now")?;
    assert_eq!(
        daemon_a.publish_vault(src.path(), vid).await?,
        2,
        "republish bumps epoch"
    );

    let out = tempfile::tempdir()?;
    let reconstructed = daemon_b.sync_from(daemon_a.addr()?, out.path()).await?;
    let got = reconstructed
        .iter()
        .find(|r| r.vid == vid)
        .context("no reconstruction")?;
    assert_eq!(got.epoch, 2, "B must reconstruct the latest epoch");
    assert_eq!(
        std::fs::read(got.out_dir.join("f.txt"))?,
        b"v2 contents are longer now"
    );

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;
    Ok(())
}

/// An owner device can remain offline across several published epochs, restart only from
/// its durable state, and then converge to the latest bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_offline_owner_reboots_and_resyncs_latest_vault() -> Result<()> {
    let state_b = tempfile::tempdir()?;
    let daemon_a = Daemon::start(State::from_seeds([0x25; 32], K_ROOT)).await?;
    let daemon_b = Daemon::start(State::from_seeds_in(state_b.path(), [0x27; 32], K_ROOT)).await?;
    let source = tempfile::tempdir()?;
    std::fs::write(source.path().join("offline.txt"), b"epoch one")?;
    let (vid, _) = daemon_a.new_vid();
    assert_eq!(daemon_a.publish_vault(source.path(), vid).await?, 1);
    let first_output = tempfile::tempdir()?;
    assert!(daemon_b
        .sync_from(daemon_a.addr()?, first_output.path())
        .await?
        .iter()
        .any(|result| result.vid == vid && result.epoch == 1));
    daemon_b.shutdown().await;
    drop(daemon_b);
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    for (epoch, content) in [(2, b"epoch two".as_slice()), (3, b"epoch three latest")] {
        std::fs::write(source.path().join("offline.txt"), content)?;
        assert_eq!(daemon_a.publish_vault(source.path(), vid).await?, epoch);
    }

    let mut rebooted_b = None;
    let mut last_lock_error = None;
    for _ in 0..50 {
        match Daemon::start(State::from_seeds_in(state_b.path(), [0x27; 32], K_ROOT)).await {
            Ok(daemon) => {
                rebooted_b = Some(daemon);
                break;
            }
            Err(error) if error.to_string().contains("Database already open") => {
                last_lock_error = Some(error);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    }
    let rebooted_b = rebooted_b.with_context(|| {
        format!(
            "prior offline-device database lock did not settle: {:#}",
            last_lock_error.expect("a retry failure has a lock error")
        )
    })?;
    let resumed_output = tempfile::tempdir()?;
    let results = rebooted_b
        .sync_from(daemon_a.addr()?, resumed_output.path())
        .await?;
    let latest = results
        .iter()
        .find(|result| result.vid == vid)
        .context("rebooted offline device did not resync the vault")?;
    assert_eq!(latest.epoch, 3);
    assert_eq!(
        std::fs::read(latest.out_dir.join("offline.txt"))?,
        b"epoch three latest"
    );

    rebooted_b.shutdown().await;
    daemon_a.shutdown().await;
    Ok(())
}

/// W3: a poison announce (node-signed so it passes delegation, but pointing at an unbacked
/// digest) must not starve the legitimate vaults; B reconstructs the real vault and skips it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poison_announce_does_not_abort_sync() -> Result<()> {
    let daemon_a = Daemon::start(State::from_seeds([0x31; 32], K_ROOT)).await?;
    let daemon_b = Daemon::start(State::from_seeds([0x37; 32], K_ROOT)).await?;

    let src = tempfile::tempdir()?;
    std::fs::write(src.path().join("real.txt"), b"the genuine article")?;
    let (vid, _n) = daemon_a.new_vid();
    daemon_a.publish_vault(src.path(), vid).await?;

    // Inject an unfetchable-but-delegated announce for a different vid.
    daemon_a.advertise_unfetchable_for_test([0xEE; 32], 1);

    let out = tempfile::tempdir()?;
    let reconstructed = daemon_b.sync_from(daemon_a.addr()?, out.path()).await?;

    let got = reconstructed
        .iter()
        .find(|r| r.vid == vid)
        .context("real vault must survive the poison announce")?;
    assert_eq!(
        std::fs::read(got.out_dir.join("real.txt"))?,
        b"the genuine article"
    );
    assert!(
        reconstructed.iter().all(|r| r.vid != [0xEE; 32]),
        "the poison vault must not be reconstructed"
    );

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;
    Ok(())
}

fn count_files(dir: &std::path::Path) -> usize {
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            n += count_files(&entry.path());
        } else {
            n += 1;
        }
    }
    n
}
