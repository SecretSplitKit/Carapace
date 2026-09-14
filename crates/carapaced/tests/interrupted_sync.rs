use anyhow::Result;
use carapace_restore::RestoreJournal;
use carapaced::{Daemon, State};
use std::path::PathBuf;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_sync_preserves_user_edits_then_resumes_from_durable_baseline() -> Result<()> {
    let source = tempfile::tempdir()?;
    let state_b = tempfile::tempdir()?;
    let a = Daemon::start(State::from_seeds([121; 32], [120; 32])).await?;
    let b = Daemon::start(State::from_seeds_in(state_b.path(), [122; 32], [120; 32])).await?;
    let (vid, _) = a.new_vid();
    std::fs::write(source.path().join("shared.txt"), b"original")?;
    a.publish_vault(source.path(), vid).await?;
    let synced = b
        .sync_from(a.addr()?, &state_b.path().join("vaults"))
        .await?;
    let target = &synced[0].out_dir;
    std::fs::write(target.join("local.txt"), b"captured local edit")?;
    b.publish_vault(target, vid).await?;
    let journal = RestoreJournal::begin(target, &[PathBuf::from("shared.txt")])?;
    drop(journal);
    std::fs::write(target.join("shared.txt"), b"user edit during interruption")?;
    std::fs::write(source.path().join("shared.txt"), b"new owner edit")?;
    a.publish_vault(source.path(), vid).await?;
    let result = b
        .sync_from(a.addr()?, &state_b.path().join("vaults"))
        .await?;
    assert_eq!(result.len(), 1, "{:?}", b.live_peer_errors());
    assert_eq!(std::fs::read(target.join("shared.txt"))?, b"new owner edit");
    assert_eq!(
        std::fs::read(target.join("local.txt"))?,
        b"captured local edit"
    );
    let backup_root = b.live_vault_statuses()[0]
        .recovery_backup
        .clone()
        .expect("visible durable backup location");
    let attempt = std::fs::read_dir(&backup_root)?.next().unwrap()?.path();
    assert_eq!(
        std::fs::read(attempt.join("shared.txt"))?,
        b"user edit during interruption"
    );
    b.publish_vault(target, vid).await?; // Finished journal no longer blocks ingest.
    b.shutdown().await;
    drop(b);
    let b = Daemon::start(State::from_seeds_in(state_b.path(), [122; 32], [120; 32])).await?;
    assert_eq!(
        b.live_vault_statuses()[0].recovery_backup,
        Some(backup_root)
    );
    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_baseline_is_refetched_before_offline_edits_are_reconciled() -> Result<()> {
    let source = tempfile::tempdir()?;
    let state_b = tempfile::tempdir()?;
    let a = Daemon::start(State::from_seeds([123; 32], [120; 32])).await?;
    let b = Daemon::start(State::from_seeds_in(state_b.path(), [124; 32], [120; 32])).await?;
    let (vid, _) = a.new_vid();
    std::fs::write(source.path().join("shared.txt"), b"original")?;
    a.publish_vault(source.path(), vid).await?;
    let synced = b
        .sync_from(a.addr()?, &state_b.path().join("vaults"))
        .await?;
    let target = synced[0].out_dir.clone();
    b.shutdown().await;
    drop(b);
    std::fs::remove_dir_all(state_b.path().join("blobs"))?;
    std::fs::write(target.join("local.txt"), b"offline edit")?;
    std::fs::write(source.path().join("shared.txt"), b"new owner edit")?;
    a.publish_vault(source.path(), vid).await?;
    let b = Daemon::start(State::from_seeds_in(state_b.path(), [124; 32], [120; 32])).await?;
    assert!(b.needs_refetch_ids(&vid).is_some());
    let result = b
        .sync_from(a.addr()?, &state_b.path().join("vaults"))
        .await?;
    assert_eq!(result.len(), 1, "{:?}", b.live_peer_errors());
    assert!(b.needs_refetch_ids(&vid).is_none());
    assert_eq!(std::fs::read(target.join("local.txt"))?, b"offline edit");
    assert_eq!(std::fs::read(target.join("shared.txt"))?, b"new owner edit");
    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unchanged_remote_manifest_still_finishes_an_interrupted_restore() -> Result<()> {
    use std::{sync::Arc, time::Duration};
    let source = tempfile::tempdir()?;
    let state_b = tempfile::tempdir()?;
    let a = Daemon::start(State::from_seeds([125; 32], [120; 32])).await?;
    let b =
        Arc::new(Daemon::start(State::from_seeds_in(state_b.path(), [126; 32], [120; 32])).await?);
    let (vid, _) = a.new_vid();
    std::fs::write(source.path().join("file.txt"), b"verified baseline")?;
    a.publish_vault(source.path(), vid).await?;
    b.enroll_own_device(a.own_device_card()).await?;
    let synced = b
        .sync_from(a.addr()?, &state_b.path().join("vaults"))
        .await?;
    let target = synced[0].out_dir.clone();
    drop(RestoreJournal::begin(
        &target,
        &[PathBuf::from("file.txt")],
    )?);
    std::fs::write(target.join("file.txt"), b"unfinished output")?;
    let runtime = Arc::clone(&b).run_live_sync(carapaced::LiveSyncConfig {
        interval: Duration::from_millis(100),
        rescan_interval: Duration::from_secs(1),
        peer_timeout: Duration::from_secs(1),
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while std::fs::read(target.join("file.txt")).ok().as_deref() != Some(b"verified baseline") {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await?;
    assert!(b.live_vault_statuses()[0].recovery_backup.is_some());
    runtime.stop().await;
    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}
