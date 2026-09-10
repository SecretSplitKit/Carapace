use anyhow::Result;
use carapaced::{Daemon, State};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vault_roots_cannot_overlap_even_when_a_registered_folder_is_missing() -> Result<()> {
    let daemon = Daemon::start(State::from_seeds([115; 32], [116; 32])).await?;
    let tree = tempfile::tempdir()?;
    let source = tree.path().join("source");
    let child = source.join("child");
    std::fs::create_dir_all(&child)?;
    let (vid, _) = daemon.new_vid();
    daemon.publish_vault(&source, vid).await?;
    // Refreshing the same vault is still valid.
    daemon.publish_vault(&source, vid).await?;
    for path in [source.as_path(), child.as_path(), tree.path()] {
        let (other, _) = daemon.new_vid();
        let error = daemon.publish_vault(path, other).await.unwrap_err();
        assert!(format!("{error:#}").contains("overlaps another registered vault"));
    }
    std::fs::remove_dir_all(&source)?;
    let (other, _) = daemon.new_vid();
    let error = daemon.publish_vault(tree.path(), other).await.unwrap_err();
    assert!(format!("{error:#}").contains("overlaps another registered vault"));
    // An unrelated folder still works while the registered source is absent.
    let unrelated = tempfile::tempdir()?;
    daemon.publish_vault(unrelated.path(), other).await?;
    daemon.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_sync_cannot_adopt_a_directory_inside_another_vault() -> Result<()> {
    let sender = Daemon::start(State::from_seeds([117; 32], [116; 32])).await?;
    let receiver = Daemon::start(State::from_seeds([118; 32], [116; 32])).await?;
    let source = tempfile::tempdir()?;
    let existing = tempfile::tempdir()?;
    std::fs::write(source.path().join("incoming"), b"remote")?;
    std::fs::write(existing.path().join("local"), b"preserve")?;
    let (remote_vid, _) = sender.new_vid();
    let (local_vid, _) = receiver.new_vid();
    sender.publish_vault(source.path(), remote_vid).await?;
    receiver.publish_vault(existing.path(), local_vid).await?;
    assert!(receiver
        .sync_from(sender.addr()?, existing.path())
        .await?
        .is_empty());
    assert!(receiver
        .live_peer_errors()
        .iter()
        .any(|(_, error)| error.contains("overlaps another registered vault")));
    assert_eq!(std::fs::read(existing.path().join("local"))?, b"preserve");
    assert_eq!(receiver.live_vault_statuses().len(), 1);
    sender.shutdown().await;
    receiver.shutdown().await;
    Ok(())
}
