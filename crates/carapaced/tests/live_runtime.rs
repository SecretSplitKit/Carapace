use anyhow::Result;
use carapaced::{Daemon, LiveSyncConfig, State};
use std::{path::Path, sync::Arc, time::Duration};

async fn wait_file(path: &Path, expected: &[u8]) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while std::fs::read(path).ok().as_deref() != Some(expected) {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "file did not converge: {} {:?}",
            path.display(),
            std::fs::read(path)
        )
    });
}
fn config() -> LiveSyncConfig {
    LiveSyncConfig {
        interval: Duration::from_millis(100),
        rescan_interval: Duration::from_secs(1),
        peer_timeout: Duration::from_secs(3),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_resumes_and_preserves_offline_edits() -> Result<()> {
    let state_a = tempfile::tempdir()?;
    let state_b = tempfile::tempdir()?;
    let source = tempfile::tempdir()?;
    let root = [0x41; 32];
    let a = Arc::new(Daemon::start(State::from_seeds_in(state_a.path(), [0x42; 32], root)).await?);
    let b = Arc::new(Daemon::start(State::from_seeds_in(state_b.path(), [0x43; 32], root)).await?);
    let run_a = Arc::clone(&a).run_live_sync(config());
    let run_b = Arc::clone(&b).run_live_sync(config());
    // Enrollment on one device is sufficient: the authenticated inbound pull
    // supplies the other device's verified return address.
    b.enroll_own_device(a.own_device_card()).await?;
    let (vid, _) = a.new_vid();
    std::fs::write(source.path().join("note.txt"), b"initial")?;
    a.publish_vault(source.path(), vid).await?;
    let vid_hex: String = vid.iter().map(|b| format!("{b:02x}")).collect();
    let target = state_b.path().join("vaults").join(vid_hex);
    wait_file(&target.join("note.txt"), b"initial").await;
    std::fs::write(source.path().join("note.txt"), b"automatic edit")?;
    wait_file(&target.join("note.txt"), b"automatic edit").await;
    run_b.stop().await;
    b.shutdown().await;
    drop(b);
    std::fs::write(target.join("offline.txt"), b"offline edit survives")?;
    std::fs::write(target.join("note.txt"), b"offline same-file edit")?;
    std::fs::write(source.path().join("note.txt"), b"online same-file edit")?;
    std::fs::write(source.path().join("remote.txt"), b"remote edit survives")?;
    let b = Arc::new(Daemon::start(State::from_seeds_in(state_b.path(), [0x43; 32], root)).await?);
    let run_b = Arc::clone(&b).run_live_sync(config());
    wait_file(&source.path().join("offline.txt"), b"offline edit survives").await;
    wait_file(&target.join("remote.txt"), b"remote edit survives").await;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let converged = [source.path(), target.as_path()].iter().all(|dir| {
                let contents: Vec<_> = std::fs::read_dir(dir)
                    .unwrap()
                    .flatten()
                    .filter_map(|entry| std::fs::read(entry.path()).ok())
                    .collect();
                contents.contains(&b"offline same-file edit".to_vec())
                    && contents.contains(&b"online same-file edit".to_vec())
            });
            if converged {
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .expect("concurrent same-file edits must both survive");
    std::fs::write(target.join("after-restart.txt"), b"watcher resumed")?;
    wait_file(&source.path().join("after-restart.txt"), b"watcher resumed").await;
    assert!(b
        .live_vault_statuses()
        .iter()
        .any(|s| s.vid == vid && s.watching && s.last_success.is_some()));
    run_a.stop().await;
    run_b.stop().await;
    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn foreign_device_cannot_enroll() -> Result<()> {
    let a = Daemon::start(State::from_seeds([1; 32], [2; 32])).await?;
    let b = Daemon::start(State::from_seeds([3; 32], [4; 32])).await?;
    assert!(a.enroll_own_device(b.own_device_card()).await.is_err());
    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn state_folders_are_never_publishable() -> Result<()> {
    let state = tempfile::tempdir()?;
    let daemon = Daemon::start(State::from_seeds_in(state.path(), [5; 32], [6; 32])).await?;
    let (vid, _) = daemon.new_vid();
    assert!(daemon.publish_vault(state.path(), vid).await.is_err());
    assert!(daemon
        .publish_vault(&state.path().join("blobs"), vid)
        .await
        .is_err());
    daemon.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_folder_reports_error_without_publishing_deletes() -> Result<()> {
    let base = tempfile::tempdir()?;
    let source = base.path().join("vault");
    let absent = base.path().join("unmounted");
    std::fs::create_dir(&source)?;
    std::fs::write(source.join("kept.txt"), b"keep me")?;
    let daemon = Arc::new(Daemon::start(State::from_seeds([7; 32], [8; 32])).await?);
    let (vid, _) = daemon.new_vid();
    let epoch = daemon.publish_vault(&source, vid).await?;
    let runtime = Arc::clone(&daemon).run_live_sync(config());
    std::fs::rename(&source, &absent)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let statuses = daemon.live_vault_statuses();
            if statuses
                .iter()
                .any(|s| s.vid == vid && s.last_error.is_some() && !s.watching)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("unavailable folder must be visible as an error");
    assert_eq!(daemon.published_vaults(), vec![(vid, epoch)]);
    assert_eq!(std::fs::read(absent.join("kept.txt"))?, b"keep me");
    runtime.stop().await;
    daemon.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wildcard_bind_advertises_concrete_addresses() -> Result<()> {
    let daemon = Daemon::start_on(
        State::from_seeds([9; 32], [10; 32]),
        carapaced::ReplicaLimits::default(),
        carapaced::NetConfig {
            bind: Some("0.0.0.0:0".parse()?),
            ..Default::default()
        },
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let card = daemon.own_device_card();
            if !card.nodes[0].addrs.is_empty() {
                assert!(card.nodes[0].addrs.iter().all(|addr| !addr
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .ip()
                    .is_unspecified()));
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .expect("wildcard endpoint must discover a dialable address");
    daemon.shutdown().await;
    Ok(())
}
