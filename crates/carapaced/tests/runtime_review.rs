use anyhow::Result;
use carapaced::{Daemon, LiveSyncConfig, State};
use std::{sync::Arc, time::Duration};

fn config() -> LiveSyncConfig {
    LiveSyncConfig {
        interval: Duration::from_millis(100),
        rescan_interval: Duration::from_secs(1),
        peer_timeout: Duration::from_secs(1),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_devices_restart_without_reenrollment() -> Result<()> {
    let state_a = tempfile::tempdir()?;
    let state_b = tempfile::tempdir()?;
    let source = tempfile::tempdir()?;
    let a =
        Arc::new(Daemon::start(State::from_seeds_in(state_a.path(), [101; 32], [100; 32])).await?);
    let b =
        Arc::new(Daemon::start(State::from_seeds_in(state_b.path(), [102; 32], [100; 32])).await?);
    let addr_a = a.addr()?;
    let addr_b = b.addr()?;
    a.enroll_own_device(b.own_device_card()).await?;
    b.enroll_own_device(a.own_device_card()).await?;
    let (vid, _) = a.new_vid();
    std::fs::write(source.path().join("note"), b"before")?;
    a.publish_vault(source.path(), vid).await?;
    let restored = b
        .sync_from(a.addr()?, &state_b.path().join("vaults"))
        .await?;
    let target = restored[0].out_dir.clone();
    a.shutdown().await;
    b.shutdown().await;
    drop(a);
    drop(b);
    std::fs::write(source.path().join("note"), b"after both restarts")?;
    let a =
        Arc::new(Daemon::start(State::from_seeds_in(state_a.path(), [101; 32], [100; 32])).await?);
    let b =
        Arc::new(Daemon::start(State::from_seeds_in(state_b.path(), [102; 32], [100; 32])).await?);
    assert_eq!(
        a.addr()?.ip_addrs().next(),
        addr_a.ip_addrs().next(),
        "device A must keep its known port"
    );
    assert_eq!(
        b.addr()?.ip_addrs().next(),
        addr_b.ip_addrs().next(),
        "device B must keep its known port"
    );
    let run_a = Arc::clone(&a).run_live_sync(config());
    let run_b = Arc::clone(&b).run_live_sync(config());
    tokio::time::timeout(Duration::from_secs(10), async {
        while std::fs::read(target.join("note")).ok().as_deref() != Some(b"after both restarts") {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .expect("restarted devices must reconnect using persisted hints");
    run_a.stop().await;
    run_b.stop().await;
    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_download_failure_is_visible_before_adoption() -> Result<()> {
    let a = Daemon::start(State::from_seeds([103; 32], [100; 32])).await?;
    let b = Arc::new(Daemon::start(State::from_seeds([104; 32], [100; 32])).await?);
    b.enroll_own_device(a.own_device_card()).await?;
    a.advertise_unfetchable_for_test([105; 32], 1);
    let runtime = Arc::clone(&b).run_live_sync(config());
    tokio::time::timeout(Duration::from_secs(5), async {
        while b.live_peer_errors().is_empty() {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .expect("first download failure must be visible even with zero local vaults");
    assert!(b.live_vault_statuses().is_empty());
    assert!(b
        .live_peer_errors()
        .iter()
        .any(|(_, error)| error.contains("vault")));
    runtime.stop().await;
    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unedited_synced_folder_can_place_a_replica() -> Result<()> {
    let a = Daemon::start(State::from_seeds([106; 32], [100; 32])).await?;
    let b = Daemon::start(State::from_seeds([107; 32], [100; 32])).await?;
    let friend = Daemon::start(State::from_seeds([108; 32], [109; 32])).await?;
    friend.befriend(b.addr()?, &b.issue_ticket()?, None).await?;
    let source = tempfile::tempdir()?;
    let target = tempfile::tempdir()?;
    std::fs::write(source.path().join("note"), b"never edited on receiver")?;
    let (vid, _) = a.new_vid();
    a.publish_vault(source.path(), vid).await?;
    b.sync_from(a.addr()?, target.path()).await?;
    assert!(
        b.own_announce_digest(&vid).is_none(),
        "this is an adopted baseline"
    );
    assert_eq!(
        b.place_replicas(vid, &[friend.addr()?], 1).await?,
        vec![friend.node_id()]
    );
    assert!(friend.holds_replica(&vid));
    let epoch = b.published_vaults()[0].1;
    let source_b = b.live_vault_statuses()[0].dir.clone();
    assert_eq!(
        b.publish_vault(&source_b, vid).await?,
        epoch,
        "unchanged refresh must not churn epochs"
    );
    a.shutdown().await;
    b.shutdown().await;
    friend.shutdown().await;
    Ok(())
}
