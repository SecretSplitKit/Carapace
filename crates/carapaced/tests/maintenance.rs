//! W4 background maintenance loop (§10.1): a maintenance round detects a dropped
//! replica and triggers repair onto a spare.
//!
//! Two shapes, both BOUNDED (§11 lesson: never wait a real cadence):
//! - `maintenance_round_detects_loss_and_repairs` drives `Daemon::maintenance_round`
//!   directly with an injected fast clock, so the PoR schedule + fail-streak logic is
//!   deterministic (no wall-clock waiting).
//! - `maintenance_loop_repairs_and_tears_down` runs the REAL spawned loop
//!   (`run_maintenance`) with a tiny tick + PoR interval, polls under a hard timeout
//!   until the repair lands, then tears the loop down and reclaims the daemon — proving
//!   the loop actually ticks and shuts down cleanly.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use carapace_replica::DEFAULT_POR_FAIL_LIMIT;
use carapaced::{Daemon, MaintenanceConfig, State};
use tokio::time::{timeout, Instant};

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// A small vault tree with enough chunks for the PoR sampler to probe.
fn make_tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let big: Vec<u8> = (0..800_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    for (rel, bytes) in [("a.txt", b"carapace".to_vec()), ("b.bin", big)] {
        std::fs::write(dir.path().join(rel), &bytes).unwrap();
    }
    dir
}

/// A befriends `peer` (peer issues the ticket): A becomes the requester, records the
/// friendship, and remembers `peer`'s dialable address for later maintenance dials.
async fn a_befriends(a: &Daemon, peer: &Daemon) -> Result<()> {
    let ticket = peer.issue_ticket()?;
    a.befriend(peer.addr()?, &ticket, None).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maintenance_round_detects_loss_and_repairs() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?; // will "hold" then lose the copy
    let c = Daemon::start(seeds(0x21, 0xC0)).await?; // the spare repair target

    // A befriends both, so A knows their addresses and may place on them.
    a_befriends(&a, &b).await?;
    a_befriends(&a, &c).await?;

    // Publish a vault, then model B as a replica that accepted placement but lost its
    // stored copy: it is a member of the vault yet holds none of its chunks.
    let src = make_tree();
    let (vid, _n) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;
    a.inject_lost_member_for_test(vid, b.node_id());
    assert!(a.replica_members(&vid).contains(&b.node_id()));

    // Drive maintenance rounds with a fast clock: B is reachable (a friend) but serves
    // no chunk, so each round scores a retention failure; after the fail limit it is
    // confirmed lost and repaired onto C (the only non-member friend candidate).
    let mut now = 1_000_000u64;
    let mut repaired = false;
    for _ in 0..(DEFAULT_POR_FAIL_LIMIT as u64 + 2) {
        let report = a.maintenance_round(now).await;
        assert!(
            report.errors.is_empty(),
            "round errors: {:?}",
            report.errors
        );
        if report.por.iter().any(|(_, r)| r.repaired) {
            repaired = true;
            break;
        }
        now += 100_000; // ~27h: well past the default 6h PoR interval + jitter
    }

    assert!(
        repaired,
        "the maintenance round must repair the lost replica"
    );
    let members = a.replica_members(&vid);
    assert!(
        !members.contains(&b.node_id()),
        "the lost replica B is dropped from the set"
    );
    assert!(
        members.contains(&c.node_id()),
        "the vault is re-replicated onto the spare C"
    );

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maintenance_loop_repairs_and_tears_down() -> Result<()> {
    let a = Arc::new(Daemon::start(seeds(0x02, 0xA1)).await?);
    let b = Daemon::start(seeds(0x12, 0xB1)).await?;
    let c = Daemon::start(seeds(0x22, 0xC1)).await?;

    a_befriends(&a, &b).await?;
    a_befriends(&a, &c).await?;

    let src = make_tree();
    let (vid, _n) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;
    a.inject_lost_member_for_test(vid, b.node_id());

    // Start the REAL background loop with a tiny tick and a 0-second PoR interval, so
    // every tick re-audits B against the wall clock. Bounded by the hard timeout below.
    let cfg = MaintenanceConfig {
        tick: Duration::from_millis(40),
        por_interval: Duration::from_secs(0),
    };
    let handle = Arc::clone(&a).run_maintenance(cfg);

    // Poll until the spawned loop repairs onto C, under a hard cap: this can never hang.
    let deadline = Instant::now() + Duration::from_secs(20);
    let repaired = loop {
        if Instant::now() >= deadline {
            break false;
        }
        let members = a.replica_members(&vid);
        if members.contains(&c.node_id()) && !members.contains(&b.node_id()) {
            break true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        repaired,
        "the spawned maintenance loop must repair within the cap"
    );

    // Tear the loop down and reclaim the sole daemon Arc — proving clean shutdown with
    // no lingering strong reference from an in-flight round (bounded).
    timeout(Duration::from_secs(5), handle.stop())
        .await
        .context("maintenance loop did not stop within the cap")?;
    let a = Arc::try_unwrap(a)
        .map_err(|_| anyhow::anyhow!("a maintenance round is still holding the daemon"))?;
    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    Ok(())
}
