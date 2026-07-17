//! Audit #1 + #6 regression: the PoR round counter (the challenge-unpredictability
//! nonce, §10.1) must be advanced + persisted at ISSUE time and must survive a reboot,
//! so a restarted daemon resumes at the NEXT round and never re-issues an already-observed
//! (hence predictable) challenge to the same replica.
//!
//! - #6: `por_audit_round` advances + commits the round BEFORE probing the replica, so
//!   even a round that turns out unreachable advances the counter (the pre-fix code left
//!   the round untouched on an unreachable probe, so a crash after a revealed challenge
//!   re-issued it).
//! - #1: `run_maintenance` stamps its interval with `AuditTracker::restamp`, which KEEPS
//!   the per-(replica,vid) round map (the pre-fix `AuditTracker::new` wiped it, resetting
//!   every replica to round 0 at boot).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use carapaced::{Daemon, MaintenanceConfig, State};

fn make_tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    // A multi-chunk file so the audit has several distinct chunks to sample.
    let big: Vec<u8> = (0..900_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    std::fs::write(dir.path().join("a.txt"), b"carapace por reboot").unwrap();
    std::fs::write(dir.path().join("b.bin"), &big).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn por_round_never_replays_across_reboot() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let node_seed = [0x71u8; 32];
    let k_root = [0x72u8; 32];
    let src = make_tree();

    // A "replica" peer whose address we capture and then take offline, so every audit
    // round below is unreachable (a fast connection-refused, like `por_unreachable`).
    let peer = Daemon::start(State::from_seeds([0x7Au8; 32], [0x7Bu8; 32])).await?;
    let peer_node = peer.node_id();
    let peer_addr = peer.addr()?;
    peer.shutdown().await;

    let members = HashMap::from([(peer_node, peer_addr)]);

    // ---- first boot: publish a vault, then run three due (unreachable) audit rounds ----
    let (vid, round_before) = {
        let a = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;
        let (vid, _n) = a.new_vid();
        a.publish_vault(src.path(), vid).await?;

        // Each round is due (the tracker starts unscheduled / the schedule elapses), and
        // each ADVANCES the round counter at issue time even though the probe fails
        // unreachable - this is the #6 property. With the pre-fix code the counter would
        // stay 0 across all three unreachable rounds.
        let mut now = 1_000_000u64;
        for i in 0..3u64 {
            let round = a
                .por_audit_round(vid, &members, &[], now)
                .await
                .context("audit round")?;
            assert_eq!(
                round.unreachable,
                vec![peer_node],
                "the offline peer is unreachable this round"
            );
            assert!(round.lost.is_empty(), "unreachable is not a retention loss");
            assert_eq!(
                a.por_round(peer_node, vid),
                i + 1,
                "each unreachable round advances the PoR round at issue time (#6)"
            );
            // Advance the clock well past the 6h default schedule so the next round is due.
            now += 100_000;
        }

        let round_before = a.por_round(peer_node, vid);
        assert_eq!(round_before, 3, "three rounds issued -> counter at 3");
        a.shutdown().await;
        (vid, round_before)
    };

    // Let the router's accept tasks drop their `Arc<Database>` so redb releases the file.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ---- second boot from the SAME dir: the round counter must survive ----
    let a2 =
        Arc::new(Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?);
    assert_eq!(
        a2.por_round(peer_node, vid),
        round_before,
        "the PoR round counter survived the reboot (never rewound to a spent round)"
    );

    // #1: starting the maintenance loop stamps the cadence via `restamp`, which must KEEP
    // the round map. The pre-fix `s.por = AuditTracker::new(..)` wiped it back to 0.
    let cfg = MaintenanceConfig {
        // A long tick + interval so the background loop does not run a real audit round
        // (and there are no placed replica members for it to audit anyway) before we read.
        tick: Duration::from_secs(3600),
        por_interval: Duration::from_secs(6 * 3600),
    };
    let handle = Arc::clone(&a2).run_maintenance(cfg);
    assert_eq!(
        a2.por_round(peer_node, vid),
        round_before,
        "run_maintenance restamp KEEPS the round map (#1): the reloaded counter is not reset to 0"
    );

    // The next issued round must be strictly greater than any spent one.
    let next = a2
        .por_audit_round(vid, &members, &[], 5_000_000)
        .await
        .context("post-reboot audit round")?;
    assert_eq!(next.unreachable, vec![peer_node]);
    assert!(
        a2.por_round(peer_node, vid) > round_before,
        "the post-reboot audit issues the NEXT round, never a spent one"
    );

    // Tear the loop down (awaits full teardown), then reclaim the sole daemon Arc.
    handle.stop().await;
    let a2 = Arc::try_unwrap(a2)
        .map_err(|_| anyhow::anyhow!("a maintenance round is still holding the daemon"))?;
    a2.shutdown().await;
    Ok(())
}
