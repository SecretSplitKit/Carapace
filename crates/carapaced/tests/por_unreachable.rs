//! C1 regression: a transiently-unreachable replica is NOT evicted by the wired
//! PoR loop. Transport failure (the peer cannot be dialed) must never advance the
//! retention loss streak - only a peer that answered with missing/wrong bytes does.
//! This exercises the real network adapter (`por_audit_round` -> `fetch_audit_samples`)
//! that introduces the unreachable=loss collapse the audit flagged.

use std::collections::HashMap;

use anyhow::{Context, Result};
use carapace_replica::{AuditAction, DEFAULT_POR_FAIL_LIMIT};
use carapaced::{Daemon, State};

fn daemon_seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_replica_is_not_evicted_by_por() -> Result<()> {
    let a = Daemon::start(daemon_seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(daemon_seeds(0x11, 0xB0)).await?;

    // Friendship so A may place a replica on B.
    let ticket = a.issue_ticket()?;
    b.befriend(a.addr()?, &ticket, None).await?;

    // Publish a vault and place one replica on B (r = 1).
    let src = make_tree();
    let (vid, _nonce) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;
    let placed = a.place_replicas(vid, &[b.addr()?], 1).await?;
    assert_eq!(placed.len(), 1, "B accepted the placement");
    assert!(a.replica_members(&vid).contains(&b.node_id()));

    // Capture B's node id + address, then take B offline: A can no longer dial it.
    let b_node = b.node_id();
    let b_addr = b.addr()?;
    b.shutdown().await;

    let members = HashMap::from([(b_node, b_addr)]);

    // Run more audit rounds than the fail limit. Each advances `now` well past the
    // per-replica schedule so the round is due. B is unreachable every time.
    let mut now = 1_000_000u64;
    for _ in 0..(DEFAULT_POR_FAIL_LIMIT as u64 + 1) {
        // No candidates: if the fix regressed and B were marked lost, repair would
        // fail to replace it - but with the fix B is simply skipped, not lost.
        let round = a
            .por_audit_round(vid, &members, &[], now)
            .await
            .context("audit round")?;

        assert!(
            round.lost.is_empty(),
            "unreachable peer must not be a retention loss"
        );
        assert!(!round.repaired, "no repair for a merely-offline peer");
        assert_eq!(
            round.unreachable,
            vec![b_node],
            "the round records B as unreachable"
        );
        assert!(
            matches!(round.audited.as_slice(), [(n, AuditAction::Skipped)] if *n == b_node),
            "B's round is Skipped, not Failed/Lost"
        );
        assert!(
            a.replica_members(&vid).contains(&b_node),
            "B stays a member"
        );
        now += 100_000;
    }

    a.shutdown().await;
    Ok(())
}
