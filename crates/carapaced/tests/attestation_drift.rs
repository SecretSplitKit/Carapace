//! W4 owner attestation cadence (§10.2): a trustee that stops attesting drops the
//! attested-live count below `M + slack`, and the maintenance round surfaces an
//! `extend` recommendation on the status surface.
//!
//! BOUNDED (§11 lesson): the attestation cadence + freshness window run against an
//! injected clock (tiny intervals, an advancing `now`), never a real daily cadence.

use std::collections::HashMap;

use anyhow::Result;
use carapace_recovery::split_root;
use carapace_share::{AttestTracker, Share, ShareAction};
use carapaced::{Daemon, State};

const SPLIT_ROOT: [u8; 32] = [0x5e; 32];

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// A befriends `peer` (peer issues the ticket), so A can dial it for challenges and
/// the trustee authorizes A's challenge as an established friend.
async fn a_befriends(a: &Daemon, peer: &Daemon) -> Result<()> {
    let ticket = peer.issue_ticket()?;
    a.befriend(peer.addr()?, &ticket, None).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn stalled_trustee_drops_live_below_target_and_surfaces_extend() -> Result<()> {
    // Owner A and three trustees. M = 2, slack = 1 => live target 3, one share of
    // headroom under the §8.3 soft cap (3*2 - 1 = 5), so a single drop recommends
    // EXTEND (not re-split).
    let a = Daemon::start(seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?;
    let c = Daemon::start(seeds(0x21, 0xC0)).await?;
    let d = Daemon::start(seeds(0x31, 0xD0)).await?;

    for t in [&b, &c, &d] {
        a_befriends(&a, t).await?;
    }

    // Split into 3 shares (M=2), hand one to each trustee, and register the owner-side
    // tracker with tiny freshness + round intervals for the injected clock.
    let (shares, _state, _warn): (Vec<Share>, _, _) =
        split_root(&SPLIT_ROOT, 2, Some(3), false).map_err(|e| anyhow::anyhow!("split: {e:?}"))?;
    let rsid = u64::from(shares[0].recovery_set_id);
    let issued = shares.len();

    let trustees = [&b, &c, &d];
    let roster: HashMap<[u8; 32], u64> = trustees
        .iter()
        .zip(&shares)
        .map(|(t, s)| (t.node_id(), u64::from(s.x)))
        .collect();
    for (t, s) in trustees.iter().zip(shares) {
        t.store_share(s);
    }

    const FRESHNESS: u64 = 100;
    const ROUND: u64 = 10;
    a.register_recovery_set(
        rsid,
        AttestTracker::with_params(2, 1, issued, FRESHNESS, ROUND, roster),
    );

    // Round 1 at t0: all three trustees answer -> live 3 == target -> healthy.
    let t0 = 1_000_000u64;
    let report = a.maintenance_round(t0).await;
    assert!(
        report.errors.is_empty(),
        "round errors: {:?}",
        report.errors
    );
    assert_eq!(
        report.drift,
        vec![(rsid, ShareAction::Healthy)],
        "with all trustees live the set is healthy"
    );
    let h0 = &a.recovery_health_at(t0)[0];
    assert_eq!((h0.live, h0.target, h0.recommendation), (3, 3, "healthy"));

    // D stops attesting; advance past the freshness window so its earlier attestation
    // ages out, then run another round: B and C refresh, D is silent.
    d.shutdown().await;
    let t1 = t0 + FRESHNESS + 1;
    let report = a.maintenance_round(t1).await;
    assert!(
        report.errors.is_empty(),
        "round errors: {:?}",
        report.errors
    );
    assert_eq!(
        report.drift,
        vec![(rsid, ShareAction::Extend { needed: 1 })],
        "one silent trustee drops live to 2 (< target 3) and recommends extend"
    );

    // The recommendation is surfaced on the status path (the /api/status source).
    let h1 = &a.recovery_health_at(t1)[0];
    assert_eq!(
        (h1.live, h1.target, h1.recommendation, h1.needed),
        (2, 3, "extend", 1),
        "attested-live drifted below M+slack; status surfaces an extend of 1"
    );

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    Ok(())
}
