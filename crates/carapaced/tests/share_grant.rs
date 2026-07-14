//! W3 ShareGrant minting / delivery / ref-refresh (§8, §7.3, §10.2).
//!
//! The owner splits a secret to a trustee set and mints one signed `ShareGrant` per
//! trustee, delivered over the `carapace/1` control stream. Each trustee VERIFIES the
//! grant (signature + embedded-share CRC + owner delegation) and stores the FULL grant
//! (roster + recovery_delay + announce refs), not a bare share — so a ceremony can
//! later locate co-trustees and the latest manifest without a live owner.
//!
//! Every test is BOUNDED (§11 lesson): no real cadence is ever waited on. The refresh
//! runs on an injected `maintenance_round(now)` with a fast clock; the delivery dials
//! are bounded by the daemon's connect timeout; daemons are torn down at the end.

use std::collections::HashSet;

use anyhow::{Context, Result};
use carapace_recovery::{build_share_grant, verify_share_grant};
use carapace_wire::{AnnounceRef, CoTrustee};
use carapaced::{Daemon, RecoveryScope, State};
use ed25519_dalek::SigningKey;

const RECOVERY_DELAY: u64 = 72 * 3600;

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// A one-file vault tree with `contents`, so a re-publish with different contents
/// bumps the epoch (the publish no-op guard skips a byte-identical re-ingest).
fn tree(contents: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("secret.txt"), contents).unwrap();
    dir
}

/// A befriends `peer` (peer issues the ticket): A becomes an established friend of the
/// peer AND records the peer's dialable address, so A can later deliver grants to it
/// and the peer authorizes A's owner-signed grant as an established friend.
async fn a_befriends(a: &Daemon, peer: &Daemon) -> Result<()> {
    let ticket = peer.issue_ticket()?;
    a.befriend(peer.addr()?, &ticket, None).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn owner_splits_to_three_trustees_who_verify_and_store_grants() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?;
    let c = Daemon::start(seeds(0x21, 0xC0)).await?;
    let d = Daemon::start(seeds(0x31, 0xD0)).await?;
    for t in [&b, &c, &d] {
        a_befriends(&a, t).await?;
    }

    // Publish a vault so the owner has a real announce ref (vid, epoch 1, digest) to
    // fold into every grant.
    let src = tree(b"epoch-one");
    let (vid, _n) = a.new_vid();
    let epoch = a.publish_vault(src.path(), vid).await?;
    assert_eq!(epoch, 1);

    // Split 2-of-3 to the three trustees and deliver a signed grant to each.
    let trustees = [b.user_id(), c.user_id(), d.user_id()];
    let report = a
        .recovery_split_grant(7, RecoveryScope::Root, 2, &trustees, RECOVERY_DELAY, false)
        .await?;
    let delivered: HashSet<[u8; 32]> = report.delivered.into_iter().collect();
    assert_eq!(
        delivered,
        trustees.iter().copied().collect::<HashSet<_>>(),
        "all three trustees must acknowledge storing their grant"
    );
    assert!(report.undelivered.is_empty(), "none should be undelivered");

    let subject = a.user_id();
    for t in [&b, &c, &d] {
        let grant = t
            .held_grant(&subject)
            .context("trustee did not store the grant")?;

        // The stored grant re-verifies (owner signature + embedded-share CRC) and
        // decodes back to a real share.
        verify_share_grant(&grant).context("stored grant failed verification")?;
        assert_eq!(grant.subject, subject, "grant subject is the owner");
        assert_eq!(
            grant.recovery_delay, RECOVERY_DELAY,
            "delay carried verbatim"
        );

        // Announce refs point at the current manifest: this owner's one vault at epoch 1.
        assert_eq!(grant.refs.len(), 1, "one announce ref for the one vault");
        assert_eq!(grant.refs[0].vid, vid);
        assert_eq!(grant.refs[0].epoch, 1);

        // The co-trustee roster is exactly the OTHER two trustees (never the holder).
        assert_eq!(grant.cotrustees.len(), 2, "roster = the two co-trustees");
        let roster_users: HashSet<[u8; 32]> = grant.cotrustees.iter().map(|c| c.user).collect();
        assert!(
            !roster_users.contains(&t.user_id()),
            "a trustee is never in its own co-trustee roster"
        );
        let mut expected = trustees.iter().copied().collect::<HashSet<_>>();
        expected.remove(&t.user_id());
        assert_eq!(roster_users, expected, "roster names the two co-trustees");
        // Each roster entry carries a reachable node hint (the co-trustee's node id).
        for co in &grant.cotrustees {
            assert_ne!(co.node, [0u8; 32], "roster entry has a node hint");
        }
    }

    // The owner's status view lists the three trustees holding a grant at epoch 1.
    let mint = a.recovery_grants();
    assert_eq!(mint.len(), 1);
    assert_eq!(mint[0].rsid, 7);
    assert_eq!(mint[0].trustees.len(), 3);
    assert!(mint[0].trustees.iter().all(|(_, delivered)| *delivered));
    assert_eq!(mint[0].refs, vec![(vid, 1)]);

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    d.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn refresh_round_advances_stored_grant_announce_refs() -> Result<()> {
    let a = Daemon::start(seeds(0x02, 0xA1)).await?;
    let b = Daemon::start(seeds(0x12, 0xB1)).await?;
    let c = Daemon::start(seeds(0x22, 0xC1)).await?;
    let d = Daemon::start(seeds(0x32, 0xD1)).await?;
    for t in [&b, &c, &d] {
        a_befriends(&a, t).await?;
    }

    let src = tree(b"epoch-one");
    let (vid, _n) = a.new_vid();
    assert_eq!(a.publish_vault(src.path(), vid).await?, 1);

    let trustees = [b.user_id(), c.user_id(), d.user_id()];
    a.recovery_split_grant(9, RecoveryScope::Root, 2, &trustees, RECOVERY_DELAY, false)
        .await?;
    let subject = a.user_id();

    // Every trustee starts holding a grant that points at epoch 1.
    for t in [&b, &c, &d] {
        let g = t.held_grant(&subject).context("no grant at epoch 1")?;
        assert_eq!(g.refs[0].epoch, 1, "grant initially points at epoch 1");
    }

    // The owner publishes a NEW vault epoch (changed contents -> epoch bumps).
    std::fs::write(src.path().join("secret.txt"), b"epoch-two-changed").unwrap();
    assert_eq!(a.publish_vault(src.path(), vid).await?, 2);

    // One maintenance round (injected fast clock) refreshes the trustees' grants to
    // point at the latest manifest. Bounded: the round is a single call, no waiting.
    let report = a.maintenance_round(1_000_000).await;
    assert!(
        report.errors.is_empty(),
        "round errors: {:?}",
        report.errors
    );
    assert!(
        report.refreshed_grants.contains(&9),
        "the refresh round must re-issue the set whose vault epoch advanced"
    );

    // Each trustee now holds a grant whose announce refs advanced to epoch 2, and the
    // refreshed grant still verifies.
    for t in [&b, &c, &d] {
        let g = t.held_grant(&subject).context("no grant after refresh")?;
        verify_share_grant(&g).context("refreshed grant failed verification")?;
        assert_eq!(g.refs.len(), 1);
        assert_eq!(g.refs[0].vid, vid);
        assert_eq!(
            g.refs[0].epoch, 2,
            "the stored grant's announce ref must advance to the new epoch"
        );
    }

    // The owner's status view reflects the advanced ref too.
    assert_eq!(a.recovery_grants()[0].refs, vec![(vid, 2)]);

    // A second round with no new epoch is a no-op (idempotent): refs stay at epoch 2.
    let report2 = a.maintenance_round(1_000_100).await;
    assert!(
        !report2.refreshed_grants.contains(&9),
        "no epoch change -> no re-issue"
    );

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    d.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grant_with_bad_signature_is_rejected_on_receipt() -> Result<()> {
    let a = Daemon::start(seeds(0x03, 0xA2)).await?;
    let b = Daemon::start(seeds(0x13, 0xB2)).await?;
    a_befriends(&a, &b).await?;

    // Build a grant, sign it, then tamper a signed field so the signature no longer
    // covers the content. The subject is irrelevant: `verify_share_grant` (signature +
    // embedded share) runs before any delegation check, so this is rejected purely on
    // the bad signature.
    let signer = SigningKey::from_bytes(&[0x77; 32]);
    let share = {
        let (shares, _state, _warn) = carapace_recovery::split_root(&[0x5e; 32], 2, Some(3), false)
            .map_err(|e| anyhow::anyhow!("split: {e:?}"))?;
        shares.into_iter().next().unwrap()
    };
    let subject = a.user_id();
    let cotrustees = vec![CoTrustee {
        user: [0xAA; 32],
        node: [0xBB; 32],
        relay_url: None,
    }];
    let refs = vec![AnnounceRef {
        vid: [0xC0; 32],
        epoch: 1,
        digest: [0xDD; 32],
    }];
    let mut grant = build_share_grant(&signer, subject, &share, RECOVERY_DELAY, cotrustees, refs);
    grant.recovery_delay = 999; // mutate a signed field without re-signing

    // Delivering the tampered grant to B: it declines (no ack) and stores nothing.
    let acked = a.deliver_grant(&b.addr()?, &grant).await?;
    assert!(!acked, "a bad-signature grant must not be acknowledged");
    assert!(
        b.held_grant(&subject).is_none(),
        "a bad-signature grant must never be stored"
    );

    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}
