//! Phase-3 hardening acceptance for the replica-store receive path:
//!
//! - S4: owner-side placement only invites established friends that are not on the
//!   owner deny-list; a stranger or a denied friend is skipped.
//! - W1: a friend's per-friend agreed storage grant is enforced as its replica
//!   quota (a placement over that friend's grant is declined and the store does
//!   not grow), two friends with different agreed grants are enforced
//!   independently, and a peer over its push rate limit is throttled - while an
//!   honest within-grant placement still succeeds.

use anyhow::Result;
use carapaced::{Daemon, ReplicaLimits, State};

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// A one-file tree, a few dozen bytes (bigger than any tiny quota below).
fn tiny_tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("note.txt"), b"carapace replica hardening bytes").unwrap();
    dir
}

/// Make `friend` befriend `owner` over a single-use ticket the owner issues,
/// with `friend` agreeing to grant `owner` `grant` bytes of replica storage
/// (`None` = the 1 GiB default).
async fn befriend(owner: &Daemon, friend: &Daemon, grant: Option<u64>) -> Result<()> {
    let ticket = owner.issue_ticket()?;
    friend.befriend(owner.addr()?, &ticket, grant).await?;
    assert!(owner.is_friend(&friend.user_id()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_placement_gates_on_friend_and_deny_list() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?; // friend, placed
    let c = Daemon::start(seeds(0x21, 0xC0)).await?; // friend, deny-listed
    let stranger = Daemon::start(seeds(0x31, 0xD0)).await?; // never befriended

    befriend(&a, &b, None).await?;
    befriend(&a, &c, None).await?;

    let src = tiny_tree();
    let (vid, _n) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;

    // Deny C explicitly even though it is a friend.
    a.deny_replica_peer(c.node_id());

    // Offer B (friend), C (denied friend), stranger (non-friend). Only B is placed.
    let placed = a
        .place_replicas(vid, &[b.addr()?, c.addr()?, stranger.addr()?], 3)
        .await?;
    assert_eq!(placed, vec![b.node_id()], "only the allowed friend is placed");
    assert!(b.holds_replica(&vid), "friend B stored the replica");
    assert!(!c.holds_replica(&vid), "deny-listed friend C was skipped");
    assert!(!stranger.holds_replica(&vid), "non-friend stranger was skipped (S4)");

    for d in [a, b, c, stranger] {
        d.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_quota_and_rate_limit_cut_off_pushes() -> Result<()> {
    let a = Daemon::start(seeds(0x02, 0xA1)).await?;
    // A friend that agrees, at add-friend time, to grant A only 10 bytes of
    // replica storage - any real placement exceeds it.
    let stingy = Daemon::start(seeds(0x12, 0xB1)).await?;
    // A friend whose rate-limit bucket is empty and never refills.
    let throttled = Daemon::start_with_limits(
        seeds(0x22, 0xC1),
        ReplicaLimits { rate_capacity: 0, rate_refill_per_sec: 0, ..Default::default() },
    )
    .await?;
    // An honest friend granting A the default (1 GiB).
    let honest = Daemon::start(seeds(0x32, 0xD1)).await?;

    befriend(&a, &stingy, Some(10)).await?; // stingy grants A exactly 10 bytes
    befriend(&a, &throttled, None).await?;
    befriend(&a, &honest, None).await?;

    let src = tiny_tree();
    let (vid, _n) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;

    // Over-grant peer declines; nothing is stored past the 10-byte agreed limit.
    let placed = a.place_replicas(vid, &[stingy.addr()?], 1).await?;
    assert!(placed.is_empty(), "placement over the agreed grant is declined (W1)");
    assert!(!stingy.holds_replica(&vid), "over-grant peer stored nothing");

    // Rate-limited peer (empty bucket) is throttled and declines.
    let placed = a.place_replicas(vid, &[throttled.addr()?], 1).await?;
    assert!(placed.is_empty(), "rate-limited placement is throttled (W1)");
    assert!(!throttled.holds_replica(&vid), "throttled peer stored nothing");

    // Honest within-grant placement still succeeds.
    let placed = a.place_replicas(vid, &[honest.addr()?], 1).await?;
    assert_eq!(placed, vec![honest.node_id()], "within-grant placement succeeds");
    assert!(honest.holds_replica(&vid), "honest peer stored the replica");

    for d in [a, stingy, throttled, honest] {
        d.shutdown().await;
    }
    Ok(())
}

// W1 per-friend: one storage node grants two friends different limits and
// enforces them independently by WHO is placing. `store` grants `small` only 10
// bytes but `big` the 1 GiB default; a real placement is refused from `small`
// yet accepted from `big`, proving the quota is sourced per-friend (looked up by
// the placing friend's user pubkey), not from a single global default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_per_friend_grants_enforced_independently() -> Result<()> {
    let store = Daemon::start(seeds(0x03, 0xA2)).await?; // the storage node
    let small = Daemon::start(seeds(0x13, 0xB2)).await?; // granted 10 bytes
    let big = Daemon::start(seeds(0x23, 0xC2)).await?; // granted the default

    // `store` befriends each owner, agreeing a different grant per friend.
    befriend(&small, &store, Some(10)).await?; // store grants `small` 10 bytes
    befriend(&big, &store, None).await?; // store grants `big` the 1 GiB default

    let small_src = tiny_tree();
    let (small_vid, _n) = small.new_vid();
    small.publish_vault(small_src.path(), small_vid).await?;

    let big_src = tiny_tree();
    let (big_vid, _n) = big.new_vid();
    big.publish_vault(big_src.path(), big_vid).await?;

    // `small` is over its 10-byte grant on `store`: declined.
    let placed = small.place_replicas(small_vid, &[store.addr()?], 1).await?;
    assert!(placed.is_empty(), "small friend's over-grant placement is declined");
    assert!(!store.holds_replica(&small_vid), "store held nothing for the small friend");

    // `big`, placing the SAME-size tree on the SAME node, is within its default
    // grant: accepted. Same store, same bytes, opposite outcome by friend.
    let placed = big.place_replicas(big_vid, &[store.addr()?], 1).await?;
    assert_eq!(placed, vec![store.node_id()], "big friend's within-grant placement succeeds");
    assert!(store.holds_replica(&big_vid), "store held the big friend's replica");

    for d in [store, small, big] {
        d.shutdown().await;
    }
    Ok(())
}
