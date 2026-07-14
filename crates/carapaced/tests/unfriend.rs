//! §9.3 unfriend / re-split inbound-handler acceptance (W5), exercised over real
//! `carapace/1` control streams between live daemons - NOT by calling the pure state
//! functions directly. This is where the authorization lives (`serve_friendship_end`,
//! `serve_delete_request`, `serve_share_destroy`), so it is where the tests must bind.
//!
//! Covered:
//!  1. Positive: `Daemon::unfriend` drives the FriendshipEnd + DeleteRequest over the
//!     wire and the peer actually tears down ITS side (drops the friendship, deletes the
//!     replica it held for us).
//!  2. Negative: a current friend cannot (a) force us to unfriend by sending a
//!     FriendshipEnd that names a THIRD PARTY, nor (b) destroy a share we hold for an
//!     UNRELATED owner by sending a ShareDestroy naming that owner's subject/rsid.
//!
//! Every test is BOUNDED: dials are capped by the daemon's connect timeout; no cadence
//! is ever waited on; daemons are torn down at the end.

use anyhow::Result;
use carapace_wire::{FriendshipEnd, ShareDestroy, Signed};
use carapaced::{Daemon, RecoveryScope, State};
use ed25519_dalek::SigningKey;

const RECOVERY_DELAY: u64 = 72 * 3600;
const RSID: u64 = 7;

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// The node signing key a daemon seeded with `State::from_seeds([node;32], _)` runs, so
/// a test can sign a control frame AS that node (to model a malicious insider's device).
fn node_key(node: u8) -> SigningKey {
    SigningKey::from_bytes(&[node; 32])
}

fn tree(contents: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("secret.txt"), contents).unwrap();
    dir
}

/// `dialer` befriends `issuer` (issuer hands out the ticket): they become mutual
/// established friends AND `dialer` records `issuer`'s dialable address.
async fn befriend(dialer: &Daemon, issuer: &Daemon) -> Result<()> {
    let ticket = issuer.issue_ticket()?;
    dialer.befriend(issuer.addr()?, &ticket, None).await?;
    Ok(())
}

/// §9.3 steps 1-2 over the wire: `unfriend` must make the EX-FRIEND tear down its own
/// side - drop the friendship (FriendshipEnd) and delete the replica it stored for us
/// (DeleteRequest) - not merely mutate the initiator's local state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unfriend_tears_down_the_peer_over_the_wire() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?;
    // A dials B to befriend, so A records B's address (needed to reach B on unfriend).
    befriend(&a, &b).await?;
    assert!(a.is_friend(&b.user_id()) && b.is_friend(&a.user_id()));

    // A publishes a vault and places a replica on B: B now holds data OF A.
    let src = tree(b"epoch-one");
    let (vid, _n) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;
    let placed = a.place_replicas(vid, &[b.addr()?], 1).await?;
    assert_eq!(placed, vec![b.node_id()], "B accepted the replica");
    assert!(
        b.holds_replica(&vid),
        "B stores A's replica before unfriend"
    );

    // A unfriends B. This is best-effort to B's last-known address, awaited inside.
    let outcome = a.unfriend(b.user_id()).await?;
    assert!(outcome.was_friend);
    assert!(
        !a.is_friend(&b.user_id()),
        "the initiator drops the friendship locally"
    );

    // The peer's inbound handlers actually fired over the wire:
    assert!(
        !b.is_friend(&a.user_id()),
        "FriendshipEnd made B drop its friendship with A"
    );
    assert!(
        !b.holds_replica(&vid),
        "DeleteRequest made B delete the replica it held for A"
    );

    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

/// The authorization negatives that the two W5 blockers were about. A current friend B
/// of the victim V must not be able to (a) forge V into unfriending B by naming a third
/// party in a FriendshipEnd, nor (b) destroy the share V holds for an unrelated owner A.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn forged_friendship_end_and_share_destroy_are_rejected() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA1)).await?; // owner of the split secret
    let b = Daemon::start(seeds(0x11, 0xB1)).await?; // malicious insider (trustee + V's friend)
    let c = Daemon::start(seeds(0x21, 0xC1)).await?; // honest co-trustee
    let v = Daemon::start(seeds(0x31, 0xD1)).await?; // victim trustee

    // A befriends all three trustees (so A can deliver grants they authorize).
    for t in [&b, &c, &v] {
        befriend(&a, t).await?;
    }
    // B is an established friend of V: exactly the insider whose node V will resolve as
    // an owner (owner B), and who is authorized on V's control stream.
    befriend(&b, &v).await?;
    assert!(v.is_friend(&b.user_id()));

    // A splits 2-of-3 to [B, C, V]; V ends up holding A's share (subject = A, rsid = 7).
    let trustees = [b.user_id(), c.user_id(), v.user_id()];
    a.recovery_split_grant(
        RSID,
        RecoveryScope::Root,
        2,
        &trustees,
        RECOVERY_DELAY,
        false,
    )
    .await?;
    assert!(
        v.held_grant(&a.user_id()).is_some(),
        "V holds A's share before the attacks"
    );

    // --- (a) FriendshipEnd naming a THIRD PARTY must not tear down V<->B ---
    let mut end = FriendshipEnd {
        user: [0x99; 32], // NOT V: B is "ending friendship with" some unrelated user
        ts: 1_700_000_000,
        by: [0; 32],
        sig: [0; 64],
    };
    end.sign(&node_key(0x11)); // signed by B's own node key
    b.send_control_frame(&v.addr()?, &end).await?;
    assert!(
        v.is_friend(&b.user_id()),
        "a FriendshipEnd that does not name V must be ignored"
    );

    // --- (b1) ShareDestroy naming owner A must be rejected: B is not A ---
    // B knows A's rsid (it is a co-trustee) and signs a destroy for A's share.
    let mut ds_wrong_owner = ShareDestroy {
        subject: a.user_id(),
        rsid: RSID,
        by: [0; 32],
        sig: [0; 64],
    };
    ds_wrong_owner.sign(&node_key(0x11));
    b.send_control_frame(&v.addr()?, &ds_wrong_owner).await?;
    assert!(
        v.held_grant(&a.user_id()).is_some(),
        "a friend that is not the subject-owner cannot destroy the subject's share"
    );

    // --- (b2) ShareDestroy naming B as subject but A's rsid must be rejected ---
    // Here owner_user_of_node(B) == subject(B) passes, but the rsid belongs to A, so the
    // rsid->subject binding must refuse it.
    let mut ds_wrong_rsid = ShareDestroy {
        subject: b.user_id(),
        rsid: RSID,
        by: [0; 32],
        sig: [0; 64],
    };
    ds_wrong_rsid.sign(&node_key(0x11));
    b.send_control_frame(&v.addr()?, &ds_wrong_rsid).await?;
    assert!(
        v.held_grant(&a.user_id()).is_some(),
        "naming an rsid that belongs to a different owner cannot destroy that owner's share"
    );

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    v.shutdown().await;
    Ok(())
}
