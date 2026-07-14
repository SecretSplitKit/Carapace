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

/// §9.3.4 W5 (gap 1): unfriending a TRUSTEE does not auto-start the re-split. It records a
/// PENDING one (surfaced with the suggested new set, the ex-trustee excluded) and delivers
/// NO new grants until the user starts it via `start_pending_resplit`. This is the §9.3.4
/// prompt flow: the user, not the daemon, decides to re-split.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn unfriending_a_trustee_leaves_a_pending_resplit_until_started() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA2)).await?; // owner of the split secret
    let b = Daemon::start(seeds(0x11, 0xB2)).await?; // trustee to be unfriended
    let c = Daemon::start(seeds(0x21, 0xC2)).await?; // honest co-trustee
    let v = Daemon::start(seeds(0x31, 0xD2)).await?; // honest co-trustee

    for t in [&b, &c, &v] {
        befriend(&a, t).await?;
    }
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
        a.pending_resplit_statuses().is_empty(),
        "no pending re-split before any unfriend"
    );
    assert!(
        a.resplit_statuses().is_empty(),
        "no open re-split before any unfriend"
    );

    // Unfriend a trustee: the re-split is DETECTED but left PENDING (§9.3.4 prompt).
    let outcome = a.unfriend(b.user_id()).await?;
    assert!(outcome.was_friend);
    assert_eq!(
        outcome.resplit_rsids,
        vec![RSID],
        "the trustee's recovery set is named as needing a re-split"
    );

    let pending = a.pending_resplit_statuses();
    assert_eq!(pending.len(), 1, "exactly one re-split is pending");
    assert_eq!(pending[0].old_rsid, RSID);
    assert_eq!(pending[0].ex_trustee, b.user_id());
    let suggested: Vec<[u8; 32]> = pending[0].suggested.iter().map(|t| t.user).collect();
    assert!(
        !suggested.contains(&b.user_id()),
        "the suggested new set excludes the ex-trustee"
    );
    assert_eq!(
        suggested.len(),
        2,
        "suggested new set is the two remaining trustees"
    );
    assert!(suggested.contains(&c.user_id()) && suggested.contains(&v.user_id()));
    assert!(
        a.resplit_statuses().is_empty(),
        "unfriend does NOT open the re-split or deliver new-set grants"
    );

    // The user starts it: it becomes OPEN (delivering) and is cleared from the prompt.
    let status = a.start_pending_resplit(RSID, None).await?;
    assert_eq!(status.old_rsid, RSID);
    assert_eq!(
        status.new_total, 2,
        "the new set is the two remaining trustees"
    );
    assert!(
        a.pending_resplit_statuses().is_empty(),
        "starting clears the pending prompt"
    );
    let open = a.resplit_statuses();
    assert_eq!(open.len(), 1, "the re-split is now open and driving");
    assert_eq!(open[0].old_rsid, RSID);

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    v.shutdown().await;
    Ok(())
}

/// §9.3.1 W5 (gap 2): a daemon that RECEIVES a FriendshipEnd from a peer it placed data on
/// must send ITS OWN DeleteRequest(s) for what it placed - deferred to the maintenance loop
/// (the control handler has no endpoint to dial out). Here B placed a replica on A; when B
/// receives A's FriendshipEnd, B tears down and, after a maintenance round, asks A to delete
/// B's replica. A keeps its side of the friendship so it still honors the request and the
/// deletion is observable end to end. A DeleteRequest never triggers a FriendshipEnd, so
/// this cannot loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receiving_friendship_end_sends_reciprocal_delete_requests() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA3)).await?;
    let b = Daemon::start(seeds(0x11, 0xB3)).await?;
    // B dials A to befriend, so B records A's address (needed to reach A with the delete).
    befriend(&b, &a).await?;
    assert!(a.is_friend(&b.user_id()) && b.is_friend(&a.user_id()));

    // B publishes a vault and places a replica on A: A now holds data OF B.
    let src = tree(b"b-epoch-one");
    let (vid, _n) = b.new_vid();
    b.publish_vault(src.path(), vid).await?;
    let placed = b.place_replicas(vid, &[a.addr()?], 1).await?;
    assert_eq!(placed, vec![a.node_id()], "A accepted B's replica");
    assert!(a.holds_replica(&vid), "A stores B's replica before the end");

    // A sends B a validly signed FriendshipEnd naming B, but keeps its OWN friendship with
    // B (so it still authorizes B's reciprocal DeleteRequest - we can then observe A delete
    // B's data). This isolates the RECEIVE-path reciprocal-send; in a full mutual unfriend A
    // would already have dropped B's data in its own teardown.
    let mut end = FriendshipEnd {
        user: b.user_id(),
        ts: 1_700_000_000,
        by: [0; 32],
        sig: [0; 64],
    };
    end.sign(&node_key(0x01)); // A's node key
    a.send_control_frame(&b.addr()?, &end).await?;
    assert!(
        !b.is_friend(&a.user_id()),
        "B tore down its friendship on receiving the FriendshipEnd"
    );

    // B's maintenance loop drains the queued reciprocal DeleteRequest and sends it to A.
    let _ = b.maintenance_round(1_700_000_100).await;

    assert!(
        !a.holds_replica(&vid),
        "B's reciprocal DeleteRequest made A delete the replica B had placed on it"
    );

    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}
