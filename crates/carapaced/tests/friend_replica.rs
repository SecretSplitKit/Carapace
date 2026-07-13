//! Phase-1-close acceptance: friendship handshake, friendship-gated control
//! stream (W5), replica placement, repair, and reconstruction from a surviving
//! replica - all over in-process localhost iroh endpoints.
//!
//! Topology: owner `A` with a second delegated device `A2` (shared `k_root`);
//! three independent friends `B`, `C`, `E`; and a stranger `D`.
//!
//! 1. A issues single-use tickets; B, C, and E each drive `befriend` to a
//!    dual-signed `Friendship`, persisted on both sides.
//! 2. A publishes a vault and places replicas on B and C (r = 2).
//! 3. W5: the stranger D pulls A's control stream and receives no documents,
//!    while a friend (B) does - proving the gate keys on the friend graph.
//! 4. B is declared unreachable past grace; A repairs onto the spare friend E
//!    and re-announces the new set {C, E}.
//! 5. A2 (a delegated device of A) reconstructs the vault: documents from A,
//!    ciphertext blobs from the surviving replica C. Bytes match A's source.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result};
use carapace_replica::Health;
use carapaced::{Daemon, State};

fn daemon_seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// A small multi-file, multi-chunk tree (well under the 16 MiB replica-blob cap).
fn make_tree() -> (tempfile::TempDir, BTreeMap<String, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut expected = BTreeMap::new();
    let big: Vec<u8> = (0..1_500_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("readme.txt", b"hello carapace replicas".to_vec()),
        ("empty.bin", Vec::new()),
        ("nested/blob.bin", big),
    ];
    for (rel, bytes) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        expected.insert(rel.to_string(), bytes);
    }
    (dir, expected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn friend_gate_replica_placement_repair_and_recovery() -> Result<()> {
    // Owner A and its second delegated device A2 share one k_root.
    const ROOT_A: u8 = 0xA0;
    let a = Daemon::start(daemon_seeds(0x01, ROOT_A)).await?;
    let a2 = Daemon::start(daemon_seeds(0x02, ROOT_A)).await?;
    assert_eq!(a.user_id(), a2.user_id(), "A and A2 are one user");
    assert_ne!(a.node_id(), a2.node_id(), "distinct devices");

    // Independent friends and one stranger.
    let b = Daemon::start(daemon_seeds(0x11, 0xB0)).await?;
    let c = Daemon::start(daemon_seeds(0x21, 0xC0)).await?;
    let e = Daemon::start(daemon_seeds(0x31, 0xE0)).await?;
    let d = Daemon::start(daemon_seeds(0x41, 0xD0)).await?;

    // ---- 1. friendship handshakes: A issues, each friend befriends A ----
    for friend in [&b, &c, &e] {
        let ticket = a.issue_ticket()?;
        let fr = friend.befriend(a.addr()?, &ticket, None).await?;
        fr.verify().context("friendship must be dual-signed")?;
        assert!(
            friend.is_friend(&a.user_id()),
            "friend side persists friendship"
        );
        assert!(a.is_friend(&friend.user_id()), "A side persists friendship");
        // Same dual-signed record on both sides.
        assert_eq!(a.friendship_with(&friend.user_id()), Some(fr));
    }
    // A ticket is single-use: replaying B's flow with a spent token must fail.
    let spent = a.issue_ticket()?;
    b.befriend(a.addr()?, &spent, None).await?; // consumes it
    assert!(
        b.befriend(a.addr()?, &spent, None).await.is_err(),
        "a spent ticket must be refused (single-use §6)"
    );

    // ---- 2. publish + place replicas on B and C (r = 2) ----
    let (src, expected) = make_tree();
    let (vid, _nonce) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;

    let placed = a.place_replicas(vid, &[b.addr()?, c.addr()?], 2).await?;
    assert_eq!(placed.len(), 2, "both friends accepted the placement");
    let members = a.replica_members(&vid);
    assert!(members.contains(&b.node_id()) && members.contains(&c.node_id()));
    assert!(
        b.holds_replica(&vid) && c.holds_replica(&vid),
        "replicas stored the blobs"
    );

    // ---- 3. W5: stranger gets nothing; a friend gets the document set ----
    let (dc, da, dg) = d.pull_doc_counts(a.addr()?).await?;
    assert_eq!(
        (dc, da, dg),
        (0, 0, 0),
        "unauthorized dialer D is served no documents (W5)"
    );
    let (bc, ba, bg) = b.pull_doc_counts(a.addr()?).await?;
    assert!(
        ba >= 1 && bg >= 1 && bc >= 1,
        "a friend is served cards/announces/grants"
    );

    // ---- 4. repair: B lost past grace -> re-replicate onto spare friend E ----
    let mut healths = HashMap::new();
    healths.insert(b.node_id(), Health::UnreachableSince(0)); // now - 0 >> 24h grace
    let changed = a
        .repair_vault(vid, &healths, &[c.addr()?, e.addr()?])
        .await?;
    assert!(changed, "repair changed the member set");
    let members = a.replica_members(&vid);
    assert!(
        !members.contains(&b.node_id()),
        "lost replica B was dropped"
    );
    assert!(
        members.contains(&c.node_id()) && members.contains(&e.node_id()),
        "set is now {{C, E}}"
    );
    assert!(
        e.holds_replica(&vid),
        "the fresh replica E stored the blobs"
    );

    // ---- 5. delegated device A2 reconstructs: docs from A, blobs from C ----
    let out = tempfile::tempdir()?;
    let reconstructed = a2
        .reconstruct_from_replica(a.addr()?, c.addr()?, out.path())
        .await?;
    let got = reconstructed
        .iter()
        .find(|r| r.vid == vid)
        .context("A2 must reconstruct the vault from the surviving replica")?;
    for (rel, bytes) in &expected {
        let path = got.out_dir.join(rel);
        let recovered = std::fs::read(&path).with_context(|| format!("missing {rel}"))?;
        assert_eq!(&recovered, bytes, "content mismatch for {rel}");
    }

    for daemon in [a, a2, b, c, e, d] {
        daemon.shutdown().await;
    }
    Ok(())
}
