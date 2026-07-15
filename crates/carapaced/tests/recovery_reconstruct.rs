//! §8.4 end-to-end DATA recovery: the ceremony -> replica -> reconstruct path the
//! project was missing. `full_ceremony_recovers_k_root` (tests/ceremony.rs) proves a
//! key-less claimant recovers `K_root`; `friend_gate_replica_placement...`
//! (tests/friend_replica.rs) proves a *delegated* device reconstructs off a replica
//! while the owner is live. This test joins them for the real recovery scenario: the
//! owner is GONE, and a FRESH claimant device that recovered only `K_root` must fetch
//! and decrypt the actual file content off a surviving friend's replica.
//!
//! Flow: owner A publishes a multi-file vault and places a replica on friend B (the
//! placement now also ships the owner-signed announce + FileGrant, §8.4); A splits
//! `K_root` 2-of-3 to trustees B, C, D. A then "loses every device". A fresh claimant
//! runs the full ceremony (collect M shares -> recover `K_root`, re-derive identity),
//! stands itself up as a `Daemon` on the recovered key, and reconstructs the vault
//! from B - authenticating as an owner-delegated device (`ReplicaDevice`) with a card
//! its re-derived user key signed. The assertion is CONTENT: every file byte-matches
//! the source, not merely that `K_root` came back.
//!
//! Bounded (§11 lesson): the 72 h abort delay is driven by an INJECTED clock, all
//! dials are connect-timeout bounded, and every daemon is torn down.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use carapaced::{ClaimantDevice, Daemon, RecoveryScope, State};

/// The owner's abort window carried in every grant (§8.5 default): 72 hours.
const DELAY: u64 = 72 * 3600;
/// A fixed injected wall clock the ceremony starts at (bounded tests never use real time).
const T0: u64 = 1_800_000_000;

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// `a` befriends `peer` (peer issues the ticket): both sides persist the friendship and
/// the other's card, so `a` can place a replica / deliver grants and `peer` authorizes
/// `a`'s owner-signed docs.
async fn a_befriends(a: &Daemon, peer: &Daemon) -> Result<()> {
    let ticket = peer.issue_ticket()?;
    a.befriend(peer.addr()?, &ticket, None).await?;
    Ok(())
}

/// A small multi-file, multi-chunk tree (well under the 16 MiB replica-blob cap) so the
/// reconstruct genuinely exercises envelope + several ciphertext chunks.
fn make_tree() -> (tempfile::TempDir, BTreeMap<String, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut expected = BTreeMap::new();
    let big: Vec<u8> = (0..1_500_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "readme.txt",
            b"recover my actual bytes, not just K_root".to_vec(),
        ),
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

/// THE missing acceptance test: a fresh claimant recovers `K_root` through the full
/// ceremony, then reconstructs the owner's vault CONTENT from a surviving replica.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ceremony_then_reconstruct_recovers_file_content() -> Result<()> {
    // Owner A and three friends B, C, D (trustees). B additionally holds a vault replica.
    let a = Daemon::start(seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?;
    let c = Daemon::start(seeds(0x21, 0xC0)).await?;
    let d = Daemon::start(seeds(0x31, 0xD0)).await?;
    for t in [&b, &c, &d] {
        a_befriends(&a, t).await?;
    }

    // A publishes a real vault and places a replica on friend B. The placement now also
    // pushes A's owner-signed VaultAnnounce + FileGrant, which B retains (§8.4).
    let (src, expected) = make_tree();
    let (vid, _nonce) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;
    let placed = a.place_replicas(vid, &[b.addr()?], 1).await?;
    assert_eq!(
        placed,
        vec![b.node_id()],
        "B accepted the replica placement"
    );
    assert!(b.holds_replica(&vid), "B stored the vault blobs");

    // A splits K_root 2-of-3 to B, C, D (W3 grants delivered).
    let subject = a.user_id();
    let trustees = [b.user_id(), c.user_id(), d.user_id()];
    let report = a
        .recovery_split_grant(7, RecoveryScope::Root, 2, &trustees, DELAY, false)
        .await?;
    assert_eq!(report.delivered.len(), 3, "all three grants delivered");
    let roster = [b.user_id(), c.user_id(), d.user_id()];

    // ---- A "loses every device": shut the owner down. The replica (B) and trustees
    // (B, C, D) survive; recovery must complete without A. ----
    a.shutdown().await;

    // ---- Full recovery ceremony from a fresh key-less claimant (§8.5). ----
    for t in [&b, &c, &d] {
        t.set_test_clock(T0);
    }
    let claimant = ClaimantDevice::new()?;
    let (open, id) = b.ceremony_sponsor_open(
        subject,
        "the heir".into(),
        claimant.ceremony_enc(),
        claimant.new_node(),
        "owner lost all devices".into(),
        T0,
    )?;
    b.deliver_recovery_open(&c.addr()?, &open).await?;
    b.deliver_recovery_open(&d.addr()?, &open).await?;

    // B and C approve (M = 2 reached) and broadcast their approvals to the co-trustees.
    let ap_b = b.ceremony_approve(id, T0 + 10)?;
    b.send_ceremony_approve(&c.addr()?, &ap_b).await?;
    b.send_ceremony_approve(&d.addr()?, &ap_b).await?;
    let ap_c = c.ceremony_approve(id, T0 + 20)?;
    c.send_ceremony_approve(&b.addr()?, &ap_c).await?;
    c.send_ceremony_approve(&d.addr()?, &ap_c).await?;

    // Past the delay the two approving trustees release their sealed shares.
    for t in [&b, &c, &d] {
        t.set_test_clock(T0 + DELAY);
    }
    let shares = claimant
        .collect_raw(&open, &[b.addr()?, c.addr()?, d.addr()?])
        .await?;
    assert_eq!(shares.len(), 2, "the two approving trustees release");
    let recovered = claimant.recover_from(&shares, &roster)?;
    assert_eq!(
        recovered.user_id, subject,
        "re-derived user key equals the original owner's"
    );

    // ---- §8.4 data recovery: stand the claimant up as a full Daemon on the recovered
    // K_root + its own node identity, then reconstruct the vault off the surviving
    // replica B. The claimant is a FRESH device (new node key) presenting a card its
    // re-derived owner-user key signed; B admits it as an owner-delegated ReplicaDevice
    // and serves the retained announce + grant + owner card + blobs. ----
    let recovered_daemon =
        Daemon::start(State::from_seeds(claimant.node_seed(), *recovered.k_root)).await?;
    assert_eq!(
        recovered_daemon.user_id(),
        subject,
        "the recovered daemon is the same user as the lost owner"
    );

    let out = tempfile::tempdir()?;
    let reconstructed = recovered_daemon
        .reconstruct_from_replica(b.addr()?, b.addr()?, out.path())
        .await?;
    let got = reconstructed
        .iter()
        .find(|r| r.vid == vid)
        .context("the claimant must reconstruct the owner's vault from the replica")?;

    // THE POINT: the claimant recovered the ACTUAL FILE CONTENT, byte-for-byte.
    for (rel, bytes) in &expected {
        let path = got.out_dir.join(rel);
        let recovered_bytes =
            std::fs::read(&path).with_context(|| format!("missing reconstructed file {rel}"))?;
        assert_eq!(
            &recovered_bytes, bytes,
            "content mismatch for {rel}: recovery must yield the real bytes, not just K_root"
        );
    }

    recovered_daemon.shutdown().await;
    for t in [b, c, d] {
        t.shutdown().await;
    }
    Ok(())
}
