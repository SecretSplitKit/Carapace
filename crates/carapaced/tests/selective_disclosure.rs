//! §7.4 acceptance: selective disclosure + fetch authorization (adversarial D3).
//!
//! Topology: owner `A` publishes a vault of three files F1, F2, F3. Friends `B`
//! (the audience) and `C` (a friend NOT in the audience) both befriend `A`.
//!
//! 1. A discloses exactly F1, F2 to B; B opens the grant, fetches, and
//!    reconstructs byte-identical F1, F2 — and only those. F3's keys never appear
//!    in B's grant, so B cannot derive them.
//! 2. D3: C authenticates as a friend and holds a LEAKED copy of B's grant, yet is
//!    refused the granted chunk — the blob gate enforces audience membership, so a
//!    leaked grant document alone authorizes nothing. B (the real audience) fetches
//!    the same chunk successfully.
//! 3. Snapshot: A edits F1 and republishes (epoch 2); a fresh disclosure of F1
//!    carries new chunk keys disjoint from the epoch-1 grant, proving a grant never
//!    extends to future content.

use std::collections::HashSet;

use anyhow::Result;
use carapaced::{Daemon, State};

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// Three small single-chunk files (each well under the 256 KiB FastCDC minimum).
fn make_vault() -> (tempfile::TempDir, [(&'static str, &'static [u8]); 3]) {
    let dir = tempfile::tempdir().unwrap();
    let files: [(&str, &[u8]); 3] = [
        ("f1.txt", b"file one contents"),
        ("f2.txt", b"file two contents, a little longer"),
        ("f3.txt", b"file three is the secret one"),
    ];
    for (rel, bytes) in files {
        std::fs::write(dir.path().join(rel), bytes).unwrap();
    }
    (dir, files)
}

async fn befriend(owner: &Daemon, friend: &Daemon) -> Result<()> {
    let ticket = owner.issue_ticket()?;
    friend.befriend(owner.addr()?, &ticket, None).await?;
    assert!(owner.is_friend(&friend.user_id()) && friend.is_friend(&owner.user_id()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selective_disclosure_and_fetch_authorization() -> Result<()> {
    let a = Daemon::start(seeds(0x01, 0xA0)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?; // audience
    let c = Daemon::start(seeds(0x21, 0xC0)).await?; // friend, NOT audience

    befriend(&a, &b).await?;
    befriend(&a, &c).await?;

    let (src, files) = make_vault();
    let (vid, _nonce) = a.new_vid();
    assert_eq!(a.publish_vault(src.path(), vid).await?, 1);

    // ---- 1. A discloses exactly F1, F2 to B ----
    let grant = a.disclose_files(vid, &["f1.txt", "f2.txt"], &[b.user_id()])?;
    assert_eq!(grant.epoch, 1, "grant is a snapshot of the published epoch");
    assert_eq!(
        grant.audience,
        vec![b.user_id()],
        "audience is the explicit friend list"
    );

    // B opens, fetches, and reconstructs exactly F1, F2 (byte-identical).
    let out_b = tempfile::tempdir()?;
    let written = b.fetch_disclosed(&grant, a.addr()?, out_b.path()).await?;
    assert_eq!(
        written.len(),
        2,
        "only the two disclosed files are reconstructed"
    );

    let vid_hex = hex(&vid);
    let base = out_b.path().join(&vid_hex);
    for (rel, bytes) in files {
        let path = base.join(rel);
        if rel == "f3.txt" {
            assert!(
                !path.exists(),
                "F3 was NOT disclosed and must not be reconstructed"
            );
        } else {
            assert_eq!(&std::fs::read(&path)?, bytes, "content mismatch for {rel}");
        }
    }

    // B's grant discloses exactly F1, F2's chunks; F3's keys are nowhere in it, so B
    // cannot derive them.
    let b_ids: HashSet<[u8; 32]> = b.granted_chunk_ids(&grant)?.into_iter().collect();
    assert!(!b_ids.is_empty(), "B's grant discloses F1, F2 chunk ids");
    // F1 and F2 are distinct single-chunk files, so the grant discloses two ids: one
    // drives the fetch-gate probes below, the other the W8 re-serve regression (it must
    // stay untouched by `try_fetch_chunk`, which would otherwise populate B's store).
    let mut b_id_list: Vec<[u8; 32]> = b_ids.iter().copied().collect();
    b_id_list.sort_unstable();
    assert_eq!(
        b_id_list.len(),
        2,
        "F1, F2 each contribute one distinct chunk id"
    );

    // ---- 2. D3: a non-audience friend C, holding the LEAKED grant, is refused ----
    // C cannot even open the grant (not addressed to it): no keys, no ChunkIDs.
    assert!(
        c.granted_chunk_ids(&grant).is_err(),
        "non-audience C cannot open the leaked grant to learn its keys"
    );
    // C authenticates as a friend of A (populates A's blob-read allow-set for C).
    let _ = c.pull_doc_counts(a.addr()?).await?;
    // Even authenticated AND knowing a granted ChunkID (leaked out of band here via
    // the test), C is refused the chunk: the gate enforces audience membership.
    let a_granted = b_id_list[0];
    assert!(
        c.try_fetch_chunk(a.addr()?, a_granted).await.is_err(),
        "non-audience C is refused the granted chunk despite holding the grant (D3)"
    );
    // The real audience B, having authenticated during fetch_disclosed, may fetch it.
    assert!(
        b.try_fetch_chunk(a.addr()?, a_granted).await.is_ok(),
        "audience B may fetch the granted chunk"
    );

    // ---- W8 regression: B must NOT re-serve the disclosed ciphertext ----
    // B fetched F1/F2's ciphertext during fetch_disclosed above. That ciphertext must
    // land in a throwaway store, never B's router-served blob store: otherwise any
    // dialer knowing the ChunkID could pull the ciphertext straight off B, voiding the
    // disclosure gate and revocation. Probe a granted chunk B fetched ONLY via
    // fetch_disclosed (b_id_list[1] - not the one the try_fetch_chunk probe above pulled
    // into B's store). C dials B raw and must be refused.
    let disclosed_only = b_id_list[1];
    assert!(
        c.try_fetch_chunk(b.addr()?, disclosed_only).await.is_err(),
        "B must not re-serve disclosed ciphertext to an arbitrary dialer (W8)"
    );

    // ---- 3. snapshot: edit F1, republish; a new grant's keys are disjoint ----
    std::fs::write(
        src.path().join("f1.txt"),
        b"file one, EDITED - different bytes now",
    )?;
    assert_eq!(
        a.publish_vault(src.path(), vid).await?,
        2,
        "republish bumps the epoch"
    );

    let grant2 = a.disclose_files(vid, &["f1.txt"], &[b.user_id()])?;
    assert_eq!(grant2.epoch, 2);
    let ids2: HashSet<[u8; 32]> = b.granted_chunk_ids(&grant2)?.into_iter().collect();

    // The epoch-2 F1 chunk ids (`ids2`) share nothing with the epoch-1 grant's ids
    // (`b_ids`, which are epoch-1 F1 + F2): the edit gave F1 new plaintext, hence new
    // convergent keys and new ChunkIDs, and F2's stable ids are for a different file.
    // A grant thus never extends to future content (snapshot by construction).
    assert!(
        ids2.is_disjoint(&b_ids),
        "epoch-2 F1 chunks are disjoint from the epoch-1 grant (snapshot)"
    );

    for d in [a, b, c] {
        d.shutdown().await;
    }
    Ok(())
}

fn hex(b: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}
