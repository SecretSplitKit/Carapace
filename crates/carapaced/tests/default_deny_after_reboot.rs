//! Audit #4 regression (design §3.5 / §11 default-deny after reboot).
//!
//! A device reaches gate state through a §11 merge (`publish_merged`): a receiver with its
//! own concurrent edit pulls a peer's concurrent edit, reconciles, and RE-PUBLISHES the
//! merged vault - inserting `owned_chunks` (incl. the merged manifest-envelope digest),
//! `announces`, `grants`, and `vault_blobs`. The pre-fix `publish_merged` returned WITHOUT
//! committing, so after a reboot the device default-denied its OWN merged blobs (owned_chunks
//! empty) and rolled back its own announce.
//!
//! The merge is the LAST persisted op before the reboot (any later `persist_locked` - e.g. a
//! disclose - would re-commit the whole state and mask the missing commit), so the reload
//! exercises `publish_merged`'s own persistence. After reboot the fetch gate must decide from
//! the reloaded state:
//!
//! - an owner device (same `k_root`) is SERVED the merge-unique envelope chunk (owned_chunks
//!   survived - the #4 catch);
//! - an unauthenticated stranger is REFUSED it (F1 default-deny);
//! - a disclosed audience friend is SERVED a disclosed chunk (the audience arm survived).

use anyhow::{Context, Result};
use carapaced::{Daemon, State};

const K_ROOT: [u8; 32] = [0x84u8; 32];

async fn befriend(owner: &Daemon, friend: &Daemon) -> Result<()> {
    let ticket = owner.issue_ticket()?;
    friend.befriend(owner.addr()?, &ticket, None).await?;
    assert!(
        owner.is_friend(&friend.user_id()) && friend.is_friend(&owner.user_id()),
        "friendship must be mutual"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_deny_survives_reboot_after_merge() -> Result<()> {
    let b_dir = tempfile::tempdir()?;
    let b_seed = [0x8Bu8; 32];

    // Peer A and device B share ONE user (same k_root), distinct nodes: two owner devices.
    let a = Daemon::start(State::from_seeds([0x8Au8; 32], K_ROOT)).await?;
    // A disclosed-audience friend (its own user), and an unrelated stranger.
    let f = Daemon::start(State::from_seeds([0x8Fu8; 32], [0xF0u8; 32])).await?;
    let stranger = Daemon::start(State::from_seeds([0x8Cu8; 32], [0xC0u8; 32])).await?;

    let (merged_digest, disclosed_chunk) = {
        let b = Daemon::start(State::from_seeds_in(b_dir.path(), b_seed, K_ROOT)).await?;

        // Concurrent edits to the SAME vid with no shared ancestry: neither version vector
        // dominates, so B's pull-from-A reconciles into a §11 merge + republish.
        let (vid, _n) = a.new_vid();
        let src_a = tempfile::tempdir()?;
        let src_b = tempfile::tempdir()?;
        std::fs::write(
            src_a.path().join("notes.txt"),
            b"device A wrote these notes",
        )?;
        std::fs::write(
            src_b.path().join("notes.txt"),
            b"device B wrote different notes",
        )?;
        assert_eq!(a.publish_vault(src_a.path(), vid).await?, 1);
        assert_eq!(b.publish_vault(src_b.path(), vid).await?, 1);

        // Friendship + disclosure of B's OWN published chunk to F, BEFORE the merge. This
        // persists (whole-state), so it must precede the merge - otherwise its commit would
        // mask publish_merged's missing one. The disclosed chunk is B's notes.txt chunk,
        // owned via publish_vault and retained across the merge (owned_chunks is additive).
        befriend(&b, &f).await?;
        let grant = b.disclose_files(vid, &["notes.txt"], &[f.user_id()])?;
        let disclosed_chunk = *f
            .granted_chunk_ids(&grant)?
            .first()
            .context("disclosure grant covers a chunk")?;

        // A single directed pull: B sees A's concurrent edit, merges, and runs
        // `publish_merged` - the LAST persisted op before the reboot. It inserts the merged
        // manifest-envelope digest into owned_chunks.
        let out = tempfile::tempdir()?;
        let recon = b.sync_from(a.addr()?, out.path()).await?;
        assert!(
            recon.iter().any(|r| r.vid == vid),
            "B reconstructs (and merges) the vault"
        );

        // The merge-unique chunk: the merged envelope digest, owned ONLY via publish_merged.
        let merged_digest = b
            .own_announce_digest(&vid)
            .context("B has a merged announce")?;
        assert!(
            b.owns_chunk(&merged_digest),
            "publish_merged put the merged envelope digest in owned_chunks (in RAM)"
        );

        b.shutdown().await;
        (merged_digest, disclosed_chunk)
    };

    // Let redb release the file before re-opening the same dir.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ---- reboot B from the SAME dir: gate state must be reloaded from disk ----
    let b2 = Daemon::start(State::from_seeds_in(b_dir.path(), b_seed, K_ROOT)).await?;

    // Robust non-network signal for #4: the merge-unique owned chunk survived. Pre-fix, the
    // merged owned_chunks/announce were never committed, so this is absent after reload.
    assert!(
        b2.owns_chunk(&merged_digest),
        "audit #4: publish_merged's owned_chunks (merged envelope digest) must survive the reboot"
    );

    let b2_addr = b2.addr()?;

    // (1) owner device: authenticate (classifies A as our own device), then fetch the
    // merge-unique envelope chunk -> SERVED only if the merged owned_chunks survived (#4).
    a.pull_doc_counts(b2_addr.clone())
        .await
        .context("owner device authenticates to rebooted B")?;
    assert!(
        a.try_fetch_chunk(b2_addr.clone(), merged_digest)
            .await
            .is_ok(),
        "an owner device is served its own merged envelope chunk after reboot (#4)"
    );

    // (2) stranger (never authenticated, unrelated k_root): default-deny -> REFUSED.
    assert!(
        stranger
            .try_fetch_chunk(b2_addr.clone(), merged_digest)
            .await
            .is_err(),
        "an unauthenticated stranger is refused (F1 default-deny)"
    );

    // (3) disclosed audience friend: authenticate (classifies F as a friend), then fetch the
    // disclosed chunk. Served only because BOTH owned_chunks and the disclosure audience
    // survived the reboot.
    f.pull_doc_counts(b2_addr.clone())
        .await
        .context("friend authenticates to rebooted B")?;
    assert!(
        f.try_fetch_chunk(b2_addr.clone(), disclosed_chunk)
            .await
            .is_ok(),
        "a disclosed audience friend is served the disclosed chunk after reboot"
    );

    for d in [a, f, stranger, b2] {
        d.shutdown().await;
    }
    Ok(())
}
