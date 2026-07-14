//! W7 anti-entropy store-and-forward (§6): "reach any one friend re-syncs the rest."
//!
//! A and C are NOT friends and never dial each other; both friend B. A's signed
//! VaultAnnounce must reach C through B: B stores the third-party announce it learned
//! from A and re-serves it to C during anti-entropy. BOUNDED (hard per-call timeouts).

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use carapaced::{Daemon, Reconstructed, State};
use iroh::EndpointAddr;

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// `dialer` befriends `acceptor` (acceptor issues the ticket): the acceptor learns the
/// dialer as a friend, so the dialer can later pull documents from it.
async fn befriend(dialer: &Daemon, acceptor: &Daemon) -> Result<()> {
    let ticket = acceptor.issue_ticket()?;
    dialer.befriend(acceptor.addr()?, &ticket, None).await?;
    Ok(())
}

/// A bounded document pull: fail loudly on a hang instead of blocking the suite.
async fn pull(d: &Daemon, peer: EndpointAddr, out: &Path) -> Result<Vec<Reconstructed>> {
    match tokio::time::timeout(Duration::from_secs(20), d.sync_from(peer, out)).await {
        Ok(res) => res,
        Err(_) => bail!("sync_from did not finish within the cap: hang/deadlock"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn owner_announce_reaches_a_friend_of_a_friend() -> Result<()> {
    let a = Daemon::start(seeds(0x0a, 0xA0)).await?; // owner
    let b = Daemon::start(seeds(0x0b, 0xB0)).await?; // the mutual friend / relay hop
    let c = Daemon::start(seeds(0x0c, 0xC0)).await?; // never friends with A

    // Friendship edges: B<->A and C<->B only. A and C never exchange anything.
    befriend(&b, &a).await?; // B befriends A: A now knows B
    befriend(&c, &b).await?; // C befriends B: B now knows C

    // A publishes a vault, producing a signed VaultAnnounce.
    let src = tempfile::tempdir()?;
    std::fs::write(src.path().join("doc.txt"), b"owned by A")?;
    let (vid, _n) = a.new_vid();
    let epoch = a.publish_vault(src.path(), vid).await?;

    // C does not know the announce before anything syncs.
    assert!(
        c.known_announce(&vid).is_none(),
        "C must not know A's announce before store-and-forward"
    );

    // B pulls from A and learns (stores) A's card + announce.
    let out_b = tempfile::tempdir()?;
    pull(&b, a.addr()?, out_b.path()).await?;
    assert_eq!(
        b.known_announce(&vid),
        Some((a.node_id(), epoch)),
        "B stores the third-party announce it learned from A"
    );

    // C pulls from B ONLY. B re-serves A's announce; C never dials A.
    let out_c = tempfile::tempdir()?;
    pull(&c, b.addr()?, out_c.path()).await?;

    assert_eq!(
        c.known_announce(&vid),
        Some((a.node_id(), epoch)),
        "A's signed announce reached C through B without C ever dialing A (§6/W7)"
    );
    // Sanity: A and C are not friends (no edge was ever created between them).
    assert!(!a.is_friend(&c.user_id()), "A and C are not friends");
    assert!(!c.is_friend(&a.user_id()), "C and A are not friends");

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    Ok(())
}
