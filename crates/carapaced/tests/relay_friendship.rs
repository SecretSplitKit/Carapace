//! §6 acceptance: NAT-blind connectivity over self-hosted relays only.
//!
//! Two daemons `A` and `B`, each running its own embedded self-hosted relay and
//! bound loopback. Neither is ever told the other's direct socket address: A's
//! relay URL reaches B via A's issued ticket, and B's relay URL reaches A via the
//! ContactCard B presents during the handshake. From only those relay hints they
//! complete a friendship and A places a small vault replica on B - the entire
//! bootstrap traverses the relay path.
//!
//! Structural relay proof (same caveat as `carapace-net`'s relay test): both peers
//! run on loopback, so iroh *may* background-upgrade to a direct loopback path
//! after the relay bootstraps the connection. The relay-only guarantee is
//! structural: neither peer is given a direct address and there is no discovery
//! service, so the embedded relays are the only thing that can bootstrap the
//! connection at all.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use carapaced::{Daemon, NetConfig, State};

/// A daemon that runs its own embedded relay, bound loopback for in-process use.
async fn relay_daemon(node: u8, root: u8) -> Result<Daemon> {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let cfg = NetConfig {
        bind: Some(loopback),
        run_relay: Some(loopback),
        ..NetConfig::default()
    };
    Daemon::start_on(
        State::from_seeds([node; 32], [root; 32]),
        Default::default(),
        cfg,
    )
    .await
}

/// A small multi-chunk tree, well under the 16 MiB replica-blob cap.
fn make_tree() -> (tempfile::TempDir, BTreeMap<String, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut expected = BTreeMap::new();
    let big: Vec<u8> = (0..1_500_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("readme.txt", b"hello relay replicas".to_vec()),
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
async fn relay_only_friendship_and_replica() -> Result<()> {
    let a = relay_daemon(0x01, 0xA0).await?;
    let b = relay_daemon(0x11, 0xB0).await?;

    // Both must advertise a self-hosted relay (§6).
    let a_relay = a
        .advertised_relay_url()
        .context("A must advertise its embedded relay")?;
    assert!(a_relay.starts_with("http://"), "plain-HTTP relay url");
    assert!(
        b.advertised_relay_url().is_some(),
        "B must advertise its embedded relay"
    );

    // Each endpoint registers on its own relay so it is reachable by relay
    // fallback before we try to connect through it.
    for d in [&a, &b] {
        tokio::time::timeout(Duration::from_secs(15), d.wait_online())
            .await
            .context("endpoint failed to register with its relay in time")?;
    }

    // ---- friendship, NAT-blind: B dials A by node id only ----
    // The ticket A issues carries A's relay URL (and no direct address); B injects
    // that hint and dials A's bare node id over the relay.
    let ticket = a.issue_ticket()?;
    assert!(
        ticket.relay_urls.contains(&a_relay),
        "issued ticket advertises A's relay ({a_relay})"
    );
    assert!(
        ticket.addrs.is_empty(),
        "ticket carries no direct address - relay path only"
    );

    let fr = b
        .befriend_at(a.node_id(), &[], &ticket, None)
        .await
        .context("relay-only befriend must succeed with no direct address")?;
    fr.verify().context("friendship must be dual-signed")?;
    assert!(a.is_friend(&b.user_id()) && b.is_friend(&a.user_id()));

    // ---- small vault replica, NAT-blind: A places on B by node id only ----
    // A learned B's relay from the ContactCard B presented during the handshake,
    // so A can reach B's bare node id over the relay with no direct address.
    let (src, expected) = make_tree();
    let (vid, _nonce) = a.new_vid();
    a.publish_vault(src.path(), vid).await?;

    let placed = a
        .place_replicas_at(vid, &[(b.node_id(), vec![])], 1)
        .await
        .context("relay-only replica placement must succeed")?;
    assert_eq!(
        placed,
        vec![b.node_id()],
        "B accepted the replica over relay"
    );
    assert!(
        b.holds_replica(&vid),
        "B stored the pushed replica blobs (transferred over the relay path)"
    );
    // The blobs really moved: the source tree is ~1.5 MiB across two files.
    assert!(!expected.is_empty());

    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}
