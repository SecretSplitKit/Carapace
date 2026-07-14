//! End-to-end: two localhost iroh endpoints. The server ingests a directory
//! into an iroh-blobs store and advertises a signed `VaultAnnounce`; the client
//! runs anti-entropy, fetches the manifest envelope + every chunk by ChunkID,
//! and reconstructs byte-identical plaintext through `carapace-vault`. Plus a
//! unit test for the monotonic-version rollback rule.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use carapace_net::endpoint::ALPN;
use carapace_net::{
    read_msg, write_msg, AllowList, CarapaceEndpoint, CarapaceRelay, DocStore, IrohBlobStore,
    Reject, SyncHandler,
};
use carapace_vault::{
    ingest_dir, new_vid, open_envelope, reconstruct, ChunkStore, MemoryStore, VaultKeys,
};
use carapace_wire::{ContactCard, Hello, ManifestEnvelope, Offers, Signed, VaultAnnounce};
use ed25519_dalek::SigningKey;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::BlobsProtocol;

const K_ROOT: [u8; 32] = [0x33; 32];

/// Populate a temp directory with a mix of files (including one large enough to
/// be cut into multiple FastCDC chunks, a nested file, and an empty file).
fn make_tree() -> (tempfile::TempDir, BTreeMap<String, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut expected = BTreeMap::new();

    let big: Vec<u8> = (0..(3 * 1024 * 1024u32))
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("readme.txt", b"hello carapace".to_vec()),
        ("empty.bin", Vec::new()),
        ("nested/deep/data.bin", big),
        ("nested/note.md", b"# note\nsome text\n".repeat(50)),
    ];
    for (rel, bytes) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        expected.insert(rel.replace('\\', "/"), bytes);
    }
    (dir, expected)
}

fn make_card(user: &SigningKey, version: u64) -> ContactCard {
    let mut card = ContactCard {
        user: user.verifying_key().to_bytes(),
        display: "server".into(),
        enc_pub: [0x11; 32],
        nodes: vec![],
        offers: Offers {
            storage_bytes: 0,
            relay: false,
            trustee: false,
        },
        version,
        by: [0; 32],
        sig: [0; 64],
    };
    card.sign(user);
    card
}

fn signed_announce(
    node: &SigningKey,
    vid: [u8; 32],
    epoch: u64,
    digest: [u8; 32],
    replicas: Vec<[u8; 32]>,
) -> VaultAnnounce {
    let mut ann = VaultAnnounce {
        vid,
        epoch,
        replicas,
        digest,
        by: [0; 32],
        sig: [0; 64],
    };
    ann.sign(node);
    ann
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_fetch_and_reconstruct() -> Result<()> {
    let user = SigningKey::from_bytes(&[0x07; 32]);
    let server_node = SigningKey::from_bytes(&[0x09; 32]);
    let client_node = SigningKey::from_bytes(&[0x0b; 32]);

    // ---- server: ingest into a plain store, then load blobs into iroh ----
    let (src, expected) = make_tree();
    let (vid, _nonce) = new_vid(&user.verifying_key().to_bytes());
    let vkeys = VaultKeys::derive(&K_ROOT, vid);
    let epoch = 1u64;

    let mut mem = MemoryStore::new();
    let ingest = ingest_dir(src.path(), &server_node, &vkeys, epoch, &mut mem)?;

    let server_ep = CarapaceEndpoint::bind(&server_node).await?;
    assert_eq!(
        server_ep.node_id(),
        server_node.verifying_key().to_bytes(),
        "iroh EndpointId must equal the carapace node id"
    );

    let blobs = IrohBlobStore::new();
    // Manifest envelope: its blob hash must equal the announced digest.
    let env_digest = blobs.add(&ingest.envelope.to_bytes()).await?;
    assert_eq!(
        env_digest, ingest.digest,
        "envelope blob hash == manifestDigest"
    );
    // Every sealed chunk: blob hash == ChunkID by construction.
    for f in &ingest.manifest.files {
        for (id, _len) in &f.chunks {
            let ct = mem.get(id)?.expect("chunk present in source store");
            let h = blobs.add(&ct).await?;
            assert_eq!(&h, id, "iroh blob hash must equal carapace ChunkID");
        }
    }

    let announce = signed_announce(
        &server_node,
        vid,
        epoch,
        ingest.digest,
        vec![server_ep.node_id()],
    );
    let card = make_card(&user, 1);
    let handler = SyncHandler {
        hello: Hello {
            protocol: 1,
            card_version: 1,
            roles: 1,
        },
        cards: Arc::new(vec![card]),
        announces: Arc::new(vec![announce]),
    };

    let router = Router::builder(server_ep.endpoint().clone())
        .accept(iroh_blobs::ALPN, BlobsProtocol::new(blobs.mem(), None))
        .accept(ALPN, handler)
        .spawn();

    // ---- client: anti-entropy, then blob fetch, then reconstruct ----
    let client_ep = CarapaceEndpoint::bind(&client_node).await?;
    let server_addr = server_ep.direct_addr()?;

    let sync_conn = client_ep.connect(server_addr.clone(), ALPN).await?;
    let mut docs = DocStore::new();
    let accepted = carapace_net::pull_documents(
        &sync_conn,
        &Hello {
            protocol: 1,
            card_version: 0,
            roles: 0,
        },
        &mut docs,
    )
    .await?;
    assert!(
        accepted >= 2,
        "expected to accept the card and the announce, got {accepted}"
    );
    drop(sync_conn);

    let got = docs
        .announce_for_vid(&vid)
        .context("no announce for vid")?
        .clone();
    assert_eq!(got.digest, ingest.digest);
    assert_eq!(got.epoch, epoch);

    let bconn = client_ep.connect(server_addr, iroh_blobs::ALPN).await?;
    let cstore = IrohBlobStore::new();

    // Fetch the manifest envelope by its digest, verify + open it.
    cstore.fetch(&bconn, got.digest).await?;
    let env_bytes = cstore.get_bytes(got.digest).await?;
    let envelope = ManifestEnvelope::from_bytes(&env_bytes)?;
    let k_manifest: [u8; 32] = *vkeys.k_manifest;
    let manifest = open_envelope(&envelope, &k_manifest)?;
    assert_eq!(manifest.vid, vid);

    // Fetch every chunk by ChunkID into the client's iroh store.
    for f in &manifest.files {
        for (id, _len) in &f.chunks {
            cstore.fetch(&bconn, *id).await?;
        }
    }

    // Reconstruct through carapace-vault, using the iroh-backed ChunkStore. The
    // sync ChunkStore bridge block_on's, so run it off the async worker.
    let out = tempfile::tempdir()?;
    let out_path = out.path().to_path_buf();
    let keys = ingest.keys;
    let manifest_for_blocking = manifest.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        reconstruct(&manifest_for_blocking, &cstore, &keys, &out_path)?;
        Ok(())
    })
    .await??;

    // Byte-identity check against the source.
    for (rel, bytes) in &expected {
        let got = std::fs::read(out.path().join(rel))
            .with_context(|| format!("reconstructed file missing: {rel}"))?;
        assert_eq!(&got, bytes, "content mismatch for {rel}");
    }

    router.shutdown().await.ok();
    server_ep.close().await;
    client_ep.close().await;
    Ok(())
}

#[test]
fn rollback_rule_rejects_stale_and_equal_versions() {
    let signer = SigningKey::from_bytes(&[0x05; 32]);
    let mut store = DocStore::new();

    // ---- VaultAnnounce: monotonic per (signer, vid) on epoch ----
    let a5 = signed_announce(&signer, [1; 32], 5, [2; 32], vec![]);
    assert_eq!(store.offer_announce(&a5), Ok(true));
    // equal epoch is a rollback
    assert_eq!(
        store.offer_announce(&a5),
        Err(Reject::Rollback { seen: 5, got: 5 })
    );
    // lower epoch is a rollback
    let a4 = signed_announce(&signer, [1; 32], 4, [3; 32], vec![]);
    assert_eq!(
        store.offer_announce(&a4),
        Err(Reject::Rollback { seen: 5, got: 4 })
    );
    // higher epoch is accepted
    let a6 = signed_announce(&signer, [1; 32], 6, [4; 32], vec![]);
    assert_eq!(store.offer_announce(&a6), Ok(true));
    // a different vid from the same signer tracks its own line
    let b1 = signed_announce(&signer, [9; 32], 1, [5; 32], vec![]);
    assert_eq!(store.offer_announce(&b1), Ok(true));

    // tampering the epoch after signing invalidates the signature
    let mut forged = a6.clone();
    forged.epoch = 100;
    assert_eq!(store.offer_announce(&forged), Err(Reject::BadSignature));

    // ---- ContactCard: monotonic per signer on version ----
    let user = SigningKey::from_bytes(&[0x06; 32]);
    let c1 = make_card(&user, 1);
    assert_eq!(store.offer_card(&c1), Ok(true));
    assert_eq!(
        store.offer_card(&c1),
        Err(Reject::Rollback { seen: 1, got: 1 })
    );
    let c2 = make_card(&user, 2);
    assert_eq!(store.offer_card(&c2), Ok(true));
}

// W9/§2: a peer advertising an unknown suite id is rejected, never negotiated
// down. A server whose `Hello.protocol` is 99 must make the client's anti-entropy
// pull fail instead of silently proceeding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_protocol_peer_is_rejected() -> Result<()> {
    let user = SigningKey::from_bytes(&[0x41; 32]);
    let server_node = SigningKey::from_bytes(&[0x42; 32]);
    let client_node = SigningKey::from_bytes(&[0x43; 32]);

    let server_ep = CarapaceEndpoint::bind(&server_node).await?;
    let handler = SyncHandler {
        // A future/unknown suite advertised on the carapace/1 ALPN.
        hello: Hello {
            protocol: 99,
            card_version: 1,
            roles: 1,
        },
        cards: Arc::new(vec![make_card(&user, 1)]),
        announces: Arc::new(vec![]),
    };
    let router = Router::builder(server_ep.endpoint().clone())
        .accept(ALPN, handler)
        .spawn();

    let client_ep = CarapaceEndpoint::bind(&client_node).await?;
    let server_addr = server_ep.direct_addr()?;
    let conn = client_ep.connect(server_addr, ALPN).await?;

    let mut docs = DocStore::new();
    let res = carapace_net::pull_documents(
        &conn,
        &Hello {
            protocol: 1,
            card_version: 0,
            roles: 0,
        },
        &mut docs,
    )
    .await;
    assert!(
        res.is_err(),
        "a peer advertising protocol=99 must be rejected, not negotiated down"
    );

    router.shutdown().await.ok();
    server_ep.close().await;
    client_ep.close().await;
    Ok(())
}

/// Accept exactly one `carapace/1` connection on `ep`, read one `Hello` frame and
/// echo it straight back, then keep the connection open until the peer closes it.
async fn echo_one_hello(ep: Endpoint) -> Result<()> {
    let incoming = ep.accept().await.context("no incoming connection")?;
    let conn = incoming
        .accept()
        .context("accept incoming")?
        .await
        .context("await connection")?;
    let (mut send, mut recv) = conn.accept_bi().await.context("accept_bi")?;
    let hello: Hello = read_msg(&mut recv).await?;
    write_msg(&mut send, &hello).await?;
    send.finish()?;
    conn.closed().await;
    Ok(())
}

/// Relay fallback (§6): two endpoints that know ONLY each other's self-hosted
/// relay URL - no direct-address hints - open a `carapace/1` connection and
/// round-trip a frame. Since neither peer knows a direct address for the other
/// and there is no discovery service, the embedded relay is the only thing that
/// can bootstrap the connection: this is the path taken when peers can't dial
/// directly (both behind symmetric NAT).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_fallback_connects_and_roundtrips() -> Result<()> {
    let a_key = SigningKey::from_bytes(&[0x21; 32]);
    let b_key = SigningKey::from_bytes(&[0x22; 32]);

    // A self-hosted, plain-HTTP relay (no TLS, no certificate). Friend-gated: only
    // A and B are admitted (C1 - the relay is not an open forwarder).
    let access = Arc::new(AllowList::new([
        a_key.verifying_key().to_bytes(),
        b_key.verifying_key().to_bytes(),
    ]));
    let relay = CarapaceRelay::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), access).await?;
    let relay_url = relay.relay_url();
    assert_eq!(
        relay_url.scheme(),
        "http",
        "embedded relay must be plain HTTP"
    );

    // Both endpoints are configured with ONLY this relay; no direct-addr hints.
    let a = CarapaceEndpoint::bind_on(
        &a_key,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        std::slice::from_ref(&relay_url),
    )
    .await?;
    let b = CarapaceEndpoint::bind_on(
        &b_key,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        std::slice::from_ref(&relay_url),
    )
    .await?;

    // Wait for both to register with the relay (become reachable via it).
    tokio::time::timeout(Duration::from_secs(30), a.online())
        .await
        .context("A did not come online via the relay")?;
    tokio::time::timeout(Duration::from_secs(30), b.online())
        .await
        .context("B did not come online via the relay")?;

    // A accepts one carapace/1 connection and echoes the frame.
    let accept = tokio::spawn(echo_one_hello(a.endpoint().clone()));

    // B learns A only as {node_id, relay_url} - the StaticProvider hint - then
    // dials A by bare node id, forcing resolution through the relay.
    b.add_peer(EndpointAddr::new(a.id()).with_relay_url(relay_url.clone()));

    let sent = Hello {
        protocol: 1,
        card_version: 42,
        roles: 5,
    };
    let echoed = tokio::time::timeout(Duration::from_secs(30), async {
        let conn = b.connect(EndpointAddr::new(a.id()), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
        write_msg(&mut send, &sent).await?;
        send.finish()?;
        let echoed: Hello = read_msg(&mut recv).await?;

        // The peer is reachable purely because of the relay: assert a relay
        // transport path to A is known while the connection is live.
        let info = b
            .endpoint()
            .remote_info(a.id())
            .await
            .context("no remote info for A")?;
        let via_relay = info.addrs().any(|ta| ta.addr().is_relay());
        assert!(via_relay, "expected a relay transport path to peer A");

        anyhow::Ok(echoed)
    })
    .await
    .context("relay round-trip timed out")??;

    assert_eq!(
        echoed, sent,
        "frame must round-trip unchanged through the relay"
    );

    accept.await.context("accept task panicked")??;
    a.close().await;
    b.close().await;
    relay.shutdown().await?;
    Ok(())
}

/// Direct path: two endpoints with NO relay configured connect purely from a
/// direct-address hint injected into the peer's `MemoryLookup` (id + bound
/// socket), and round-trip a frame. Proves the `add_peer` direct-dial path and
/// that the relay is not involved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_addr_hint_connects_and_roundtrips() -> Result<()> {
    let a_key = SigningKey::from_bytes(&[0x31; 32]);
    let b_key = SigningKey::from_bytes(&[0x32; 32]);

    // No relays: direct-address dialing only.
    let a =
        CarapaceEndpoint::bind_on(&a_key, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &[]).await?;
    let b =
        CarapaceEndpoint::bind_on(&b_key, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &[]).await?;

    let accept = tokio::spawn(echo_one_hello(a.endpoint().clone()));

    // B learns A as {node_id, direct socket} - no relay - then dials by bare id.
    b.add_peer(a.direct_addr()?);

    let sent = Hello {
        protocol: 1,
        card_version: 7,
        roles: 3,
    };
    let echoed = tokio::time::timeout(Duration::from_secs(30), async {
        let conn = b.connect(EndpointAddr::new(a.id()), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
        write_msg(&mut send, &sent).await?;
        send.finish()?;
        let echoed: Hello = read_msg(&mut recv).await?;
        anyhow::Ok(echoed)
    })
    .await
    .context("direct round-trip timed out")??;

    assert_eq!(
        echoed, sent,
        "frame must round-trip unchanged over the direct path"
    );

    accept.await.context("accept task panicked")??;
    a.close().await;
    b.close().await;
    Ok(())
}
