//! End-to-end replica placement + repair scenarios (§10.1), injected clock and
//! in-process stores.

use std::collections::HashMap;

use carapace_crypto::content::chunk_id;
use carapace_replica::{
    Health, PlacementCtx, Policy, ReplicaError, ReplicaPeer, ReplicaSet, DEFAULT_GRACE_SECS,
};
use carapace_vault::{ChunkStore, MemoryStore};
use carapace_wire::{Manifest, ManifestEnvelope, Signed};
use ed25519_dalek::SigningKey;

// ------------------------------------------------------------------ fixtures

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A tiny vault: an owner store populated with two ciphertext chunks, a manifest
/// naming them, and an envelope signed by the owner node. Chunk `len` equals the
/// ciphertext blob length so quota accounting is exact.
struct Vault {
    owner_node: SigningKey,
    store: MemoryStore,
    manifest: Manifest,
    env: ManifestEnvelope,
}

impl Vault {
    fn ctx(&self) -> PlacementCtx<'_, MemoryStore> {
        PlacementCtx::new(&self.store, &self.manifest, &self.env)
    }
}

fn make_vault(owner_seed: u8) -> Vault {
    let owner_node = key(owner_seed);
    let vid = [owner_seed; 32];
    let mut store = MemoryStore::new();

    let mut chunk = |data: &[u8]| -> ([u8; 32], u64) {
        let id = chunk_id(data);
        store.put(id, data.to_vec()).unwrap();
        (id, data.len() as u64)
    };
    let c0 = chunk(b"ciphertext-chunk-zero-opaque-bytes");
    let c1 = chunk(b"ciphertext-chunk-one-more-opaque-bytes!!");

    let manifest = Manifest {
        vid,
        epoch: 1,
        authors: vec![owner_node.verifying_key().to_bytes()],
        files: vec![carapace_wire::FileEntry {
            path: "a.txt".into(),
            mode: 0o644,
            mtime: 0,
            size: 74,
            chunks: vec![c0, c1],
            file_hash: [7u8; 32],
            version: vec![],
            deleted: false,
        }],
        vv: vec![],
    };

    let mut env = ManifestEnvelope {
        vid,
        epoch: 1,
        nonce: [0u8; 24],
        ct: manifest.to_bytes(),
        by: [0; 32],
        sig: [0; 64],
    };
    env.sign(&owner_node);

    Vault { owner_node, store, manifest, env }
}

fn open_peer(seed: u8) -> ReplicaPeer {
    ReplicaPeer::new(key(seed), Policy::open())
}

// --------------------------------------------------------------------- tests

#[test]
fn places_to_r3_accepting_friends() {
    let v = make_vault(1);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);

    let mut friends: Vec<ReplicaPeer> = (10..13).map(open_peer).collect();
    for f in &mut friends {
        assert!(set.add_replica(f, &v.ctx()).unwrap());
    }

    assert_eq!(set.members().len(), 3);
    assert!(set.satisfied());

    // Each accepting friend actually holds the envelope + both chunks.
    for f in &friends {
        assert!(f.holds(&v.manifest.vid));
        assert_eq!(f.blob_count(), 2);
    }

    // The announce reflects exactly the accepted set and verifies.
    let ann = set.announce();
    ann.verify().unwrap();
    assert_eq!(ann.replicas, set.members().to_vec());
    assert_eq!(ann.by, v.owner_node.verifying_key().to_bytes());
}

#[test]
fn decline_is_honored() {
    let v = make_vault(2);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);

    // A friend that will only store 8 bytes declines a placement bigger than that.
    let mut stingy = ReplicaPeer::new(key(20), Policy::with_quota(8));
    assert!(!set.add_replica(&mut stingy, &v.ctx()).unwrap());
    assert!(!stingy.holds(&v.manifest.vid));
    assert_eq!(set.members().len(), 0);
}

#[test]
fn deny_list_honored_both_directions() {
    let v = make_vault(3);
    let peer_a = key(30);
    let peer_b = key(31);

    // Owner-side deny-list: owner refuses to place on peer_a.
    let owner_policy = Policy::open().deny_peer(peer_a.verifying_key().to_bytes());
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), owner_policy, &v.manifest, &v.env);
    let mut a = ReplicaPeer::new(peer_a, Policy::open());
    assert!(!set.add_replica(&mut a, &v.ctx()).unwrap());
    assert!(!a.holds(&v.manifest.vid));

    // Peer-side deny-list: peer_b refuses to store for this owner.
    let owner_pk = v.owner_node.verifying_key().to_bytes();
    let mut b = ReplicaPeer::new(peer_b, Policy::open().deny_peer(owner_pk));
    assert!(!set.add_replica(&mut b, &v.ctx()).unwrap());
    assert!(!b.holds(&v.manifest.vid));

    assert_eq!(set.members().len(), 0);
}

#[test]
fn unreachable_within_grace_no_repair() {
    let v = make_vault(4);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);
    let mut friends: Vec<ReplicaPeer> = (40..43).map(open_peer).collect();
    for f in &mut friends {
        set.add_replica(f, &v.ctx()).unwrap();
    }
    let base_epoch = set.epoch();
    let members_before = set.members().to_vec();

    // One member went unreachable an hour ago; grace is 24 h.
    let now = 100_000;
    let mut healths = HashMap::new();
    healths.insert(members_before[0], Health::UnreachableSince(now - 3_600));

    let mut spare: Vec<ReplicaPeer> = vec![open_peer(50)];
    let announce = set
        .repair(&healths, now, DEFAULT_GRACE_SECS, &v.ctx(), &mut spare)
        .unwrap();

    assert!(announce.is_none(), "no repair inside the grace window");
    assert_eq!(set.members(), members_before.as_slice());
    assert_eq!(set.epoch(), base_epoch);
    assert!(!spare[0].holds(&v.manifest.vid));
}

#[test]
fn past_grace_repairs_to_fresh_friend() {
    let v = make_vault(5);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);
    let mut friends: Vec<ReplicaPeer> = (60..63).map(open_peer).collect();
    for f in &mut friends {
        set.add_replica(f, &v.ctx()).unwrap();
    }
    let base_epoch = set.epoch();
    let lost = set.members()[0];

    // Lost past the grace window.
    let now = 1_000_000;
    let mut healths = HashMap::new();
    healths.insert(lost, Health::UnreachableSince(now - DEFAULT_GRACE_SECS - 1));

    let mut spare: Vec<ReplicaPeer> = vec![open_peer(70)];
    let fresh_id = spare[0].node_id();

    let announce = set
        .repair(&healths, now, DEFAULT_GRACE_SECS, &v.ctx(), &mut spare)
        .unwrap()
        .expect("repair should re-place and re-announce");

    // Invariant restored: still r members, lost dropped, fresh friend added.
    assert_eq!(set.members().len(), 3);
    assert!(!set.members().contains(&lost));
    assert!(set.members().contains(&fresh_id));

    // The fresh friend really holds the data now.
    assert!(spare[0].holds(&v.manifest.vid));
    assert_eq!(spare[0].blob_count(), 2);

    // The new announce carries the new set at a bumped epoch and verifies.
    announce.verify().unwrap();
    assert_eq!(announce.replicas, set.members().to_vec());
    assert!(!announce.replicas.contains(&lost));
    assert!(announce.replicas.contains(&fresh_id));
    assert!(announce.epoch > base_epoch);
    assert_eq!(set.epoch(), announce.epoch);
}

#[test]
fn unfriended_repairs_immediately() {
    let v = make_vault(6);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);
    let mut friends: Vec<ReplicaPeer> = (80..83).map(open_peer).collect();
    for f in &mut friends {
        set.add_replica(f, &v.ctx()).unwrap();
    }
    let ex_friend = set.members()[1];

    let now = 42; // no grace needed: unfriend is confirmed loss now
    let mut healths = HashMap::new();
    healths.insert(ex_friend, Health::Unfriended);

    let mut spare: Vec<ReplicaPeer> = vec![open_peer(90)];
    let fresh_id = spare[0].node_id();
    let announce = set
        .repair(&healths, now, DEFAULT_GRACE_SECS, &v.ctx(), &mut spare)
        .unwrap()
        .expect("unfriend forces an immediate repair");

    assert!(!set.members().contains(&ex_friend));
    assert!(set.members().contains(&fresh_id));
    assert_eq!(set.members().len(), 3);
    announce.verify().unwrap();
}

#[test]
fn repair_skips_deny_listed_and_already_holding_candidates() {
    let v = make_vault(7);
    let denied_id = key(101).verifying_key().to_bytes();
    let owner_policy = Policy::open().deny_peer(denied_id);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), owner_policy, &v.manifest, &v.env);

    // Two current members; one (good) will be lost, the other (good2) survives.
    let mut good = open_peer(100);
    let mut good2 = open_peer(102);
    set.add_replica(&mut good, &v.ctx()).unwrap();
    set.add_replica(&mut good2, &v.ctx()).unwrap();
    let good_id = good.node_id();
    let good2_id = good2.node_id();
    let fresh_id = key(110).verifying_key().to_bytes();

    let now = 2_000_000;
    let mut healths = HashMap::new();
    healths.insert(good_id, Health::UnreachableSince(now - DEFAULT_GRACE_SECS - 1));

    // Candidate list, in order: the deny-listed peer (owner skips it), a peer
    // with good2's identity (already a member -> no-op), and a fresh friend
    // (the one actually placed to restore the invariant).
    let mut candidates = vec![
        ReplicaPeer::new(key(101), Policy::open()),
        open_peer(102),
        open_peer(110),
    ];

    let announce = set
        .repair(&healths, now, DEFAULT_GRACE_SECS, &v.ctx(), &mut candidates)
        .unwrap()
        .expect("repair replaces the lost member");

    assert_eq!(set.members().len(), 2);
    assert!(!set.members().contains(&good_id));
    assert!(set.members().contains(&good2_id));
    assert!(set.members().contains(&fresh_id));
    assert!(!set.members().contains(&denied_id));
    // The deny-listed candidate was never given the data.
    assert!(!candidates[0].holds(&v.manifest.vid));
    announce.verify().unwrap();
}

#[test]
fn read_availability_holds_while_one_replica_present() {
    let v = make_vault(8);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);
    let mut friends: Vec<ReplicaPeer> = (120..123).map(open_peer).collect();
    for f in &mut friends {
        set.add_replica(f, &v.ctx()).unwrap();
    }
    let ids: Vec<[u8; 32]> = set.members().to_vec();
    let now = 5_000;

    // Owner offline, two of three unreachable, one still reachable -> readable.
    let mut healths = HashMap::new();
    healths.insert(ids[0], Health::UnreachableSince(now - 10));
    healths.insert(ids[1], Health::UnreachableSince(now - 10));
    healths.insert(ids[2], Health::Reachable);
    assert!(set.readable(&healths, false));

    // Now the last one drops too, owner still offline -> not readable.
    healths.insert(ids[2], Health::UnreachableSince(now - 10));
    assert!(!set.readable(&healths, false));

    // Owner device reachable rescues availability regardless of replicas.
    assert!(set.readable(&healths, true));
}

// W1: the quota is enforced on the RECEIVE side, cumulatively per vault. A first
// push that exactly fits is admitted; a second push that would carry the vault
// past its granted quota is rejected with no partial mutation of the store.
#[test]
fn receive_enforces_quota_cumulatively() {
    let v = make_vault(11);
    let chunks: Vec<([u8; 32], Vec<u8>)> = v
        .manifest
        .files
        .iter()
        .flat_map(|f| f.chunks.iter())
        .map(|(id, _)| (*id, v.store.get(id).unwrap().unwrap()))
        .collect();
    let incoming = v.env.to_bytes().len() as u64
        + chunks.iter().map(|(_, d)| d.len() as u64).sum::<u64>();

    // Grant exactly one push worth of bytes.
    let mut peer = ReplicaPeer::new(key(200), Policy::with_quota(incoming));
    peer.receive(&v.env, chunks.clone()).unwrap();
    assert!(peer.holds(&v.manifest.vid));
    let blobs_after_first = peer.blob_count();

    // A second push for the same vault would double the received total and breach
    // the quota: it is cut off, and the store does not exceed the quota.
    assert!(matches!(
        peer.receive(&v.env, chunks.clone()),
        Err(ReplicaError::QuotaExceeded { .. })
    ));
    assert_eq!(peer.blob_count(), blobs_after_first, "rejected push did not grow the store");
}

#[test]
fn placed_chunks_round_trip_from_the_replica() {
    let v = make_vault(9);
    let mut set = ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);
    let mut friend = open_peer(130);
    set.add_replica(&mut friend, &v.ctx()).unwrap();

    // Every chunk the manifest names is retrievable from the replica, byte-exact.
    for f in &v.manifest.files {
        for (id, _) in &f.chunks {
            let got = friend.chunk(id).expect("replica serves the chunk");
            assert_eq!(chunk_id(&got), *id, "served bytes hash to their ChunkID");
            assert_eq!(v.store.get(id).unwrap().unwrap(), got);
        }
    }
    // And the envelope it holds is the owner-signed one.
    assert_eq!(friend.envelope(&v.manifest.vid).unwrap(), &v.env);
}
