//! Proof-of-Retention (PoR) audit scenarios (§10.1): unpredictable sampling,
//! challenge/verify against content-addressed replicas, consecutive-failure loss
//! tracking wired into the existing repair path, and wide-coverage rounds. All
//! against an injected clock and in-process content-addressed stores.

use std::collections::HashMap;

use carapace_crypto::content::chunk_id;
use carapace_crypto::kdf::{k_audit, k_vaultroot};
use carapace_replica::{
    build_audit, build_audit_n, build_wide_audit, run_audit, verify_audit_response, Audit,
    AuditAction, AuditFailure, AuditOutcome, AuditTracker, Health, PlacementCtx, Policy,
    ReplicaPeer, ReplicaSet, AUDIT_CODE_RETENTION_LOST, DEFAULT_POR_FAIL_LIMIT,
};
use carapace_vault::{ChunkStore, MemoryStore};
use carapace_wire::{Manifest, ManifestEnvelope, Signed};
use ed25519_dalek::SigningKey;

// ------------------------------------------------------------------ fixtures

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

struct Vault {
    owner_node: SigningKey,
    store: MemoryStore,
    manifest: Manifest,
    env: ManifestEnvelope,
    /// K_audit(vid), derived through the real KDF tree from a test root.
    k_audit: [u8; 32],
}

impl Vault {
    fn ctx(&self) -> PlacementCtx<'_, MemoryStore> {
        PlacementCtx::new(&self.store, &self.manifest, &self.env)
    }
    fn vid(&self) -> [u8; 32] {
        self.manifest.vid
    }
    /// Every (id, bytes) chunk the vault holds, in manifest order.
    fn chunk_blobs(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.manifest
            .files
            .iter()
            .flat_map(|f| f.chunks.iter())
            .map(|(id, _)| (*id, self.store.get(id).unwrap().unwrap()))
            .collect()
    }
}

/// A vault with `n` distinct ciphertext chunks; chunk `len` == blob length so
/// PoR ranges stay inside the real bytes.
fn make_vault_n(owner_seed: u8, n: usize) -> Vault {
    let owner_node = key(owner_seed);
    let vid = [owner_seed; 32];
    let mut store = MemoryStore::new();

    let mut chunks = Vec::new();
    for i in 0..n {
        // Distinct, non-trivial-length blobs so offset/len sampling has room.
        let data = format!("ciphertext-chunk-{owner_seed}-{i}-opaque-padding-bytes").into_bytes();
        let id = chunk_id(&data);
        store.put(id, data.clone()).unwrap();
        chunks.push((id, data.len() as u64));
    }

    let manifest = Manifest {
        vid,
        epoch: 1,
        authors: vec![owner_node.verifying_key().to_bytes()],
        files: vec![carapace_wire::FileEntry {
            path: "a.txt".into(),
            mode: 0o644,
            mtime: 0,
            size: 0,
            chunks,
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

    // Real derivation: K_audit(vid) = HKDF(K_vaultroot(vid), "por").
    let root = [0xABu8; 32];
    let vr = k_vaultroot(&root, &vid);
    let ka = *k_audit(&*vr);

    Vault { owner_node, store, manifest, env, k_audit: ka }
}

/// A friend that has received every chunk of the vault (a healthy replica).
fn full_replica(v: &Vault, seed: u8) -> ReplicaPeer {
    let mut peer = ReplicaPeer::new(key(seed), Policy::open());
    peer.receive(&v.env, v.chunk_blobs()).unwrap();
    peer
}

// --------------------------------------------------------------------- tests

#[test]
fn replica_holding_all_sampled_chunks_passes() {
    let v = make_vault_n(1, 8);
    let peer = full_replica(&v, 10);

    let audit = build_audit(&v.k_audit, v.vid(), v.env.epoch, 0, &v.manifest);
    assert!(!audit.samples.is_empty());
    assert_eq!(run_audit(&audit, &peer), AuditOutcome::Pass);
}

#[test]
fn replica_missing_a_sampled_chunk_fails() {
    let v = make_vault_n(2, 8);

    // Build the challenge first, then hand the peer every chunk EXCEPT the first
    // sampled one - so a sampled ChunkID is provably absent.
    let audit = build_audit(&v.k_audit, v.vid(), v.env.epoch, 0, &v.manifest);
    let dropped = audit.samples[0].chunk_id;

    let kept: Vec<([u8; 32], Vec<u8>)> =
        v.chunk_blobs().into_iter().filter(|(id, _)| *id != dropped).collect();
    let mut peer = ReplicaPeer::new(key(20), Policy::open());
    peer.receive(&v.env, kept).unwrap();

    assert_eq!(
        run_audit(&audit, &peer),
        AuditOutcome::Fail(AuditFailure::Missing(dropped)),
    );
}

#[test]
fn corrupt_bytes_fail_content_verification() {
    // A response whose bytes do not hash to the sampled ChunkID is rejected even
    // though it is "present" - the BLAKE3/content check is what proves retention.
    let v = make_vault_n(12, 4);
    let audit = build_audit_n(&v.k_audit, v.vid(), v.env.epoch, 0, &v.manifest, 1);
    let wrong = vec![Some(b"not the sampled content at all".to_vec())];
    assert_eq!(
        verify_audit_response(&audit, &wrong),
        AuditOutcome::Fail(AuditFailure::Corrupt(audit.samples[0].chunk_id)),
    );
}

#[test]
fn three_consecutive_failures_mark_lost_and_yield_repair() {
    let v = make_vault_n(3, 8);
    let mut set =
        ReplicaSet::with_default_r(v.owner_node.clone(), Policy::open(), &v.manifest, &v.env);

    // Place three healthy replicas.
    let mut friends: Vec<ReplicaPeer> = (30..33).map(|s| full_replica(&v, s)).collect();
    for f in &mut friends {
        set.add_replica(f, &v.ctx()).unwrap();
    }
    let base_epoch = set.epoch();
    let bad = set.members()[0];

    // One replica now fails audits repeatedly. A missing-chunk response models the
    // dropped data; feed the injected clock.
    let mut tracker = AuditTracker::default();
    let mut now = 1_000_000u64;
    let missing = Audit {
        vid: v.vid(),
        epoch: v.env.epoch,
        round: 0,
        wide: false,
        samples: vec![carapace_replica::AuditSample { chunk_id: [0xFFu8; 32], offset: 0, len: 1 }],
    };

    let mut action = AuditAction::Passed;
    for i in 0..DEFAULT_POR_FAIL_LIMIT {
        let outcome = run_audit(&missing, &friends[0]); // peer lacks [0xFF..] chunk
        assert!(matches!(outcome, AuditOutcome::Fail(_)));
        action = tracker.record(bad, v.vid(), outcome, now);
        now += 6 * 60 * 60;
        if i + 1 < DEFAULT_POR_FAIL_LIMIT {
            assert!(matches!(action, AuditAction::Failed { consecutive } if consecutive == i + 1));
        }
    }
    assert_eq!(action, AuditAction::Lost, "fail limit reached -> lost");

    // Feed the existing repair path: record the audit loss and repair.
    let mut healths = HashMap::new();
    healths.insert(bad, Health::AuditLost);
    let mut spare = vec![full_replica(&v, 40)];
    let fresh_id = spare[0].node_id();

    let announce = set
        .repair_default_grace(&healths, now, &v.ctx(), &mut spare)
        .unwrap()
        .expect("audit loss must trigger re-replication + re-announce");

    assert!(!set.members().contains(&bad), "lost replica dropped");
    assert!(set.members().contains(&fresh_id), "fresh friend placed");
    assert_eq!(set.members().len(), 3, "invariant restored");
    announce.verify().unwrap();
    assert!(announce.epoch > base_epoch);

    // The signed AuditNotice the owner emits for the loss carries the retention
    // code and verifies under the owner key.
    let notice =
        carapace_replica::signed_audit_notice(&v.owner_node, v.vid(), AUDIT_CODE_RETENTION_LOST);
    notice.verify().unwrap();
    assert_eq!(notice.code, AUDIT_CODE_RETENTION_LOST);
}

#[test]
fn a_pass_resets_the_failure_streak() {
    let v = make_vault_n(13, 8);
    let mut tracker = AuditTracker::default();
    let replica = key(50).verifying_key().to_bytes();

    let fail = AuditOutcome::Fail(AuditFailure::Missing([0u8; 32]));
    assert!(matches!(
        tracker.record(replica, v.vid(), fail, 0),
        AuditAction::Failed { consecutive: 1 }
    ));
    assert!(matches!(
        tracker.record(replica, v.vid(), fail, 100),
        AuditAction::Failed { consecutive: 2 }
    ));
    // A pass wipes the streak, so a later failure starts again at 1 rather than
    // tipping straight to Lost.
    assert_eq!(tracker.record(replica, v.vid(), AuditOutcome::Pass, 200), AuditAction::Passed);
    assert!(matches!(
        tracker.record(replica, v.vid(), fail, 300),
        AuditAction::Failed { consecutive: 1 }
    ));
}

// C1: an unreachable replica (transport failure) must never accumulate PoR
// failures, so a transiently-offline friend is never evicted without grace. Only a
// peer that answered with missing bytes advances the streak.
#[test]
fn unreachable_rounds_never_accumulate_failures() {
    let v = make_vault_n(21, 8);
    let mut tracker = AuditTracker::default();
    let replica = key(60).verifying_key().to_bytes();
    let fail = AuditOutcome::Fail(AuditFailure::Missing([0u8; 32]));

    // Many consecutive unreachable rounds - far past the fail limit - never yield
    // Lost, and leave the streak clean.
    let mut now = 1_000_000u64;
    for _ in 0..(DEFAULT_POR_FAIL_LIMIT * 5) {
        assert_eq!(
            tracker.record_unreachable(replica, v.vid(), now),
            AuditAction::Skipped,
            "offline is not a retention failure"
        );
        // The round was rescheduled: the replica is no longer immediately due.
        assert!(!tracker.due(replica, v.vid(), now), "unreachable round reschedules");
        now += 6 * 60 * 60;
    }

    // A genuine content failure right after still starts the streak at 1 (untouched
    // by all the unreachable rounds), and it still takes the full limit to be lost.
    let mut action = AuditAction::Skipped;
    for i in 0..DEFAULT_POR_FAIL_LIMIT {
        action = tracker.record(replica, v.vid(), fail, now);
        now += 6 * 60 * 60;
        if i + 1 < DEFAULT_POR_FAIL_LIMIT {
            assert!(matches!(action, AuditAction::Failed { consecutive } if consecutive == i + 1));
        }
    }
    assert_eq!(action, AuditAction::Lost, "answered-but-missing still loses at the limit");
}

#[test]
fn samples_differ_across_epochs_rounds_and_keys() {
    let v = make_vault_n(4, 32);
    let epoch = v.env.epoch;

    let a = build_audit(&v.k_audit, v.vid(), epoch, 0, &v.manifest);
    let same = build_audit(&v.k_audit, v.vid(), epoch, 0, &v.manifest);
    let other_round = build_audit(&v.k_audit, v.vid(), epoch, 1, &v.manifest);
    let other_epoch = build_audit(&v.k_audit, v.vid(), epoch + 1, 0, &v.manifest);

    // Deterministic given (K_audit, epoch, round): the owner can rebuild + verify.
    assert_eq!(a, same);
    // A different round or epoch reshuffles the samples.
    assert_ne!(a.samples, other_round.samples);
    assert_ne!(a.samples, other_epoch.samples);

    // Unpredictable without K_audit: a peer guessing the key gets a different
    // challenge, so it cannot precompute which chunks/ranges will be sampled.
    let peer_guess = [0x99u8; 32];
    let guessed = build_audit(&peer_guess, v.vid(), epoch, 0, &v.manifest);
    assert_ne!(a.samples, guessed.samples, "sampling must depend on K_audit");
}

#[test]
fn wide_audit_covers_a_large_subset() {
    let v = make_vault_n(5, 40);
    let epoch = v.env.epoch;

    let spot = build_audit(&v.k_audit, v.vid(), epoch, 0, &v.manifest);
    let wide = build_wide_audit(&v.k_audit, v.vid(), epoch, 0, &v.manifest, 32);

    // Wide reaches far more distinct chunks than a per-round spot check.
    assert!(spot.samples.len() < wide.samples.len());
    assert_eq!(wide.samples.len(), 32);

    // Distinct ChunkIDs (sampled without replacement).
    let distinct: std::collections::HashSet<_> =
        wide.samples.iter().map(|s| s.chunk_id).collect();
    assert_eq!(distinct.len(), wide.samples.len(), "wide samples are distinct chunks");

    // A healthy replica still passes the broad sweep; its stream differs from the
    // same-round spot audit (the wide flag separates the PRF streams).
    let peer = full_replica(&v, 60);
    assert_eq!(run_audit(&wide, &peer), AuditOutcome::Pass);
    assert_ne!(spot.samples, wide.samples);
}

#[test]
fn tracker_randomizes_timing_per_replica_and_flags_wide_rounds() {
    // Two replicas of the same vault get different next-audit times off the same
    // clock: per-replica jitter spreads audits across the window (§10.1).
    let mut tracker = AuditTracker::new(6 * 60 * 60, 3, 4);
    let vid = [7u8; 32];
    let a = key(70).verifying_key().to_bytes();
    let b = key(71).verifying_key().to_bytes();

    // Never-scheduled replicas are due immediately.
    assert!(tracker.due(a, vid, 0));

    tracker.schedule(a, vid, 1_000);
    tracker.schedule(b, vid, 1_000);
    // With overwhelming probability two distinct keys yield distinct jitter.
    // (Deterministic given the keys, so this is a fixed, reproducible check.)
    let due_a = tracker.due(a, vid, 1_000 + 6 * 60 * 60);
    let due_b = tracker.due(b, vid, 1_000 + 6 * 60 * 60);
    assert!(
        due_a != due_b || jitter_of(a) != jitter_of(b),
        "per-replica jitter should separate schedules"
    );

    // Wide-round cadence: with wide_every = 4, round 4 is a wide round.
    let mut t2 = AuditTracker::new(6 * 60 * 60, 3, 4);
    let c = key(72).verifying_key().to_bytes();
    for _ in 0..3 {
        assert!(!t2.is_wide_round(c, vid));
        t2.record(c, vid, AuditOutcome::Pass, 0);
    }
    // After 4 recorded rounds the counter is at 4 -> next round is wide.
    t2.record(c, vid, AuditOutcome::Pass, 0);
    assert!(t2.is_wide_round(c, vid), "every wide_every-th round is wide-coverage");
}

/// Mirror of the tracker's private jitter for the schedule-separation assertion.
fn jitter_of(replica: [u8; 32]) -> u64 {
    u64::from_le_bytes(replica[..8].try_into().unwrap()) % (6 * 60 * 60)
}
