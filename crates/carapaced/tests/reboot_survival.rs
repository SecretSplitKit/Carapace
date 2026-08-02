//! §6 reboot-survival + at-rest sealing tests: a daemon is started against a fixed state dir,
//! mutated, dropped, and re-started. The published vault, sealed owner split-state, fetch-gate
//! owned-chunk set, and F3 own-card version floor must all survive.

use anyhow::Result;
use carapaced::{Daemon, MaintenanceConfig, RecoveryScope, State};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

fn make_tree() -> (tempfile::TempDir, BTreeMap<String, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut expected = BTreeMap::new();
    for (rel, bytes) in [
        ("readme.txt", b"hello carapace reboot".to_vec()),
        ("nested/note.md", b"# note\npersisted\n".repeat(20)),
    ] {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        expected.insert(rel.to_string(), bytes);
    }
    (dir, expected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reboot_preserves_vault_split_and_card_version() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let node_seed = [0x41u8; 32];
    let k_root = [0x42u8; 32];
    let (src, _expected) = make_tree();

    // ---- first boot: publish a vault + record an owner split-state (SEAL) ----
    let (vid, v1_card, share_word) = {
        let d = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;
        let (vid, _nonce) = d.new_vid();
        let epoch = d.publish_vault(src.path(), vid).await?;
        assert_eq!(epoch, 1, "first publish is epoch 1");

        let (jsons, _warn) = d.recovery_split(7, RecoveryScope::Root, 2, 3, false)?;
        assert_eq!(d.split_state_count(), 1);
        // Pull a distinctive BIP39 share word to later assert it never appears in plaintext
        // in state.redb (the split-state is SEALed). Exclude structural/label words so the
        // needle is real share material, not schema text.
        let stop = [
            "carapace",
            "device",
            "scheme",
            "threshold",
            "recovery",
            "backup",
            "version",
            "mnemonic",
            "shamir",
            "bip39",
            "words",
            "share",
            "shares",
            "created",
            "kind",
            "total",
            "chela",
        ];
        let json = &jsons[0];
        let word = json
            .split(|c: char| !c.is_ascii_lowercase())
            .filter(|w| w.len() >= 6 && !stop.contains(w))
            .max_by_key(|w| w.len())
            .expect("share JSON has a BIP39 word")
            .to_string();

        let v1 = d.own_card_version();
        d.shutdown().await;
        (vid, v1, word)
    };
    // Let the router's accept tasks finish so redb releases the single-open lock before reopen.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ---- at-rest sealing (§5.1): no share plaintext in state.redb ----
    let db_bytes = std::fs::read(state_dir.path().join("state.redb"))?;
    let needle = share_word.as_bytes();
    assert!(
        !db_bytes
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle)),
        "share word {share_word:?} leaked in plaintext into state.redb (must be SEALed)"
    );

    // ---- second boot from the SAME dir: state must survive ----
    let d2 = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;

    // SEAL survived + decrypted under the correct K_root (fail-loud path exercised).
    assert_eq!(
        d2.split_state_count(),
        1,
        "owner split-state survived the reboot"
    );

    // F3: the own-card version strictly increases across the restart.
    assert!(
        d2.own_card_version() > v1_card,
        "own-card version must strictly increase across a restart (F3): before={}, after={}",
        v1_card,
        d2.own_card_version()
    );

    // Assert the published blobs are present in the reopened FsStore, blob by blob: the no-op
    // republish below proves the manifest re-derived but compares file entries only, so it
    // would pass identically with every chunk lost.
    let (digest, chunks) = d2
        .vault_blob_ids(&vid)
        .expect("vault_blobs re-derived from the FsStore envelope after reboot");
    assert!(
        d2.blob_present(digest).await,
        "manifest-envelope blob present in FsStore after reboot"
    );
    for (i, id) in chunks.iter().enumerate() {
        assert!(
            d2.blob_present(*id).await,
            "chunk {i} present in FsStore after reboot"
        );
    }

    // epochs + vault_blobs survived: re-publishing the identical tree is a no-op returning the
    // same epoch (the guard compares the re-derived manifest's files).
    let epoch2 = d2.publish_vault(src.path(), vid).await?;
    assert_eq!(
        epoch2, 1,
        "epoch + vault_blobs survived: identical re-publish is a no-op at epoch 1"
    );

    d2.shutdown().await;
    Ok(())
}

/// The binary boot path: the daemon lives in an `Arc` with maintenance running (whose rounds
/// persist state) and is shut down via `&self` while other `Arc` clones exist. A published
/// vault must survive that lifecycle plus a reboot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_boot_path_maintenance_rounds_preserve_vault() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let node_seed = [0x71u8; 32];
    let k_root = [0x72u8; 32];
    let (src, _expected) = make_tree();

    let (vid, digest, chunks) = {
        let d = Arc::new(
            Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?,
        );
        // Fast tick so several maintenance rounds (and their persists) actually run.
        let maintenance = Arc::clone(&d).run_maintenance(MaintenanceConfig {
            tick: Duration::from_millis(20),
            ..MaintenanceConfig::default()
        });
        let (vid, _nonce) = d.new_vid();
        assert_eq!(d.publish_vault(src.path(), vid).await?, 1);
        let (digest, chunks) = d.vault_blob_ids(&vid).expect("published blob source");
        // Let a few post-publish rounds run and persist.
        tokio::time::sleep(Duration::from_millis(150)).await;
        maintenance.stop().await;
        // Shut down exactly like the binary: via `&self`, with the Arc still held.
        d.shutdown().await;
        (vid, digest, chunks)
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let d2 = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;
    assert_eq!(
        d2.published_vaults(),
        vec![(vid, 1)],
        "vault survives the binary boot path (maintenance persists + &self shutdown)"
    );
    assert!(
        d2.blob_present(digest).await,
        "envelope present after reboot"
    );
    for id in &chunks {
        assert!(d2.blob_present(*id).await, "chunk present after reboot");
    }
    d2.shutdown().await;
    Ok(())
}

/// §3.5: a vault whose manifest cannot be re-derived at startup (here blobs/ deleted between
/// boots) must KEEP its persisted blob-source record as needs-refetch across further reboots
/// until a republish repairs it. The bug: the failed re-derive dropped the source and the next
/// persist rewrote the VAULT_BLOBS row without it, silently vanishing the vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rederive_failure_keeps_blob_source_until_republished() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let node_seed = [0x81u8; 32];
    let k_root = [0x82u8; 32];
    let (src, _expected) = make_tree();

    // Boot 1: publish, remember the blob source, shut down cleanly.
    let (vid, digest, chunks) = {
        let d = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;
        let (vid, _nonce) = d.new_vid();
        assert_eq!(d.publish_vault(src.path(), vid).await?, 1);
        let ids = d.vault_blob_ids(&vid).expect("published blob source");
        d.shutdown().await;
        (vid, ids.0, ids.1)
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Damage: the served blob store is gone (a botched restore, or future GC gone wrong).
    std::fs::remove_dir_all(state_dir.path().join("blobs"))?;

    // Boot 2: re-derive fails; the vault is not servable but its blob source must be retained
    // as needs-refetch. This boot's own startup persists are the clobber vector.
    {
        let d = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;
        assert!(
            d.published_vaults().is_empty(),
            "underivable vault is not listed as published"
        );
        assert_eq!(
            d.needs_refetch_ids(&vid),
            Some((digest, chunks.clone())),
            "boot 2 retains the blob source of the underivable vault"
        );
        d.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Boot 3: the record survived boot 2's persists. Republish repairs: new epoch, listed
    // again, record cleared.
    {
        let d = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;
        assert_eq!(
            d.needs_refetch_ids(&vid),
            Some((digest, chunks.clone())),
            "needs-refetch record survives further reboots until repaired"
        );
        let epoch = d.publish_vault(src.path(), vid).await?;
        assert_eq!(epoch, 2, "repair republish bumps past the persisted epoch");
        assert_eq!(d.published_vaults(), vec![(vid, 2)]);
        assert_eq!(
            d.needs_refetch_ids(&vid),
            None,
            "republish clears the needs-refetch record"
        );
        d.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Boot 4: the repaired vault is a normally-listed vault again.
    let d = Daemon::start(State::from_seeds_in(state_dir.path(), node_seed, k_root)).await?;
    assert_eq!(d.published_vaults(), vec![(vid, 2)]);
    assert_eq!(d.needs_refetch_ids(&vid), None);
    d.shutdown().await;
    Ok(())
}

/// The real binary key path: `State::load_or_generate` reads/writes the key files on disk, so
/// a genuine reboot re-derives `k_root` from the file. The other reboot tests use
/// `from_seeds_in` (a fixed `k_root`), so none exercise a key-file round-trip: a mismatched
/// boot-2 `k_root` would fail `open_envelope` and route the vault to needs-refetch. Covers both
/// plaintext-seed and `CARAPACE_PASSPHRASE`-sealed (Argon2id) key files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_or_generate_key_path_survives_reboot() -> Result<()> {
    reboot_via_load_or_generate(None).await?;
    // Argon2id-sealed key files. The env var is process-global: set only for this segment and
    // clear immediately after (no other test in this binary reads it).
    std::env::set_var("CARAPACE_PASSPHRASE", "correct horse battery staple");
    let sealed = reboot_via_load_or_generate(Some("root.key")).await;
    std::env::remove_var("CARAPACE_PASSPHRASE");
    sealed?;
    Ok(())
}

/// Boot from a real on-disk identity, publish, shut down, reboot from the same dir via
/// `load_or_generate`, and assert the vault is still listed (manifest re-derived, so `k_root`
/// round-tripped). `sealed_key` also asserts that key file is at-rest sealed on disk.
async fn reboot_via_load_or_generate(sealed_key: Option<&str>) -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let (src, _expected) = make_tree();

    let (vid, node_id, digest, chunks) = {
        let d = Daemon::start(State::load_or_generate_insecure(state_dir.path())?).await?;
        let (vid, _nonce) = d.new_vid();
        assert_eq!(d.publish_vault(src.path(), vid).await?, 1);
        assert_eq!(
            d.published_vaults(),
            vec![(vid, 1)],
            "vault listed on first boot"
        );
        let (digest, chunks) = d.vault_blob_ids(&vid).expect("published blob source");
        let node_id = d.node_id();
        d.shutdown().await;
        (vid, node_id, digest, chunks)
    };

    if let Some(name) = sealed_key {
        let on_disk = std::fs::read(state_dir.path().join(name))?;
        assert!(
            on_disk.starts_with(b"CRPCSEAL"),
            "{name} must be at-rest sealed when CARAPACE_PASSPHRASE is set"
        );
    }

    // Let redb release its single-open lock before re-opening the same file.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Reboot from the same dir (re-reads the key files); a `k_root` that did not round-trip
    // would fail `rederive_manifest` and drop the vault from published_vaults.
    let d2 = Daemon::start(State::load_or_generate_insecure(state_dir.path())?).await?;
    assert_eq!(
        d2.node_id(),
        node_id,
        "node identity re-derived identically from the persisted node.key"
    );
    assert_eq!(
        d2.published_vaults(),
        vec![(vid, 1)],
        "vault survives a real load_or_generate reboot (k_root re-derived from the key file)"
    );
    assert!(
        d2.blob_present(digest).await,
        "manifest envelope present after reboot"
    );
    for id in &chunks {
        assert!(d2.blob_present(*id).await, "chunk present after reboot");
    }
    d2.shutdown().await;
    Ok(())
}

/// §3.5 tripwire is NOT triggered on a genuinely fresh dir (no blobs/, no state.redb):
/// a clean first boot must succeed and create state.redb.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_dir_boots_and_creates_state_db() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let d = Daemon::start(State::from_seeds_in(
        state_dir.path(),
        [0x51; 32],
        [0x52; 32],
    ))
    .await?;
    d.shutdown().await;
    assert!(
        state_dir.path().join("state.redb").exists(),
        "a fresh boot must create state.redb"
    );
    Ok(())
}

/// A missing database beside durable artifacts must fail before networking starts and must
/// not create a replacement empty database.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_state_database_fails_closed() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let state = || State::from_seeds_in(state_dir.path(), [0x61; 32], [0x62; 32]);

    let first = Daemon::start(state()).await?;
    first.shutdown().await;
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let db_path = state_dir.path().join("state.redb");
    std::fs::remove_file(&db_path)?;
    let err = Daemon::start(state())
        .await
        .err()
        .expect("missing durable state must fail");
    assert!(
        err.to_string().contains("durable artifacts exist"),
        "unexpected startup error: {err:#}"
    );
    assert!(
        !db_path.exists(),
        "failed startup must not create an empty replacement database"
    );
    Ok(())
}
