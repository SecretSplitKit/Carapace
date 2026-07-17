//! Design §6 reboot-survival + at-rest sealing acceptance tests.
//!
//! A daemon is started against a FIXED state dir (`State::from_seeds_in`), mutated
//! across the persisted categories, dropped, then RE-STARTED from the same dir. The
//! durable state must survive: the published vault (epochs + re-derived manifest), the
//! sealed owner split-state, the default-deny fetch gate's owned-chunk set, and the F3
//! own-card version floor (strictly increasing across the restart).

use anyhow::Result;
use carapaced::{Daemon, RecoveryScope, State};
use std::collections::BTreeMap;

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
        // Pull a distinctive BIP39-style share word out of the JSON to later assert it
        // never appears in plaintext in state.redb (the split-state is SEALed under
        // K_root). Exclude the JSON's own structural/label words so the needle is real
        // share material, not schema text that legitimately appears in a card.
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
    // Give the router's accept tasks a moment to finish so every `Arc<Database>` clone
    // drops and redb releases the single-open lock before we re-open the same file.
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

    // The published blobs are genuinely PRESENT in the reopened FsStore — asserted
    // directly, blob by blob. The no-op republish below proves the manifest
    // re-derived, but on its own it cannot prove chunk survival: the no-op guard
    // compares manifest FILE entries only, so it would pass identically with every
    // chunk blob lost.
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

    // epochs + vault_blobs survived: re-publishing the identical tree is a no-op that
    // returns the SAME epoch (the no-op guard compares the re-derived manifest's files,
    // proving the manifest was rebuilt from the FsStore envelope + K_manifest).
    let epoch2 = d2.publish_vault(src.path(), vid).await?;
    assert_eq!(
        epoch2, 1,
        "epoch + vault_blobs survived: identical re-publish is a no-op at epoch 1"
    );

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
