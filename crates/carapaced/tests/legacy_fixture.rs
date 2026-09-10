use std::io::Read;

use anyhow::Result;
use base64::Engine;
use carapaced::{inspect_state_database, migrate_legacy_state, Daemon, ReplicaLimits, State};
use flate2::read::GzDecoder;

const FIXTURE: &str = include_str!("fixtures/legacy-rich-v1.redb.gz.b64");

#[tokio::test]
async fn frozen_unversioned_fixture_opens_and_binds_identity() -> Result<()> {
    let encoded: String = FIXTURE
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let compressed = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let mut database = Vec::new();
    GzDecoder::new(&compressed[..]).read_to_end(&mut database)?;
    assert_eq!(database.len(), 1_056_768);

    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("state.redb");
    std::fs::write(&db_path, database)?;
    let state = State::from_seeds_in(dir.path(), [7; 32], [3; 32]);

    let before = std::fs::read(&db_path)?;
    let inspection = inspect_state_database(&state, &db_path)?;
    assert_eq!(inspection.owned_vaults, 1);
    assert_eq!(inspection.held_replicas, 1);
    assert_eq!(inspection.held_shares, 1);
    assert_eq!(inspection.recovery_sets, 1);
    assert_eq!(inspection.ceremonies, 0);
    assert_eq!(
        std::fs::read(&db_path)?,
        before,
        "inspection must be read-only"
    );

    let startup = Daemon::start_with_limits(state, ReplicaLimits::default()).await;
    assert!(
        startup.is_err(),
        "normal startup must refuse unversioned state"
    );

    let state = State::from_seeds_in(dir.path(), [7; 32], [3; 32]);
    let backup = migrate_legacy_state(&state)?;
    assert!(backup.is_file());
    let daemon = Daemon::start_with_limits(state, ReplicaLimits::default()).await?;
    assert!(daemon.own_card_version() >= 12_345);
    assert!(daemon.published_vaults().is_empty());
    assert_eq!(daemon.vault_blob_ids(&[1; 32]), None);
    assert_eq!(
        daemon.needs_refetch_ids(&[1; 32]),
        Some(([8; 32], vec![[2; 32], [3; 32]]))
    );
    assert_eq!(daemon.share_health_counts().0, 1);
    let grants = daemon.recovery_grants();
    assert_eq!(grants.len(), 1);
    assert!(!daemon.paper_cards(grants[0].rsid)?.is_empty());
    daemon.shutdown().await;
    drop(daemon); // Release the database lock before offline inspection.

    let matching = State::from_seeds_in(dir.path(), [7; 32], [3; 32]);
    let migrated = inspect_state_database(&matching, &db_path)?;
    assert_eq!(migrated, inspection);
    let wrong_node = State::from_seeds_in(dir.path(), [0x33; 32], [3; 32]);
    assert!(inspect_state_database(&wrong_node, &db_path).is_err());
    Ok(())
}
