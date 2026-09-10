use anyhow::Result;
use carapaced::{inspect_existing_state, State};

#[test]
fn inspection_validates_existing_state_without_network_startup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let node_seed = [0x31; 32];
    let root_seed = [0x42; 32];

    let db = redb::Database::create(dir.path().join("state.redb"))?;
    drop(db);
    let report = inspect_existing_state(&State::from_seeds_in(dir.path(), node_seed, root_seed))?;
    assert_eq!(report.owned_vaults, 0);
    assert_eq!(report.held_replicas, 0);
    assert_eq!(report.held_shares, 0);
    assert_eq!(report.recovery_sets, 0);
    assert_eq!(report.ceremonies, 0);
    Ok(())
}

#[test]
fn inspection_never_creates_a_missing_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let error = inspect_existing_state(&State::from_seeds_in(dir.path(), [0x31; 32], [0x42; 32]))
        .unwrap_err();

    assert!(error.to_string().contains("does not exist"));
    assert!(!path.exists());
}
