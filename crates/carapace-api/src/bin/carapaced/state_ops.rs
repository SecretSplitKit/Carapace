//! Read-only state operator commands for the `carapaced` binary.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use carapaced::{
    initialize_empty_state, inspect_existing_state, inspect_state_database,
    migrate_legacy_state as migrate_legacy_database, State,
};

const AUDIT_LOG: &str = "operator-audit.log";
const RESET_CONFIRMATION: &str = "RESET SECURITY STATE";

pub(crate) fn inspect_state(rest: Vec<String>) -> Result<()> {
    let (state_dir, insecure) = parse_inspect_args(rest)?;
    let state = load_existing_identity(&state_dir, insecure)?;
    let report = inspect_existing_state(&state)?;

    println!("state directory: {}", state_dir.display());
    println!("identity: valid");
    println!("database: valid");
    println!("owned vaults: {}", report.owned_vaults);
    println!("held replicas: {}", report.held_replicas);
    println!("held shares: {}", report.held_shares);
    println!("recovery sets: {}", report.recovery_sets);
    println!("ceremonies: {}", report.ceremonies);
    Ok(())
}

pub(crate) fn migrate_legacy_state(rest: Vec<String>) -> Result<()> {
    let (state_dir, insecure) = parse_confirmed_existing_args(rest)?;
    let state = load_existing_identity(&state_dir, insecure)?;
    let backup = migrate_legacy_database(&state)?;
    append_audit(
        &state_dir,
        "migrate-legacy-state",
        "validated and migrated legacy state to schema 2; preserved backup",
    )?;
    println!(
        "legacy state migration complete; protected backup: {}",
        backup.display()
    );
    Ok(())
}

fn parse_confirmed_existing_args(rest: Vec<String>) -> Result<(PathBuf, bool)> {
    let mut state_dir = None;
    let mut confirmed = None;
    let mut insecure = false;
    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => state_dir = Some(next_path(&mut it, "--state-dir")?),
            "--confirm-state-dir" => confirmed = Some(next_path(&mut it, "--confirm-state-dir")?),
            "--insecure-plaintext-keys" => insecure = true,
            other => bail!("unknown legacy migration flag {other:?}"),
        }
    }
    Ok((confirmed_dir(state_dir, confirmed)?, insecure))
}

pub(crate) fn initialize_empty(rest: Vec<String>) -> Result<()> {
    let (state_dir, insecure) = parse_initialize_args(rest)?;
    let state = load_or_create_identity(&state_dir, insecure)?;
    append_audit(
        &state_dir,
        "initialize-empty-start",
        "validated explicit state directory",
    )?;
    initialize_empty_state(&state)?;
    append_audit(
        &state_dir,
        "initialize-empty",
        "created identity-bound empty state",
    )?;
    println!("initialized empty state: {}", state_dir.display());
    Ok(())
}

pub(crate) fn restore_backup(rest: Vec<String>) -> Result<()> {
    let mut state_dir = None;
    let mut backup = None;
    let mut confirmed = None;
    let mut insecure = false;
    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => state_dir = Some(next_path(&mut it, "--state-dir")?),
            "--backup" => backup = Some(next_path(&mut it, "--backup")?),
            "--confirm-state-dir" => confirmed = Some(next_path(&mut it, "--confirm-state-dir")?),
            "--insecure-plaintext-keys" => insecure = true,
            other => bail!("unknown restore-backup flag {other:?}"),
        }
    }
    let state_dir = confirmed_dir(state_dir, confirmed)?;
    let backup = backup.context("--backup is required")?;
    let state = load_existing_identity(&state_dir, insecure)?;
    inspect_state_database(&state, &backup).context("validate backup before restore")?;
    append_audit(
        &state_dir,
        "restore-backup-start",
        &format!("validated backup {}", backup.display()),
    )?;

    let active = state_dir.join("state.redb");
    let prior = state_dir.join("state.redb.before-restore");
    let staged = state_dir.join("state.redb.restore-staged");
    if prior.exists() || staged.exists() {
        bail!("a prior restore artifact exists; inspect it before retrying");
    }
    copy_durable(&backup, &staged)?;
    inspect_state_database(&state, &staged).context("validate staged backup")?;
    if active.exists() {
        std::fs::rename(&active, &prior).context("preserve current state database")?;
    }
    if let Err(error) = std::fs::rename(&staged, &active) {
        if prior.exists() {
            let _ = std::fs::rename(&prior, &active);
        }
        return Err(error).context("activate restored state database");
    }
    if let Err(error) = inspect_existing_state(&state) {
        let failed = state_dir.join("state.redb.failed-restore");
        let _ = std::fs::rename(&active, &failed);
        if prior.exists() {
            std::fs::rename(&prior, &active).context("roll back failed restore")?;
        }
        sync_dir(&state_dir)?;
        return Err(error).context("validate activated state database; prior state restored");
    }
    sync_dir(&state_dir)?;
    append_audit(
        &state_dir,
        "restore-backup",
        &format!("restored {}; prior database preserved", backup.display()),
    )?;
    println!("restored state database: {}", active.display());
    if prior.exists() {
        println!("prior database: {}", prior.display());
    }
    Ok(())
}

pub(crate) fn reset_security_state(rest: Vec<String>) -> Result<()> {
    let (state_dir, insecure) = parse_reset_args(rest)?;
    let state = load_existing_identity(&state_dir, insecure)?;
    inspect_existing_state(&state).context("validate current state before reset")?;

    eprintln!("WARNING: reset-security-state clears rollback and replay history, fetch authorization, friendships, replica placement, and recovery ceremony state.");
    eprintln!("The current database and encrypted blobs will move to a recoverable backup.");
    eprintln!("Confirmed state directory: {}", state_dir.display());
    append_audit(
        &state_dir,
        "reset-security-state-start",
        "validated current state and explicit destructive confirmation",
    )?;

    let backup_dir = state_dir.join("security-reset-backup");
    if backup_dir.exists() {
        bail!("reset backup already exists at {backup_dir:?}");
    }
    create_private_dir(&backup_dir)?;
    let active = state_dir.join("state.redb");
    let backup_db = backup_dir.join("state.redb");
    std::fs::rename(&active, &backup_db).context("preserve state database for reset")?;
    let blobs = state_dir.join("blobs");
    let backup_blobs = backup_dir.join("blobs");
    if blobs.exists() {
        if let Err(error) = std::fs::rename(&blobs, &backup_blobs) {
            let _ = std::fs::rename(&backup_db, &active);
            return Err(error).context("preserve blob store for reset");
        }
    }
    if let Err(error) = initialize_empty_state(&state) {
        let _ = std::fs::remove_file(&active);
        let _ = std::fs::rename(&backup_db, &active);
        if backup_blobs.exists() {
            let _ = std::fs::rename(&backup_blobs, &blobs);
        }
        return Err(error).context("initialize replacement security state");
    }
    sync_dir(&state_dir)?;
    append_audit(
        &state_dir,
        "reset-security-state",
        "reset rollback, authorization, friendship, replica, and recovery state; preserved prior database and blobs",
    )?;
    println!(
        "security state reset; recoverable backup: {}",
        backup_dir.display()
    );
    Ok(())
}

fn parse_inspect_args(rest: Vec<String>) -> Result<(PathBuf, bool)> {
    let mut state_dir = None;
    let mut insecure = false;
    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => {
                state_dir = Some(it.next().context("--state-dir needs a value")?.into())
            }
            "--insecure-plaintext-keys" => insecure = true,
            other => bail!("unknown inspect-state flag {other:?}"),
        }
    }
    Ok((state_dir.context("--state-dir is required")?, insecure))
}

fn parse_initialize_args(rest: Vec<String>) -> Result<(PathBuf, bool)> {
    let mut state_dir = None;
    let mut confirmed = None;
    let mut insecure = false;
    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => state_dir = Some(next_path(&mut it, "--state-dir")?),
            "--confirm-state-dir" => confirmed = Some(next_path(&mut it, "--confirm-state-dir")?),
            "--insecure-plaintext-keys" => insecure = true,
            other => bail!("unknown initialize-empty flag {other:?}"),
        }
    }
    Ok((confirmed_dir(state_dir, confirmed)?, insecure))
}

fn parse_reset_args(rest: Vec<String>) -> Result<(PathBuf, bool)> {
    let mut state_dir = None;
    let mut confirmed = None;
    let mut phrase = None;
    let mut insecure = false;
    let mut it = rest.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--state-dir" => state_dir = Some(next_path(&mut it, "--state-dir")?),
            "--confirm-state-dir" => confirmed = Some(next_path(&mut it, "--confirm-state-dir")?),
            "--confirm-reset" => phrase = Some(it.next().context("--confirm-reset needs a value")?),
            "--insecure-plaintext-keys" => insecure = true,
            other => bail!("unknown reset-security-state flag {other:?}"),
        }
    }
    if phrase.as_deref() != Some(RESET_CONFIRMATION) {
        bail!("--confirm-reset must be exactly {RESET_CONFIRMATION:?}");
    }
    Ok((confirmed_dir(state_dir, confirmed)?, insecure))
}

fn confirmed_dir(state_dir: Option<PathBuf>, confirmed: Option<PathBuf>) -> Result<PathBuf> {
    let state_dir = state_dir.context("--state-dir is required")?;
    let confirmed = confirmed.context("--confirm-state-dir is required")?;
    let state_dir = std::fs::canonicalize(&state_dir)
        .with_context(|| format!("resolve state directory {state_dir:?}"))?;
    let confirmed = std::fs::canonicalize(&confirmed)
        .with_context(|| format!("resolve confirmed state directory {confirmed:?}"))?;
    if state_dir != confirmed {
        bail!("confirmed state directory does not match --state-dir");
    }
    Ok(state_dir)
}

fn next_path(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf> {
    Ok(it
        .next()
        .with_context(|| format!("{flag} needs a value"))?
        .into())
}

fn load_or_create_identity(state_dir: &Path, insecure: bool) -> Result<State> {
    if insecure {
        State::load_or_generate_insecure(state_dir)
    } else {
        State::load_or_generate(state_dir)
    }
}

fn load_existing_identity(state_dir: &Path, insecure: bool) -> Result<State> {
    let credential = state_dir.join("credential.id");
    let node = state_dir.join("node.key");
    let root = state_dir.join("root.key");

    if insecure {
        if !node.is_file() || !root.is_file() {
            bail!(
                "insecure state inspection requires existing root.key and node.key files in {state_dir:?}"
            );
        }
        return State::load_or_generate_insecure(state_dir);
    }

    if !credential.is_file() {
        bail!(
            "secure state inspection requires an existing credential.id in {state_dir:?}; use --insecure-plaintext-keys only for an existing development state"
        );
    }
    if node.exists() || root.exists() {
        bail!("legacy key files exist beside credential.id in {state_dir:?}");
    }
    State::load_or_generate(state_dir)
}

fn copy_durable(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(unix)]
    let mut input = {
        use rustix::fs::{openat, Mode, OFlags, CWD};
        let descriptor = openat(
            CWD,
            source,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .with_context(|| format!("open backup without following links {source:?}"))?;
        std::fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut input =
        std::fs::File::open(source).with_context(|| format!("open backup {source:?}"))?;
    let mut output = create_private_file(destination)?;
    std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copy backup to {destination:?}"))?;
    output.sync_all().context("sync staged state database")?;
    sync_dir(
        destination
            .parent()
            .context("staged database has no parent")?,
    )
}

fn append_audit(state_dir: &Path, action: &str, detail: &str) -> Result<()> {
    use std::io::Write;
    let path = state_dir.join(AUDIT_LOG);
    let mut file = open_private_append(&path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    let action = action.replace(['\t', '\r', '\n'], " ");
    let detail = detail.replace(['\t', '\r', '\n'], " ");
    writeln!(file, "{now}\t{action}\t{detail}").context("write operator audit record")?;
    file.sync_all().context("sync operator audit record")?;
    sync_dir(state_dir)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create private file {path:?}"))
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create private file {path:?}"))
}

#[cfg(unix)]
fn open_private_append(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open private audit log {path:?}"))
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .with_context(|| format!("open audit log {path:?}"))
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("create private backup directory {path:?}"))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir(path).with_context(|| format!("create backup directory {path:?}"))
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("open directory {path:?} for sync"))?
        .sync_all()
        .with_context(|| format!("sync directory {path:?}"))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_requires_an_explicit_state_directory() {
        let error = parse_inspect_args(Vec::new()).unwrap_err();
        assert!(error.to_string().contains("--state-dir is required"));
    }

    #[test]
    fn legacy_migration_requires_the_matching_state_directory() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let other = root.path().join("other");
        std::fs::create_dir(&state).unwrap();
        std::fs::create_dir(&other).unwrap();
        let missing = parse_confirmed_existing_args(vec![
            "--state-dir".to_string(),
            state.display().to_string(),
        ])
        .unwrap_err();
        assert!(missing
            .to_string()
            .contains("--confirm-state-dir is required"));

        let mismatch = parse_confirmed_existing_args(vec![
            "--state-dir".to_string(),
            state.display().to_string(),
            "--confirm-state-dir".to_string(),
            other.display().to_string(),
        ])
        .unwrap_err();
        assert!(mismatch
            .to_string()
            .contains("confirmed state directory does not match"));
    }

    #[test]
    fn inspect_refuses_to_create_an_identity() {
        let dir = tempfile::tempdir().unwrap();
        let error = match load_existing_identity(dir.path(), false) {
            Err(error) => error,
            Ok(_) => panic!("inspection unexpectedly created an identity"),
        };

        assert!(error.to_string().contains("credential.id"));
        assert!(!dir.path().join("credential.id").exists());
        assert!(!dir.path().join("root.key").exists());
        assert!(!dir.path().join("node.key").exists());
    }

    #[test]
    fn insecure_inspect_requires_a_complete_existing_pair() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("root.key"), [0u8; 32]).unwrap();

        let error = match load_existing_identity(dir.path(), true) {
            Err(error) => error,
            Ok(_) => panic!("inspection unexpectedly accepted an incomplete identity"),
        };
        assert!(error.to_string().contains("root.key and node.key"));
        assert!(!dir.path().join("node.key").exists());
    }

    fn insecure_args(command: &str, dir: &Path) -> Vec<String> {
        let mut args = vec![
            "--state-dir".to_string(),
            dir.display().to_string(),
            "--insecure-plaintext-keys".to_string(),
        ];
        if matches!(command, "initialize" | "restore" | "reset") {
            args.extend(["--confirm-state-dir".to_string(), dir.display().to_string()]);
        }
        if command == "reset" {
            args.extend([
                "--confirm-reset".to_string(),
                RESET_CONFIRMATION.to_string(),
            ]);
        }
        args
    }

    #[test]
    fn initialize_creates_valid_state_and_an_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        initialize_empty(insecure_args("initialize", dir.path())).unwrap();

        assert!(dir.path().join("state.redb").is_file());
        assert!(dir.path().join(AUDIT_LOG).is_file());
        inspect_state(insecure_args("inspect", dir.path())).unwrap();
        assert!(initialize_empty(insecure_args("initialize", dir.path())).is_err());
    }

    #[test]
    fn reset_preserves_database_and_blob_data() {
        let dir = tempfile::tempdir().unwrap();
        initialize_empty(insecure_args("initialize", dir.path())).unwrap();
        std::fs::create_dir(dir.path().join("blobs")).unwrap();
        std::fs::write(dir.path().join("blobs/retained"), b"ciphertext").unwrap();

        reset_security_state(insecure_args("reset", dir.path())).unwrap();

        let backup = dir.path().join("security-reset-backup");
        assert!(backup.join("state.redb").is_file());
        assert_eq!(
            std::fs::read(backup.join("blobs/retained")).unwrap(),
            b"ciphertext"
        );
        assert!(dir.path().join("state.redb").is_file());
        inspect_state(insecure_args("inspect", dir.path())).unwrap();
        let audit = std::fs::read_to_string(dir.path().join(AUDIT_LOG)).unwrap();
        assert!(audit.contains("reset-security-state-start"));
        assert!(audit.contains("\treset-security-state\t"));
    }

    #[test]
    fn reset_requires_the_exact_confirmation_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = insecure_args("restore", dir.path());
        args.extend(["--confirm-reset".to_string(), "yes".to_string()]);

        let error = parse_reset_args(args).unwrap_err();
        assert!(error.to_string().contains(RESET_CONFIRMATION));
    }

    #[test]
    fn restore_validates_before_it_replaces_current_state() {
        let dir = tempfile::tempdir().unwrap();
        initialize_empty(insecure_args("initialize", dir.path())).unwrap();
        let backup = dir.path().join("external-backup.redb");
        std::fs::copy(dir.path().join("state.redb"), &backup).unwrap();
        let mut args = insecure_args("restore", dir.path());
        args.extend(["--backup".to_string(), backup.display().to_string()]);

        restore_backup(args).unwrap();

        assert!(dir.path().join("state.redb.before-restore").is_file());
        inspect_state(insecure_args("inspect", dir.path())).unwrap();
        assert!(std::fs::read_to_string(dir.path().join(AUDIT_LOG))
            .unwrap()
            .contains("\trestore-backup\t"));
    }

    #[test]
    fn restore_and_reset_interruption_leave_start_without_completion() {
        let restore_dir = tempfile::tempdir().unwrap();
        initialize_empty(insecure_args("initialize", restore_dir.path())).unwrap();
        let backup = restore_dir.path().join("external-backup.redb");
        std::fs::copy(restore_dir.path().join("state.redb"), &backup).unwrap();
        std::fs::write(
            restore_dir.path().join("state.redb.restore-staged"),
            b"stop",
        )
        .unwrap();
        let mut restore_args = insecure_args("restore", restore_dir.path());
        restore_args.extend(["--backup".to_string(), backup.display().to_string()]);
        assert!(restore_backup(restore_args).is_err());
        let restore_audit = std::fs::read_to_string(restore_dir.path().join(AUDIT_LOG)).unwrap();
        assert!(restore_audit.contains("restore-backup-start"));
        assert!(!restore_audit.contains("\trestore-backup\t"));

        let reset_dir = tempfile::tempdir().unwrap();
        initialize_empty(insecure_args("initialize", reset_dir.path())).unwrap();
        std::fs::create_dir(reset_dir.path().join("security-reset-backup")).unwrap();
        assert!(reset_security_state(insecure_args("reset", reset_dir.path())).is_err());
        let reset_audit = std::fs::read_to_string(reset_dir.path().join(AUDIT_LOG)).unwrap();
        assert!(reset_audit.contains("reset-security-state-start"));
        assert!(!reset_audit.contains("\treset-security-state\t"));
    }
}
