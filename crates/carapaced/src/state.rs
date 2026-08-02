//! Daemon identity state. Production stores the node and root seeds in the operating-system
//! credential store. The state directory contains only a non-secret credential identifier.
//! Legacy key files are available only for confirmed migration or explicit insecure testing.

use anyhow::{bail, ensure, Context, Result};
use carapace_crypto::atrest::{self, AtRestBlob};
use carapace_crypto::identity::user_key_from_seed;
use carapace_crypto::kdf::k_userid;
use ed25519_dalek::SigningKey;
use keyring::{Entry, Error as KeyringError};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Env var holding the at-rest passphrase; present -> key files Argon2id-sealed.
const PASSPHRASE_ENV: &str = "CARAPACE_PASSPHRASE";

const KEYRING_SERVICE: &str = "org.secretsplitkit.carapace";
const CREDENTIAL_ID_FILE: &str = "credential.id";

/// Magic prefix marking a key file as an at-rest-sealed blob (vs. a raw seed).
const ATREST_MAGIC: &[u8; 8] = b"CRPCSEAL";

/// Loaded (or freshly generated) daemon state.
pub struct State {
    /// This device's node signing key.
    pub node_key: SigningKey,
    /// The user master key, shared across a user's devices.
    pub k_root: Zeroizing<[u8; 32]>,
    /// State directory holding the key files, durable `blobs/`, and `state.redb`. `None`
    /// for seed-only [`State::from_seeds`]: the daemon uses a process-unique ephemeral dir.
    pub dir: Option<PathBuf>,
    /// True iff this run freshly generated the identity (neither key file existed before).
    /// The startup tripwire uses this to tell a genuine first start from a wiped
    /// `state.redb` beside a surviving identity.
    pub keys_freshly_generated: bool,
}

impl State {
    /// Install a recovered root key and fresh node seed in the operating-system credential
    /// store. The target must not contain an identity or durable state.
    pub(crate) fn install_recovered(
        dir: &Path,
        node_seed: [u8; 32],
        k_root: [u8; 32],
    ) -> Result<Self> {
        require_private_state_acl_support()?;
        ensure_private_directory(dir)?;
        for name in [
            CREDENTIAL_ID_FILE,
            "root.key",
            "node.key",
            "state.redb",
            "blobs",
        ] {
            if dir.join(name).exists() {
                bail!("refusing to replace existing recovery target artifact {name:?}");
            }
        }

        let credential_id = new_credential_id()?;
        store_keyring_identity(&credential_id, &k_root, &node_seed)?;
        let credential_path = dir.join(CREDENTIAL_ID_FILE);
        if let Err(error) = write_secret(&credential_path, credential_id.as_bytes()) {
            delete_keyring_identity(&credential_id);
            return Err(error).context("activate recovered credential identifier");
        }
        Ok(Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(k_root),
            dir: Some(dir.to_path_buf()),
            keys_freshly_generated: false,
        })
    }

    pub(crate) fn remove_installed_recovery(&self) {
        let Some(dir) = &self.dir else { return };
        let path = dir.join(CREDENTIAL_ID_FILE);
        if let Ok(id) = std::fs::read_to_string(&path) {
            delete_keyring_identity(id.trim());
        }
        let _ = std::fs::remove_file(path);
    }

    /// Load the node and root keys from the operating-system credential store. A new
    /// installation creates both secrets there and writes only a non-secret identifier in
    /// the state directory.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        require_private_state_acl_support()?;
        ensure_private_directory(dir)?;
        let node_path = dir.join("node.key");
        let root_path = dir.join("root.key");
        if node_path.exists() || root_path.exists() {
            bail!(
                "legacy key files exist in {dir:?}; run the confirmed key-storage migration before production startup"
            );
        }
        let credential_path = dir.join(CREDENTIAL_ID_FILE);
        let (credential_id, keys_freshly_generated) = if credential_path.exists() {
            let id = std::fs::read_to_string(&credential_path)
                .with_context(|| format!("read {credential_path:?}"))?;
            let id = id.trim().to_string();
            if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("invalid credential identifier in {credential_path:?}");
            }
            (id, false)
        } else {
            let id = new_credential_id()?;
            create_keyring_identity(&id)?;
            if let Err(error) = write_secret(&credential_path, id.as_bytes()) {
                delete_keyring_identity(&id);
                return Err(error);
            }
            (id, true)
        };
        let node_seed = get_keyring_seed(&credential_id, "node")?;
        let root = get_keyring_seed(&credential_id, "root")?;
        Ok(Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(root),
            dir: Some(dir.to_path_buf()),
            keys_freshly_generated,
        })
    }

    /// Explicit insecure-development mode. This keeps the legacy key-file behavior and must
    /// not be used for a production or non-loopback daemon.
    pub fn load_or_generate_insecure(dir: &Path) -> Result<Self> {
        ensure_private_directory(dir)?;
        let passphrase = std::env::var(PASSPHRASE_ENV).ok().map(Zeroizing::new);
        let pass = passphrase.as_ref().map(|p| p.as_bytes());
        let node_path = dir.join("node.key");
        let root_path = dir.join("root.key");
        if node_path.exists() != root_path.exists() {
            bail!(
                "incomplete identity in {dir:?}: root.key and node.key must either both exist or both be absent"
            );
        }
        // Fresh iff neither key existed before this call; captured before the seeds are written.
        let keys_freshly_generated = !node_path.exists() && !root_path.exists();
        let node_seed = load_or_generate_seed(&node_path, pass)?;
        let root = load_or_generate_seed(&root_path, pass)?;
        Ok(Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(root),
            dir: Some(dir.to_path_buf()),
            keys_freshly_generated,
        })
    }

    /// Open an existing identity whose two local key files are passphrase protected.
    /// This mode never creates keys and never reads the passphrase from the environment.
    pub fn load_protected_local(dir: &Path, passphrase: &[u8]) -> Result<Self> {
        require_private_state_acl_support()?;
        ensure_private_directory(dir)?;
        ensure!(!passphrase.is_empty(), "the terminal passphrase is empty");
        let node_path = dir.join("node.key");
        let root_path = dir.join("root.key");
        ensure!(
            node_path.exists() && root_path.exists(),
            "terminal-passphrase mode requires existing protected root.key and node.key files"
        );
        ensure!(
            !dir.join(CREDENTIAL_ID_FILE).exists(),
            "terminal-passphrase mode cannot be combined with a credential-store identity"
        );
        let node_seed = load_existing_seed(&node_path, Some(passphrase))?;
        let root = load_existing_seed(&root_path, Some(passphrase))?;
        Ok(Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(root),
            dir: Some(dir.to_path_buf()),
            keys_freshly_generated: false,
        })
    }

    /// Move a complete legacy key pair into the operating-system credential store. The
    /// original files are removed only after the new source re-opens with identical seeds.
    pub fn migrate_legacy_keys(dir: &Path) -> Result<PathBuf> {
        migrate_legacy_keys_with(dir, &KeyringCredentialStore, &mut NoMigrationHooks)
    }

    /// Build state directly from raw seeds (tests, scripted two-device setups sharing a
    /// `k_root`). No state directory: the daemon persists to an ephemeral dir.
    pub fn from_seeds(node_seed: [u8; 32], k_root: [u8; 32]) -> Self {
        Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(k_root),
            dir: None,
            // Never writes key files; the tripwire keys on durable `blobs/` presence.
            keys_freshly_generated: false,
        }
    }

    /// Like [`State::from_seeds`] but pinned to a state directory, so a test can reboot a
    /// fresh daemon from the same seeds AND durable `blobs/`/`state.redb`.
    pub fn from_seeds_in(dir: &Path, node_seed: [u8; 32], k_root: [u8; 32]) -> Self {
        Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(k_root),
            dir: Some(dir.to_path_buf()),
            keys_freshly_generated: false,
        }
    }

    /// The user signing key: `Ed25519(seed = HKDF(k_root, "…user-identity"))`.
    pub fn user_key(&self) -> SigningKey {
        user_key_from_seed(&k_userid(&*self.k_root))
    }
}

trait CredentialStore {
    fn write(&self, credential_id: &str, kind: &str, seed: &[u8; 32]) -> Result<()>;
    fn read(&self, credential_id: &str, kind: &str) -> Result<[u8; 32]>;
    fn delete(&self, credential_id: &str, kind: &str);
}

struct KeyringCredentialStore;

impl CredentialStore for KeyringCredentialStore {
    fn write(&self, credential_id: &str, kind: &str, seed: &[u8; 32]) -> Result<()> {
        keyring_entry(credential_id, kind)?
            .set_secret(seed)
            .map_err(|error| {
                anyhow::anyhow!("store {kind} seed in operating-system credentials: {error}")
            })
    }

    fn read(&self, credential_id: &str, kind: &str) -> Result<[u8; 32]> {
        get_keyring_seed(credential_id, kind)
    }

    fn delete(&self, credential_id: &str, kind: &str) {
        if let Ok(entry) = keyring_entry(credential_id, kind) {
            let _ = entry.delete_credential();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationPoint {
    BackupSynced,
    CredentialIdSynced,
    BeforeNodeRemoval,
    BeforeRootRemoval,
}

trait MigrationHooks {
    fn reach(&mut self, _point: MigrationPoint) -> Result<()> {
        Ok(())
    }
}

struct NoMigrationHooks;
impl MigrationHooks for NoMigrationHooks {}

fn migrate_legacy_keys_with(
    dir: &Path,
    store: &dyn CredentialStore,
    hooks: &mut dyn MigrationHooks,
) -> Result<PathBuf> {
    require_private_state_acl_support()?;
    let credential_path = dir.join(CREDENTIAL_ID_FILE);
    if credential_path.exists() {
        bail!("{credential_path:?} already exists; key migration is not required");
    }
    let node_path = dir.join("node.key");
    let root_path = dir.join("root.key");
    if !node_path.exists() || !root_path.exists() {
        bail!("migration requires both root.key and node.key in {dir:?}");
    }
    let passphrase = std::env::var(PASSPHRASE_ENV).ok().map(Zeroizing::new);
    let pass = passphrase.as_ref().map(|p| p.as_bytes());
    let node = load_existing_seed(&node_path, pass)?;
    let root = load_existing_seed(&root_path, pass)?;

    let backup = dir.join("legacy-key-backup");
    let staged_backup = dir.join(".legacy-key-backup-staged");
    if staged_backup.exists() {
        std::fs::remove_dir_all(&staged_backup)
            .context("remove incomplete staged legacy-key backup")?;
        sync_parent(&staged_backup)?;
    }
    if backup.exists() {
        bail!("legacy key backup already exists at {backup:?}");
    }
    create_private_dir(&staged_backup)?;
    write_secret(&staged_backup.join("node.key"), &std::fs::read(&node_path)?)?;
    write_secret(&staged_backup.join("root.key"), &std::fs::read(&root_path)?)?;
    std::fs::File::open(&staged_backup)?.sync_all()?;
    hooks.reach(MigrationPoint::BackupSynced)?;
    std::fs::rename(&staged_backup, &backup).context("activate legacy-key backup")?;
    sync_parent(&backup)?;

    let id = new_credential_id()?;
    store.write(&id, "root", &root)?;
    if let Err(error) = store.write(&id, "node", &node) {
        store.delete(&id, "root");
        return Err(error);
    }
    if let Err(error) = write_secret(&credential_path, id.as_bytes()) {
        store.delete(&id, "root");
        store.delete(&id, "node");
        return Err(error);
    }
    let result = (|| {
        hooks.reach(MigrationPoint::CredentialIdSynced)?;
        let stored_node = store.read(&id, "node")?;
        let stored_root = store.read(&id, "root")?;
        if stored_node != node || stored_root != root {
            bail!("migrated credential verification returned different identity seeds");
        }
        hooks.reach(MigrationPoint::BeforeNodeRemoval)?;
        std::fs::remove_file(&node_path).with_context(|| format!("remove {node_path:?}"))?;
        hooks.reach(MigrationPoint::BeforeRootRemoval)?;
        std::fs::remove_file(&root_path).with_context(|| format!("remove {root_path:?}"))?;
        sync_parent(&root_path)
    })();
    if let Err(error) = result {
        if !node_path.exists() {
            write_secret(&node_path, &std::fs::read(backup.join("node.key"))?)
                .context("restore node.key after incomplete source removal")?;
        }
        if !root_path.exists() {
            write_secret(&root_path, &std::fs::read(backup.join("root.key"))?)
                .context("restore root.key after incomplete source removal")?;
        }
        let _ = std::fs::remove_file(&credential_path);
        let _ = sync_parent(&credential_path);
        store.delete(&id, "root");
        store.delete(&id, "node");
        return Err(error);
    }
    Ok(backup)
}

#[cfg(windows)]
fn require_private_state_acl_support() -> Result<()> {
    bail!(
        "secure production startup on Windows is disabled until Carapace enforces private ACLs on the state directory and files"
    )
}

#[cfg(unix)]
pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    use rustix::fs::{fchmod, fsync, openat, Mode, OFlags, CWD};
    use std::os::unix::fs::DirBuilderExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("private directory path is not a real directory: {path:?}")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .with_context(|| format!("create private directory {path:?}"))?;
        }
        Err(error) => return Err(error).with_context(|| format!("inspect directory {path:?}")),
    }
    let directory = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("open private directory {path:?}"))?;
    fchmod(&directory, Mode::from_raw_mode(0o700))
        .map_err(std::io::Error::from)
        .with_context(|| format!("restrict private directory {path:?}"))?;
    fsync(&directory)
        .map_err(std::io::Error::from)
        .with_context(|| format!("sync directory {path:?}"))
}

#[cfg(not(unix))]
pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create directory {path:?}"))
}

#[cfg(not(windows))]
fn require_private_state_acl_support() -> Result<()> {
    Ok(())
}

fn new_credential_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow::anyhow!("generate credential id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn keyring_entry(credential_id: &str, kind: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, &format!("{credential_id}:{kind}"))
        .map_err(|e| anyhow::anyhow!("open operating-system credential entry: {e}"))
}

fn create_keyring_identity(credential_id: &str) -> Result<()> {
    let mut root = Zeroizing::new([0u8; 32]);
    let mut node = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *root).map_err(|e| anyhow::anyhow!("generate root seed: {e}"))?;
    getrandom::getrandom(&mut *node).map_err(|e| anyhow::anyhow!("generate node seed: {e}"))?;

    store_keyring_identity(credential_id, &root, &node)
}

fn store_keyring_identity(credential_id: &str, root: &[u8; 32], node: &[u8; 32]) -> Result<()> {
    let root_entry = keyring_entry(credential_id, "root")?;
    let node_entry = keyring_entry(credential_id, "node")?;
    root_entry
        .set_secret(root)
        .map_err(|e| anyhow::anyhow!("store root seed in operating-system credentials: {e}"))?;
    if let Err(e) = node_entry.set_secret(node) {
        let _ = root_entry.delete_credential();
        bail!("store node seed in operating-system credentials: {e}");
    }
    if let Err(error) = ensure_keyring_seed(&root_entry, root, "root")
        .and_then(|()| ensure_keyring_seed(&node_entry, node, "node"))
    {
        let _ = root_entry.delete_credential();
        let _ = node_entry.delete_credential();
        return Err(error);
    }
    Ok(())
}

fn delete_keyring_identity(credential_id: &str) {
    for kind in ["root", "node"] {
        if let Ok(entry) = keyring_entry(credential_id, kind) {
            let _ = entry.delete_credential();
        }
    }
}

fn load_existing_seed(path: &Path, passphrase: Option<&[u8]>) -> Result<[u8; 32]> {
    if !path.exists() {
        bail!("legacy key file {path:?} is missing");
    }
    load_or_generate_seed(path, passphrase)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("create protected backup directory {path:?}"))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir(path).with_context(|| format!("create backup directory {path:?}"))
}

fn ensure_keyring_seed(entry: &Entry, expected: &[u8; 32], kind: &str) -> Result<()> {
    let stored = entry
        .get_secret()
        .map_err(|e| anyhow::anyhow!("verify {kind} seed in operating-system credentials: {e}"))?;
    if stored.as_slice() != expected {
        bail!("operating-system credential verification failed for {kind} seed");
    }
    Ok(())
}

fn get_keyring_seed(credential_id: &str, kind: &str) -> Result<[u8; 32]> {
    let entry = keyring_entry(credential_id, kind)?;
    let bytes = entry.get_secret().map_err(|e| match e {
        KeyringError::NoEntry => anyhow::anyhow!(
            "{kind} seed is missing from the operating-system credential store; restore the credential backup"
        ),
        other => anyhow::anyhow!("read {kind} seed from operating-system credentials: {other}"),
    })?;
    seed32(&bytes, Path::new(kind))
}

/// Read a 32-byte seed file, or generate + persist one. `Some` passphrase -> the seed is
/// Argon2id-sealed at rest, else raw plaintext (0600 on unix). A passphrase/plaintext
/// mismatch either way is an explicit error, never a silent wrong result.
fn load_or_generate_seed(path: &Path, passphrase: Option<&[u8]>) -> Result<[u8; 32]> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("read {path:?}"))?;
        if let Some(sealed) = bytes.strip_prefix(ATREST_MAGIC) {
            let pass = passphrase
                .with_context(|| format!("{path:?} is sealed but {PASSPHRASE_ENV} is unset"))?;
            let blob = decode_atrest(sealed)
                .with_context(|| format!("malformed sealed key file {path:?}"))?;
            let secret = atrest::open_at_rest(pass, &blob)
                .map_err(|e| anyhow::anyhow!("open {path:?}: {e}"))?;
            return seed32(&secret, path);
        }
        if passphrase.is_some() {
            bail!("{path:?} is a plaintext seed but {PASSPHRASE_ENV} is set; remove it or unset the passphrase");
        }
        return seed32(&bytes, path);
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).map_err(|e| anyhow::anyhow!("generate key seed: {e}"))?;
    match passphrase {
        Some(pass) => {
            let blob = atrest::seal_at_rest(pass, &*seed)
                .map_err(|e| anyhow::anyhow!("seal {path:?}: {e}"))?;
            let mut out = Vec::with_capacity(ATREST_MAGIC.len() + 48 + blob.ciphertext.len());
            out.extend_from_slice(ATREST_MAGIC);
            encode_atrest(&blob, &mut out);
            write_secret(path, &out)?;
        }
        None => write_secret(path, &*seed)?,
    }
    Ok(*seed)
}

/// Copy a 32-byte seed out of a buffer, erroring on any other length.
fn seed32(bytes: &[u8], path: &Path) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        bail!("key file {path:?} is {} bytes, expected 32", bytes.len());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes);
    Ok(seed)
}

/// Serialize an `AtRestBlob` (self-describing) as
/// `salt(16) ‖ nonce(24) ‖ m_cost.be4 ‖ t_cost.be4 ‖ p_cost.be4 ‖ ciphertext`.
fn encode_atrest(blob: &AtRestBlob, out: &mut Vec<u8>) {
    out.extend_from_slice(&blob.salt);
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.m_cost.to_be_bytes());
    out.extend_from_slice(&blob.t_cost.to_be_bytes());
    out.extend_from_slice(&blob.p_cost.to_be_bytes());
    out.extend_from_slice(&blob.ciphertext);
}

/// Inverse of [`encode_atrest`]. The fixed header is 16 + 24 + 4 + 4 + 4 = 52 B.
fn decode_atrest(b: &[u8]) -> Result<AtRestBlob> {
    const HEADER: usize = 16 + 24 + 4 + 4 + 4;
    if b.len() < HEADER {
        bail!("sealed blob too short: {} bytes", b.len());
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&b[0..16]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&b[16..40]);
    let m_cost = u32::from_be_bytes(b[40..44].try_into().expect("4 bytes"));
    let t_cost = u32::from_be_bytes(b[44..48].try_into().expect("4 bytes"));
    let p_cost = u32::from_be_bytes(b[48..52].try_into().expect("4 bytes"));
    Ok(AtRestBlob {
        salt,
        nonce,
        m_cost,
        t_cost,
        p_cost,
        ciphertext: b[HEADER..].to_vec(),
    })
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {path:?}"))?;
    f.write_all(bytes)
        .with_context(|| format!("write {path:?}"))?;
    f.sync_all().with_context(|| format!("sync {path:?}"))?;
    sync_parent(path)
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {path:?}"))?;
    use std::io::Write;
    file.write_all(bytes)
        .with_context(|| format!("write {path:?}"))?;
    file.sync_all().with_context(|| format!("sync {path:?}"))?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("secret file has no parent directory")?;
    std::fs::File::open(parent)
        .with_context(|| format!("open parent directory {parent:?}"))?
        .sync_all()
        .with_context(|| format!("sync parent directory {parent:?}"))
}

#[cfg(not(unix))]
fn sync_parent(path: &Path) -> Result<()> {
    path.parent()
        .context("secret file has no parent directory")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::collections::HashMap;
    #[cfg(unix)]
    use std::sync::Mutex;

    #[cfg(unix)]
    #[derive(Default)]
    struct FakeCredentialStore {
        values: Mutex<HashMap<(String, String), [u8; 32]>>,
        fail_write: Option<usize>,
        fail_read: bool,
        writes: Mutex<usize>,
    }

    #[cfg(unix)]
    impl CredentialStore for FakeCredentialStore {
        fn write(&self, id: &str, kind: &str, seed: &[u8; 32]) -> Result<()> {
            let mut writes = self.writes.lock().unwrap();
            *writes += 1;
            if self.fail_write == Some(*writes) {
                bail!("injected credential write failure");
            }
            self.values
                .lock()
                .unwrap()
                .insert((id.to_string(), kind.to_string()), *seed);
            Ok(())
        }

        fn read(&self, id: &str, kind: &str) -> Result<[u8; 32]> {
            if self.fail_read {
                bail!("injected credential verification failure");
            }
            self.values
                .lock()
                .unwrap()
                .get(&(id.to_string(), kind.to_string()))
                .copied()
                .context("missing fake credential")
        }

        fn delete(&self, id: &str, kind: &str) {
            self.values
                .lock()
                .unwrap()
                .remove(&(id.to_string(), kind.to_string()));
        }
    }

    #[cfg(unix)]
    struct FailAt(Option<MigrationPoint>);
    #[cfg(unix)]
    impl MigrationHooks for FailAt {
        fn reach(&mut self, point: MigrationPoint) -> Result<()> {
            if self.0 == Some(point) {
                bail!("injected migration failure at {point:?}");
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    fn legacy_pair(dir: &Path) {
        write_secret(&dir.join("node.key"), &[0x31; 32]).unwrap();
        write_secret(&dir.join("root.key"), &[0x52; 32]).unwrap();
    }

    #[cfg(unix)]
    fn assert_original_pair(dir: &Path, store: &FakeCredentialStore) {
        assert_eq!(std::fs::read(dir.join("node.key")).unwrap(), [0x31; 32]);
        assert_eq!(std::fs::read(dir.join("root.key")).unwrap(), [0x52; 32]);
        assert!(!dir.join(CREDENTIAL_ID_FILE).exists());
        assert!(store.values.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn migration_failures_never_leave_mixed_identity_state() {
        let scenarios = [
            (Some(1), false, None),
            (Some(2), false, None),
            (None, true, None),
            (None, false, Some(MigrationPoint::BackupSynced)),
            (None, false, Some(MigrationPoint::CredentialIdSynced)),
            (None, false, Some(MigrationPoint::BeforeNodeRemoval)),
            (None, false, Some(MigrationPoint::BeforeRootRemoval)),
        ];
        for (fail_write, fail_read, point) in scenarios {
            let dir = tempfile::tempdir().unwrap();
            legacy_pair(dir.path());
            let store = FakeCredentialStore {
                fail_write,
                fail_read,
                ..Default::default()
            };
            assert!(migrate_legacy_keys_with(dir.path(), &store, &mut FailAt(point)).is_err());
            assert_original_pair(dir.path(), &store);
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_activation_survives_child_process_kill() {
        struct Barrier {
            ready: PathBuf,
        }
        impl MigrationHooks for Barrier {
            fn reach(&mut self, point: MigrationPoint) -> Result<()> {
                if point == MigrationPoint::BackupSynced {
                    std::fs::write(&self.ready, b"ready")?;
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
                Ok(())
            }
        }

        if let Ok(path) = std::env::var("CARAPACE_MIGRATION_KILL_DIR") {
            let dir = PathBuf::from(path);
            let _ = migrate_legacy_keys_with(
                &dir,
                &FakeCredentialStore::default(),
                &mut Barrier {
                    ready: dir.join("barrier.ready"),
                },
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        legacy_pair(dir.path());
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("state::tests::backup_activation_survives_child_process_kill")
            .arg("--nocapture")
            .env("CARAPACE_MIGRATION_KILL_DIR", dir.path())
            .spawn()
            .unwrap();
        let ready = dir.path().join("barrier.ready");
        for _ in 0..200 {
            if ready.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            ready.exists(),
            "child did not reach the backup sync barrier"
        );
        child.kill().unwrap();
        child.wait().unwrap();

        let store = FakeCredentialStore::default();
        assert_original_pair(dir.path(), &store);
        migrate_legacy_keys_with(dir.path(), &store, &mut FailAt(None)).unwrap();
        assert!(!dir.path().join("node.key").exists());
        assert!(!dir.path().join("root.key").exists());
        let id = std::fs::read_to_string(dir.path().join(CREDENTIAL_ID_FILE)).unwrap();
        assert_eq!(store.read(&id, "node").unwrap(), [0x31; 32]);
        assert_eq!(store.read(&id, "root").unwrap(), [0x52; 32]);
    }

    // With a passphrase: sealed (magic + ciphertext, never the raw seed), re-opens to the
    // same seed, and a wrong/absent passphrase fails to open rather than returning garbage.
    #[test]
    fn sealed_at_rest_roundtrips_and_hides_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        let pass = b"correct horse battery staple";

        let seed = load_or_generate_seed(&path, Some(pass)).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        assert!(
            on_disk.starts_with(ATREST_MAGIC),
            "sealed file must carry the magic"
        );
        assert!(
            !on_disk.windows(32).any(|w| w == seed),
            "raw seed must not appear on disk"
        );

        // Same passphrase reloads the same seed.
        assert_eq!(load_or_generate_seed(&path, Some(pass)).unwrap(), seed);
        // Wrong passphrase fails to open.
        assert!(load_or_generate_seed(&path, Some(b"wrong")).is_err());
        // A sealed file requires a passphrase.
        assert!(load_or_generate_seed(&path, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn protected_local_identity_opens_only_with_the_supplied_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let passphrase = b"terminal-only secret";
        let node = load_or_generate_seed(&dir.path().join("node.key"), Some(passphrase)).unwrap();
        let root = load_or_generate_seed(&dir.path().join("root.key"), Some(passphrase)).unwrap();

        let state = State::load_protected_local(dir.path(), passphrase).unwrap();
        assert_eq!(state.node_key.to_bytes(), node);
        assert_eq!(&*state.k_root, &root);
        assert!(State::load_protected_local(dir.path(), b"").is_err());
        assert!(State::load_protected_local(dir.path(), b"wrong").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn plaintext_seed_roundtrips_without_passphrase() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let seed = load_or_generate_seed(&path, None).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            seed,
            "plaintext file is the raw seed"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_or_generate_seed(&path, None).unwrap(), seed);
        // Presenting a passphrase for a plaintext file is a hard error, not a
        // silent re-seal or wrong read.
        assert!(load_or_generate_seed(&path, Some(b"x")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn production_startup_fails_closed_without_private_acls() {
        let dir = tempfile::tempdir().unwrap();
        let error = State::load_or_generate(dir.path())
            .err()
            .expect("Windows startup must fail closed");
        assert!(error.to_string().contains("private ACLs"));
        assert!(!dir.path().join(CREDENTIAL_ID_FILE).exists());
    }

    #[test]
    fn incomplete_key_pair_is_refused_without_generating_a_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let node_path = dir.path().join("node.key");
        std::fs::write(&node_path, [0x41; 32]).unwrap();

        let err = State::load_or_generate_insecure(dir.path())
            .err()
            .expect("an incomplete identity must fail");
        assert!(err.to_string().contains("incomplete identity"));
        assert!(node_path.exists(), "the surviving key stays untouched");
        assert!(
            !dir.path().join("root.key").exists(),
            "startup must not generate the missing key"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_directories_are_restricted_and_links_are_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let parent = tempfile::tempdir().unwrap();
        let state = parent.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o777)).unwrap();
        ensure_private_directory(&state).unwrap();
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let target = parent.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let linked = parent.path().join("linked");
        symlink(&target, &linked).unwrap();
        assert!(ensure_private_directory(&linked).is_err());
    }
}
