//! Daemon persistent state: a state directory holding this device's node key and
//! (for the demo) the user master key `k_root`. Both are load-or-generate.
//!
//! `node.key` — 32-byte Ed25519 node secret seed (unique per device).
//! `root.key` — 32-byte user master key `k_root` (SHARED across a user's
//!              devices; the source of `K_userid`, `K_manifest`, `K_content`,
//!              and `K_disclose`).
//!
//! At-rest protection (W4): if `CARAPACE_PASSPHRASE` is set, both key files are
//! sealed with `carapace-crypto::atrest` (Argon2id -> XChaCha20-Poly1305) so a
//! stolen disk/backup/snapshot yields only ciphertext. Without a passphrase the
//! seeds are written as plaintext (0600 on unix); this is the documented demo
//! fallback and does NOT protect `k_root` — whose compromise is total vault and
//! identity compromise — against anything that can read the file. On non-unix the
//! plaintext fallback additionally has no permission restriction; set a
//! passphrase there.
//!
//! ponytail: no config file; the state dir *is* the config (listen = localhost,
//! discovery = none / direct addr). Add a config when a knob actually varies.

use anyhow::{bail, Context, Result};
use carapace_crypto::atrest::{self, AtRestBlob};
use carapace_crypto::identity::user_key_from_seed;
use carapace_crypto::kdf::k_userid;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Environment variable holding the at-rest passphrase (W4). When present, key
/// files are Argon2id-sealed; when absent, seeds are stored as plaintext.
const PASSPHRASE_ENV: &str = "CARAPACE_PASSPHRASE";

/// Magic prefix marking a key file as an at-rest-sealed blob (vs. a raw seed).
const ATREST_MAGIC: &[u8; 8] = b"CRPCSEAL";

/// Loaded (or freshly generated) daemon state.
pub struct State {
    /// This device's node signing key.
    pub node_key: SigningKey,
    /// The user master key, shared across a user's devices.
    pub k_root: Zeroizing<[u8; 32]>,
    /// The state directory holding `node.key`/`root.key` and (design §3) the durable
    /// `blobs/` store and `state.redb`. `None` for a seed-only [`State::from_seeds`]:
    /// the daemon then uses a process-unique ephemeral directory (cleaned up on drop),
    /// so a from-seeds test daemon persists nowhere permanent. A reboot test uses
    /// [`State::load_or_generate`] twice against the same dir.
    pub dir: Option<PathBuf>,
    /// True iff this run FRESHLY generated the identity (neither `node.key` nor
    /// `root.key` existed before). The daemon's §3.5 startup tripwire uses this to tell a
    /// genuine first start (an empty `state.redb` is expected) from a WIPED `state.redb`
    /// beside a surviving identity - the worst variant, where firing loudly matters.
    pub keys_freshly_generated: bool,
}

impl State {
    /// Load the node and root keys from `dir`, generating and persisting any that
    /// are absent. Creates `dir` if needed. Reads the optional at-rest passphrase
    /// from `CARAPACE_PASSPHRASE`.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("create state dir {dir:?}"))?;
        let passphrase = std::env::var(PASSPHRASE_ENV).ok().map(Zeroizing::new);
        let pass = passphrase.as_ref().map(|p| p.as_bytes());
        let node_path = dir.join("node.key");
        let root_path = dir.join("root.key");
        // Fresh identity iff NEITHER key existed before this call (a genuine first run).
        // Captured before `load_or_generate_seed` writes them, so the §3.5 tripwire can
        // distinguish a first start from a wiped `state.redb` beside a surviving identity.
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

    /// Build state directly from raw seeds (used in tests and for scripted
    /// two-device setups that share a `k_root`). No state directory: the daemon
    /// persists to a process-unique ephemeral dir it cleans up on drop.
    pub fn from_seeds(node_seed: [u8; 32], k_root: [u8; 32]) -> Self {
        Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(k_root),
            dir: None,
            // Seed-only: this constructor never writes key files, so the §3.5 tripwire for
            // it keys on the durable `blobs/` presence, not a fresh-identity flag.
            keys_freshly_generated: false,
        }
    }

    /// Like [`State::from_seeds`] but pinned to a specific state directory, so a test
    /// can drop the daemon and reboot a fresh one from the SAME seeds AND the same
    /// durable `blobs/`/`state.redb` (design §6 reboot-survival tests).
    pub fn from_seeds_in(dir: &Path, node_seed: [u8; 32], k_root: [u8; 32]) -> Self {
        Self {
            node_key: SigningKey::from_bytes(&node_seed),
            k_root: Zeroizing::new(k_root),
            dir: Some(dir.to_path_buf()),
            // Seed-only (does not write key files): the reboot tests using this rely on
            // the durable `blobs/` presence for the tripwire, not a fresh-identity flag.
            keys_freshly_generated: false,
        }
    }

    /// The user signing key: `Ed25519(seed = HKDF(k_root, "…user-identity"))`.
    /// Identical across a user's devices because `k_root` is shared.
    pub fn user_key(&self) -> SigningKey {
        user_key_from_seed(&k_userid(&*self.k_root))
    }
}

/// Read a 32-byte seed file, or generate + persist one. When `passphrase` is
/// `Some`, the seed is Argon2id-sealed at rest; otherwise it is stored as a raw
/// plaintext seed (0600 on unix). A sealed file loaded without a passphrase (or
/// vice versa) is an explicit error rather than a silent wrong result.
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
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    // ponytail: no OS-ACL restriction here (would need a Windows-specific crate);
    // set CARAPACE_PASSPHRASE on non-unix so the file is Argon2id-sealed instead.
    std::fs::write(path, bytes).with_context(|| format!("write {path:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // W4: with a passphrase, key files are sealed (magic + ciphertext, never the
    // raw seed) and re-open to the identical seed; a wrong/absent passphrase
    // fails to open rather than returning garbage.
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

    #[test]
    fn plaintext_seed_roundtrips_without_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let seed = load_or_generate_seed(&path, None).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            seed,
            "plaintext file is the raw seed"
        );
        assert_eq!(load_or_generate_seed(&path, None).unwrap(), seed);
        // Presenting a passphrase for a plaintext file is a hard error, not a
        // silent re-seal or wrong read.
        assert!(load_or_generate_seed(&path, Some(b"x")).is_err());
    }
}
