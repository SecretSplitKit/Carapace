//! Daemon persistent state: a directory holding this device's node key and the user
//! master key `k_root`, both load-or-generate.
//!
//! `node.key` — 32-byte Ed25519 node secret seed (unique per device).
//! `root.key` — 32-byte user master key `k_root` (shared across a user's devices).
//!
//! At-rest protection: if `CARAPACE_PASSPHRASE` is set, both key files are sealed with
//! `carapace-crypto::atrest` (Argon2id -> XChaCha20-Poly1305). Without a passphrase the
//! seeds are plaintext (0600 on unix, no restriction on non-unix); the documented demo
//! fallback that does NOT protect `k_root` against anything that can read the file.

use anyhow::{bail, Context, Result};
use carapace_crypto::atrest::{self, AtRestBlob};
use carapace_crypto::identity::user_key_from_seed;
use carapace_crypto::kdf::k_userid;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Env var holding the at-rest passphrase; present -> key files Argon2id-sealed.
const PASSPHRASE_ENV: &str = "CARAPACE_PASSPHRASE";

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
    /// Load the node and root keys from `dir`, generating and persisting any that
    /// are absent. Creates `dir` if needed. Reads the optional at-rest passphrase
    /// from `CARAPACE_PASSPHRASE`.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("create state dir {dir:?}"))?;
        let passphrase = std::env::var(PASSPHRASE_ENV).ok().map(Zeroizing::new);
        let pass = passphrase.as_ref().map(|p| p.as_bytes());
        let node_path = dir.join("node.key");
        let root_path = dir.join("root.key");
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
