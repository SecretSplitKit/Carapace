//! carapace-vault: vault identity, directory ingest into a sealed manifest plus
//! a content-addressed chunk store, and reconstruction back to plaintext
//! (protocol §5, §7, §11). Network-independent — no iroh here.
//!
//! - [`vid`] / [`new_vid`]: vault identity `BLAKE3-256(user_pubkey ‖ nonce)`.
//! - [`ChunkStore`]: content-addressed ciphertext store ([`MemoryStore`],
//!   [`FsStore`]).
//! - [`ingest_dir`]: walk a tree, FastCDC-chunk + seal each file, populate the
//!   store, and build a [`Manifest`] + sealed, node-signed [`ManifestEnvelope`].
//! - [`open_envelope`] / [`reconstruct`]: verify + decrypt back to bytes/disk.
//!
//! Every cryptographic primitive routes through `carapace-crypto`; every wire
//! encoding routes through `carapace-wire`. Nothing is re-implemented here.

mod store;

pub use store::{ChunkStore, FsStore, MemoryStore, StoreError};

use carapace_crypto::content::{self, chunk_ranges};
use carapace_crypto::kdf::{self, Key32};
use carapace_wire::{FileEntry, Manifest, ManifestEnvelope, Vv};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

/// Errors from vault ingest, sealing, or reconstruction.
#[derive(Debug)]
pub enum VaultError {
    /// Filesystem error.
    Io(std::io::Error),
    /// Chunk seal/open (AEAD) failure.
    Chunk(content::ChunkError),
    /// Manifest AEAD seal or open failed.
    ManifestAead,
    /// A wire (CBOR / signature) error.
    Wire(carapace_wire::Error),
    /// Chunk store error.
    Store(StoreError),
    /// A referenced chunk was absent from the store during reconstruction.
    MissingChunk([u8; 32]),
    /// No decryption key was supplied for a referenced chunk.
    MissingKey([u8; 32]),
    /// Recovered file bytes did not match the manifest's `file_hash`.
    FileHashMismatch(String),
    /// A manifest path was absolute or escaped the output root (`..`).
    UnsafePath(String),
    /// System clock / metadata could not produce a valid mtime.
    BadMtime,
    /// The system CSPRNG failed.
    Rng,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "io: {e}"),
            VaultError::Chunk(e) => write!(f, "chunk: {e}"),
            VaultError::ManifestAead => write!(f, "manifest AEAD failed"),
            VaultError::Wire(e) => write!(f, "wire: {e}"),
            VaultError::Store(e) => write!(f, "store: {e}"),
            VaultError::MissingChunk(_) => write!(f, "referenced chunk missing from store"),
            VaultError::MissingKey(_) => write!(f, "no key for referenced chunk"),
            VaultError::FileHashMismatch(p) => write!(f, "file hash mismatch for {p}"),
            VaultError::UnsafePath(p) => write!(f, "unsafe manifest path: {p}"),
            VaultError::BadMtime => write!(f, "invalid file mtime"),
            VaultError::Rng => write!(f, "system RNG failed"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}
impl From<content::ChunkError> for VaultError {
    fn from(e: content::ChunkError) -> Self {
        VaultError::Chunk(e)
    }
}
impl From<carapace_wire::Error> for VaultError {
    fn from(e: carapace_wire::Error) -> Self {
        VaultError::Wire(e)
    }
}
impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        VaultError::Store(e)
    }
}

// ---------------- vault identity (§7.1) ---------------------------------

/// `vid = BLAKE3-256(user_pubkey ‖ creation_nonce)`.
pub fn vid(user_pubkey: &[u8; 32], creation_nonce: &[u8; 16]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(user_pubkey);
    h.update(creation_nonce);
    *h.finalize().as_bytes()
}

/// Mint a new vault: draw a 16-byte CSPRNG `creation_nonce` and derive its
/// `vid`. Returns `(vid, nonce)` so the caller can persist the nonce.
pub fn new_vid(user_pubkey: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let mut nonce = [0u8; 16];
    // ponytail: OS-CSPRNG failure at vault-mint is unrecoverable and not
    // attacker-reachable (S8); `expect` here keeps `new_vid` infallible for its
    // callers. The RNG-failure path that a peer *can* reach (`seal_manifest`)
    // propagates a `VaultError::Rng` instead.
    getrandom::getrandom(&mut nonce).expect("CSPRNG");
    (vid(user_pubkey, &nonce), nonce)
}

// ---------------- per-vault keys ----------------------------------------

/// The two vault-scoped keys the vault logic needs, derived off `K_root` for a
/// given `vid` per the §4 HKDF tree.
pub struct VaultKeys {
    /// The vault id these keys are scoped to.
    pub vid: [u8; 32],
    /// `K_content(vid)` — convergent chunk sealing.
    pub k_content: Key32,
    /// `K_manifest(vid)` — manifest-envelope AEAD.
    pub k_manifest: Key32,
}

impl VaultKeys {
    /// Derive `K_content` and `K_manifest` for `vid` from the user's `K_root`.
    pub fn derive(k_root: &[u8], vid: [u8; 32]) -> Self {
        let vr = kdf::k_vaultroot(k_root, &vid);
        VaultKeys { vid, k_content: kdf::k_content(&*vr), k_manifest: kdf::k_manifest(&*vr) }
    }
}

// ---------------- chunk key map -----------------------------------------

/// A chunk's decryption secret. `chunk_key`/`nonce` derive one-way from
/// `K_content` + plaintext hash, so they cannot be recovered from the manifest
/// (which stores only `{id, len}`); the owner persists them alongside it.
#[derive(Clone)]
pub struct ChunkSecret {
    /// XChaCha20-Poly1305 key.
    pub chunk_key: Zeroizing<[u8; 32]>,
    /// 24-byte nonce.
    pub nonce: Zeroizing<[u8; 24]>,
}

/// Map from ChunkID to the secret needed to open that blob.
pub type ChunkKeys = HashMap<[u8; 32], ChunkSecret>;

/// The product of [`ingest_dir`].
pub struct Ingest {
    /// The plaintext manifest (also carried, sealed, inside `envelope`).
    pub manifest: Manifest,
    /// The sealed, node-signed manifest envelope.
    pub envelope: ManifestEnvelope,
    /// `manifestDigest = BLAKE3(envelope.to_bytes())` (§7.2).
    pub digest: [u8; 32],
    /// Per-chunk secrets, needed to [`reconstruct`].
    pub keys: ChunkKeys,
}

// ---------------- ingest (§5, §7) ---------------------------------------

/// Walk `dir`, seal every file's chunks into `store`, and build the manifest +
/// sealed envelope for epoch `epoch`, node-signed by `node_key`.
///
/// Files are visited in sorted path order for a deterministic manifest. Each
/// file's chunks are FastCDC-cut, sealed with `aad = vid`, and stored under
/// their ChunkID. The per-file and manifest version vectors are keyed by the
/// signing node's pubkey at `epoch`.
pub fn ingest_dir<S: ChunkStore>(
    dir: &Path,
    node_key: &SigningKey,
    keys: &VaultKeys,
    epoch: u64,
    store: &mut S,
) -> Result<Ingest, VaultError> {
    let node_pub = node_key.verifying_key().to_bytes();
    let vv: Vv = vec![(node_pub, epoch)];

    let mut rel_paths = Vec::new();
    collect_files(dir, dir, &mut rel_paths)?;
    rel_paths.sort();

    let mut files = Vec::with_capacity(rel_paths.len());
    let mut key_map: ChunkKeys = HashMap::new();

    for rel in &rel_paths {
        let full = dir.join(rel);
        let meta = fs::metadata(&full)?;
        let data = fs::read(&full)?;
        let file_hash = *blake3::hash(&data).as_bytes();

        let mut chunk_refs: Vec<([u8; 32], u64)> = Vec::new();
        for (off, len) in chunk_ranges(&data) {
            let plaintext = &data[off..off + len];
            let sealed = content::seal_chunk(&*keys.k_content, &keys.vid, plaintext)?;
            store.put(sealed.chunk_id, sealed.ciphertext)?;
            chunk_refs.push((sealed.chunk_id, len as u64));
            key_map.entry(sealed.chunk_id).or_insert(ChunkSecret {
                chunk_key: sealed.chunk_key,
                nonce: sealed.nonce,
            });
        }

        files.push(FileEntry {
            path: rel_to_slash(rel),
            mode: file_mode(&meta),
            mtime: file_mtime(&meta)?,
            size: data.len() as u64,
            chunks: chunk_refs,
            file_hash,
            version: vv.clone(),
            deleted: false,
        });
    }

    let manifest =
        Manifest { vid: keys.vid, epoch, authors: vec![node_pub], files, vv };
    let envelope = seal_manifest(&manifest, keys, node_key)?;
    let digest = *blake3::hash(&envelope.to_bytes()).as_bytes();

    Ok(Ingest { manifest, envelope, digest, keys: key_map })
}

/// Additional-data for the manifest AEAD: `vid ‖ epoch.be8` (§7.2).
fn manifest_aad(vid: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(40);
    aad.extend_from_slice(vid);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Seal a manifest under `K_manifest(vid)` (XChaCha20-Poly1305, aad =
/// `vid‖epoch`) and node-sign the envelope per B.3 (doc-type 24).
pub fn seal_manifest(
    manifest: &Manifest,
    keys: &VaultKeys,
    node_key: &SigningKey,
) -> Result<ManifestEnvelope, VaultError> {
    // S7: the manifest plaintext is scrubbed on drop (it names every chunk).
    let pt = Zeroizing::new(manifest.to_bytes());
    let mut nonce = [0u8; 24];
    // S8: propagate a CSPRNG failure instead of panicking.
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Rng)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*keys.k_manifest));
    let aad = manifest_aad(&manifest.vid, manifest.epoch);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pt[..], aad: &aad })
        .map_err(|_| VaultError::ManifestAead)?;

    let mut env = ManifestEnvelope {
        vid: manifest.vid,
        epoch: manifest.epoch,
        nonce,
        ct,
        by: [0; 32],
        sig: [0; 64],
    };
    env.sign(node_key);
    Ok(env)
}

/// Verify the envelope's node signature and decrypt the manifest under
/// `K_manifest(vid)`.
pub fn open_envelope(
    env: &ManifestEnvelope,
    k_manifest: &[u8; 32],
) -> Result<Manifest, VaultError> {
    env.verify()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(k_manifest));
    let aad = manifest_aad(&env.vid, env.epoch);
    let pt = cipher
        .decrypt(XNonce::from_slice(&env.nonce), Payload { msg: &env.ct, aad: &aad })
        .map_err(|_| VaultError::ManifestAead)?;
    Ok(Manifest::from_bytes(&pt)?)
}

// ---------------- reconstruction (§5) -----------------------------------

/// Decrypt one file's ordered chunks from `store` into its plaintext bytes,
/// verifying the recovered bytes against `entry.file_hash`.
pub fn reconstruct_file<S: ChunkStore>(
    entry: &FileEntry,
    vid: &[u8; 32],
    store: &S,
    keys: &ChunkKeys,
) -> Result<Vec<u8>, VaultError> {
    let mut out = Vec::with_capacity(entry.size as usize);
    for (id, _len) in &entry.chunks {
        let ct = store.get(id)?.ok_or(VaultError::MissingChunk(*id))?;
        let secret = keys.get(id).ok_or(VaultError::MissingKey(*id))?;
        let pt = content::open_chunk(&secret.chunk_key, &secret.nonce, &ct, vid)?;
        out.extend_from_slice(&pt);
    }
    if *blake3::hash(&out).as_bytes() != entry.file_hash {
        return Err(VaultError::FileHashMismatch(entry.path.clone()));
    }
    Ok(out)
}

/// Reconstruct every non-deleted file in `manifest` from `store` + `keys`,
/// writing each to `out_dir` at its (validated, non-escaping) relative path.
pub fn reconstruct<S: ChunkStore>(
    manifest: &Manifest,
    store: &S,
    keys: &ChunkKeys,
    out_dir: &Path,
) -> Result<(), VaultError> {
    for entry in &manifest.files {
        if entry.deleted {
            continue;
        }
        let bytes = reconstruct_file(entry, &manifest.vid, store, keys)?;
        let dest = safe_join(out_dir, &entry.path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &bytes)?;
    }
    Ok(())
}

// ---------------- filesystem helpers ------------------------------------

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), VaultError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            collect_files(root, &path, out)?;
        } else if ty.is_file() {
            let rel = path.strip_prefix(root).expect("path is under root").to_path_buf();
            out.push(rel);
        }
        // symlinks and other node types are skipped
    }
    Ok(())
}

fn rel_to_slash(rel: &Path) -> String {
    rel.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(unix)]
fn file_mode(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() as u64
}
#[cfg(not(unix))]
fn file_mode(_meta: &fs::Metadata) -> u64 {
    0o644
}

fn file_mtime(meta: &fs::Metadata) -> Result<u64, VaultError> {
    let modified = meta.modified()?;
    modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| VaultError::BadMtime)
}

/// Join a manifest-supplied relative path onto `base`, rejecting absolute paths
/// and any `..` escape (a manifest may be hostile).
///
/// S9 (deferred to the foreign-manifest phase): two residual gaps remain for a
/// *cross-user* hostile manifest — a Windows alternate-data-stream component
/// (`foo:bar`) is not filtered (a blanket `:` reject would break legitimate unix
/// filenames), and `reconstruct`'s `fs::write` follows a pre-existing symlink at
/// the destination. Phase 1 manifests are same-user-trusted, so this is safe as
/// is; tighten both before honoring a friend's manifest.
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf, VaultError> {
    let mut out = base.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains('\\') {
            return Err(VaultError::UnsafePath(rel.to_string()));
        }
        out.push(part);
    }
    // Reject a rel that resolved to nothing (e.g. "" or "/").
    if out == base {
        return Err(VaultError::UnsafePath(rel.to_string()));
    }
    Ok(out)
}
