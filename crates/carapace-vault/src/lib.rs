//! carapace-vault: vault identity, directory ingest into a sealed manifest plus
//! a content-addressed chunk store, and reconstruction back to plaintext
//! (protocol §5, §7, §11). Network-independent. Crypto routes through
//! `carapace-crypto`, wire encoding through `carapace-wire`.

pub mod merge;
mod store;

pub use merge::{
    bump, canon_vv, concurrent, dominates, merge_entries, merge_manifests, merge_vv, vv_equal,
    MergedManifest,
};
pub use store::{ChunkStore, FsStore, MemoryStore, StoreError};

use carapace_crypto::content::{self, chunk_ranges};
use carapace_crypto::kdf::{self, Key32};
use carapace_wire::{FileEntry, Manifest, ManifestEnvelope, Vv};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use std::collections::{HashMap, HashSet};
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
    /// A decrypted chunk's `BLAKE3(plaintext)` did not match the manifest's stored
    /// `pt_hash` (Option B integrity check, §4.2).
    ChunkHashMismatch([u8; 32]),
    /// A manifest path was absolute or escaped the output root (`..`).
    UnsafePath(String),
    /// A non-UTF8 filename: a lossy collapse could alias it onto a distinct file,
    /// so it is refused rather than silently merged.
    NonUtf8Path(String),
    /// System clock / metadata could not produce a valid mtime.
    BadMtime,
    /// The system CSPRNG failed.
    Rng,
    /// Shared restore validation or output failed.
    Restore(carapace_restore::Error),
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
            VaultError::ChunkHashMismatch(_) => {
                write!(f, "chunk plaintext hash mismatch (pt_hash)")
            }
            VaultError::UnsafePath(p) => write!(f, "unsafe manifest path: {p}"),
            VaultError::NonUtf8Path(p) => write!(f, "non-UTF8 file path: {p}"),
            VaultError::BadMtime => write!(f, "invalid file mtime"),
            VaultError::Rng => write!(f, "system RNG failed"),
            VaultError::Restore(e) => write!(f, "{e}"),
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
impl From<carapace_restore::Error> for VaultError {
    fn from(e: carapace_restore::Error) -> Self {
        VaultError::Restore(e)
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
    // ponytail: CSPRNG failure at vault-mint is not attacker-reachable (S8), so
    // `expect` keeps `new_vid` infallible; the peer-reachable path
    // (`seal_manifest`) propagates `VaultError::Rng` instead.
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
        VaultKeys {
            vid,
            k_content: kdf::k_content(&*vr),
            k_manifest: kdf::k_manifest(&*vr),
        }
    }
}

// ---------------- chunk key map -----------------------------------------

/// A chunk's decryption secret, derived one-way from `K_content` + `pt_hash`. A
/// `K_content` holder re-derives it via [`chunk_keys_from_manifest`] (Option B, §4).
#[derive(Clone)]
pub struct ChunkSecret {
    /// XChaCha20-Poly1305 key.
    pub chunk_key: Zeroizing<[u8; 32]>,
    /// 24-byte nonce.
    pub nonce: Zeroizing<[u8; 24]>,
}

/// Map from ChunkID to the secret needed to open that blob.
pub type ChunkKeys = HashMap<[u8; 32], ChunkSecret>;

/// Option B (§4.2): re-derive the per-chunk `ChunkKeys` from `K_content` alone,
/// using each chunk's stored `pt_hash`. Lets an owner or recovery claimant
/// reconstruct from the sealed manifest with no `FileGrant`.
pub fn chunk_keys_from_manifest(manifest: &Manifest, k_content: &[u8]) -> ChunkKeys {
    let mut keys = HashMap::new();
    for f in &manifest.files {
        for (id, pt_hash, _len) in &f.chunks {
            keys.entry(*id).or_insert_with(|| ChunkSecret {
                chunk_key: kdf::chunk_key(k_content, pt_hash),
                nonce: kdf::chunk_nonce(k_content, pt_hash),
            });
        }
    }
    keys
}

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

/// Walk `dir` (sorted path order, deterministic manifest), FastCDC-cut and seal
/// each file's chunks (`aad = vid`) into `store`, and build the manifest + sealed
/// envelope for `epoch`, node-signed by `node_key`.
///
/// Per-file version vectors follow §11 against `prev` (the device's previously-
/// published manifest, or `None` for a first ingest): a changed/new/resurrected
/// file bumps this node's component, an unchanged file carries its vector forward,
/// and a disappeared file becomes a bumped tombstone so the delete propagates.
pub fn ingest_dir<S: ChunkStore>(
    dir: &Path,
    node_key: &SigningKey,
    keys: &VaultKeys,
    epoch: u64,
    prev: Option<&Manifest>,
    store: &mut S,
) -> Result<Ingest, VaultError> {
    let node_pub = node_key.verifying_key().to_bytes();

    // Prior per-path entries, for VV carry-forward / bump and tombstoning.
    let prev_by_path: HashMap<&str, &FileEntry> = prev
        .map(|m| m.files.iter().map(|f| (f.path.as_str(), f)).collect())
        .unwrap_or_default();

    let mut rel_paths = Vec::new();
    collect_files(dir, dir, &mut rel_paths)?;
    rel_paths.sort();

    let mut files = Vec::with_capacity(rel_paths.len());
    let mut key_map: ChunkKeys = HashMap::new();
    let mut on_disk: HashSet<String> = HashSet::with_capacity(rel_paths.len());

    for rel in &rel_paths {
        let full = dir.join(rel);
        let meta = fs::metadata(&full)?;
        let data = fs::read(&full)?;
        let file_hash = *blake3::hash(&data).as_bytes();

        let mut chunk_refs: Vec<([u8; 32], [u8; 32], u64)> = Vec::new();
        for (off, len) in chunk_ranges(&data) {
            let plaintext = &data[off..off + len];
            let sealed = content::seal_chunk(&*keys.k_content, &keys.vid, plaintext)?;
            store.put(sealed.chunk_id, sealed.ciphertext)?;
            // pt_hash in the manifest lets a K_content holder re-derive key/nonce (Option B, §4).
            chunk_refs.push((sealed.chunk_id, sealed.pt_hash, len as u64));
            key_map.entry(sealed.chunk_id).or_insert(ChunkSecret {
                chunk_key: sealed.chunk_key,
                nonce: sealed.nonce,
            });
        }

        let path = rel_to_slash(rel)
            .ok_or_else(|| VaultError::NonUtf8Path(rel.to_string_lossy().into_owned()))?;
        let version = match prev_by_path.get(path.as_str()) {
            // Unchanged live file: carry the prior vector forward untouched.
            Some(p) if !p.deleted && p.file_hash == file_hash => p.version.clone(),
            // Changed file, or a resurrection of a prior tombstone: bump us.
            Some(p) => bump(&p.version, &node_pub),
            // Brand-new file: {node: 1}.
            None => bump(&Vv::new(), &node_pub),
        };
        on_disk.insert(path.clone());

        files.push(FileEntry {
            path,
            mode: file_mode(&meta),
            mtime: file_mtime(&meta)?,
            size: data.len() as u64,
            chunks: chunk_refs,
            file_hash,
            version,
            deleted: false,
        });
    }

    // Tombstones for prior paths no longer on disk.
    if let Some(prevm) = prev {
        for f in &prevm.files {
            if on_disk.contains(&f.path) {
                continue;
            }
            if f.deleted {
                // Persist the existing tombstone so the delete keeps propagating.
                files.push(f.clone());
            } else {
                // Newly deleted -> fresh tombstone with our component bumped.
                files.push(FileEntry {
                    path: f.path.clone(),
                    mode: f.mode,
                    mtime: f.mtime,
                    size: 0,
                    chunks: Vec::new(),
                    file_hash: [0u8; 32],
                    version: bump(&f.version, &node_pub),
                    deleted: true,
                });
            }
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    // Manifest-level vector: prior state joined with this node at this epoch.
    let vv = merge_vv(
        &prev.map(|m| m.vv.clone()).unwrap_or_default(),
        &vec![(node_pub, epoch)],
    );
    let manifest = Manifest {
        vid: keys.vid,
        epoch,
        authors: vec![node_pub],
        files,
        vv,
    };
    let envelope = seal_manifest(&manifest, keys, node_key)?;
    let digest = *blake3::hash(&envelope.to_bytes()).as_bytes();

    Ok(Ingest {
        manifest,
        envelope,
        digest,
        keys: key_map,
    })
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
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &pt[..],
                aad: &aad,
            },
        )
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
        .decrypt(
            XNonce::from_slice(&env.nonce),
            Payload {
                msg: &env.ct,
                aad: &aad,
            },
        )
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
    let lengths: Vec<u64> = entry.chunks.iter().map(|chunk| chunk.2).collect();
    let capacity = carapace_restore::checked_file_layout(&entry.path, entry.size, &lengths)?;
    let mut out = Vec::with_capacity(capacity);
    for (id, pt_hash, len) in &entry.chunks {
        let ct = store.get(id)?.ok_or(VaultError::MissingChunk(*id))?;
        let secret = keys.get(id).ok_or(VaultError::MissingKey(*id))?;
        let pt = content::open_chunk(&secret.chunk_key, &secret.nonce, &ct, vid)?;
        // Option B integrity check (§4.2): also catches a store returning the wrong
        // (but validly-keyed) chunk for this id.
        if blake3::hash(&pt).as_bytes() != pt_hash {
            return Err(VaultError::ChunkHashMismatch(*id));
        }
        if u64::try_from(pt.len()).ok() != Some(*len) {
            return Err(VaultError::Restore(carapace_restore::Error::InvalidLayout(
                entry.path.clone(),
            )));
        }
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
    let live: Vec<_> = manifest
        .files
        .iter()
        .filter(|entry| !entry.deleted)
        .collect();
    let paths = carapace_restore::validate_operation(
        live.iter().map(|entry| (entry.path.as_str(), entry.size)),
    )?;
    carapace_restore::reject_existing_hard_link_aliases(out_dir, &paths)?;
    let mut journal = carapace_restore::RestoreJournal::begin(out_dir, &paths)?;
    for (index, (entry, relative)) in live.into_iter().zip(paths).enumerate() {
        let lengths: Vec<u64> = entry.chunks.iter().map(|chunk| chunk.2).collect();
        carapace_restore::checked_file_layout(&entry.path, entry.size, &lengths)?;
        let chunks = entry.chunks.iter().map(|(id, pt_hash, len)| {
            let ct = store.get(id)?.ok_or(VaultError::MissingChunk(*id))?;
            let secret = keys.get(id).ok_or(VaultError::MissingKey(*id))?;
            let plaintext =
                content::open_chunk(&secret.chunk_key, &secret.nonce, &ct, &manifest.vid)?;
            if blake3::hash(&plaintext).as_bytes() != pt_hash {
                return Err(VaultError::ChunkHashMismatch(*id));
            }
            if plaintext.len() as u64 != *len {
                return Err(VaultError::Restore(carapace_restore::Error::InvalidLayout(
                    entry.path.clone(),
                )));
            }
            Ok(plaintext)
        });
        carapace_restore::write_atomic_chunks(
            out_dir,
            &relative,
            chunks,
            entry.size,
            &entry.file_hash,
            entry.mode,
            entry.mtime,
        )
        .map_err(|error| match error {
            carapace_restore::StreamError::Source(error) => error,
            carapace_restore::StreamError::Restore(error) => VaultError::Restore(error),
        })?;
        journal.mark_complete(index)?;
    }
    journal.finish()?;
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
            let rel = path
                .strip_prefix(root)
                .expect("path is under root")
                .to_path_buf();
            out.push(rel);
        }
        // symlinks and other node types are skipped
    }
    Ok(())
}

/// Join a relative path's normal components with `/`, returning `None` on a
/// non-UTF8 component. A lossy collapse could alias two distinct filenames onto
/// one manifest path and merge their content, so it is refused at the source.
fn rel_to_slash(rel: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for c in rel.components() {
        if let Component::Normal(s) = c {
            parts.push(s.to_str()?.to_string());
        }
    }
    Some(parts.join("/"))
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
