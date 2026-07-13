//! Content-addressed chunk storage: ciphertext blobs keyed by their ChunkID
//! (`BLAKE3-256(ciphertext)`). The `iroh-blobs`-backed store lives in
//! `carapace-net`; this crate ships only the in-memory and filesystem stores
//! the vault logic and its tests need.

use carapace_crypto::content::chunk_id;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Failures from a [`ChunkStore`].
#[derive(Debug)]
pub enum StoreError {
    /// The blob's `BLAKE3` hash did not equal the ChunkID it was `put` under.
    /// Storing it would violate the §5 rule "peers MUST NOT retain a blob whose
    /// hash mismatches its ChunkID".
    IdMismatch {
        /// ChunkID the caller supplied.
        expected: [u8; 32],
        /// Hash actually computed over the bytes.
        got: [u8; 32],
    },
    /// Underlying filesystem error.
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IdMismatch { expected, got } => write!(
                f,
                "chunk id mismatch: expected {}, blob hashes to {}",
                hex32(expected),
                hex32(got)
            ),
            StoreError::Io(e) => write!(f, "chunk store io: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// Content-addressed store of sealed ciphertext blobs. Keys are ChunkIDs; a
/// `put` whose bytes do not hash to the given id is rejected, so a populated
/// store is self-verifying.
pub trait ChunkStore {
    /// Store `data` under `id`. Errors unless `BLAKE3(data) == id`.
    fn put(&mut self, id: [u8; 32], data: Vec<u8>) -> Result<(), StoreError>;
    /// Fetch a blob, or `None` if absent.
    fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError>;
    /// Whether a blob is present.
    fn has(&self, id: &[u8; 32]) -> Result<bool, StoreError>;
}

/// Reject any blob whose content hash disagrees with its declared ChunkID.
fn check_id(id: &[u8; 32], data: &[u8]) -> Result<(), StoreError> {
    let got = chunk_id(data);
    if &got == id {
        Ok(())
    } else {
        Err(StoreError::IdMismatch { expected: *id, got })
    }
}

/// In-memory `HashMap` store.
#[derive(Default)]
pub struct MemoryStore {
    blobs: HashMap<[u8; 32], Vec<u8>>,
}

impl MemoryStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of stored blobs.
    pub fn len(&self) -> usize {
        self.blobs.len()
    }
    /// Whether the store holds no blobs.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

impl ChunkStore for MemoryStore {
    fn put(&mut self, id: [u8; 32], data: Vec<u8>) -> Result<(), StoreError> {
        check_id(&id, &data)?;
        self.blobs.insert(id, data);
        Ok(())
    }
    fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.blobs.get(id).cloned())
    }
    fn has(&self, id: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self.blobs.contains_key(id))
    }
}

/// Filesystem store: one file per blob, named `hex(ChunkID)` under `root`.
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
    fn path(&self, id: &[u8; 32]) -> PathBuf {
        self.root.join(hex32(id))
    }
}

impl ChunkStore for FsStore {
    fn put(&mut self, id: [u8; 32], data: Vec<u8>) -> Result<(), StoreError> {
        check_id(&id, &data)?;
        // Content-addressed: identical bytes yield the same path, so an existing
        // blob is already correct. Write unconditionally; it is idempotent.
        fs::write(self.path(&id), &data)?;
        Ok(())
    }
    fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(self.path(id)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
    fn has(&self, id: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self.path(id).exists())
    }
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_put_get_has_and_id_check() {
        let mut s = MemoryStore::new();
        let data = b"sealed ciphertext".to_vec();
        let id = chunk_id(&data);
        assert!(!s.has(&id).unwrap());
        s.put(id, data.clone()).unwrap();
        assert!(s.has(&id).unwrap());
        assert_eq!(s.get(&id).unwrap().unwrap(), data);
        // wrong id is rejected
        let bad = [0u8; 32];
        assert!(matches!(s.put(bad, b"x".to_vec()), Err(StoreError::IdMismatch { .. })));
    }
}
