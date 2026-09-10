//! Shared validation and atomic output for restored files.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_CHUNKS_PER_FILE: usize = 1_000_000;
pub const MAX_FILES: usize = 100_000;
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_COMPONENTS: usize = 256;
const JOURNAL_NAME: &str = ".carapace-restore-journal";

/// Refuse to ingest a tree while a prior restore is recorded as incomplete.
pub fn refuse_pending_journal(root: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(root.join(JOURNAL_NAME)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Error::InvalidLayout(
            "incomplete restore journal".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// Reports whether a prior restore journal is present without interpreting I/O
/// failures as journal absence.
pub fn has_pending_journal(root: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(root.join(JOURNAL_NAME)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug)]
pub enum Error {
    UnsafePath(String),
    PathCollision(String),
    Limit(&'static str),
    InvalidLayout(String),
    Io(io::Error),
}

#[derive(Debug)]
pub enum StreamError<E> {
    Source(E),
    Restore(Error),
}

impl<E> From<Error> for StreamError<E> {
    fn from(error: Error) -> Self {
        Self::Restore(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafePath(path) => write!(f, "unsafe restore path: {path}"),
            Self::PathCollision(path) => write!(f, "restore path collision: {path}"),
            Self::Limit(limit) => write!(f, "restore limit exceeded: {limit}"),
            Self::InvalidLayout(path) => write!(f, "invalid restored file layout: {path}"),
            Self::Io(error) => write!(f, "restore I/O: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A durable record of one multi-file restore. Callers restart the full, idempotent
/// operation when this file exists. Each completed file is recorded before the next
/// file starts, so a terminated restore leaves a tracked mixed tree.
pub struct RestoreJournal {
    root: PathBuf,
    paths: Vec<PathBuf>,
    completed: Vec<bool>,
    _lock: Option<File>,
}

impl RestoreJournal {
    pub fn begin(root: &Path, paths: &[PathBuf]) -> Result<Self, Error> {
        fs::create_dir_all(root)?;
        let operation_lock = lock_restore_root(root)?;
        cleanup_stale_temporary_files(root, paths)?;
        let mut journal = Self {
            root: root.to_path_buf(),
            paths: paths.to_vec(),
            completed: vec![false; paths.len()],
            _lock: operation_lock,
        };
        journal.persist()?;
        Ok(journal)
    }

    pub fn mark_complete(&mut self, index: usize) -> Result<(), Error> {
        let completed = self
            .completed
            .get_mut(index)
            .ok_or(Error::InvalidLayout("restore journal index".to_owned()))?;
        *completed = true;
        self.persist()
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.completed.iter().any(|complete| !complete) {
            return Err(Error::InvalidLayout(
                "incomplete restore journal".to_owned(),
            ));
        }
        fs::remove_file(self.root.join(JOURNAL_NAME))?;
        sync_directory(&self.root)?;
        Ok(())
    }

    fn persist(&mut self) -> Result<(), Error> {
        let mut text = String::from("carapace-restore-v1\n");
        for (path, complete) in self.paths.iter().zip(&self.completed) {
            let path = path
                .to_str()
                .ok_or_else(|| Error::InvalidLayout("non-Unicode restore path".to_owned()))?;
            text.push(if *complete { '1' } else { '0' });
            text.push('\t');
            for byte in path.as_bytes() {
                use std::fmt::Write as _;
                write!(text, "{byte:02x}").expect("write to string");
            }
            text.push('\n');
        }
        write_atomic(
            &self.root,
            Path::new(JOURNAL_NAME),
            text.as_bytes(),
            0o600,
            0,
        )?;
        Ok(())
    }
}

#[cfg(unix)]
fn cleanup_stale_temporary_files(root: &Path, paths: &[PathBuf]) -> Result<(), Error> {
    use rustix::fs::{self as unix, AtFlags, FileType, Mode, OFlags, CWD};

    let root_descriptor = unix::openat(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut parents = HashSet::new();
    for path in paths {
        parents.insert(path.parent().unwrap_or_else(|| Path::new("")).to_path_buf());
    }
    for relative_parent in parents {
        let mut descriptor = root_descriptor.try_clone()?;
        let mut parent_path = root.to_path_buf();
        let mut missing = false;
        for component in relative_parent.components() {
            parent_path.push(component.as_os_str());
            match unix::openat(
                &descriptor,
                component.as_os_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(next) => descriptor = next,
                Err(rustix::io::Errno::NOENT) => {
                    missing = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if missing {
            continue;
        }
        for entry in fs::read_dir(&parent_path)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name_text) = name.to_str() else {
                continue;
            };
            if !is_restore_temporary_name(name_text) {
                continue;
            }
            match unix::statat(&descriptor, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_file() => {
                    unix::unlinkat(&descriptor, &name, AtFlags::empty())?;
                }
                Ok(_) | Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
            }
        }
        unix::fsync(&descriptor)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn cleanup_stale_temporary_files(_root: &Path, _paths: &[PathBuf]) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn is_restore_temporary_name(name: &str) -> bool {
    let Some(body) = name
        .strip_prefix(".carapace-restore-")
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, nonce)) = body.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && nonce.len() == 16
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(unix)]
fn lock_restore_root(root: &Path) -> Result<Option<File>, Error> {
    use rustix::fs::{self as unix, FlockOperation, Mode, OFlags, CWD};

    let directory = unix::openat(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    unix::flock(&directory, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error::InvalidLayout("another restore operation is active".to_owned()))?;
    Ok(Some(File::from(directory)))
}

#[cfg(not(unix))]
fn lock_restore_root(_root: &Path) -> Result<Option<File>, Error> {
    Ok(None)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), Error> {
    rustix::fs::fsync(File::open(path)?)?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
impl From<rustix::io::Errno> for Error {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from(error))
    }
}

pub fn checked_file_layout(path: &str, size: u64, chunks: &[u64]) -> Result<usize, Error> {
    if size > MAX_FILE_BYTES {
        return Err(Error::Limit("file bytes"));
    }
    if chunks.len() > MAX_CHUNKS_PER_FILE {
        return Err(Error::Limit("chunks per file"));
    }
    let mut total = 0u64;
    for length in chunks {
        if *length > MAX_CHUNK_BYTES {
            return Err(Error::Limit("chunk bytes"));
        }
        total = total
            .checked_add(*length)
            .ok_or(Error::Limit("file bytes"))?;
    }
    if total != size {
        return Err(Error::InvalidLayout(path.to_owned()));
    }
    usize::try_from(size).map_err(|_| Error::Limit("addressable file bytes"))
}

pub fn validate_operation<'a>(
    files: impl IntoIterator<Item = (&'a str, u64)>,
) -> Result<Vec<PathBuf>, Error> {
    let mut paths = Vec::new();
    let mut names = HashSet::new();
    let mut total = 0u64;
    for (path, size) in files {
        if paths.len() >= MAX_FILES {
            return Err(Error::Limit("files per operation"));
        }
        if size > MAX_FILE_BYTES {
            return Err(Error::Limit("file bytes"));
        }
        total = total.checked_add(size).ok_or(Error::Limit("total bytes"))?;
        if total > MAX_TOTAL_BYTES {
            return Err(Error::Limit("total bytes"));
        }
        let relative = validate_path(path)?;
        let folded: String = path.nfc().flat_map(char::to_lowercase).collect();
        if !names.insert(folded) {
            return Err(Error::PathCollision(path.to_owned()));
        }
        paths.push(relative);
    }
    Ok(paths)
}

#[cfg(unix)]
pub fn reject_existing_hard_link_aliases(root: &Path, paths: &[PathBuf]) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;

    let mut identities = HashSet::new();
    for relative in paths {
        let destination = root.join(relative);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::UnsafePath(relative.display().to_string()));
            }
            Ok(metadata) => {
                if !identities.insert((metadata.dev(), metadata.ino())) {
                    return Err(Error::PathCollision(relative.display().to_string()));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn reject_existing_hard_link_aliases(_root: &Path, _paths: &[PathBuf]) -> Result<(), Error> {
    Ok(())
}

pub fn validate_path(path: &str) -> Result<PathBuf, Error> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.eq_ignore_ascii_case(JOURNAL_NAME)
    {
        return Err(Error::UnsafePath(path.to_owned()));
    }
    let mut out = PathBuf::new();
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() > MAX_COMPONENTS {
        return Err(Error::Limit("path components"));
    }
    for part in parts {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains(['\\', ':'])
            || is_windows_device(part)
            || part.ends_with([' ', '.'])
        {
            return Err(Error::UnsafePath(path.to_owned()));
        }
        out.push(part);
    }
    Ok(out)
}

fn is_windows_device(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or(part)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

pub fn write_atomic(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    mode: u64,
    mtime: u64,
) -> Result<PathBuf, Error> {
    #[cfg(unix)]
    return write_atomic_unix(root, relative, bytes, mode, mtime);

    #[cfg(not(unix))]
    {
        write_atomic_portable(root, relative, bytes, mode, mtime)
    }
}

/// Remove a validated restored file without following a link in its parent chain.
pub fn remove_file(root: &Path, relative: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use rustix::fs::{self as unix, AtFlags, FileType, Mode, OFlags, CWD};

        let mut parent = unix::openat(
            CWD,
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let file_name = relative
            .file_name()
            .ok_or_else(|| Error::UnsafePath(relative.display().to_string()))?;
        if let Some(components) = relative.parent() {
            for component in components.components() {
                match unix::openat(
                    &parent,
                    component.as_os_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(next) => parent = next,
                    Err(rustix::io::Errno::NOENT) => return Ok(()),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        match unix::statat(&parent, file_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_file() => {
                unix::unlinkat(&parent, file_name, AtFlags::empty())?;
                unix::fsync(&parent)?;
            }
            Ok(_) => return Err(Error::UnsafePath(relative.display().to_string())),
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        let secured = portable_destination(root, relative)?;
        #[cfg(windows)]
        let destination = secured.destination.clone();
        #[cfg(not(windows))]
        let destination = {
            refuse_link(root)?;
            let mut destination = root.to_path_buf();
            for component in relative.components() {
                destination.push(component);
                if destination != root.join(relative) {
                    match fs::symlink_metadata(&destination) {
                        Ok(metadata)
                            if metadata.file_type().is_dir()
                                && !metadata.file_type().is_symlink() => {}
                        Ok(_) => return Err(Error::UnsafePath(relative.display().to_string())),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            destination
        };
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::UnsafePath(relative.display().to_string()));
            }
        }
        match fs::remove_file(destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Write bounded plaintext chunks to a private temporary file, verify the final length and
/// BLAKE3 hash, then atomically activate it. A source error or verification failure leaves
/// the old destination unchanged.
#[cfg(unix)]
pub fn write_atomic_chunks<I, E>(
    root: &Path,
    relative: &Path,
    chunks: I,
    expected_size: u64,
    expected_hash: &[u8; 32],
    mode: u64,
    mtime: u64,
) -> Result<PathBuf, StreamError<E>>
where
    I: IntoIterator<Item = Result<Vec<u8>, E>>,
{
    use rustix::fs::{self as unix, AtFlags, FileType, Mode, OFlags, CWD};

    if expected_size > MAX_FILE_BYTES {
        return Err(Error::Limit("file bytes").into());
    }
    fs::create_dir_all(root).map_err(Error::from)?;
    let mut parent = unix::openat(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(Error::from)?;
    let file_name = relative
        .file_name()
        .ok_or_else(|| Error::UnsafePath(relative.display().to_string()))?;
    if let Some(components) = relative.parent() {
        for component in components.components() {
            let name = component.as_os_str();
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            parent = match unix::openat(&parent, name, flags, Mode::empty()) {
                Ok(directory) => directory,
                Err(rustix::io::Errno::NOENT) => {
                    unix::mkdirat(&parent, name, Mode::from_raw_mode(0o700))
                        .map_err(Error::from)?;
                    unix::openat(&parent, name, flags, Mode::empty()).map_err(Error::from)?
                }
                Err(error) => return Err(Error::from(error).into()),
            };
        }
    }
    match unix::statat(&parent, file_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_file() => {}
        Ok(_) => return Err(Error::UnsafePath(relative.display().to_string()).into()),
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(Error::from(error).into()),
    }
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| Error::Io(io::Error::other("random source failed")))?;
    let temporary = format!(
        ".carapace-restore-{}-{:016x}.tmp",
        std::process::id(),
        u64::from_le_bytes(nonce)
    );
    let result = (|| {
        let descriptor = unix::openat(
            &parent,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(Error::from)?;
        let mut file = File::from(descriptor);
        let mut hasher = blake3::Hasher::new();
        let mut written = 0u64;
        let mut chunk_count = 0usize;
        for chunk in chunks {
            chunk_count = chunk_count
                .checked_add(1)
                .ok_or(Error::Limit("chunks per file"))?;
            if chunk_count > MAX_CHUNKS_PER_FILE {
                return Err(Error::Limit("chunks per file").into());
            }
            let chunk = chunk.map_err(StreamError::Source)?;
            if chunk.len() as u64 > MAX_CHUNK_BYTES {
                return Err(Error::Limit("chunk bytes").into());
            }
            written = written
                .checked_add(chunk.len() as u64)
                .ok_or(Error::Limit("file bytes"))?;
            if written > expected_size {
                return Err(Error::InvalidLayout(relative.display().to_string()).into());
            }
            file.write_all(&chunk).map_err(Error::from)?;
            hasher.update(&chunk);
        }
        if written != expected_size || hasher.finalize().as_bytes() != expected_hash {
            return Err(Error::InvalidLayout(relative.display().to_string()).into());
        }
        let modified = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(mtime))
            .ok_or_else(|| Error::InvalidLayout(relative.display().to_string()))?;
        file.set_modified(modified).map_err(Error::from)?;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode((mode & 0o0755) as u32))
            .map_err(Error::from)?;
        file.flush().map_err(Error::from)?;
        file.sync_all().map_err(Error::from)?;
        drop(file);
        unix::renameat(&parent, temporary.as_str(), &parent, file_name).map_err(Error::from)?;
        unix::fsync(&parent).map_err(Error::from)?;
        Ok(root.join(relative))
    })();
    if result.is_err() {
        let _ = unix::unlinkat(&parent, temporary.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(not(unix))]
pub fn write_atomic_chunks<I, E>(
    root: &Path,
    relative: &Path,
    chunks: I,
    expected_size: u64,
    expected_hash: &[u8; 32],
    _mode: u64,
    mtime: u64,
) -> Result<PathBuf, StreamError<E>>
where
    I: IntoIterator<Item = Result<Vec<u8>, E>>,
{
    if expected_size > MAX_FILE_BYTES {
        return Err(Error::Limit("file bytes").into());
    }
    let secured = portable_destination(root, relative)?;
    let (parent, destination) = (&secured.parent, &secured.destination);
    let mut temporary = tempfile::NamedTempFile::new_in(&parent).map_err(Error::from)?;
    let mut hasher = blake3::Hasher::new();
    let mut written = 0u64;
    let mut count = 0usize;
    for chunk in chunks {
        count += 1;
        if count > MAX_CHUNKS_PER_FILE {
            return Err(Error::Limit("chunks per file").into());
        }
        let chunk = chunk.map_err(StreamError::Source)?;
        if chunk.len() as u64 > MAX_CHUNK_BYTES {
            return Err(Error::Limit("chunk bytes").into());
        }
        written = written
            .checked_add(chunk.len() as u64)
            .ok_or(Error::Limit("file bytes"))?;
        if written > expected_size {
            return Err(Error::InvalidLayout(relative.display().to_string()).into());
        }
        temporary.write_all(&chunk).map_err(Error::from)?;
        hasher.update(&chunk);
    }
    if written != expected_size || hasher.finalize().as_bytes() != expected_hash {
        return Err(Error::InvalidLayout(relative.display().to_string()).into());
    }
    let modified = std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(mtime))
        .ok_or_else(|| Error::InvalidLayout(relative.display().to_string()))?;
    temporary
        .as_file()
        .set_modified(modified)
        .map_err(Error::from)?;
    temporary.as_file().sync_all().map_err(Error::from)?;
    persist_replace(temporary.into_temp_path(), &destination)?;
    Ok(destination.clone())
}

#[cfg(not(unix))]
struct PortableDestination {
    parent: PathBuf,
    destination: PathBuf,
    #[cfg(windows)]
    _directory_handles: Vec<File>,
}

#[cfg(not(unix))]
fn portable_destination(root: &Path, relative: &Path) -> Result<PortableDestination, Error> {
    fs::create_dir_all(root)?;
    #[cfg(windows)]
    let mut handles = Vec::new();
    #[cfg(windows)]
    handles.push(open_locked_directory(root)?);
    #[cfg(not(windows))]
    refuse_link(root)?;
    let mut parent = root.to_path_buf();
    let file_name = relative
        .file_name()
        .ok_or_else(|| Error::UnsafePath(relative.display().to_string()))?;
    if let Some(components) = relative.parent() {
        for component in components.components() {
            parent.push(component);
            match fs::symlink_metadata(&parent) {
                Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink() => {}
                Ok(_) => return Err(Error::UnsafePath(relative.display().to_string())),
                Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&parent)?,
                Err(error) => return Err(Error::Io(error)),
            }
            #[cfg(windows)]
            handles.push(open_locked_directory(&parent)?);
        }
    }
    let destination = parent.join(file_name);
    if let Ok(meta) = fs::symlink_metadata(&destination) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(Error::UnsafePath(relative.display().to_string()));
        }
    }
    Ok(PortableDestination {
        parent,
        destination,
        #[cfg(windows)]
        _directory_handles: handles,
    })
}

#[cfg(not(unix))]
fn write_atomic_portable(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    _mode: u64,
    mtime: u64,
) -> Result<PathBuf, Error> {
    let secured = portable_destination(root, relative)?;
    let destination = &secured.destination;
    let mut temporary = tempfile::NamedTempFile::new_in(&secured.parent)?;
    let result = (|| {
        let file = temporary.as_file_mut();
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        let modified = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(mtime))
            .ok_or_else(|| Error::InvalidLayout(relative.display().to_string()))?;
        file.set_modified(modified)?;
        persist_replace(temporary.into_temp_path(), &destination)?;
        Ok(destination.clone())
    })();
    result
}

/// Opens a directory itself (rather than its reparse target) and retains an
/// exclusive-delete handle. Holding every ancestor this way prevents another
/// process from renaming an inspected directory and substituting a junction
/// before the temporary file is activated.
#[cfg(windows)]
fn open_locked_directory(path: &Path) -> Result<File, Error> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 1;

    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::UnsafePath(path.display().to_string()));
    }
    Ok(file)
}

#[cfg(unix)]
fn write_atomic_unix(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    mode: u64,
    mtime: u64,
) -> Result<PathBuf, Error> {
    write_atomic_unix_with_hook(root, relative, bytes, mode, mtime, |_| Ok(()))
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitStage {
    TemporaryCreated,
    TemporarySynced,
    Renamed,
    ParentSynced,
}

#[cfg(unix)]
fn write_atomic_unix_with_hook(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    mode: u64,
    mtime: u64,
    mut hook: impl FnMut(CommitStage) -> io::Result<()>,
) -> Result<PathBuf, Error> {
    use rustix::fs::{self as unix, AtFlags, FileType, Mode, OFlags, CWD};

    fs::create_dir_all(root)?;
    let mut parent = unix::openat(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file_name = relative
        .file_name()
        .ok_or_else(|| Error::UnsafePath(relative.display().to_string()))?;
    if let Some(components) = relative.parent() {
        for component in components.components() {
            let name = component.as_os_str();
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let next = match unix::openat(&parent, name, flags, Mode::empty()) {
                Ok(directory) => directory,
                Err(rustix::io::Errno::NOENT) => {
                    unix::mkdirat(&parent, name, Mode::from_raw_mode(0o700))?;
                    unix::openat(&parent, name, flags, Mode::empty())?
                }
                Err(error) => return Err(io::Error::from(error).into()),
            };
            parent = next;
        }
    }
    match unix::statat(&parent, file_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_file() => {}
        Ok(_) => return Err(Error::UnsafePath(relative.display().to_string())),
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(io::Error::from(error).into()),
    }

    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| Error::Io(io::Error::other("random source failed")))?;
    let temporary = format!(
        ".carapace-restore-{}-{:016x}.tmp",
        std::process::id(),
        u64::from_le_bytes(nonce)
    );
    let result = (|| {
        let descriptor = unix::openat(
            &parent,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let mut file = File::from(descriptor);
        hook(CommitStage::TemporaryCreated)?;
        file.write_all(bytes)?;
        let modified = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(mtime))
            .ok_or_else(|| Error::InvalidLayout(relative.display().to_string()))?;
        file.set_modified(modified)?;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode((mode & 0o0755) as u32))?;
        file.flush()?;
        file.sync_all()?;
        hook(CommitStage::TemporarySynced)?;
        drop(file);
        unix::renameat(&parent, temporary.as_str(), &parent, file_name)?;
        hook(CommitStage::Renamed)?;
        unix::fsync(&parent)?;
        hook(CommitStage::ParentSynced)?;
        Ok(root.join(relative))
    })();
    if result.is_err() {
        let _ = unix::unlinkat(&parent, temporary.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(all(not(unix), not(windows)))]
fn persist_replace(temporary: tempfile::TempPath, destination: &Path) -> Result<(), Error> {
    let old_permissions = match fs::symlink_metadata(destination) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.permissions().readonly() => {
            let permissions = metadata.permissions();
            let mut writable = permissions.clone();
            writable.set_readonly(false);
            fs::set_permissions(destination, writable)?;
            Some(permissions)
        }
        Ok(_) => None,
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Err(error) = temporary.persist(destination) {
        if let Some(permissions) = old_permissions {
            fs::set_permissions(destination, permissions)?;
        }
        return Err(Error::Io(error.error));
    }
    Ok(())
}

#[cfg(windows)]
fn persist_replace(temporary: tempfile::TempPath, destination: &Path) -> Result<(), Error> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let opened = fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(destination);
    let old_permissions = match opened {
        Ok(file) => {
            let metadata = file.metadata()?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::UnsafePath(destination.display().to_string()));
            }
            if metadata.permissions().readonly() {
                let permissions = metadata.permissions();
                let mut writable = permissions.clone();
                writable.set_readonly(false);
                file.set_permissions(writable)?;
                Some((file, permissions))
            } else {
                None
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Err(error) = temporary.persist(destination) {
        if let Some((file, permissions)) = old_permissions {
            file.set_permissions(permissions)?;
        }
        return Err(Error::Io(error.error));
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn refuse_link(path: &Path) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(Error::UnsafePath(path.display().to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_windows_escapes_and_device_names() {
        for path in [
            "C:foo",
            "C:/foo",
            "foo:stream",
            "CON",
            "aux.txt",
            "COM1.log",
            "LPT9",
            "a\\b",
        ] {
            assert!(validate_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn rejects_internal_restore_control_paths() {
        for path in [JOURNAL_NAME, ".CARAPACE-RESTORE-JOURNAL"] {
            assert!(
                validate_path(path).is_err(),
                "accepted reserved path {path}"
            );
        }
        assert!(validate_path("nested/.carapace-restore-journal").is_ok());

        let root = tempfile::tempdir().unwrap();
        assert!(refuse_pending_journal(root.path()).is_ok());
        std::fs::write(root.path().join(JOURNAL_NAME), b"pending").unwrap();
        assert!(refuse_pending_journal(root.path()).is_err());
    }

    #[test]
    fn detects_case_and_unicode_collisions() {
        assert!(validate_operation([("same", 0), ("same", 0)]).is_err());
        assert!(validate_operation([("A.txt", 0), ("a.txt", 0)]).is_err());
        assert!(validate_operation([("e\u{301}.txt", 0), ("é.txt", 0)]).is_err());
    }

    #[test]
    fn rejects_direct_resource_boundaries_and_layout_mismatch() {
        assert!(validate_operation([("same", 0), ("same", 0)]).is_err());
        assert!(validate_operation([("A", 0), ("a", 0)]).is_err());
        assert!(validate_operation([("e\u{301}", 0), ("é", 0)]).is_err());
        assert!(checked_file_layout("large", MAX_FILE_BYTES + 1, &[]).is_err());
        assert!(checked_file_layout("chunk", 1, &[MAX_CHUNK_BYTES + 1]).is_err());
        assert!(checked_file_layout("mismatch", 2, &[1]).is_err());
        let too_many = vec![0; MAX_CHUNKS_PER_FILE + 1];
        assert!(checked_file_layout("chunks", 0, &too_many).is_err());
        let total = (0..17).map(|index| (format!("file-{index}"), MAX_FILE_BYTES));
        let names: Vec<_> = total.collect();
        assert!(
            validate_operation(names.iter().map(|(path, size)| (path.as_str(), *size))).is_err()
        );
        let deep = std::iter::repeat_n("a", MAX_COMPONENTS + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert!(validate_path(&deep).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_hard_link_aliases_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        std::fs::write(&first, b"old").unwrap();
        std::fs::hard_link(&first, &second).unwrap();
        let paths = vec![PathBuf::from("first"), PathBuf::from("second")];
        assert!(reject_existing_hard_link_aliases(temp.path(), &paths).is_err());
        assert_eq!(std::fs::read(&first).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn streaming_verification_preserves_old_file_on_failure() {
        let temp = tempfile::tempdir().unwrap();
        let relative = Path::new("file");
        write_atomic(temp.path(), relative, b"old", 0o600, 0).unwrap();
        let wrong_hash = [0u8; 32];
        let chunks = vec![Ok::<_, io::Error>(b"new".to_vec())];
        assert!(
            write_atomic_chunks(temp.path(), relative, chunks, 3, &wrong_hash, 0o600, 0,).is_err()
        );
        assert_eq!(std::fs::read(temp.path().join(relative)).unwrap(), b"old");

        let expected = *blake3::hash(b"new-complete").as_bytes();
        let chunks = vec![
            Ok::<_, io::Error>(b"new-".to_vec()),
            Err(io::Error::other("injected source failure")),
        ];
        assert!(
            write_atomic_chunks(temp.path(), relative, chunks, 12, &expected, 0o600, 0,).is_err()
        );
        assert_eq!(std::fs::read(temp.path().join(relative)).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_refuses_links_and_strips_dangerous_mode() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), temp.path().join("link")).unwrap();
        assert!(write_atomic(temp.path(), Path::new("link/x"), b"x", 0o4777, 0).is_err());
        std::fs::create_dir(temp.path().join("one")).unwrap();
        std::fs::create_dir(temp.path().join("one/two")).unwrap();
        symlink(outside.path(), temp.path().join("one/two/three")).unwrap();
        assert!(
            write_atomic(temp.path(), Path::new("one/two/three/deep"), b"x", 0o600, 0,).is_err()
        );
        let final_target = outside.path().join("final-target");
        std::fs::write(&final_target, b"unchanged").unwrap();
        symlink(&final_target, temp.path().join("final-link")).unwrap();
        assert!(write_atomic(
            temp.path(),
            Path::new("final-link"),
            b"replacement",
            0o600,
            0,
        )
        .is_err());
        assert_eq!(std::fs::read(final_target).unwrap(), b"unchanged");
        let path = write_atomic(temp.path(), Path::new("ok"), b"x", 0o6777, 0).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o0755
        );
        assert_eq!(std::fs::read(temp.path().join("ok")).unwrap(), b"x");
    }

    #[cfg(windows)]
    #[test]
    fn atomic_write_refuses_reparse_directory() {
        use std::os::windows::fs::symlink_dir;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink_dir(outside.path(), temp.path().join("link")).unwrap();
        assert!(write_atomic(temp.path(), Path::new("link/x"), b"x", 0, 0).is_err());
        assert!(!outside.path().join("x").exists());
    }

    #[cfg(windows)]
    #[test]
    fn retained_directory_handles_block_parent_substitution() {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        const FILE_SHARE_DELETE: u32 = 4;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let secured = portable_destination(temp.path(), Path::new("parent/file")).unwrap();

        let mutation_capable_open = || {
            fs::OpenOptions::new()
                .access_mode(FILE_WRITE_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&parent)
        };
        assert!(mutation_capable_open().is_err());
        assert!(std::fs::rename(&parent, temp.path().join("moved")).is_err());
        drop(secured);
        assert!(mutation_capable_open().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_replaces_content_without_leaving_temporary_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = Path::new("result.txt");
        write_atomic(temp.path(), path, b"first", 0o600, 0).unwrap();
        write_atomic(temp.path(), path, b"second", 0o600, 0).unwrap();
        assert_eq!(std::fs::read(temp.path().join(path)).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn commit_stage_failures_leave_one_complete_version() {
        for stage in [
            CommitStage::TemporaryCreated,
            CommitStage::TemporarySynced,
            CommitStage::Renamed,
            CommitStage::ParentSynced,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = Path::new("result.txt");
            write_atomic(temp.path(), path, b"old-complete", 0o600, 0).unwrap();
            let result = write_atomic_unix_with_hook(
                temp.path(),
                path,
                b"new-complete",
                0o600,
                0,
                |point| {
                    if point == stage {
                        Err(io::Error::other("injected commit-stage stop"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
            let content = std::fs::read(temp.path().join(path)).unwrap();
            let expected = if matches!(
                stage,
                CommitStage::TemporaryCreated | CommitStage::TemporarySynced
            ) {
                b"old-complete".as_slice()
            } else {
                b"new-complete".as_slice()
            };
            assert_eq!(content, expected, "invalid file at {stage:?}");
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn temporary_file_is_private_before_plaintext_write() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let result = write_atomic_unix_with_hook(
            temp.path(),
            Path::new("public.txt"),
            b"plaintext",
            0o755,
            0,
            |stage| {
                if stage == CommitStage::TemporaryCreated {
                    let entry = std::fs::read_dir(temp.path())?.next().unwrap()?;
                    let mode = entry.metadata()?.permissions().mode() & 0o777;
                    assert_eq!(mode, 0o600);
                    return Err(io::Error::other("stop before plaintext write"));
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn restore_journal_tracks_interruption_and_clean_restart() {
        let temp = tempfile::tempdir().unwrap();
        let paths = vec![PathBuf::from("one"), PathBuf::from("two")];
        let mut first = RestoreJournal::begin(temp.path(), &paths).unwrap();
        write_atomic(temp.path(), &paths[0], b"old-one", 0o600, 0).unwrap();
        first.mark_complete(0).unwrap();
        drop(first);
        let journal_path = temp.path().join(JOURNAL_NAME);
        let interrupted = std::fs::read_to_string(&journal_path).unwrap();
        assert!(interrupted.lines().nth(1).unwrap().starts_with("1\t"));
        assert!(interrupted.lines().nth(2).unwrap().starts_with("0\t"));

        let mut resumed = RestoreJournal::begin(temp.path(), &paths).unwrap();
        for (index, path) in paths.iter().enumerate() {
            write_atomic(temp.path(), path, b"new-complete", 0o600, 0).unwrap();
            resumed.mark_complete(index).unwrap();
        }
        resumed.finish().unwrap();
        assert!(!journal_path.exists());
        assert_eq!(
            std::fs::read(temp.path().join("one")).unwrap(),
            b"new-complete"
        );
        assert_eq!(
            std::fs::read(temp.path().join("two")).unwrap(),
            b"new-complete"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_journal_refuses_links_and_concurrent_operations() {
        use std::os::unix::fs::symlink;

        let paths = vec![PathBuf::from("one")];
        let linked_journal = tempfile::tempdir().unwrap();
        let outside = linked_journal.path().join("outside");
        std::fs::write(&outside, b"unchanged").unwrap();
        symlink(&outside, linked_journal.path().join(JOURNAL_NAME)).unwrap();
        assert!(RestoreJournal::begin(linked_journal.path(), &paths).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");

        let active = tempfile::tempdir().unwrap();
        let first = RestoreJournal::begin(active.path(), &paths).unwrap();
        let error = RestoreJournal::begin(active.path(), &paths)
            .err()
            .expect("a concurrent restore must fail");
        assert!(error.to_string().contains("active"));
        drop(first);
        assert!(RestoreJournal::begin(active.path(), &paths).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn child_process_kill_cleans_stale_temp_and_resumes_idempotently() {
        const CHILD_ENV: &str = "CARAPACE_RESTORE_KILL_CHILD";
        const ROOT_ENV: &str = "CARAPACE_RESTORE_KILL_ROOT";
        const BARRIER_ENV: &str = "CARAPACE_RESTORE_KILL_BARRIER";

        if std::env::var_os(CHILD_ENV).is_some() {
            let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
            let barrier = PathBuf::from(std::env::var_os(BARRIER_ENV).unwrap());
            let paths = vec![PathBuf::from("output")];
            let _journal = RestoreJournal::begin(&root, &paths).unwrap();
            let _ =
                write_atomic_unix_with_hook(&root, &paths[0], b"new-complete", 0o600, 0, |stage| {
                    if stage == CommitStage::TemporarySynced {
                        std::fs::write(&barrier, b"ready")?;
                        loop {
                            std::thread::park();
                        }
                    }
                    Ok(())
                });
            unreachable!("the parent must kill the child at the barrier");
        }

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("restore");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("output"), b"old-complete").unwrap();
        let barrier = temp.path().join("barrier");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::child_process_kill_cleans_stale_temp_and_resumes_idempotently",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .env(ROOT_ENV, &root)
            .env(BARRIER_ENV, &barrier)
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if barrier.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(barrier.exists(), "child did not reach the commit barrier");
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        assert_eq!(std::fs::read(root.join("output")).unwrap(), b"old-complete");
        assert!(directory_has_restore_temp(&root));

        let paths = vec![PathBuf::from("output")];
        let mut journal = RestoreJournal::begin(&root, &paths).unwrap();
        assert!(!directory_has_restore_temp(&root));
        write_atomic(&root, &paths[0], b"new-complete", 0o600, 0).unwrap();
        journal.mark_complete(0).unwrap();
        journal.finish().unwrap();
        assert_eq!(std::fs::read(root.join("output")).unwrap(), b"new-complete");
    }

    #[cfg(unix)]
    fn directory_has_restore_temp(root: &Path) -> bool {
        std::fs::read_dir(root).unwrap().any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().to_str().map(is_restore_temporary_name))
                .unwrap_or(false)
        })
    }

    #[cfg(windows)]
    #[test]
    fn atomic_replacement_preserves_then_replaces_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = Path::new("result.txt");
        write_atomic(temp.path(), path, b"first", 0, 0).unwrap();
        let destination = temp.path().join(path);
        let mut permissions = std::fs::metadata(&destination).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&destination, permissions).unwrap();
        write_atomic(temp.path(), path, b"second", 0, 0).unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}
