//! Durable runtime-state persistence. `state.redb` is the on-disk source of truth;
//! every mutation funnels the whole `Shared` + `DocStore` back in one redb txn via
//! [`persist_all`]. State is KB-MB, so re-persisting all of it per mutation is cheap;
//! `persist_all` destructures `Shared` with no `..` glob, so a new field fails to
//! compile until categorized (SEAL / PLAIN / EPH / DERIVE). Secret categories are
//! AEAD-sealed under `HKDF(K_root,"carapace/v1/state-seal")` before touching redb.

use anyhow::{anyhow, bail, ensure, Context, Result};
use redb::{Database, ReadableDatabase, TableDefinition};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use super::{
    signer_qualifies, AlarmRecord, CeremonyTerminal, CeremonyTombstone, EndpointAddr, EndpointId,
    GrantedTrustee, OpenResplit, OwnerGrants, PendingResplit, Placement, RecoveryScope,
    RecoverySet, ResplitPeer, Shared, TrackedCeremony, VaultBlobs, MAX_CEREMONY_TOMBSTONES,
    MAX_RECOVERY_OPENS_PER_WINDOW, MAX_RECOVERY_RATE_KEYS,
};
use carapace_crypto::state_seal;
use carapace_disclose::DisclosureTable;
use carapace_friend::Resplit;
use carapace_net::DocStore;
use carapace_recovery::{share_from_json, share_to_json, CeremonyState};
use carapace_replica::AuditTracker;
use carapace_share::{AttestTracker, Share, ShareMonitor};
use carapace_wire::messages::Message;
use carapace_wire::{
    AnnounceRef, CeremonyAbort, ContactCard, Friendship, ShareGrant, VaultAnnounce,
};

/// The single redb table: category name -> serialized (SEAL categories additionally
/// state-sealed) blob. One row per category.
const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("state");

/// Current redb schema version. This is independent of the sealed-row AAD format version.
const CURRENT_SCHEMA_VERSION: u32 = 2;
const MIN_SCHEMA_VERSION: u32 = 1;

/// Upgrade class for the currently supported state schemas.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MigrationPolicy {
    Current,
    /// Only the four-byte schema marker changes after every category validates.
    AdditiveMarker,
}

#[cfg(test)]
fn migration_policy(stored: Option<u32>) -> MigrationPolicy {
    match stored {
        Some(CURRENT_SCHEMA_VERSION) => MigrationPolicy::Current,
        None | Some(MIN_SCHEMA_VERSION) => MigrationPolicy::AdditiveMarker,
        Some(_) => unreachable!("read_schema_version rejects unsupported versions"),
    }
}

// Length-prefixed binary codec: variable-width `bytes` fields carry a big-endian u32
// length prefix; the reader bounds-checks every read.

pub(crate) struct W {
    buf: Vec<u8>,
}

impl W {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub(crate) fn u8(&mut self, x: u8) {
        self.buf.push(x);
    }
    pub(crate) fn u32(&mut self, x: u32) {
        self.buf.extend_from_slice(&x.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, x: u64) {
        self.buf.extend_from_slice(&x.to_be_bytes());
    }
    pub(crate) fn len(&mut self, x: usize) {
        self.u32(u32::try_from(x).expect("persist count fits u32"));
    }
    /// Raw fixed-width bytes, no length prefix (reader must know the width).
    pub(crate) fn fixed(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.buf.extend_from_slice(b);
    }
    pub(crate) fn bool(&mut self, b: bool) {
        self.u8(b as u8);
    }
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// A bounds-checked decoder: malformed/truncated input is a loud error, never a panic.
pub(crate) struct R<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> R<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    /// Safe pre-alloc size for `n` upcoming elements, capped by unconsumed bytes: every
    /// element eats >=1 byte, so this clamps a hostile length prefix to real input size
    /// instead of a multi-GB eager `with_capacity` OOM before the loop errors.
    fn cap(&self, n: usize) -> usize {
        n.min(self.b.len().saturating_sub(self.pos))
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).context("persist length overflow")?;
        let s = self
            .b
            .get(self.pos..end)
            .context("persist blob truncated")?;
        self.pos = end;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    pub(crate) fn len(&mut self) -> Result<usize> {
        Ok(self.u32()? as usize)
    }
    pub(crate) fn arr16(&mut self) -> Result<[u8; 16]> {
        Ok(self.take(16)?.try_into().expect("16 bytes"))
    }
    pub(crate) fn arr32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
    pub(crate) fn arr64(&mut self) -> Result<[u8; 64]> {
        Ok(self.take(64)?.try_into().expect("64 bytes"))
    }
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.len()?;
        self.take(n)
    }
    pub(crate) fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }
    /// True once every byte has been consumed (trailing-garbage guard).
    pub(crate) fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

/// Open (creating if absent) `state.redb` at `path`, restricting it to `0600` on unix.
pub(crate) fn open_db(path: &Path) -> Result<Database> {
    #[cfg(unix)]
    let db = {
        use rustix::fs::{openat, Mode, OFlags, CWD};

        let descriptor = openat(
            CWD,
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)
        .with_context(|| format!("open private state db {path:?}"))?;
        Database::builder()
            .create_file(std::fs::File::from(descriptor))
            .with_context(|| format!("open state db {path:?}"))?
    };
    #[cfg(not(unix))]
    let db = Database::create(path).with_context(|| format!("open state db {path:?}"))?;
    restrict_perms(path)?;
    Ok(db)
}

/// Open an existing state database without creating it or changing its permissions.
pub(crate) fn open_existing_db(path: &Path) -> Result<Database> {
    ensure!(path.is_file(), "state database {path:?} does not exist");
    #[cfg(unix)]
    {
        use rustix::fs::{openat, Mode, OFlags, CWD};
        let descriptor = openat(
            CWD,
            path,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .with_context(|| format!("open existing private state db {path:?}"))?;
        Database::builder()
            .create_file(std::fs::File::from(descriptor))
            .with_context(|| format!("open existing state db {path:?}"))
    }
    #[cfg(not(unix))]
    Database::open(path).with_context(|| format!("open existing state db {path:?}"))
}

/// Whether `state.redb` already exists (startup tripwire: blobs/keys present but no
/// state.redb => a wiped/mismatched state dir, fail loudly rather than start fresh).
pub(crate) fn db_exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(unix)]
fn restrict_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {path:?}"))
}

#[cfg(not(unix))]
fn restrict_perms(_path: &Path) -> Result<()> {
    Ok(())
}

/// Read one category blob from a read transaction; `None` if the row is absent.
pub(crate) fn read_row(db: &Database, key: &str) -> Result<Option<Vec<u8>>> {
    let txn = db.begin_read().context("begin read txn")?;
    let table = match txn.open_table(STATE) {
        Ok(t) => t,
        // A brand-new db has no table yet: treat as empty.
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e).context("open state table (read)"),
    };
    Ok(table
        .get(key)
        .context("read row")?
        .map(|v| v.value().to_vec()))
}

// Category row keys: one redb row per category.
mod cat {
    // PLAIN (signed/public/metadata; no secret).
    pub const CARDS: &str = "cards";
    pub const ANNOUNCES: &str = "announces";
    pub const GRANTS: &str = "grants";
    pub const EPOCHS: &str = "epochs";
    pub const FRIENDSHIPS: &str = "friendships";
    pub const FRIENDS: &str = "friends";
    pub const FRIEND_GRANTS: &str = "friend_grants";
    pub const WORKING_DIRS: &str = "working_dirs";
    pub const OWNED_CHUNKS: &str = "owned_chunks";
    pub const MEMBERS: &str = "members";
    pub const REPLICA_TARGET: &str = "replica_target";
    pub const HELD: &str = "held";
    pub const REPLICA_CHUNKS: &str = "replica_chunks";
    pub const REPLICA_OWNER: &str = "replica_owner";
    pub const REPLICA_MEMBERS: &str = "replica_members";
    pub const REPLICA_ANNOUNCE: &str = "replica_announce";
    pub const REPLICA_DENY: &str = "replica_deny";
    pub const HELD_SHARE_SUBJECTS: &str = "held_share_subjects";
    pub const DISCLOSURE: &str = "disclosure";
    pub const POR: &str = "por";
    pub const CEREMONIES: &str = "ceremonies";
    pub const CEREMONY_ALARMS: &str = "ceremony_alarms";
    pub const ABORTED_CEREMONIES: &str = "aborted_ceremonies";
    pub const CEREMONY_SUBJECT_RATE: &str = "ceremony_subject_rate";
    pub const CEREMONY_SPONSOR_RATE: &str = "ceremony_sponsor_rate";
    pub const CEREMONY_TOMBSTONES: &str = "ceremony_tombstones";
    pub const CEREMONY_RELEASED: &str = "ceremony_released";
    pub const PENDING_RESPLITS: &str = "pending_resplits";
    pub const PENDING_DELETE_SENDS: &str = "pending_delete_sends";
    pub const UNFRIENDED_NODES: &str = "unfriended_nodes";
    pub const VAULT_BLOBS: &str = "vault_blobs"; // DERIVE: only {vid -> digest, chunk_ids}
    pub const DOC_CARDS: &str = "doc_cards";
    pub const DOC_ANNOUNCES: &str = "doc_announces";
    pub const CARD_VERSION: &str = "card_version"; // F3 monotonic own-card version floor
    pub const SCHEMA_VERSION: &str = "schema_version";

    // SEAL (AEAD-sealed under HKDF(K_root,"carapace/v1/state-seal") before touching redb).
    pub const HELD_SHARES: &str = "held_shares";
    pub const HELD_GRANTS: &str = "held_grants";
    pub const GRANTED: &str = "granted";
    pub const SPLIT_STATES: &str = "split_states";
    pub const RESPLITS: &str = "resplits";
    pub const IDENTITY: &str = "identity";
}

/// Every row a schema-2 database must contain, even when its logical collection is empty.
const REQUIRED_SCHEMA2_CATEGORIES: &[&str] = &[
    cat::CARDS,
    cat::ANNOUNCES,
    cat::GRANTS,
    cat::EPOCHS,
    cat::FRIENDSHIPS,
    cat::FRIENDS,
    cat::FRIEND_GRANTS,
    cat::WORKING_DIRS,
    cat::OWNED_CHUNKS,
    cat::MEMBERS,
    cat::REPLICA_TARGET,
    cat::HELD,
    cat::REPLICA_CHUNKS,
    cat::REPLICA_OWNER,
    cat::REPLICA_MEMBERS,
    cat::REPLICA_ANNOUNCE,
    cat::REPLICA_DENY,
    cat::HELD_SHARE_SUBJECTS,
    cat::DISCLOSURE,
    cat::POR,
    cat::CEREMONIES,
    cat::CEREMONY_ALARMS,
    cat::ABORTED_CEREMONIES,
    cat::CEREMONY_SUBJECT_RATE,
    cat::CEREMONY_SPONSOR_RATE,
    cat::CEREMONY_TOMBSTONES,
    cat::CEREMONY_RELEASED,
    cat::PENDING_RESPLITS,
    cat::PENDING_DELETE_SENDS,
    cat::UNFRIENDED_NODES,
    cat::VAULT_BLOBS,
    cat::DOC_CARDS,
    cat::DOC_ANNOUNCES,
    cat::CARD_VERSION,
    cat::HELD_SHARES,
    cat::HELD_GRANTS,
    cat::GRANTED,
    cat::SPLIT_STATES,
    cat::RESPLITS,
    cat::IDENTITY,
];

/// The `state_seal` aad `table` component for every SEAL row (per-row `key` is the
/// category name): binds a sealed blob to its slot so a cross-category move fails to open.
const SEAL_TABLE: &[u8] = b"state";

// Leaf encoders/decoders shared across categories.

fn enc_set32(w: &mut W, set: &HashSet<[u8; 32]>) {
    w.len(set.len());
    for x in set {
        w.fixed(x);
    }
}
fn dec_set32(r: &mut R) -> Result<HashSet<[u8; 32]>> {
    let n = r.len()?;
    let mut set = HashSet::with_capacity(r.cap(n));
    for _ in 0..n {
        set.insert(r.arr32()?);
    }
    Ok(set)
}

fn enc_map32_32(w: &mut W, m: &HashMap<[u8; 32], [u8; 32]>) {
    w.len(m.len());
    for (k, v) in m {
        w.fixed(k);
        w.fixed(v);
    }
}
fn dec_map32_32(r: &mut R) -> Result<HashMap<[u8; 32], [u8; 32]>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        m.insert(r.arr32()?, r.arr32()?);
    }
    Ok(m)
}

fn enc_map32_u64(w: &mut W, m: &HashMap<[u8; 32], u64>) {
    w.len(m.len());
    for (k, v) in m {
        w.fixed(k);
        w.u64(*v);
    }
}
fn dec_map32_u64(r: &mut R) -> Result<HashMap<[u8; 32], u64>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        m.insert(r.arr32()?, r.u64()?);
    }
    Ok(m)
}

fn enc_map32_veclist(w: &mut W, m: &HashMap<[u8; 32], Vec<[u8; 32]>>) {
    w.len(m.len());
    for (k, v) in m {
        w.fixed(k);
        w.len(v.len());
        for x in v {
            w.fixed(x);
        }
    }
}
fn dec_map32_veclist(r: &mut R) -> Result<HashMap<[u8; 32], Vec<[u8; 32]>>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let k = r.arr32()?;
        let cnt = r.len()?;
        let mut v = Vec::with_capacity(r.cap(cnt));
        for _ in 0..cnt {
            v.push(r.arr32()?);
        }
        m.insert(k, v);
    }
    Ok(m)
}

fn enc_frame_list<M: Message>(w: &mut W, items: impl Iterator<Item = M>) {
    let v: Vec<M> = items.collect();
    w.len(v.len());
    for it in &v {
        w.bytes(&it.encode_frame());
    }
}
fn dec_frame_list<M: Message>(r: &mut R) -> Result<Vec<M>> {
    let n = r.len()?;
    let mut out = Vec::with_capacity(r.cap(n));
    for _ in 0..n {
        out.push(M::decode_frame(r.bytes()?).map_err(|e| anyhow!("decode framed row: {e}"))?);
    }
    Ok(out)
}

fn enc_map32_frame<M: Message>(w: &mut W, m: &HashMap<[u8; 32], M>) {
    w.len(m.len());
    for (k, v) in m {
        w.fixed(k);
        w.bytes(&v.encode_frame());
    }
}
fn dec_map32_frame<M: Message>(r: &mut R) -> Result<HashMap<[u8; 32], M>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let k = r.arr32()?;
        m.insert(
            k,
            M::decode_frame(r.bytes()?).map_err(|e| anyhow!("decode framed map row: {e}"))?,
        );
    }
    Ok(m)
}

fn enc_opt_str(w: &mut W, s: &Option<String>) {
    match s {
        Some(v) => {
            w.u8(1);
            w.bytes(v.as_bytes());
        }
        None => w.u8(0),
    }
}
fn dec_opt_str(r: &mut R) -> Result<Option<String>> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(dec_str(r)?)),
        t => bail!("bad option tag {t}"),
    }
}
fn dec_str(r: &mut R) -> Result<String> {
    String::from_utf8(r.bytes()?.to_vec()).context("persisted string not utf-8")
}

fn enc_ref(w: &mut W, a: &AnnounceRef) {
    w.fixed(&a.vid);
    w.u64(a.epoch);
    w.fixed(&a.digest);
}
fn dec_ref(r: &mut R) -> Result<AnnounceRef> {
    Ok(AnnounceRef {
        vid: r.arr32()?,
        epoch: r.u64()?,
        digest: r.arr32()?,
    })
}
fn enc_refs(w: &mut W, refs: &[AnnounceRef]) {
    w.len(refs.len());
    for a in refs {
        enc_ref(w, a);
    }
}
fn dec_refs(r: &mut R) -> Result<Vec<AnnounceRef>> {
    let n = r.len()?;
    let mut v = Vec::with_capacity(r.cap(n));
    for _ in 0..n {
        v.push(dec_ref(r)?);
    }
    Ok(v)
}

fn enc_scope(w: &mut W, s: &RecoveryScope) {
    match s {
        RecoveryScope::Root => w.u8(0),
        RecoveryScope::Vault(v) => {
            w.u8(1);
            w.fixed(v);
        }
    }
}
fn dec_scope(r: &mut R) -> Result<RecoveryScope> {
    match r.u8()? {
        0 => Ok(RecoveryScope::Root),
        1 => Ok(RecoveryScope::Vault(r.arr32()?)),
        t => bail!("bad recovery scope tag {t}"),
    }
}

/// One owner-held trustee record (embeds a secret `Share`; only written in a SEAL row).
fn enc_granted_trustee(w: &mut W, t: &GrantedTrustee) {
    w.fixed(&t.user);
    w.fixed(&t.node);
    enc_opt_str(w, &t.relay_url);
    w.bytes(share_to_json(&t.share).as_bytes());
    w.bool(t.delivered);
}
fn dec_granted_trustee(r: &mut R) -> Result<GrantedTrustee> {
    let user = r.arr32()?;
    let node = r.arr32()?;
    let relay_url = dec_opt_str(r)?;
    let share = share_from_json(&dec_str(r)?).map_err(|e| anyhow!("decode trustee share: {e}"))?;
    let delivered = r.bool()?;
    Ok(GrantedTrustee {
        user,
        node,
        relay_url,
        share,
        delivered,
    })
}

/// One re-split peer: node + an optional grant to deliver (a NEW-set member).
fn enc_resplit_peer(w: &mut W, p: &ResplitPeer) {
    w.fixed(&p.node);
    match &p.grant {
        Some(g) => {
            w.u8(1);
            w.bytes(&g.encode_frame());
        }
        None => w.u8(0),
    }
}
fn dec_resplit_peer(r: &mut R) -> Result<ResplitPeer> {
    let node = r.arr32()?;
    let grant = match r.u8()? {
        0 => None,
        1 => Some(ShareGrant::decode_frame(r.bytes()?).map_err(|e| anyhow!("decode grant: {e}"))?),
        t => bail!("bad resplit-peer grant tag {t}"),
    };
    Ok(ResplitPeer { node, grant })
}

// The funnel: persist the whole Shared + DocStore in one txn.

/// Persist every durable category of `Shared` + `docs` into `txn`, sealing secret
/// categories under `k_root` first. Caller commits `txn` BEFORE any externally visible
/// effect and crashes on commit failure. `Shared` is destructured with no `..` glob, so
/// every field is persisted or explicitly discarded and a new field fails to compile.
pub(crate) fn persist_all(
    txn: &redb::WriteTransaction,
    s: &Shared,
    docs: &DocStore,
    k_root: &[u8; 32],
    identity: &StateIdentity,
) -> Result<()> {
    let Shared {
        // --- SEAL ---
        held_shares,
        held_grants,
        granted,
        split_states,
        resplits,
        // --- PLAIN ---
        cards,
        announces,
        grants,
        epochs,
        friendships,
        friends,
        friend_grants,
        working_dirs,
        owned_chunks,
        members,
        replica_target,
        held,
        replica_chunks,
        replica_owner,
        replica_members,
        replica_announce,
        replica_deny,
        held_share_subjects,
        disclosure,
        por,
        ceremonies,
        ceremony_alarms,
        aborted_ceremonies,
        ceremony_subject_rate,
        ceremony_sponsor_rate,
        ceremony_tombstones,
        ceremony_released,
        pending_resplits,
        pending_delete_sends,
        unfriended_nodes,
        // --- DERIVE ---
        vault_blobs,
        needs_refetch,
        // --- PLAIN-rebuild: reconstructed from `granted` at load ---
        share_sets,
        // --- EPH: rebuilt on reconnect / never persisted ---
        tickets,
        peer_addrs,
        peer_last_seen,
        rate,
        relay_health,
        vault_keys,
        blob_auth,
        root_split_pending,
        test_now,
    } = s;

    // EPH: caches, rate limiter, per-session auth, test clock, invite tickets, and vault
    // chunk keys (NEVER persist: a write-through is a key dump).
    let _ = (
        tickets,
        peer_addrs,
        peer_last_seen,
        rate,
        relay_health,
        vault_keys,
        blob_auth,
        root_split_pending,
        test_now,
    );
    // PLAIN-rebuild: `share_sets` reconstructed from `granted` at load.
    let _ = share_sets;

    let mut t = txn.open_table(STATE).context("open state table (write)")?;

    put(
        &mut t,
        cat::SCHEMA_VERSION,
        CURRENT_SCHEMA_VERSION.to_be_bytes().to_vec(),
    )?;

    // ---- PLAIN document lists ----
    put_frame_list(&mut t, cat::CARDS, cards.iter().cloned())?;
    put_frame_list(&mut t, cat::ANNOUNCES, announces.iter().cloned())?;
    put_frame_list(&mut t, cat::GRANTS, grants.iter().cloned())?;

    // ---- PLAIN maps ----
    put(&mut t, cat::EPOCHS, enc(|w| enc_map32_u64(w, epochs)))?;
    put(&mut t, cat::FRIENDSHIPS, enc_friendships(friendships))?;
    put(&mut t, cat::FRIENDS, enc(|w| enc_map32_frame(w, friends)))?;
    put(
        &mut t,
        cat::FRIEND_GRANTS,
        enc(|w| enc_map32_u64(w, friend_grants)),
    )?;
    put(&mut t, cat::WORKING_DIRS, enc_working_dirs(working_dirs))?;
    put(
        &mut t,
        cat::OWNED_CHUNKS,
        enc(|w| enc_map32_32(w, owned_chunks)),
    )?;
    put(&mut t, cat::MEMBERS, enc(|w| enc_map32_veclist(w, members)))?;
    put(
        &mut t,
        cat::REPLICA_TARGET,
        enc_replica_target(replica_target),
    )?;
    put(&mut t, cat::HELD, enc(|w| enc_set32(w, held)))?;
    put(
        &mut t,
        cat::REPLICA_CHUNKS,
        enc(|w| enc_map32_32(w, replica_chunks)),
    )?;
    put(
        &mut t,
        cat::REPLICA_OWNER,
        enc(|w| enc_map32_32(w, replica_owner)),
    )?;
    put(
        &mut t,
        cat::REPLICA_MEMBERS,
        enc(|w| enc_map32_veclist(w, replica_members)),
    )?;
    put(
        &mut t,
        cat::REPLICA_ANNOUNCE,
        enc(|w| enc_map32_frame(w, replica_announce)),
    )?;
    put(
        &mut t,
        cat::REPLICA_DENY,
        enc(|w| enc_set32(w, replica_deny)),
    )?;
    put(
        &mut t,
        cat::HELD_SHARE_SUBJECTS,
        enc_held_share_subjects(held_share_subjects),
    )?;
    put(&mut t, cat::DISCLOSURE, disclosure.to_bytes())?;
    put(&mut t, cat::POR, por.to_bytes())?;
    put(&mut t, cat::CEREMONIES, enc_ceremonies(ceremonies))?;
    // C1: bound the durable alarm map to qualifying sponsors (unauthenticated dialers
    // write these, so a stranger's alarm stays RAM-only).
    put(
        &mut t,
        cat::CEREMONY_ALARMS,
        enc_alarms(ceremony_alarms, held_grants, friends, docs),
    )?;
    // C1: bound the durable abort map to qualifying signers.
    put(
        &mut t,
        cat::ABORTED_CEREMONIES,
        enc_aborted(aborted_ceremonies, held_grants, friends, docs),
    )?;
    put(
        &mut t,
        cat::CEREMONY_SUBJECT_RATE,
        enc_rate_history(ceremony_subject_rate),
    )?;
    put(
        &mut t,
        cat::CEREMONY_SPONSOR_RATE,
        enc_rate_history(ceremony_sponsor_rate),
    )?;
    put(
        &mut t,
        cat::CEREMONY_TOMBSTONES,
        enc_ceremony_tombstones(ceremony_tombstones),
    )?;
    put(
        &mut t,
        cat::CEREMONY_RELEASED,
        enc(|w| {
            w.len(ceremony_released.len());
            for (id, new_node) in ceremony_released {
                w.fixed(id);
                w.fixed(new_node);
            }
        }),
    )?;
    put(
        &mut t,
        cat::PENDING_RESPLITS,
        enc_pending_resplits(pending_resplits),
    )?;
    put(
        &mut t,
        cat::PENDING_DELETE_SENDS,
        enc_pending_delete_sends(pending_delete_sends),
    )?;
    put(
        &mut t,
        cat::UNFRIENDED_NODES,
        enc(|w| enc_set32(w, unfriended_nodes)),
    )?;

    // DERIVE: vault_blobs -> only {vid -> digest, chunk_ids} (never the manifest),
    // unioned with needs-refetch sources so a failed re-derive never erases a vault's
    // blob-source record. `vault_blobs` wins on a vid in both.
    put(
        &mut t,
        cat::VAULT_BLOBS,
        enc_vault_blobs(vault_blobs, needs_refetch),
    )?;

    // F3: monotonic own-card version floor = max own card.version.
    let card_version = cards.iter().map(|c| c.version).max().unwrap_or(0);
    put(
        &mut t,
        cat::CARD_VERSION,
        card_version.to_be_bytes().to_vec(),
    )?;

    // DocStore rollback high-water marks.
    put_frame_list(&mut t, cat::DOC_CARDS, docs.cards().cloned())?;
    put_frame_list(&mut t, cat::DOC_ANNOUNCES, docs.announces().cloned())?;

    // SEAL rows (sealed before touching redb).
    put_sealed(
        &mut t,
        cat::HELD_SHARES,
        k_root,
        enc_held_shares(held_shares),
    )?;
    put_sealed(
        &mut t,
        cat::HELD_GRANTS,
        k_root,
        enc(|w| enc_map32_frame(w, held_grants)),
    )?;
    put_sealed(&mut t, cat::GRANTED, k_root, enc_granted(granted))?;
    put_sealed(
        &mut t,
        cat::SPLIT_STATES,
        k_root,
        enc_split_states(split_states),
    )?;
    put_sealed(&mut t, cat::RESPLITS, k_root, enc_resplits(resplits))?;
    put_sealed(
        &mut t,
        cat::IDENTITY,
        k_root,
        enc(|w| {
            w.fixed(&identity.user);
            w.fixed(&identity.node);
        }),
    )?;

    Ok(())
}

/// Persist the whole state in one txn and commit, fail-loud: a commit failure CRASHES
/// rather than continuing with RAM ahead of disk. Caller holds the `shared` (and, on the
/// `_with` path, `docs`) lock across this call and calls it before any visible effect.
pub(crate) fn commit_all(
    db: &Database,
    s: &Shared,
    docs: &DocStore,
    k_root: &[u8; 32],
    identity: &StateIdentity,
) {
    if try_commit_all(db, s, docs, k_root, identity).is_err() {
        // abort(), not panic: a panic here fires under the caller's `shared` write lock,
        // poisoning it and wedging the daemon half-alive; abort takes the process down clean.
        super::ops::log("persistence.commit_failed", None);
        std::process::abort();
    }
}

pub(crate) fn try_commit_all(
    db: &Database,
    s: &Shared,
    docs: &DocStore,
    k_root: &[u8; 32],
    identity: &StateIdentity,
) -> Result<()> {
    let txn = db.begin_write().context("begin redb write txn")?;
    persist_all(&txn, s, docs, k_root, identity)?;
    txn.commit().context("commit redb state txn")?;
    Ok(())
}

/// Run `f` against a fresh writer and return the bytes.
fn enc(f: impl FnOnce(&mut W)) -> Vec<u8> {
    let mut w = W::new();
    f(&mut w);
    w.into_vec()
}

type StateTable<'a> = redb::Table<'a, &'static str, &'static [u8]>;

fn put(t: &mut StateTable<'_>, key: &str, bytes: Vec<u8>) -> Result<()> {
    t.insert(key, bytes.as_slice())
        .with_context(|| format!("persist row {key}"))?;
    Ok(())
}

fn put_frame_list<M: Message>(
    t: &mut StateTable<'_>,
    key: &str,
    items: impl Iterator<Item = M>,
) -> Result<()> {
    put(t, key, enc(|w| enc_frame_list(w, items)))
}

fn enc_friendship(w: &mut W, f: &Friendship) {
    w.fixed(&f.a);
    w.fixed(&f.b);
    w.u64(f.established);
    w.fixed(&f.sig_a);
    w.fixed(&f.sig_b);
}
fn dec_friendship(r: &mut R) -> Result<Friendship> {
    Ok(Friendship {
        a: r.arr32()?,
        b: r.arr32()?,
        established: r.u64()?,
        sig_a: r.arr64()?,
        sig_b: r.arr64()?,
    })
}
fn enc_friendships(m: &HashMap<[u8; 32], Friendship>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (k, v) in m {
            w.fixed(k);
            enc_friendship(w, v);
        }
    })
}

/// Seal `plaintext` under `k_root` bound to `(SEAL_TABLE, key)`, then store it.
fn put_sealed(
    t: &mut StateTable<'_>,
    key: &str,
    k_root: &[u8; 32],
    plaintext: Vec<u8>,
) -> Result<()> {
    // Secret-equivalent plaintext: wrap so it is wiped after sealing, not left in freed heap.
    let plaintext = Zeroizing::new(plaintext);
    let sealed = state_seal::seal(k_root, SEAL_TABLE, key.as_bytes(), &plaintext)
        .map_err(|e| anyhow!("seal {key}: {e}"))?;
    put(t, key, sealed)
}

// ---- category encoders that need more than a leaf helper ----

fn enc_working_dirs(m: &HashMap<[u8; 32], PathBuf>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (k, v) in m {
            w.fixed(k);
            w.bytes(v.to_string_lossy().as_bytes());
        }
    })
}

fn enc_replica_target(m: &HashMap<[u8; 32], usize>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (k, v) in m {
            w.fixed(k);
            w.u64(*v as u64);
        }
    })
}

fn enc_held_share_subjects(m: &HashMap<u64, [u8; 32]>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (k, v) in m {
            w.u64(*k);
            w.fixed(v);
        }
    })
}

fn enc_ceremonies(m: &HashMap<[u8; 16], TrackedCeremony>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (id, c) in m {
            w.fixed(id);
            w.bytes(&c.state.to_bytes());
            w.bool(c.approved);
            w.bool(c.takeover);
        }
    })
}

/// Persist only alarms whose sponsor (the `RecoveryOpen` signer) qualifies: a stranger's
/// alarm stays RAM-only so an unauthenticated open cannot append to disk unbounded. The
/// subject is deliberately not a qualifier (it is public: an attacker would set it to us).
fn enc_alarms(
    m: &HashMap<[u8; 16], AlarmRecord>,
    held_grants: &HashMap<[u8; 32], ShareGrant>,
    friends: &HashMap<[u8; 32], ContactCard>,
    docs: &DocStore,
) -> Vec<u8> {
    enc(|w| {
        let rows: Vec<(&[u8; 16], &AlarmRecord)> = m
            .iter()
            .filter(|(_, a)| signer_qualifies(&a.sponsor, held_grants, friends, docs))
            .collect();
        w.len(rows.len());
        for (id, a) in rows {
            w.fixed(id);
            w.fixed(&a.subject);
            w.fixed(&a.sponsor);
            w.bytes(a.claimant_display.as_bytes());
            w.bytes(a.reason.as_bytes());
            w.bool(a.is_self_subject);
            w.bool(a.aborted);
            w.bool(a.takeover);
        }
    })
}

/// Persist only aborts whose signer qualifies; a stranger's abort stays RAM-only.
fn enc_aborted(
    m: &HashMap<[u8; 16], Vec<CeremonyAbort>>,
    held_grants: &HashMap<[u8; 32], ShareGrant>,
    friends: &HashMap<[u8; 32], ContactCard>,
    docs: &DocStore,
) -> Vec<u8> {
    let qualifies =
        |signer: &[u8; 32]| -> bool { signer_qualifies(signer, held_grants, friends, docs) };
    enc(|w| {
        // First collect rows that have at least one qualifying abort so the count matches.
        let rows: Vec<(&[u8; 16], Vec<&CeremonyAbort>)> = m
            .iter()
            .filter_map(|(id, aborts)| {
                let keep: Vec<&CeremonyAbort> =
                    aborts.iter().filter(|a| qualifies(&a.by)).collect();
                if keep.is_empty() {
                    None
                } else {
                    Some((id, keep))
                }
            })
            .collect();
        w.len(rows.len());
        for (id, keep) in rows {
            w.fixed(id);
            w.len(keep.len());
            for a in keep {
                w.bytes(&a.encode_frame());
            }
        }
    })
}

fn enc_rate_history(history: &HashMap<[u8; 32], Vec<u64>>) -> Vec<u8> {
    enc(|w| {
        w.len(history.len());
        for (key, events) in history {
            w.fixed(key);
            w.len(events.len());
            for event in events {
                w.u64(*event);
            }
        }
    })
}

fn enc_ceremony_tombstones(tombstones: &HashMap<[u8; 16], CeremonyTombstone>) -> Vec<u8> {
    enc(|w| {
        w.len(tombstones.len());
        for (id, tombstone) in tombstones {
            w.fixed(id);
            w.fixed(&tombstone.subject);
            w.fixed(&tombstone.sponsor);
            w.u64(tombstone.terminal_at);
            w.u8(match tombstone.terminal {
                CeremonyTerminal::Completed => 1,
                CeremonyTerminal::Aborted => 2,
                CeremonyTerminal::Expired => 3,
                CeremonyTerminal::Rejected => 4,
                CeremonyTerminal::Failed => 5,
            });
        }
    })
}

fn enc_pending_resplits(m: &HashMap<u64, PendingResplit>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (rsid, p) in m {
            w.u64(*rsid);
            w.fixed(&p.ex_trustee);
            w.len(p.suggested.len());
            for u in &p.suggested {
                w.fixed(u);
            }
        }
    })
}

fn enc_pending_delete_sends(v: &[(Vec<EndpointAddr>, Placement)]) -> Vec<u8> {
    enc(|w| {
        w.len(v.len());
        for (addrs, placement) in v {
            // Node ids only; direct addresses are hints, rebuilt via relay on reconnect.
            w.len(addrs.len());
            for a in addrs {
                w.fixed(a.id.as_bytes());
            }
            w.len(placement.replica_vids.len());
            for vid in &placement.replica_vids {
                w.fixed(vid);
            }
            w.bool(placement.held_shares);
        }
    })
}

fn enc_vault_blobs(
    m: &HashMap<[u8; 32], VaultBlobs>,
    needs_refetch: &HashMap<[u8; 32], BlobSource>,
) -> Vec<u8> {
    // Retained-but-underivable sources ride in the same row; a vid in `m` supersedes them.
    let extra: Vec<_> = needs_refetch
        .iter()
        .filter(|(vid, _)| !m.contains_key(*vid))
        .collect();
    enc(|w| {
        w.len(m.len() + extra.len());
        for (vid, vb) in m {
            w.fixed(vid);
            w.fixed(&vb.digest);
            w.len(vb.chunk_ids.len());
            for c in &vb.chunk_ids {
                w.fixed(c);
            }
        }
        for &(vid, (digest, chunk_ids)) in &extra {
            w.fixed(vid);
            w.fixed(digest);
            w.len(chunk_ids.len());
            for c in chunk_ids {
                w.fixed(c);
            }
        }
    })
}

fn enc_held_shares(m: &HashMap<u64, (Share, ShareMonitor)>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (rsid, (share, _monitor)) in m {
            // ShareMonitor is EPH (rebuilt on load).
            w.u64(*rsid);
            w.bytes(share_to_json(share).as_bytes());
        }
    })
}

fn enc_granted(m: &HashMap<u64, OwnerGrants>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (rsid, og) in m {
            w.u64(*rsid);
            w.fixed(&og.subject);
            w.u64(og.recovery_delay);
            w.len(og.trustees.len());
            for t in &og.trustees {
                enc_granted_trustee(w, t);
            }
            enc_refs(w, &og.refs);
        }
    })
}

fn enc_split_states(m: &HashMap<u64, RecoverySet>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (rsid, rs) in m {
            w.u64(*rsid);
            enc_scope(w, &rs.scope);
            w.bytes(&rs.state.to_bytes());
        }
    })
}

fn enc_resplits(m: &HashMap<u64, OpenResplit>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (old_rsid_key, o) in m {
            w.u64(*old_rsid_key);
            w.bytes(&o.rs.to_bytes());
            w.fixed(&o.ex_trustee);
            w.fixed(&o.subject);
            w.u64(o.old_rsid);
            w.u64(o.new_rsid);
            w.len(o.new_peers.len());
            for p in &o.new_peers {
                enc_resplit_peer(w, p);
            }
            w.len(o.old_peers.len());
            for p in &o.old_peers {
                enc_resplit_peer(w, p);
            }
            enc_set32(w, &o.delivered);
            w.len(o.new_records.len());
            for t in &o.new_records {
                enc_granted_trustee(w, t);
            }
            w.len(o.roster.len());
            for (k, v) in &o.roster {
                w.fixed(k);
                w.u64(*v);
            }
            w.u8(o.m);
            w.u64(o.recovery_delay);
            enc_refs(w, &o.refs);
            enc_scope(w, &o.scope);
            match &o.new_state {
                Some(st) => {
                    w.u8(1);
                    w.bytes(&st.to_bytes());
                }
                None => w.u8(0),
            }
            w.bool(o.registered);
        }
    })
}

// Startup load.

/// A DERIVE vault-blob source row: `(vid, manifest digest, chunk ids)`. The decrypted
/// `Manifest` is re-derived from the FsStore envelope at startup (never persisted).
pub(crate) type VaultBlobSource = ([u8; 32], [u8; 32], Vec<[u8; 32]>);

/// A vault's retained blob source keyed by vid (`Shared::needs_refetch`):
/// `(manifest-envelope digest, unique ChunkIDs)`.
pub(crate) type BlobSource = ([u8; 32], Vec<[u8; 32]>);

/// Everything reloaded from `state.redb` at startup.
pub(crate) struct Loaded {
    /// `Shared` with every persisted category filled and EPH fields defaulted.
    /// `vault_blobs` is EMPTY: its manifests are re-derived async from `vault_blob_sources`.
    pub shared: Shared,
    pub docs: DocStore,
    /// DERIVE `{vid -> (digest, chunk_ids)}` to re-derive `vault_blobs` manifests from
    /// FsStore at startup. The decoded `Manifest` is never persisted in clear.
    pub vault_blob_sources: Vec<VaultBlobSource>,
    /// F3: persisted monotonic own-card version floor. The fresh own card is minted at
    /// `max(unix_now(), card_version + 1)` so its version strictly increases across restart.
    pub card_version: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StateIdentity {
    pub user: [u8; 32],
    pub node: [u8; 32],
}

/// Load and decode all persisted state. SEAL rows are opened under `k_root`; a sealed
/// row that fails to open ABORTS startup (fail loud, never skip-and-continue — that
/// silently loses a share).
pub(crate) fn load_all(
    db: &Database,
    k_root: &[u8; 32],
    expected_identity: &StateIdentity,
) -> Result<Loaded> {
    load_all_inner(db, k_root, expected_identity, false)
}

/// Validate and decode all state without stamping a legacy schema row.
pub(crate) fn load_all_read_only(
    db: &Database,
    k_root: &[u8; 32],
    expected_identity: &StateIdentity,
) -> Result<Loaded> {
    load_all_inner(db, k_root, expected_identity, true)
}

/// Validate legacy state and atomically rewrite it as a complete identity-bound schema 2.
pub(crate) fn migrate_legacy(
    db: &Database,
    k_root: &[u8; 32],
    expected_identity: &StateIdentity,
) -> Result<()> {
    let stored = read_schema_version(db)?;
    ensure!(
        stored != Some(CURRENT_SCHEMA_VERSION),
        "state database is already schema {CURRENT_SCHEMA_VERSION}"
    );
    let mut loaded = load_all_inner(db, k_root, expected_identity, true)?;
    for (vid, digest, chunk_ids) in &loaded.vault_blob_sources {
        loaded
            .shared
            .needs_refetch
            .entry(*vid)
            .or_insert_with(|| (*digest, chunk_ids.clone()));
    }
    let txn = db
        .begin_write()
        .context("begin explicit legacy migration")?;
    persist_all(
        &txn,
        &loaded.shared,
        &loaded.docs,
        k_root,
        expected_identity,
    )?;
    txn.commit().context("commit explicit legacy migration")?;
    load_all_inner(db, k_root, expected_identity, false)?;
    Ok(())
}

fn load_all_inner(
    db: &Database,
    k_root: &[u8; 32],
    expected_identity: &StateIdentity,
    allow_legacy: bool,
) -> Result<Loaded> {
    let stored_schema = read_schema_version(db)?;
    let has_state = database_has_known_state(db)?;
    match stored_schema {
        Some(CURRENT_SCHEMA_VERSION) => validate_required_schema2_categories(db)?,
        Some(version) if !allow_legacy => bail!(
            "state schema {version} requires explicit confirmed legacy migration before startup"
        ),
        None if has_state && !allow_legacy => {
            bail!("unversioned state requires explicit confirmed legacy migration before startup")
        }
        None if !has_state => {
            return Ok(Loaded {
                shared: Shared::default(),
                docs: DocStore::new(),
                vault_blob_sources: Vec::new(),
                card_version: 0,
            })
        }
        _ => {}
    }
    let mut s = Shared::default();

    // ---- PLAIN document lists ----
    if let Some(b) = read_row(db, cat::CARDS)? {
        s.cards = dec_frame_list(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::ANNOUNCES)? {
        s.announces = dec_frame_list(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::GRANTS)? {
        s.grants = dec_frame_list(&mut R::new(&b))?;
    }

    // ---- PLAIN maps ----
    if let Some(b) = read_row(db, cat::EPOCHS)? {
        s.epochs = dec_map32_u64(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::FRIENDSHIPS)? {
        s.friendships = dec_friendships(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::FRIENDS)? {
        s.friends = dec_map32_frame(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::FRIEND_GRANTS)? {
        s.friend_grants = dec_map32_u64(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::WORKING_DIRS)? {
        s.working_dirs = dec_working_dirs(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::OWNED_CHUNKS)? {
        s.owned_chunks = dec_map32_32(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::MEMBERS)? {
        s.members = dec_map32_veclist(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::REPLICA_TARGET)? {
        s.replica_target = dec_replica_target(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::HELD)? {
        s.held = dec_set32(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::REPLICA_CHUNKS)? {
        s.replica_chunks = dec_map32_32(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::REPLICA_OWNER)? {
        s.replica_owner = dec_map32_32(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::REPLICA_MEMBERS)? {
        s.replica_members = dec_map32_veclist(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::REPLICA_ANNOUNCE)? {
        s.replica_announce = dec_map32_frame(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::REPLICA_DENY)? {
        s.replica_deny = dec_set32(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::HELD_SHARE_SUBJECTS)? {
        s.held_share_subjects = dec_held_share_subjects(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::DISCLOSURE)? {
        s.disclosure =
            DisclosureTable::from_bytes(&b).map_err(|e| anyhow!("decode disclosure: {e}"))?;
    }
    if let Some(b) = read_row(db, cat::POR)? {
        s.por = AuditTracker::from_bytes(&b).map_err(|e| anyhow!("decode por: {e}"))?;
    }
    if let Some(b) = read_row(db, cat::CEREMONIES)? {
        s.ceremonies = dec_ceremonies(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::CEREMONY_ALARMS)? {
        s.ceremony_alarms = dec_alarms(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::ABORTED_CEREMONIES)? {
        s.aborted_ceremonies = dec_aborted(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::CEREMONY_SUBJECT_RATE)? {
        s.ceremony_subject_rate = dec_rate_history(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::CEREMONY_SPONSOR_RATE)? {
        s.ceremony_sponsor_rate = dec_rate_history(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::CEREMONY_TOMBSTONES)? {
        s.ceremony_tombstones = dec_ceremony_tombstones(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::CEREMONY_RELEASED)? {
        s.ceremony_released = dec_released_ceremonies(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::PENDING_RESPLITS)? {
        s.pending_resplits = dec_pending_resplits(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::PENDING_DELETE_SENDS)? {
        s.pending_delete_sends = dec_pending_delete_sends(&mut R::new(&b))?;
    }
    if let Some(b) = read_row(db, cat::UNFRIENDED_NODES)? {
        s.unfriended_nodes = dec_set32(&mut R::new(&b))?;
    }

    // ---- SEAL rows (fail loud on open failure) ----
    if let Some(b) = read_sealed(db, cat::HELD_SHARES, k_root)? {
        s.held_shares = dec_held_shares(&mut R::new(&b))?;
    }
    if let Some(b) = read_sealed(db, cat::HELD_GRANTS, k_root)? {
        s.held_grants = dec_map32_frame(&mut R::new(&b))?;
    }
    if let Some(b) = read_sealed(db, cat::GRANTED, k_root)? {
        s.granted = dec_granted(&mut R::new(&b))?;
    }
    if let Some(b) = read_sealed(db, cat::SPLIT_STATES, k_root)? {
        s.split_states = dec_split_states(&mut R::new(&b))?;
    }
    if let Some(b) = read_sealed(db, cat::RESPLITS, k_root)? {
        s.resplits = dec_resplits(&mut R::new(&b))?;
    }
    if let Some(b) = read_sealed(db, cat::IDENTITY, k_root)? {
        let mut reader = R::new(&b);
        let stored = StateIdentity {
            user: reader.arr32()?,
            node: reader.arr32()?,
        };
        ensure!(reader.done(), "state identity row has trailing bytes");
        ensure!(
            stored == *expected_identity,
            "state database belongs to a different user or node identity"
        );
    }

    // ---- PLAIN-rebuild: share_sets from granted ----
    s.share_sets = rebuild_share_sets(&s.granted);

    // ---- DERIVE: vault_blob sources (manifests re-derived by the caller) ----
    let vault_blob_sources = match read_row(db, cat::VAULT_BLOBS)? {
        Some(b) => dec_vault_blob_sources(&mut R::new(&b))?,
        None => Vec::new(),
    };

    let card_version = match read_row(db, cat::CARD_VERSION)? {
        Some(b) => u64::from_be_bytes(
            b.as_slice()
                .try_into()
                .map_err(|_| anyhow!("card_version row is not 8 bytes"))?,
        ),
        None => 0,
    };

    // ---- DocStore high-water marks ----
    let mut docs = DocStore::new();
    if let Some(b) = read_row(db, cat::DOC_CARDS)? {
        for c in dec_frame_list::<ContactCard>(&mut R::new(&b))? {
            docs.offer_card(&c)
                .map_err(|e| anyhow!("reload doc card: {e}"))?;
        }
    }
    if let Some(b) = read_row(db, cat::DOC_ANNOUNCES)? {
        for a in dec_frame_list::<VaultAnnounce>(&mut R::new(&b))? {
            docs.offer_announce(&a)
                .map_err(|e| anyhow!("reload doc announce: {e}"))?;
        }
    }

    let loaded = Loaded {
        shared: s,
        docs,
        vault_blob_sources,
        card_version,
    };

    // The supported migration is additive: after every row opens, atomically replace only
    // the four-byte schema marker. It does not transform or re-seal a category. Therefore a
    // staged database, capacity-sized copy, and migration backup cannot protect more data
    // than redb's transaction already protects. A failed commit leaves the old marker and
    // every old row intact, so startup retries the same validation. Any future policy that
    // transforms rows must use a staged, verified backup and explicit free-space preflight.
    Ok(loaded)
}

fn database_has_known_state(db: &Database) -> Result<bool> {
    if read_row(db, cat::SCHEMA_VERSION)?.is_some() {
        return Ok(true);
    }
    for key in REQUIRED_SCHEMA2_CATEGORIES {
        if read_row(db, key)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_required_schema2_categories(db: &Database) -> Result<()> {
    for key in REQUIRED_SCHEMA2_CATEGORIES {
        ensure!(
            read_row(db, key)?.is_some(),
            "schema {CURRENT_SCHEMA_VERSION} state is missing required category {key:?}; restore a complete backup"
        );
    }
    Ok(())
}

fn read_schema_version(db: &Database) -> Result<Option<u32>> {
    let Some(bytes) = read_row(db, cat::SCHEMA_VERSION)? else {
        return Ok(None);
    };
    let version = u32::from_be_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("state schema version row is not 4 bytes"))?,
    );
    ensure!(
        (MIN_SCHEMA_VERSION..=CURRENT_SCHEMA_VERSION).contains(&version),
        "unsupported state schema version {version}; supported range is {MIN_SCHEMA_VERSION}..={CURRENT_SCHEMA_VERSION}"
    );
    Ok(Some(version))
}

#[cfg(test)]
fn stamp_schema_version_with_interruption(db: &Database, commit: bool) -> Result<()> {
    let txn = db
        .begin_write()
        .context("begin interrupted schema transaction")?;
    {
        let mut table = txn.open_table(STATE)?;
        put(
            &mut table,
            cat::SCHEMA_VERSION,
            CURRENT_SCHEMA_VERSION.to_be_bytes().to_vec(),
        )?;
    }
    if commit {
        txn.commit()?;
    }
    Ok(())
}

/// Open a SEAL row under `k_root`. Absent -> `None`; present-but-unopenable -> loud
/// error (never skip a share that will not decrypt).
fn read_sealed(db: &Database, key: &str, k_root: &[u8; 32]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match read_row(db, key)? {
        None => Ok(None),
        Some(sealed) => {
            // Keep the `Zeroizing` buffer open produced (no `to_vec()`): the decoder
            // borrows it and it is wiped when the caller's binding drops.
            let opened =
                state_seal::open(k_root, SEAL_TABLE, key.as_bytes(), &sealed).map_err(|e| {
                    anyhow!(
                    "FAIL LOUD: sealed state row {key} would not open ({e}); refusing to start \
                     rather than silently lose secret state"
                )
                })?;
            Ok(Some(opened))
        }
    }
}

fn rebuild_share_sets(granted: &HashMap<u64, OwnerGrants>) -> HashMap<u64, AttestTracker> {
    granted
        .iter()
        .map(|(rsid, og)| {
            let m = og.trustees.first().map(|t| t.share.threshold).unwrap_or(1);
            let roster: HashMap<[u8; 32], u64> = og
                .trustees
                .iter()
                .map(|t| (t.node, u64::from(t.share.x)))
                .collect();
            (*rsid, AttestTracker::new(m, og.trustees.len(), roster))
        })
        .collect()
}

// ---- category decoders mirroring the encoders ----

fn dec_friendships(r: &mut R) -> Result<HashMap<[u8; 32], Friendship>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let k = r.arr32()?;
        m.insert(k, dec_friendship(r)?);
    }
    Ok(m)
}

fn dec_working_dirs(r: &mut R) -> Result<HashMap<[u8; 32], PathBuf>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let k = r.arr32()?;
        m.insert(k, PathBuf::from(dec_str(r)?));
    }
    Ok(m)
}

fn dec_replica_target(r: &mut R) -> Result<HashMap<[u8; 32], usize>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let k = r.arr32()?;
        m.insert(k, r.u64()? as usize);
    }
    Ok(m)
}

fn dec_held_share_subjects(r: &mut R) -> Result<HashMap<u64, [u8; 32]>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let k = r.u64()?;
        m.insert(k, r.arr32()?);
    }
    Ok(m)
}

fn dec_ceremonies(r: &mut R) -> Result<HashMap<[u8; 16], TrackedCeremony>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let id = r.arr16()?;
        let state =
            CeremonyState::from_bytes(r.bytes()?).map_err(|e| anyhow!("decode ceremony: {e}"))?;
        let approved = r.bool()?;
        let takeover = r.bool()?;
        m.insert(
            id,
            TrackedCeremony {
                state,
                approved,
                takeover,
            },
        );
    }
    Ok(m)
}

fn dec_alarms(r: &mut R) -> Result<HashMap<[u8; 16], AlarmRecord>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let id = r.arr16()?;
        let subject = r.arr32()?;
        let sponsor = r.arr32()?;
        let claimant_display = dec_str(r)?;
        let reason = dec_str(r)?;
        let is_self_subject = r.bool()?;
        let aborted = r.bool()?;
        let takeover = r.bool()?;
        m.insert(
            id,
            AlarmRecord {
                subject,
                sponsor,
                claimant_display,
                reason,
                is_self_subject,
                aborted,
                takeover,
            },
        );
    }
    Ok(m)
}

fn dec_aborted(r: &mut R) -> Result<HashMap<[u8; 16], Vec<CeremonyAbort>>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let id = r.arr16()?;
        let cnt = r.len()?;
        let mut v = Vec::with_capacity(r.cap(cnt));
        for _ in 0..cnt {
            v.push(
                CeremonyAbort::decode_frame(r.bytes()?)
                    .map_err(|e| anyhow!("decode abort: {e}"))?,
            );
        }
        m.insert(id, v);
    }
    Ok(m)
}

fn dec_rate_history(r: &mut R) -> Result<HashMap<[u8; 32], Vec<u64>>> {
    let n = r.len()?;
    ensure!(
        n <= MAX_RECOVERY_RATE_KEYS,
        "recovery rate history exceeds bound"
    );
    let mut history = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let key = r.arr32()?;
        let count = r.len()?;
        ensure!(
            count <= MAX_RECOVERY_OPENS_PER_WINDOW,
            "recovery rate events exceed bound"
        );
        let mut events = Vec::with_capacity(r.cap(count));
        for _ in 0..count {
            events.push(r.u64()?);
        }
        history.insert(key, events);
    }
    Ok(history)
}

fn dec_ceremony_tombstones(r: &mut R) -> Result<HashMap<[u8; 16], CeremonyTombstone>> {
    let n = r.len()?;
    ensure!(
        n <= MAX_CEREMONY_TOMBSTONES,
        "ceremony tombstones exceed bound"
    );
    let mut tombstones = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let id = r.arr16()?;
        let subject = r.arr32()?;
        let sponsor = r.arr32()?;
        let terminal_at = r.u64()?;
        let terminal = match r.u8()? {
            1 => CeremonyTerminal::Completed,
            2 => CeremonyTerminal::Aborted,
            3 => CeremonyTerminal::Expired,
            4 => CeremonyTerminal::Rejected,
            5 => CeremonyTerminal::Failed,
            value => return Err(anyhow!("invalid ceremony terminal value {value}")),
        };
        tombstones.insert(
            id,
            CeremonyTombstone {
                subject,
                sponsor,
                terminal_at,
                terminal,
            },
        );
    }
    Ok(tombstones)
}

fn dec_released_ceremonies(r: &mut R) -> Result<HashMap<[u8; 16], [u8; 32]>> {
    let count = r.len()?;
    ensure!(
        count <= super::MAX_CEREMONY_RECORDS,
        "released ceremonies exceed bound"
    );
    let old_len = count
        .checked_mul(16)
        .context("released ceremony length overflow")?;
    let new_len = count
        .checked_mul(48)
        .context("released ceremony length overflow")?;
    ensure!(
        r.remaining() == old_len || r.remaining() == new_len,
        "released ceremony row has an invalid length"
    );
    let has_node_binding = r.remaining() == new_len;
    let mut released = HashMap::with_capacity(r.cap(count));
    for _ in 0..count {
        let id = r.arr16()?;
        let new_node = if has_node_binding {
            r.arr32()?
        } else {
            [0; 32]
        };
        released.insert(id, new_node);
    }
    Ok(released)
}

fn dec_pending_resplits(r: &mut R) -> Result<HashMap<u64, PendingResplit>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let rsid = r.u64()?;
        let ex_trustee = r.arr32()?;
        let cnt = r.len()?;
        let mut suggested = Vec::with_capacity(r.cap(cnt));
        for _ in 0..cnt {
            suggested.push(r.arr32()?);
        }
        m.insert(
            rsid,
            PendingResplit {
                ex_trustee,
                suggested,
            },
        );
    }
    Ok(m)
}

fn dec_pending_delete_sends(r: &mut R) -> Result<Vec<(Vec<EndpointAddr>, Placement)>> {
    let n = r.len()?;
    let mut out = Vec::with_capacity(r.cap(n));
    for _ in 0..n {
        let acount = r.len()?;
        let mut addrs = Vec::with_capacity(r.cap(acount));
        for _ in 0..acount {
            let node = r.arr32()?;
            if let Ok(id) = EndpointId::from_bytes(&node) {
                addrs.push(EndpointAddr::new(id));
            }
        }
        let vcount = r.len()?;
        let mut replica_vids = Vec::with_capacity(r.cap(vcount));
        for _ in 0..vcount {
            replica_vids.push(r.arr32()?);
        }
        let held_shares = r.bool()?;
        out.push((
            addrs,
            Placement {
                replica_vids,
                held_shares,
            },
        ));
    }
    Ok(out)
}

fn dec_vault_blob_sources(r: &mut R) -> Result<Vec<VaultBlobSource>> {
    let n = r.len()?;
    let mut out = Vec::with_capacity(r.cap(n));
    for _ in 0..n {
        let vid = r.arr32()?;
        let digest = r.arr32()?;
        let cnt = r.len()?;
        let mut chunk_ids = Vec::with_capacity(r.cap(cnt));
        for _ in 0..cnt {
            chunk_ids.push(r.arr32()?);
        }
        out.push((vid, digest, chunk_ids));
    }
    Ok(out)
}

fn dec_held_shares(r: &mut R) -> Result<HashMap<u64, (Share, ShareMonitor)>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let rsid = r.u64()?;
        let share = share_from_json(&dec_str(r)?).map_err(|e| anyhow!("decode held share: {e}"))?;
        // ShareMonitor is EPH: fresh default monitor.
        m.insert(rsid, (share, ShareMonitor::new()));
    }
    Ok(m)
}

fn dec_granted(r: &mut R) -> Result<HashMap<u64, OwnerGrants>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let rsid = r.u64()?;
        let subject = r.arr32()?;
        let recovery_delay = r.u64()?;
        let tcount = r.len()?;
        let mut trustees = Vec::with_capacity(r.cap(tcount));
        for _ in 0..tcount {
            trustees.push(dec_granted_trustee(r)?);
        }
        let refs = dec_refs(r)?;
        m.insert(
            rsid,
            OwnerGrants {
                subject,
                recovery_delay,
                trustees,
                refs,
            },
        );
    }
    Ok(m)
}

fn dec_split_states(r: &mut R) -> Result<HashMap<u64, RecoverySet>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let rsid = r.u64()?;
        let scope = dec_scope(r)?;
        let state = carapace_recovery::SplitState::from_bytes(r.bytes()?)
            .map_err(|e| anyhow!("decode split state: {e}"))?;
        m.insert(rsid, RecoverySet { scope, state });
    }
    Ok(m)
}

fn dec_resplits(r: &mut R) -> Result<HashMap<u64, OpenResplit>> {
    let n = r.len()?;
    let mut m = HashMap::with_capacity(r.cap(n));
    for _ in 0..n {
        let key = r.u64()?;
        let rs = Resplit::from_bytes(r.bytes()?).map_err(|e| anyhow!("decode resplit: {e}"))?;
        let ex_trustee = r.arr32()?;
        let subject = r.arr32()?;
        let old_rsid = r.u64()?;
        let new_rsid = r.u64()?;
        let npc = r.len()?;
        let mut new_peers = Vec::with_capacity(r.cap(npc));
        for _ in 0..npc {
            new_peers.push(dec_resplit_peer(r)?);
        }
        let opc = r.len()?;
        let mut old_peers = Vec::with_capacity(r.cap(opc));
        for _ in 0..opc {
            old_peers.push(dec_resplit_peer(r)?);
        }
        let delivered = dec_set32(r)?;
        let nrc = r.len()?;
        let mut new_records = Vec::with_capacity(r.cap(nrc));
        for _ in 0..nrc {
            new_records.push(dec_granted_trustee(r)?);
        }
        let rc = r.len()?;
        let mut roster = HashMap::with_capacity(r.cap(rc));
        for _ in 0..rc {
            let k = r.arr32()?;
            roster.insert(k, r.u64()?);
        }
        let m_thresh = r.u8()?;
        let recovery_delay = r.u64()?;
        let refs = dec_refs(r)?;
        let scope = dec_scope(r)?;
        let new_state = match r.u8()? {
            0 => None,
            1 => Some(
                carapace_recovery::SplitState::from_bytes(r.bytes()?)
                    .map_err(|e| anyhow!("decode resplit new_state: {e}"))?,
            ),
            t => bail!("bad resplit new_state tag {t}"),
        };
        let registered = r.bool()?;
        m.insert(
            key,
            OpenResplit {
                rs,
                ex_trustee,
                subject,
                old_rsid,
                new_rsid,
                new_peers,
                old_peers,
                delivered,
                new_records,
                roster,
                m: m_thresh,
                recovery_delay,
                refs,
                scope,
                new_state,
                registered,
            },
        );
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn state_database_is_private_from_creation_and_refuses_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.redb");
        let database = open_db(&path).unwrap();
        drop(database);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let target = directory.path().join("target.redb");
        std::fs::write(&target, b"not a database").unwrap();
        let linked = directory.path().join("linked.redb");
        symlink(&target, &linked).unwrap();
        assert!(open_db(&linked).is_err());
        assert!(open_existing_db(&linked).is_err());
    }

    #[test]
    fn codec_roundtrips_mixed_fields() {
        let mut w = W::new();
        w.u8(7);
        w.u32(0xDEAD_BEEF);
        w.u64(0x0102_0304_0506_0708);
        w.bool(true);
        w.bool(false);
        w.fixed(&[0xAB; 32]);
        w.bytes(b"hello");
        w.bytes(b"");
        w.len(3);
        let bytes = w.into_vec();

        let mut r = R::new(&bytes);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(r.bool().unwrap());
        assert!(!r.bool().unwrap());
        assert_eq!(r.arr32().unwrap(), [0xAB; 32]);
        assert_eq!(r.bytes().unwrap(), b"hello");
        assert_eq!(r.bytes().unwrap(), b"");
        assert_eq!(r.len().unwrap(), 3);
        assert!(r.done());
    }

    #[test]
    fn reader_rejects_truncation_without_panic() {
        let mut r = R::new(&[0u8; 3]);
        assert!(r.u32().is_err()); // wants 4 bytes, only 3 present
        let mut r2 = R::new(&[0u8; 4]);
        assert!(r2.u32().is_ok());
        assert!(r2.u8().is_err()); // exhausted
    }

    #[test]
    fn reader_truncated_bytes_is_error() {
        // A length prefix claiming more than remains must error, not panic.
        let mut w = W::new();
        w.len(100);
        w.fixed(b"short");
        let bytes = w.into_vec();
        let mut r = R::new(&bytes);
        assert!(r.bytes().is_err());
    }

    // Full funnel roundtrip across PLAIN + SEAL + DERIVE categories, plus fail-loud on a
    // wrong K_root.
    #[test]
    fn persist_load_roundtrips_all_categories() {
        use carapace_wire::Signed;
        use ed25519_dalek::SigningKey;

        let node = SigningKey::from_bytes(&[7u8; 32]);
        let user = SigningKey::from_bytes(&[9u8; 32]);
        let node_pub = node.verifying_key().to_bytes();
        let user_pub = user.verifying_key().to_bytes();
        let k_root = [3u8; 32];
        let identity = StateIdentity {
            user: user_pub,
            node: node_pub,
        };

        let (shares, state, _) = carapace_recovery::split_root(&k_root, 2, Some(3), false).unwrap();

        let mut own_card = crate::build_card(&user, &node, &k_root, None);
        own_card.version = 12_345;
        own_card.sign(&user);

        let mut friend_card = crate::build_card(&user, &node, &k_root, None);
        friend_card.version = 42;
        friend_card.sign(&user);

        let mut s = Shared::default();
        s.cards.push(own_card.clone());
        s.friends.insert(user_pub, friend_card.clone());
        s.epochs.insert([1u8; 32], 9);
        s.owned_chunks.insert([2u8; 32], [1u8; 32]);
        s.members.insert([1u8; 32], vec![node_pub]);
        s.held.insert([5u8; 32]);
        s.replica_target.insert([1u8; 32], 3);
        s.friend_grants.insert(user_pub, 1024);
        s.held_share_subjects.insert(1, user_pub);
        s.unfriended_nodes.insert([6u8; 32]);
        s.ceremony_subject_rate.insert(user_pub, vec![100, 200]);
        s.ceremony_sponsor_rate.insert(node_pub, vec![200]);
        s.ceremony_tombstones.insert(
            [0x51; 16],
            CeremonyTombstone {
                subject: user_pub,
                sponsor: node_pub,
                terminal_at: 300,
                terminal: CeremonyTerminal::Aborted,
            },
        );
        s.ceremony_released.insert([0x52; 16], [0x53; 32]);
        let open = carapace_recovery::open_recovery(
            &user,
            [0x53; 16],
            user_pub,
            1,
            "fixture claimant".into(),
            [0x54; 32],
            node_pub,
            "fixture recovery".into(),
            400,
        );
        s.ceremonies.insert(
            open.ceremony_id,
            TrackedCeremony {
                state: CeremonyState::open(&open, vec![user_pub], 1, 72 * 3600, 400).unwrap(),
                approved: false,
                takeover: false,
            },
        );
        s.working_dirs
            .insert([1u8; 32], PathBuf::from("/tmp/vault"));
        s.pending_delete_sends.push((
            vec![EndpointAddr::new(
                EndpointId::from_bytes(&node_pub).unwrap(),
            )],
            Placement {
                replica_vids: vec![[4u8; 32]],
                held_shares: true,
            },
        ));
        s.vault_blobs.insert(
            [1u8; 32],
            VaultBlobs {
                digest: [8u8; 32],
                chunk_ids: vec![[2u8; 32], [3u8; 32]],
                manifest: carapace_wire::Manifest {
                    vid: [1u8; 32],
                    epoch: 9,
                    authors: vec![],
                    files: vec![],
                    vv: vec![],
                },
            },
        );

        // SEAL categories.
        s.held_shares
            .insert(1, (shares[0].clone(), ShareMonitor::new()));
        s.split_states.insert(
            1,
            RecoverySet {
                scope: RecoveryScope::Root,
                state,
            },
        );
        s.granted.insert(
            5,
            OwnerGrants {
                subject: user_pub,
                recovery_delay: 72 * 3600,
                trustees: vec![GrantedTrustee {
                    user: user_pub,
                    node: node_pub,
                    relay_url: Some("https://relay.example".into()),
                    share: shares[1].clone(),
                    delivered: true,
                }],
                refs: vec![AnnounceRef {
                    vid: [1u8; 32],
                    epoch: 9,
                    digest: [8u8; 32],
                }],
            },
        );

        let mut docs = DocStore::new();
        docs.offer_card(&own_card).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let db = open_db(&path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            persist_all(&txn, &s, &docs, &k_root, &identity).unwrap();
            txn.commit().unwrap();
        }

        // 0600 on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let loaded = load_all(&db, &k_root, &identity).unwrap();

        assert_eq!(loaded.card_version, 12_345);
        assert_eq!(loaded.shared.cards.len(), 1);
        assert_eq!(loaded.shared.cards[0].version, 12_345);
        assert_eq!(loaded.shared.friends.get(&user_pub).unwrap().version, 42);
        assert_eq!(loaded.shared.epochs.get(&[1u8; 32]), Some(&9));
        assert_eq!(loaded.shared.owned_chunks.get(&[2u8; 32]), Some(&[1u8; 32]));
        assert_eq!(
            loaded.shared.members.get(&[1u8; 32]).unwrap(),
            &vec![node_pub]
        );
        assert!(loaded.shared.held.contains(&[5u8; 32]));
        assert_eq!(loaded.shared.replica_target.get(&[1u8; 32]), Some(&3));
        assert_eq!(loaded.shared.friend_grants.get(&user_pub), Some(&1024));
        assert_eq!(loaded.shared.held_share_subjects.get(&1), Some(&user_pub));
        assert!(loaded.shared.unfriended_nodes.contains(&[6u8; 32]));
        assert_eq!(
            loaded.shared.ceremony_subject_rate[&user_pub],
            vec![100, 200]
        );
        assert_eq!(loaded.shared.ceremony_sponsor_rate[&node_pub], vec![200]);
        let tombstone = loaded.shared.ceremony_tombstones[&[0x51; 16]];
        assert_eq!(tombstone.terminal, CeremonyTerminal::Aborted);
        assert_eq!(tombstone.terminal_at, 300);
        assert_eq!(
            loaded.shared.ceremony_released.get(&[0x52; 16]),
            Some(&[0x53; 32])
        );
        assert_eq!(
            loaded.shared.working_dirs.get(&[1u8; 32]).unwrap(),
            &PathBuf::from("/tmp/vault")
        );
        // pending_delete_sends: node id + placement survive (addrs are hints).
        let (addrs, placement) = &loaded.shared.pending_delete_sends[0];
        assert_eq!(addrs[0].id.as_bytes(), &node_pub);
        assert_eq!(placement.replica_vids, vec![[4u8; 32]]);
        assert!(placement.held_shares);
        // DERIVE sources.
        assert_eq!(loaded.vault_blob_sources.len(), 1);
        assert_eq!(loaded.vault_blob_sources[0].0, [1u8; 32]);
        assert_eq!(loaded.vault_blob_sources[0].1, [8u8; 32]);
        assert_eq!(loaded.vault_blob_sources[0].2, vec![[2u8; 32], [3u8; 32]]);
        // SEAL: shares + split-state survive byte-for-byte.
        let (held, _) = loaded.shared.held_shares.get(&1).unwrap();
        assert_eq!(share_to_json(held), share_to_json(&shares[0]));
        assert_eq!(
            &loaded.shared.split_states.get(&1).unwrap().state.to_bytes()[..],
            &s.split_states.get(&1).unwrap().state.to_bytes()[..]
        );
        let og = loaded.shared.granted.get(&5).unwrap();
        assert_eq!(
            share_to_json(&og.trustees[0].share),
            share_to_json(&shares[1])
        );
        assert_eq!(
            og.trustees[0].relay_url.as_deref(),
            Some("https://relay.example")
        );
        // share_sets rebuilt from granted.
        assert!(loaded.shared.share_sets.contains_key(&5));
        // DocStore high-water mark.
        assert!(loaded.docs.card(&user_pub).is_some());

        assert_eq!(
            read_schema_version(&db).unwrap(),
            Some(CURRENT_SCHEMA_VERSION)
        );

        let fixture_output = std::env::var_os("CARAPACE_FIXTURE_OUTPUT_DIR").map(PathBuf::from);
        if let Some(output) = &fixture_output {
            std::fs::create_dir_all(output).unwrap();
            std::fs::copy(&path, output.join("rich-schema-2.redb")).unwrap();
            for name in [
                "active-ceremony-rates-tombstones.redb",
                "split-held-shares.redb",
                "replica-gc-state.redb",
            ] {
                std::fs::copy(&path, output.join(name)).unwrap();
            }
            let empty_path = output.join("empty-schema-2.redb");
            let empty_db = open_db(&empty_path).unwrap();
            let txn = empty_db.begin_write().unwrap();
            persist_all(
                &txn,
                &Shared::default(),
                &DocStore::new(),
                &k_root,
                &identity,
            )
            .unwrap();
            txn.commit().unwrap();
        }

        // Fail loud: a wrong K_root cannot open the sealed rows.
        assert!(load_all(&db, &[0u8; 32], &identity).is_err());

        // Schema 1 -> 2 is metadata-only. An interrupted read does not stamp or rewrite
        // anything, every sealed category remains byte-identical and readable, and a later
        // full-state commit performs the upgrade. Repeating from a downgraded schema-1 marker
        // is safe and reaches schema 2 again without changing the independent seal format.
        let sealed_categories = [
            cat::HELD_SHARES,
            cat::HELD_GRANTS,
            cat::GRANTED,
            cat::SPLIT_STATES,
            cat::RESPLITS,
            cat::IDENTITY,
        ];
        for attempt in 0..2 {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                put(&mut table, cat::SCHEMA_VERSION, 1u32.to_be_bytes().to_vec()).unwrap();
            }
            txn.commit().unwrap();
            let sealed_before: Vec<_> = sealed_categories
                .iter()
                .map(|key| read_row(&db, key).unwrap())
                .collect();
            let schema_one = load_all_read_only(&db, &k_root, &identity).unwrap();
            assert!(schema_one.shared.held_shares.contains_key(&1));
            assert!(schema_one.shared.split_states.contains_key(&1));
            assert!(schema_one.shared.granted.contains_key(&5));
            assert_eq!(read_schema_version(&db).unwrap(), Some(1));
            if attempt == 0 {
                if let Some(output) = &fixture_output {
                    std::fs::copy(&path, output.join("legacy-schema-1.redb")).unwrap();
                }
            }
            for (key, before) in sealed_categories.iter().zip(&sealed_before) {
                assert_eq!(
                    &read_row(&db, key).unwrap(),
                    before,
                    "attempt {attempt}: {key}"
                );
            }

            let txn = db.begin_write().unwrap();
            persist_all(
                &txn,
                &schema_one.shared,
                &schema_one.docs,
                &k_root,
                &identity,
            )
            .unwrap();
            txn.commit().unwrap();
            assert_eq!(read_schema_version(&db).unwrap(), Some(2));
            let upgraded = load_all(&db, &k_root, &identity).unwrap();
            assert!(upgraded.shared.held_shares.contains_key(&1));
            assert!(upgraded.shared.split_states.contains_key(&1));
            assert!(upgraded.shared.granted.contains_key(&5));
        }

        // Legacy migration is explicit. Inspection opens every old row without mutation;
        // normal startup refuses it; the migration transaction adds every schema-2 row and
        // the sealed identity without changing the seal AAD format.
        {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                table.remove(cat::SCHEMA_VERSION).unwrap();
                table.remove(cat::IDENTITY).unwrap();
            }
            txn.commit().unwrap();
        }
        assert_eq!(read_schema_version(&db).unwrap(), None);
        if let Some(output) = &fixture_output {
            std::fs::copy(&path, output.join("legacy-unversioned.redb")).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let mut corrupt = bytes.clone();
            let index = corrupt.len() / 2;
            corrupt[index] ^= 0x80;
            std::fs::write(output.join("corrupt.redb"), corrupt).unwrap();
            std::fs::write(output.join("truncated.redb"), &bytes[..bytes.len() / 2]).unwrap();
            return;
        }
        if let Ok(output) = std::env::var("CARAPACE_LEGACY_FIXTURE_OUTPUT") {
            std::fs::copy(&path, output).unwrap();
            return;
        }
        assert!(load_all(&db, &k_root, &identity).is_err());
        let legacy = load_all_read_only(&db, &k_root, &identity).unwrap();
        assert!(legacy.shared.held_shares.contains_key(&1));
        assert!(legacy.shared.split_states.contains_key(&1));
        assert_eq!(read_schema_version(&db).unwrap(), None);
        migrate_legacy(&db, &k_root, &identity).unwrap();
        assert_eq!(
            read_schema_version(&db).unwrap(),
            Some(CURRENT_SCHEMA_VERSION)
        );
        let wrong_node = StateIdentity {
            user: identity.user,
            node: [0xEE; 32],
        };
        let err = load_all(&db, &k_root, &wrong_node)
            .err()
            .expect("a database bound to another node must be refused");
        assert!(err.to_string().contains("different user or node identity"));

        // Unknown newer versions fail before any state is returned.
        {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                put(
                    &mut table,
                    cat::SCHEMA_VERSION,
                    (CURRENT_SCHEMA_VERSION + 1).to_be_bytes().to_vec(),
                )
                .unwrap();
            }
            txn.commit().unwrap();
        }
        let err = load_all(&db, &k_root, &identity)
            .err()
            .expect("a newer schema must be refused");
        assert!(err.to_string().contains("unsupported state schema version"));
    }

    #[test]
    fn malicious_lifecycle_rows_over_bounds_are_rejected_before_allocation() {
        let mut keys = W::new();
        keys.len(MAX_RECOVERY_RATE_KEYS + 1);
        assert!(dec_rate_history(&mut R::new(&keys.into_vec())).is_err());

        let mut events = W::new();
        events.len(1);
        events.fixed(&[0x11; 32]);
        events.len(MAX_RECOVERY_OPENS_PER_WINDOW + 1);
        assert!(dec_rate_history(&mut R::new(&events.into_vec())).is_err());

        let mut tombstones = W::new();
        tombstones.len(MAX_CEREMONY_TOMBSTONES + 1);
        assert!(dec_ceremony_tombstones(&mut R::new(&tombstones.into_vec())).is_err());

        let mut released = W::new();
        released.len(crate::MAX_CEREMONY_RECORDS + 1);
        assert!(dec_released_ceremonies(&mut R::new(&released.into_vec())).is_err());
    }

    #[test]
    fn malicious_tombstone_terminal_tag_is_rejected() {
        let mut bytes = W::new();
        bytes.len(1);
        bytes.fixed(&[0x21; 16]);
        bytes.fixed(&[0x22; 32]);
        bytes.fixed(&[0x23; 32]);
        bytes.u64(10);
        bytes.u8(0xFF);
        assert!(dec_ceremony_tombstones(&mut R::new(&bytes.into_vec())).is_err());
    }

    #[test]
    fn rejected_and_failed_tombstones_round_trip() {
        let tombstones = HashMap::from([
            (
                [0x31; 16],
                CeremonyTombstone {
                    subject: [0x32; 32],
                    sponsor: [0x33; 32],
                    terminal_at: 40,
                    terminal: CeremonyTerminal::Rejected,
                },
            ),
            (
                [0x41; 16],
                CeremonyTombstone {
                    subject: [0x42; 32],
                    sponsor: [0x43; 32],
                    terminal_at: 50,
                    terminal: CeremonyTerminal::Failed,
                },
            ),
        ]);
        let encoded = enc_ceremony_tombstones(&tombstones);
        let decoded = dec_ceremony_tombstones(&mut R::new(&encoded)).unwrap();
        assert_eq!(decoded[&[0x31; 16]].terminal, CeremonyTerminal::Rejected);
        assert_eq!(decoded[&[0x41; 16]].terminal, CeremonyTerminal::Failed);
    }

    #[test]
    fn malicious_persisted_lifecycle_rows_fail_startup() {
        let directory = tempfile::tempdir().unwrap();
        let db = open_db(&directory.path().join("state.redb")).unwrap();
        let k_root = [0x31; 32];
        let identity = StateIdentity {
            user: [0x32; 32],
            node: [0x33; 32],
        };
        let shared = Shared::default();
        let docs = DocStore::new();
        let txn = db.begin_write().unwrap();
        persist_all(&txn, &shared, &docs, &k_root, &identity).unwrap();
        txn.commit().unwrap();

        let mut too_many_keys = W::new();
        too_many_keys.len(MAX_RECOVERY_RATE_KEYS + 1);
        let mut too_many_events = W::new();
        too_many_events.len(1);
        too_many_events.fixed(&[0x41; 32]);
        too_many_events.len(MAX_RECOVERY_OPENS_PER_WINDOW + 1);
        let mut too_many_tombstones = W::new();
        too_many_tombstones.len(MAX_CEREMONY_TOMBSTONES + 1);
        let mut too_many_released = W::new();
        too_many_released.len(crate::MAX_CEREMONY_RECORDS + 1);

        for (key, payload) in [
            (cat::CEREMONY_SUBJECT_RATE, too_many_keys.into_vec()),
            (cat::CEREMONY_SPONSOR_RATE, too_many_events.into_vec()),
            (cat::CEREMONY_TOMBSTONES, too_many_tombstones.into_vec()),
            (cat::CEREMONY_RELEASED, too_many_released.into_vec()),
        ] {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                put(&mut table, key, payload).unwrap();
            }
            txn.commit().unwrap();
            assert!(
                load_all_read_only(&db, &k_root, &identity).is_err(),
                "malicious row {key} must stop startup"
            );

            let txn = db.begin_write().unwrap();
            persist_all(&txn, &shared, &docs, &k_root, &identity).unwrap();
            txn.commit().unwrap();
        }
    }

    #[test]
    fn additive_migration_interruption_retry_and_downgrade_are_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let db = open_db(&directory.path().join("state.redb")).unwrap();
        let k_root = [0x71; 32];
        let identity = StateIdentity {
            user: [0x72; 32],
            node: [0x73; 32],
        };
        let shared = Shared::default();
        let docs = DocStore::new();
        let txn = db.begin_write().unwrap();
        persist_all(&txn, &shared, &docs, &k_root, &identity).unwrap();
        txn.commit().unwrap();
        let sealed_identity = read_row(&db, cat::IDENTITY).unwrap().unwrap();

        let set_schema_one = || {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                put(&mut table, cat::SCHEMA_VERSION, 1u32.to_be_bytes().to_vec()).unwrap();
            }
            txn.commit().unwrap();
        };
        set_schema_one();
        assert_eq!(migration_policy(Some(1)), MigrationPolicy::AdditiveMarker);

        stamp_schema_version_with_interruption(&db, false).unwrap();
        assert_eq!(read_schema_version(&db).unwrap(), Some(1));
        assert_eq!(
            read_row(&db, cat::IDENTITY).unwrap().unwrap(),
            sealed_identity
        );

        stamp_schema_version_with_interruption(&db, true).unwrap();
        assert_eq!(read_schema_version(&db).unwrap(), Some(2));
        assert_eq!(
            read_row(&db, cat::IDENTITY).unwrap().unwrap(),
            sealed_identity
        );
        load_all_read_only(&db, &k_root, &identity).unwrap();

        set_schema_one();
        assert!(load_all(&db, &k_root, &identity).is_err());
        migrate_legacy(&db, &k_root, &identity).unwrap();
        assert_eq!(read_schema_version(&db).unwrap(), Some(2));
        load_all(&db, &k_root, &identity).unwrap();
    }

    #[test]
    fn schema_two_refuses_every_missing_required_category() {
        let directory = tempfile::tempdir().unwrap();
        let db = open_db(&directory.path().join("state.redb")).unwrap();
        let k_root = [0x81; 32];
        let identity = StateIdentity {
            user: [0x82; 32],
            node: [0x83; 32],
        };
        let txn = db.begin_write().unwrap();
        persist_all(
            &txn,
            &Shared::default(),
            &DocStore::new(),
            &k_root,
            &identity,
        )
        .unwrap();
        txn.commit().unwrap();

        for key in REQUIRED_SCHEMA2_CATEGORIES {
            let original = read_row(&db, key).unwrap().expect("required row");
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                table.remove(*key).unwrap();
            }
            txn.commit().unwrap();
            let error = load_all(&db, &k_root, &identity)
                .err()
                .expect("missing required row must fail");
            assert!(error.to_string().contains(key), "{key}: {error:#}");

            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                put(&mut table, key, original).unwrap();
            }
            txn.commit().unwrap();
        }
    }
}
