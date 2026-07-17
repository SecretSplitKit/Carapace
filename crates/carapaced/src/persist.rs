//! Durable runtime-state persistence (design §3.2-§3.5).
//!
//! `state.redb` is the source of truth on disk. In-RAM `Shared` stays the hot read
//! path; every mutation boundary funnels the WHOLE `Shared` + `DocStore` back to disk
//! in one redb transaction via [`persist_all`], then commits. The state is KB-MB, so
//! re-persisting all of it per mutation is cheap and CORRECT by construction: a field
//! cannot be silently forgotten because [`persist_all`] destructures `Shared` with no
//! `..` glob, and adding a `Shared` field fails to compile until it is categorized
//! (SEAL / PLAIN / EPH / DERIVE per design §3.3).
//!
//! ponytail: whole-state re-persist per mutation. Optimize to per-table incremental
//! writes only if profiling shows the funnel is hot (KB-MB state makes it a non-issue
//! for a personal-scale daemon).
//!
//! Secret categories (Shamir shares, Chela split polynomials, share grants) are AEAD
//! -sealed under `HKDF(K_root,"carapace/v1/state-seal")` (`carapace_crypto::state_seal`)
//! BEFORE the bytes touch redb. Everything else is signed/public metadata stored plain.

use anyhow::{anyhow, bail, Context, Result};
use redb::{Database, ReadableDatabase, TableDefinition};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// Types + serialization helpers reached through the crate root (child modules see the
// parent's private items and its `use` imports).
use super::{
    AlarmRecord, EndpointAddr, EndpointId, GrantedTrustee, OpenResplit, OwnerGrants,
    PendingResplit, Placement, RecoveryScope, RecoverySet, ResplitPeer, Shared, TrackedCeremony,
    VaultBlobs,
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

/// The single redb table: category name -> serialized (and, for SEAL categories,
/// state-sealed) blob. One row per persisted category; re-persist-all overwrites
/// every row each mutation.
const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("state");

// -------------------------------------------------------------------------
// Length-prefixed binary codec (fuzz-safe reader with explicit bounds checks).
// -------------------------------------------------------------------------

/// A little append-only encoder. Fixed-width fields are written raw; variable-width
/// fields (`bytes`) are length-prefixed with a big-endian `u32`.
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
    /// A `usize` count/length, capped into a `u32` (state is KB-MB; no legitimate
    /// count exceeds `u32`).
    pub(crate) fn len(&mut self, x: usize) {
        self.u32(u32::try_from(x).expect("persist count fits u32"));
    }
    /// Raw fixed-width bytes, no length prefix (the reader must know the width).
    pub(crate) fn fixed(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    /// Length-prefixed variable bytes.
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

/// A bounds-checked decoder. Every read is guarded; malformed/truncated input is a
/// loud error, never a panic or a partial read.
pub(crate) struct R<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> R<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    /// A safe pre-allocation size for `n` upcoming elements: capped by the bytes still
    /// unconsumed (audit #11). Every element consumes at least one byte, so a legitimate
    /// count can never exceed the remaining length; a hostile length prefix
    /// (e.g. `0xFFFFFFFF` on an unauthenticated PLAIN row) is clamped to the real input
    /// size instead of triggering a multi-GB eager `with_capacity` OOM before the loop
    /// errors on truncation.
    fn cap(&self, n: usize) -> usize {
        n.min(self.b.len().saturating_sub(self.pos))
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
    /// A length/count field, returned as `usize`.
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
    /// Length-prefixed variable bytes.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.len()?;
        self.take(n)
    }
    pub(crate) fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }
    /// True once every byte has been consumed (a trailing-garbage guard for callers
    /// that expect an exact-fit blob).
    #[cfg(test)]
    pub(crate) fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

// -------------------------------------------------------------------------
// Database open (0600).
// -------------------------------------------------------------------------

/// Open (creating if absent) `state.redb` at `path`, restricting it to `0600` on unix.
/// On a non-unix host the same caveat as `state.rs::write_secret` applies (set
/// `CARAPACE_PASSPHRASE` so secrets are additionally sealed under `K_root`).
pub(crate) fn open_db(path: &Path) -> Result<Database> {
    let db = Database::create(path).with_context(|| format!("open state db {path:?}"))?;
    // Create-then-chmod leaves a brief default-perm window (mirrors the identity-file
    // caveat in state.rs); acceptable for the demo posture.
    restrict_perms(path)?;
    Ok(db)
}

/// Whether `state.redb` already exists (design §3.5 tripwire: blobs/keys present but no
/// state.redb => a wiped/mismatched state dir, fail/warn loudly rather than start fresh).
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

// -------------------------------------------------------------------------
// Raw category read/write (used by persist_all / load_all).
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// Category row keys (design §3.3). One redb row per category.
// -------------------------------------------------------------------------

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
    pub const PENDING_RESPLITS: &str = "pending_resplits";
    pub const PENDING_DELETE_SENDS: &str = "pending_delete_sends";
    pub const UNFRIENDED_NODES: &str = "unfriended_nodes";
    pub const VAULT_BLOBS: &str = "vault_blobs"; // DERIVE: only {vid -> digest, chunk_ids}
    pub const DOC_CARDS: &str = "doc_cards";
    pub const DOC_ANNOUNCES: &str = "doc_announces";
    pub const CARD_VERSION: &str = "card_version"; // F3 monotonic own-card version floor

    // SEAL (AEAD-sealed under HKDF(K_root,"carapace/v1/state-seal") before touching redb).
    pub const HELD_SHARES: &str = "held_shares";
    pub const HELD_GRANTS: &str = "held_grants";
    pub const GRANTED: &str = "granted";
    pub const SPLIT_STATES: &str = "split_states";
    pub const RESPLITS: &str = "resplits";
}

/// The redb table name used as the `state_seal` aad `table` component for every SEAL
/// row (the per-row `key` is the category name), binding a sealed blob to its exact
/// slot so a cross-category relocation fails to open (design §3.4).
const SEAL_TABLE: &[u8] = b"state";

// -------------------------------------------------------------------------
// Leaf encoders/decoders shared across categories.
// -------------------------------------------------------------------------

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

/// A `HashMap<[u8;32], M>` where `M` is a framed message (the key is stored explicitly
/// even when it equals the message signer, so load never has to re-derive it).
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

/// One owner-held trustee record (embeds a secret `Share` via its canonical JSON).
/// Only ever written inside a SEAL row.
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

// -------------------------------------------------------------------------
// The funnel (design §3.2.1): persist the WHOLE Shared + DocStore in one txn.
// -------------------------------------------------------------------------

/// Persist every durable category of `Shared` + `docs` into `txn`, sealing secret
/// categories under `k_root` first. The caller commits `txn` (design §3.2.3:
/// commit BEFORE any externally visible effect) and crashes on commit failure.
///
/// EXHAUSTIVE + COMPILE-ENFORCED (design §3.2.1): `Shared` is destructured with NO
/// `..` glob, so every field is either persisted or explicitly discarded here. Adding
/// a `Shared` field fails to compile until it is categorized.
pub(crate) fn persist_all(
    txn: &redb::WriteTransaction,
    s: &Shared,
    docs: &DocStore,
    k_root: &[u8; 32],
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
        pending_resplits,
        pending_delete_sends,
        unfriended_nodes,
        // --- DERIVE ---
        vault_blobs,
        // --- PLAIN-rebuild: reconstructed from `granted` at load (§3.3) ---
        share_sets,
        // --- EPH: rebuilt on reconnect / never persisted (§3.3) ---
        tickets,
        peer_addrs,
        peer_last_seen,
        rate,
        relay_health,
        vault_keys,
        blob_auth,
        test_now,
    } = s;

    // EPH: address/liveness caches, rate limiter, per-session auth, test clock,
    // outstanding invite tickets (die on reboot -> TicketUnknown, acceptable), and
    // vault chunk keys (NEVER persist: an accidental write-through is a key dump).
    let _ = (
        tickets,
        peer_addrs,
        peer_last_seen,
        rate,
        relay_health,
        vault_keys,
        blob_auth,
        test_now,
    );
    // PLAIN-rebuild: `share_sets` (AttestTracker) is reconstructed from `granted` at
    // load (rebuild_share_sets); its only lost state is recent attestation timestamps,
    // self-healed by the next §10.2 challenge round.
    let _ = share_sets;

    let mut t = txn.open_table(STATE).context("open state table (write)")?;

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

    // ---- DERIVE: vault_blobs -> only {vid -> digest, chunk_ids} (never the manifest) ----
    put(&mut t, cat::VAULT_BLOBS, enc_vault_blobs(vault_blobs))?;

    // ---- F3: monotonic own-card version floor = max own card.version ----
    let card_version = cards.iter().map(|c| c.version).max().unwrap_or(0);
    put(
        &mut t,
        cat::CARD_VERSION,
        card_version.to_be_bytes().to_vec(),
    )?;

    // ---- DocStore (§6 rollback high-water marks) ----
    put_frame_list(&mut t, cat::DOC_CARDS, docs.cards().cloned())?;
    put_frame_list(&mut t, cat::DOC_ANNOUNCES, docs.announces().cloned())?;

    // ---- SEAL rows (sealed before touching redb) ----
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

    Ok(())
}

/// Persist the whole state in one txn and commit it, fail-loud (design §3.2.5): a
/// commit failure CRASHES rather than continuing with RAM ahead of disk. The caller
/// holds the `shared` (and, for the `_with` path, `docs`) lock across this call so the
/// RAM mutation and the durable write share one critical section, and calls it BEFORE
/// any externally visible effect (§3.2.3-4).
pub(crate) fn commit_all(db: &Database, s: &Shared, docs: &DocStore, k_root: &[u8; 32]) {
    if let Err(e) = try_commit_all(db, s, docs, k_root) {
        // §3.2.5: the daemon DIES on a commit failure - never continue with RAM ahead of
        // disk. `abort()` (not a panic): a panic here fires while the caller holds the
        // `shared` write lock, poisoning it and wedging the daemon half-alive on every
        // later `.expect("shared lock")`. `abort()` takes the whole process down at once,
        // no unwinding, no poisoned lock.
        eprintln!(
            "carapace: FATAL redb state commit failed ({e:#}); aborting the daemon \
             (design §3.2.5: never continue with RAM ahead of disk)."
        );
        std::process::abort();
    }
}

/// One durable state commit: open a write txn, persist the whole state, and commit.
/// Any failure is returned so [`commit_all`] can abort the process loudly.
fn try_commit_all(db: &Database, s: &Shared, docs: &DocStore, k_root: &[u8; 32]) -> Result<()> {
    let txn = db.begin_write().context("begin redb write txn")?;
    persist_all(&txn, s, docs, k_root)?;
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
    // The category plaintext (share JSON, polynomial bytes, share-grant bodies) is
    // secret-equivalent. Wrap the caller's buffer (moved in, no copy) so it is WIPED after
    // sealing rather than left in freed heap - the seal-side edge of audit #10. Covers
    // every SEAL category, since all of them route through here.
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

/// C1: a party we have standing to trust - an owner whose share we hold
/// (`held_grants` subject), an established friend, or ourselves (`docs.card`). Shared by
/// the abort and alarm bounds: an unauthenticated dispatch from a stranger must never be
/// able to write a durable row (durable disk-fill DoS otherwise).
fn signer_qualifies(
    signer: &[u8; 32],
    held_grants: &HashMap<[u8; 32], ShareGrant>,
    friends: &HashMap<[u8; 32], ContactCard>,
    docs: &DocStore,
) -> bool {
    held_grants.contains_key(signer) || friends.contains_key(signer) || docs.card(signer).is_some()
}

/// C1: persist only alarms whose SPONSOR (the `RecoveryOpen` signer) is a qualifying
/// party (see [`signer_qualifies`]). A stranger can self-sign a `RecoveryOpen` for any
/// subject and dial us unauthenticated (`serve_recovery_open`); without this bound each
/// such open would append an attacker-chosen ~1MiB alarm to disk unbounded. A stranger's
/// alarm stays RAM-only (still visible to `/api/status` for the session, just not
/// durable). The subject is deliberately NOT a qualifier: it is public, so an attacker
/// would just set `subject = our pubkey` to bypass the bound.
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

/// C1: persist only aborts whose signer is a qualifying party (see [`signer_qualifies`]).
/// A stranger's abort stays RAM-only so an unauthenticated dispatch cannot fill disk.
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
            // Persist node ids only; direct addresses are hints, rebuilt via relay
            // fallback on reconnect (§6 "addresses are hints, not identities").
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

fn enc_vault_blobs(m: &HashMap<[u8; 32], VaultBlobs>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (vid, vb) in m {
            w.fixed(vid);
            w.fixed(&vb.digest);
            w.len(vb.chunk_ids.len());
            for c in &vb.chunk_ids {
                w.fixed(c);
            }
        }
    })
}

fn enc_held_shares(m: &HashMap<u64, (Share, ShareMonitor)>) -> Vec<u8> {
    enc(|w| {
        w.len(m.len());
        for (rsid, (share, _monitor)) in m {
            // ShareMonitor is EPH (CRC self-validation cadence, rebuilt on load).
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

// -------------------------------------------------------------------------
// Startup load (design §3.5).
// -------------------------------------------------------------------------

/// A DERIVE vault-blob source row: `(vid, manifest digest, chunk ids)`. The decrypted
/// `Manifest` is re-derived from the FsStore envelope at startup (never persisted).
pub(crate) type VaultBlobSource = ([u8; 32], [u8; 32], Vec<[u8; 32]>);

/// Everything reloaded from `state.redb` at startup.
pub(crate) struct Loaded {
    /// `Shared` with every persisted category filled and EPH fields left at their
    /// defaults (the daemon rebuilds `rate`/`relay_health`/… on start). `vault_blobs`
    /// is EMPTY here: its decrypted manifests are re-derived asynchronously from
    /// `vault_blob_sources` against FsStore + `K_manifest`.
    pub shared: Shared,
    /// The rollback high-water-mark store (§6).
    pub docs: DocStore,
    /// DERIVE (A1): `{vid -> (digest, chunk_ids)}` to re-derive `vault_blobs` manifests
    /// from FsStore at startup. The decoded `Manifest` is NEVER persisted in clear.
    pub vault_blob_sources: Vec<VaultBlobSource>,
    /// F3: persisted monotonic own-card version floor. The fresh own card is minted at
    /// `max(unix_now(), card_version + 1)` so its version strictly increases across a
    /// restart even under rapid relay flapping.
    pub card_version: u64,
}

/// Load and decode all persisted state (design §3.5). SEAL rows are opened under
/// `k_root`; a sealed row that fails to open ABORTS startup (fail loud, never
/// skip-and-continue — that silently loses a share). GC/router must not start until
/// after this returns and reconciliation completes.
pub(crate) fn load_all(db: &Database, k_root: &[u8; 32]) -> Result<Loaded> {
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

    // ---- PLAIN-rebuild: share_sets from granted (§3.3) ----
    s.share_sets = rebuild_share_sets(&s.granted);

    // ---- DERIVE: vault_blob sources (manifests re-derived by the caller) ----
    let vault_blob_sources = match read_row(db, cat::VAULT_BLOBS)? {
        Some(b) => dec_vault_blob_sources(&mut R::new(&b))?,
        None => Vec::new(),
    };

    // ---- F3 own-card version floor ----
    let card_version = match read_row(db, cat::CARD_VERSION)? {
        Some(b) => u64::from_be_bytes(
            b.as_slice()
                .try_into()
                .map_err(|_| anyhow!("card_version row is not 8 bytes"))?,
        ),
        None => 0,
    };

    // ---- DocStore (§6 high-water marks) ----
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

    Ok(Loaded {
        shared: s,
        docs,
        vault_blob_sources,
        card_version,
    })
}

/// Open a SEAL row under `k_root`. Absent -> `None`; present-but-unopenable -> loud
/// error (design §3.4/§3.5: never skip a share that will not decrypt).
fn read_sealed(db: &Database, key: &str, k_root: &[u8; 32]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match read_row(db, key)? {
        None => Ok(None),
        Some(sealed) => {
            // Return the `Zeroizing` buffer state_seal::open produced (do NOT `to_vec()` it
            // into a plain Vec that drops unwiped): the decoder borrows it and it is wiped
            // when the caller's binding drops - the read-side edge of audit #10.
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
            // Reconstruct a bare-id EndpointAddr; direct addrs resolve via relay/hole-punch.
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
        // ShareMonitor is EPH: a fresh default monitor (re-runs its CRC self-check cadence).
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
    // wrong K_root. Exercises the compile-enforced `persist_all` destructure against real
    // shares/split-state (the hard SEAL path) and the share_sets rebuild-from-granted.
    #[test]
    fn persist_load_roundtrips_all_categories() {
        use carapace_wire::Signed;
        use ed25519_dalek::SigningKey;

        let node = SigningKey::from_bytes(&[7u8; 32]);
        let user = SigningKey::from_bytes(&[9u8; 32]);
        let node_pub = node.verifying_key().to_bytes();
        let user_pub = user.verifying_key().to_bytes();
        let k_root = [3u8; 32];

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
            persist_all(&txn, &s, &docs, &k_root).unwrap();
            txn.commit().unwrap();
        }

        // 0600 on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let loaded = load_all(&db, &k_root).unwrap();

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

        // Fail loud: a wrong K_root cannot open the sealed rows.
        assert!(load_all(&db, &[0u8; 32]).is_err());
    }
}
