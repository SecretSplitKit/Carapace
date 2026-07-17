//! Proof-of-Retention (PoR) audits (protocol §10.1).
//!
//! The owner periodically challenges each replica to prove it still holds the
//! ciphertext chunks it accepted. Challenges are **unpredictable to the peer**:
//! the owner derives which chunks (and which byte ranges within them) to sample
//! from `K_audit(vid)` - a key only the owner holds - mixed with the announce
//! epoch and a per-replica round counter. The sampling is deterministic given
//! `(K_audit, epoch, round)` so the owner can rebuild and verify the same
//! challenge, yet a peer without `K_audit` cannot precompute the answers, so it
//! cannot discard chunks and reconstruct only the sampled ones on demand.
//!
//! A challenge is answered with BLAKE3-verified blob data. Each chunk is
//! content-addressed (its ChunkID is `BLAKE3(ciphertext)`), so returned bytes
//! verify against the sampled ChunkID by hashing - no owner-held copy and no
//! shared secret are needed. A correct response to the whole sampled set is the
//! retention proof ([`run_audit`] / [`verify_audit_response`]).
//!
//! The bytes returned for a sample must *cover* the sampled `offset..offset+len`
//! range; in the wired path the responder returns the whole content-addressed
//! chunk (verified by hash) and the range simply selects a focus sub-range, so a
//! full chunk always covers it. Production SHOULD narrow this to bao
//! verified-range streaming so only the sampled bytes cross the wire; until then
//! the per-sample `offset`/`len` are a focus record, not a fidelity boundary.
//!
//! Transport vs. content: a peer that could not be reached at all is *not* a
//! retention failure. Only a peer that answered but is missing or returns
//! non-matching bytes for a sampled chunk counts toward the loss streak. An
//! unreachable round is fed to [`AuditTracker::record_unreachable`], which
//! reschedules without touching the streak (offline is not loss, §10.1); the
//! separate reachability/grace path (`Health::UnreachableSince`) handles a peer
//! that stays gone.
//!
//! Loss tracking ([`AuditTracker`]): `N` consecutive failures (default 3, §12)
//! marks the replica lost and yields an [`AuditAction::Lost`]; the caller feeds
//! that into the existing repair path by recording [`crate::Health::AuditLost`]
//! and calling [`crate::ReplicaSet::repair`], which drops the peer and
//! re-replicates. Audit timing is randomized per replica (a deterministic
//! per-replica jitter, so scheduling stays testable under an injected clock),
//! and an occasional **wide-coverage** round ([`build_wide_audit`]) samples a
//! large random subset in one window instead of the small per-round spot check.
//!
//! # Proxy limitation (§10.1 / audit D1)
//!
//! A PoR pass proves the sampled bytes are *retrievable through the audited
//! peer* at audit time - **not** that the peer stores them exclusively or even
//! itself. A dishonest peer that discarded its copy could proxy each challenge
//! to another replica that still holds the data and relay the verified bytes
//! back; the response would verify identically. PoR therefore cannot, on its
//! own, distinguish independent storage from friend-proxied storage. The
//! accepted mitigations are all availability-side, not proofs:
//!
//! - **Randomized per-replica timing** (see [`AuditTracker::schedule`]) so a
//!   proxy cannot cheaply pre-arrange to have a helper online exactly when each
//!   audit lands.
//! - **Occasional wide-coverage audits** ([`build_wide_audit`]) that demand a
//!   large subset at once, making live proxying of the whole set expensive.
//! - **Response-time distribution watching**: a proxied answer adds a network
//!   hop, so an owner SHOULD watch each replica's latency distribution and treat
//!   a shifted tail as suspicious. This module only records the sampled ranges
//!   and leaves the timing to the caller (time [`run_audit`] at the call site);
//!   it deliberately does not build the statistics here.
//!
//! Residual friend-proxying is an availability risk only and is accepted by the
//! trust model (§10.1); it never exposes plaintext, which stays sealed.

use std::collections::HashMap;

use carapace_crypto::content::chunk_id;
use carapace_wire::{AuditNotice, Manifest, Signed};
use ed25519_dalek::SigningKey;

use crate::peer::ReplicaPeer;
use crate::ReplicaError;

/// The `(replica_node_id, vid)` key every per-replica PoR map is indexed by.
type PorKey = ([u8; 32], [u8; 32]);

/// Default PoR cadence: one spot audit per replica every 6 h (§12).
pub const DEFAULT_POR_INTERVAL_SECS: u64 = 6 * 60 * 60;
/// Default consecutive-failure limit before a replica is treated as lost (§12).
pub const DEFAULT_POR_FAIL_LIMIT: u32 = 3;
/// Default number of distinct chunks sampled by a per-round spot audit.
pub const DEFAULT_SAMPLES_PER_ROUND: usize = 4;
/// Default cadence of wide-coverage rounds: every Nth round of a replica is a
/// wide audit instead of a spot check (28 rounds x 6 h ~= weekly).
pub const DEFAULT_WIDE_EVERY: u64 = 28;
/// [`AuditNotice`] code for a retention loss (appendix B.8.20, `code=1`).
pub const AUDIT_CODE_RETENTION_LOST: u64 = 1;

/// Format tag for [`AuditTracker::to_bytes`]/[`AuditTracker::from_bytes`]. Bump
/// only on an incompatible layout change; `from_bytes` rejects any other tag so a
/// stale on-disk row fails loud rather than deserializing into wrong counters.
const POR_STATE_VERSION: u8 = 1;

/// Domain separator for the PoR sampling PRF; mixed into the keyed BLAKE3 XOF
/// alongside epoch, round, and the wide flag so distinct inputs give
/// independent sample streams.
const PRF_DOMAIN: &[u8] = b"carapace/v1/por-sample";

/// One sampled challenge: a chunk to prove retention of, and a byte range within
/// it to focus on. `offset`/`len` are bounded by the chunk's manifest length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditSample {
    /// The ChunkID (content address) being challenged.
    pub chunk_id: [u8; 32],
    /// Byte offset within the chunk the challenge focuses on.
    pub offset: u64,
    /// Length of the focused range (`>= 1` for a non-empty chunk).
    pub len: u64,
}

/// A full audit challenge: the vault/epoch/round it is bound to, whether it is a
/// wide-coverage round, and the sampled chunks. Deterministic given
/// `(K_audit, epoch, round, wide)`; rebuildable by the owner for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audit {
    /// Vault id.
    pub vid: [u8; 32],
    /// Announce epoch the challenge is bound to.
    pub epoch: u64,
    /// Per-replica round counter (the unpredictability nonce).
    pub round: u64,
    /// Whether this is a wide-coverage round (large subset).
    pub wide: bool,
    /// The sampled chunks (distinct ChunkIDs).
    pub samples: Vec<AuditSample>,
}

/// Why a single sample failed verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditFailure {
    /// The peer returned no bytes for this ChunkID - it does not hold the chunk.
    Missing([u8; 32]),
    /// The returned bytes do not hash to the sampled ChunkID (not the content).
    Corrupt([u8; 32]),
    /// The returned blob is shorter than the sampled range: the peer cannot cover
    /// `offset + len`, so it does not hold the full chunk.
    ShortRange {
        /// The ChunkID whose returned blob was too short.
        chunk_id: [u8; 32],
        /// Bytes the peer returned.
        have: usize,
        /// Bytes the sampled range needed (`offset + len`).
        need: usize,
    },
}

/// The result of verifying a peer's response to an [`Audit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Every sampled range verified: retention proven for this round.
    Pass,
    /// The first sample that failed, and why (verification is fail-fast).
    Fail(AuditFailure),
}

impl AuditOutcome {
    /// Whether the audit passed.
    pub fn is_pass(&self) -> bool {
        matches!(self, AuditOutcome::Pass)
    }
}

/// Something that can answer a PoR challenge for one sampled chunk.
///
/// In production this is an iroh-blobs verified-streaming reader that returns the
/// requested range plus a bao proof tying it to the ChunkID. The in-process
/// implementation ([`ReplicaPeer`]) returns the whole content-addressed blob,
/// which [`verify_audit_response`] BLAKE3-checks against the ChunkID (the
/// degenerate bao proof is the leaf itself); the sampled `offset`/`len` then
/// select the focused sub-range. Either way, a returned value that verifies
/// against the ChunkID is proof the responder held the content.
pub trait AuditResponder {
    /// Return content-addressed bytes covering `sample`'s chunk, or `None` if the
    /// chunk is not held. The bytes MUST verify against `sample.chunk_id`
    /// (bao-verified in production; guaranteed by the content-addressed store
    /// in-process).
    fn respond(&self, sample: &AuditSample) -> Option<Vec<u8>>;
}

impl AuditResponder for ReplicaPeer {
    fn respond(&self, sample: &AuditSample) -> Option<Vec<u8>> {
        self.chunk(&sample.chunk_id)
    }
}

/// The unique chunks a manifest references, in first-seen order, as `(id, len)`.
fn unique_chunks(manifest: &Manifest) -> Vec<([u8; 32], u64)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for f in &manifest.files {
        for (id, _pt, len) in &f.chunks {
            if seen.insert(*id) {
                out.push((*id, *len));
            }
        }
    }
    out
}

/// The keyed BLAKE3 XOF that drives all sampling for one challenge. Keying with
/// `K_audit` is what makes the stream unpredictable without that key; mixing
/// epoch, round, and the wide flag gives every challenge an independent stream.
fn prf(k_audit: &[u8; 32], epoch: u64, round: u64, wide: bool) -> blake3::OutputReader {
    let mut h = blake3::Hasher::new_keyed(k_audit);
    h.update(PRF_DOMAIN);
    h.update(&epoch.to_le_bytes());
    h.update(&round.to_le_bytes());
    h.update(&[wide as u8]);
    h.finalize_xof()
}

/// Draw the next PRF `u64` (little-endian) from the XOF stream.
fn next_u64(r: &mut blake3::OutputReader) -> u64 {
    let mut b = [0u8; 8];
    r.fill(&mut b);
    u64::from_le_bytes(b)
}

/// Pick `want` distinct chunk indices out of `n` via a PRF-driven partial
/// Fisher-Yates shuffle (sampling without replacement). Returns `min(want, n)`
/// indices; the shuffle consumes exactly that many `u64`s from `r`.
fn distinct_indices(r: &mut blake3::OutputReader, n: usize, want: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    let k = want.min(n);
    for i in 0..k {
        // Uniform-ish pick in [i, n): modulo bias is negligible for our small n
        // and does not affect the security goal (unpredictability, not uniformity).
        let j = i + (next_u64(r) as usize) % (n - i);
        idx.swap(i, j);
    }
    idx.truncate(k);
    idx
}

/// Derive an in-bounds `(offset, len)` for a chunk of length `chunk_len` from the
/// next two PRF words. An empty chunk yields `(0, 0)`.
fn range_within(r: &mut blake3::OutputReader, chunk_len: u64) -> (u64, u64) {
    if chunk_len == 0 {
        return (0, 0);
    }
    let offset = next_u64(r) % chunk_len;
    let max_len = chunk_len - offset;
    let len = 1 + next_u64(r) % max_len;
    (offset, len)
}

/// Build a challenge sampling `want` distinct chunks; shared by the spot and
/// wide-coverage constructors (they differ only in `want` and the `wide` flag,
/// which also separates their PRF streams).
fn build(
    k_audit: &[u8; 32],
    vid: [u8; 32],
    epoch: u64,
    round: u64,
    manifest: &Manifest,
    want: usize,
    wide: bool,
) -> Audit {
    let chunks = unique_chunks(manifest);
    let mut r = prf(k_audit, epoch, round, wide);
    let picks = distinct_indices(&mut r, chunks.len(), want);
    let samples = picks
        .into_iter()
        .map(|i| {
            let (id, len) = chunks[i];
            let (offset, rlen) = range_within(&mut r, len);
            AuditSample {
                chunk_id: id,
                offset,
                len: rlen,
            }
        })
        .collect();
    Audit {
        vid,
        epoch,
        round,
        wide,
        samples,
    }
}

/// Build a per-round spot audit sampling [`DEFAULT_SAMPLES_PER_ROUND`] distinct
/// chunks (or fewer if the vault has fewer). Deterministic given
/// `(k_audit, epoch, round)`; unpredictable without `k_audit`.
pub fn build_audit(
    k_audit: &[u8; 32],
    vid: [u8; 32],
    epoch: u64,
    round: u64,
    manifest: &Manifest,
) -> Audit {
    build(
        k_audit,
        vid,
        epoch,
        round,
        manifest,
        DEFAULT_SAMPLES_PER_ROUND,
        false,
    )
}

/// Build a spot audit sampling exactly `samples` distinct chunks.
pub fn build_audit_n(
    k_audit: &[u8; 32],
    vid: [u8; 32],
    epoch: u64,
    round: u64,
    manifest: &Manifest,
    samples: usize,
) -> Audit {
    build(k_audit, vid, epoch, round, manifest, samples, false)
}

/// Build a wide-coverage audit sampling `coverage` distinct chunks (capped at
/// the vault's chunk count) in one window - the occasional broad sweep that
/// raises the cost of live friend-proxying (§10.1). Its PRF stream is distinct
/// from the same-round spot audit's.
pub fn build_wide_audit(
    k_audit: &[u8; 32],
    vid: [u8; 32],
    epoch: u64,
    round: u64,
    manifest: &Manifest,
    coverage: usize,
) -> Audit {
    build(k_audit, vid, epoch, round, manifest, coverage, true)
}

/// Verify a peer's `responses` (aligned one-to-one with `audit.samples`) against
/// the challenge. Fail-fast: returns the first failing sample's reason, or
/// [`AuditOutcome::Pass`] if every sampled range verifies. A `None` response is a
/// [`AuditFailure::Missing`]; bytes that do not hash to the ChunkID are
/// [`AuditFailure::Corrupt`]; a blob too short for the range is
/// [`AuditFailure::ShortRange`].
pub fn verify_audit_response(audit: &Audit, responses: &[Option<Vec<u8>>]) -> AuditOutcome {
    for (s, resp) in audit.samples.iter().zip(responses.iter()) {
        let Some(bytes) = resp else {
            return AuditOutcome::Fail(AuditFailure::Missing(s.chunk_id));
        };
        // BLAKE3-verify the returned bytes against the content address.
        if chunk_id(bytes) != s.chunk_id {
            return AuditOutcome::Fail(AuditFailure::Corrupt(s.chunk_id));
        }
        // The verified content must actually cover the sampled range. S3:
        // saturating add so a hostile owner-supplied sample (public fields) cannot
        // overflow the range check.
        let need = s.offset.saturating_add(s.len) as usize;
        if bytes.len() < need {
            return AuditOutcome::Fail(AuditFailure::ShortRange {
                chunk_id: s.chunk_id,
                have: bytes.len(),
                need,
            });
        }
    }
    // A response set shorter than the sample set cannot cover every sample.
    if responses.len() < audit.samples.len() {
        let s = audit.samples[responses.len()];
        return AuditOutcome::Fail(AuditFailure::Missing(s.chunk_id));
    }
    AuditOutcome::Pass
}

/// Issue `audit` to `responder` and verify the answer. The convenience over
/// [`verify_audit_response`] is that it drives the responder for every sample;
/// time this call at the site to feed the response-time hook (§10.1).
pub fn run_audit(audit: &Audit, responder: &impl AuditResponder) -> AuditOutcome {
    let responses: Vec<Option<Vec<u8>>> =
        audit.samples.iter().map(|s| responder.respond(s)).collect();
    verify_audit_response(audit, &responses)
}

/// What the owner should do after recording one audit result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    /// The audit passed; the failure streak (if any) is reset.
    Passed,
    /// The audit failed but the replica is not yet lost; `consecutive` failures
    /// so far, still under the limit.
    Failed {
        /// Consecutive failures recorded for this replica so far.
        consecutive: u32,
    },
    /// Consecutive failures reached the limit: treat the replica as lost. The
    /// caller should record [`crate::Health::AuditLost`] and repair.
    Lost,
    /// The replica could not be reached at all this round (transport failure, not
    /// a content answer). The failure streak and round counter are left untouched
    /// (offline is not retention loss, §10.1) and the next audit is rescheduled.
    /// Produced by [`AuditTracker::record_unreachable`], never by
    /// [`AuditTracker::record`].
    Skipped,
}

/// Per-replica PoR bookkeeping against an injected clock: consecutive-failure
/// counts, the next scheduled audit time (randomized per replica), and a round
/// counter that also decides when a round is wide-coverage.
///
/// Keyed by `(replica_node_id, vid)` so one tracker serves every vault a set of
/// replicas holds.
pub struct AuditTracker {
    interval: u64,
    fail_limit: u32,
    wide_every: u64,
    /// (replica, vid) -> consecutive failures.
    fails: HashMap<([u8; 32], [u8; 32]), u32>,
    /// (replica, vid) -> next scheduled audit time (unix seconds).
    next: HashMap<([u8; 32], [u8; 32]), u64>,
    /// (replica, vid) -> completed round count (the audit nonce source).
    round: HashMap<([u8; 32], [u8; 32]), u64>,
}

impl AuditTracker {
    /// A tracker with the given cadence, fail limit, and wide-round period.
    pub fn new(interval: u64, fail_limit: u32, wide_every: u64) -> Self {
        Self {
            interval,
            fail_limit,
            wide_every: wide_every.max(1),
            fails: HashMap::new(),
            next: HashMap::new(),
            round: HashMap::new(),
        }
    }

    /// The current round counter for a replica/vault - use as the audit's `round`
    /// nonce when building the next challenge.
    pub fn round(&self, replica: [u8; 32], vid: [u8; 32]) -> u64 {
        self.round.get(&(replica, vid)).copied().unwrap_or(0)
    }

    /// Whether the replica's next audit is a wide-coverage round: every
    /// `wide_every`-th round (skipping round 0, the first spot check).
    pub fn is_wide_round(&self, replica: [u8; 32], vid: [u8; 32]) -> bool {
        let r = self.round(replica, vid);
        r != 0 && r.is_multiple_of(self.wide_every)
    }

    /// A deterministic per-replica timing jitter in `[0, interval)`. Derived from
    /// the node id so audits for different replicas spread across the window
    /// (§10.1) without a wall-clock RNG, keeping the injected clock reproducible.
    fn jitter(&self, replica: [u8; 32]) -> u64 {
        if self.interval == 0 {
            return 0;
        }
        u64::from_le_bytes(replica[..8].try_into().expect("32-byte id has 8 bytes")) % self.interval
    }

    /// Schedule (or reschedule) the replica's next audit relative to `now`:
    /// `now + interval + per-replica jitter`.
    pub fn schedule(&mut self, replica: [u8; 32], vid: [u8; 32], now: u64) {
        let at = now
            .saturating_add(self.interval)
            .saturating_add(self.jitter(replica));
        self.next.insert((replica, vid), at);
    }

    /// Whether the replica is due for an audit at `now` (never-scheduled = due).
    pub fn due(&self, replica: [u8; 32], vid: [u8; 32], now: u64) -> bool {
        self.next.get(&(replica, vid)).is_none_or(|&at| now >= at)
    }

    /// Record one audit result at `now`: bump the round counter, reschedule the
    /// next audit, and update the failure streak. On [`AuditOutcome::Pass`] the
    /// streak resets; on failure it increments and, at the limit, returns
    /// [`AuditAction::Lost`] (and resets the streak, since the caller will repair
    /// and drop the replica).
    pub fn record(
        &mut self,
        replica: [u8; 32],
        vid: [u8; 32],
        outcome: AuditOutcome,
        now: u64,
    ) -> AuditAction {
        let key = (replica, vid);
        *self.round.entry(key).or_insert(0) += 1;
        self.schedule(replica, vid, now);

        if outcome.is_pass() {
            self.fails.insert(key, 0);
            return AuditAction::Passed;
        }
        let f = self.fails.entry(key).or_insert(0);
        *f += 1;
        if *f >= self.fail_limit {
            *f = 0;
            AuditAction::Lost
        } else {
            AuditAction::Failed { consecutive: *f }
        }
    }

    /// Record that the replica could not be reached this round (C1): reschedule the
    /// next audit relative to `now` but leave the failure streak and round counter
    /// untouched. A transient offline peer (travel, ISP outage, closed laptop) must
    /// not accumulate PoR failures and be evicted without grace - offline is not
    /// retention loss (§10.1). Only a peer that *answered* with missing or
    /// non-matching bytes advances the streak via [`AuditTracker::record`].
    pub fn record_unreachable(
        &mut self,
        replica: [u8; 32],
        vid: [u8; 32],
        now: u64,
    ) -> AuditAction {
        self.schedule(replica, vid, now);
        AuditAction::Skipped
    }

    /// Serialize the full tracker to a deterministic, lossless byte string for the
    /// durable-persistence funnel (spec §3.3, `por` = PLAIN F4). These are counters
    /// and schedule times, not secrets; the caller decides at-rest sealing.
    ///
    /// Every field that steers a future challenge is captured, so a reboot resumes
    /// exactly where it left off instead of replaying a spent challenge sequence
    /// (§10.1):
    /// - `interval`, `fail_limit`, `wide_every` - the cadence/limit/wide-period the
    ///   scheduler and loss logic run on;
    /// - `round` - the per-(replica,vid) round counter that *is* the unpredictability
    ///   nonce; losing it re-issues an identical challenge stream for the epoch;
    /// - `fails` - the consecutive-failure streak, so a near-lost replica is not
    ///   handed a fresh streak by a reboot;
    /// - `next` - the randomized next-audit time, so timing (a §10.1 anti-proxy
    ///   mitigation) is not reset to "due now" on every restart.
    ///
    /// Map entries are emitted in sorted-key order so equal trackers yield identical
    /// bytes (stable across `HashMap` iteration order) - byte-stability the redb
    /// row-seal AAD and any dedup rely on.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(POR_STATE_VERSION);
        out.extend_from_slice(&self.interval.to_le_bytes());
        out.extend_from_slice(&self.fail_limit.to_le_bytes());
        out.extend_from_slice(&self.wide_every.to_le_bytes());
        write_u32_map(&mut out, &self.fails);
        write_u64_map(&mut out, &self.next);
        write_u64_map(&mut out, &self.round);
        out
    }

    /// Reconstruct a tracker from [`to_bytes`](Self::to_bytes). Fails loud
    /// ([`ReplicaError::PorStateCorrupt`]) on a wrong version tag, truncation, or
    /// trailing bytes: silently loading partial state would drop round counters and
    /// reopen the §10.1 PoR replay window, so the funnel must abort startup instead.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReplicaError> {
        let mut r = Reader { b: bytes, pos: 0 };
        let version = r.u8()?;
        if version != POR_STATE_VERSION {
            return Err(ReplicaError::PorStateCorrupt("unknown por state version"));
        }
        let interval = r.u64()?;
        let fail_limit = r.u32()?;
        let wide_every = r.u64()?;
        let fails = read_u32_map(&mut r)?;
        let next = read_u64_map(&mut r)?;
        let round = read_u64_map(&mut r)?;
        if r.pos != bytes.len() {
            return Err(ReplicaError::PorStateCorrupt("trailing bytes"));
        }
        Ok(Self {
            interval,
            fail_limit,
            wide_every,
            fails,
            next,
            round,
        })
    }
}

/// Emit `count(u64) ‖ [replica(32) ‖ vid(32) ‖ value(4)]*`, entries sorted by key.
fn write_u32_map(out: &mut Vec<u8>, m: &HashMap<PorKey, u32>) {
    let mut entries: Vec<_> = m.iter().collect();
    entries.sort_unstable_by_key(|(k, _)| **k);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for ((replica, vid), v) in entries {
        out.extend_from_slice(replica);
        out.extend_from_slice(vid);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Emit `count(u64) ‖ [replica(32) ‖ vid(32) ‖ value(8)]*`, entries sorted by key.
fn write_u64_map(out: &mut Vec<u8>, m: &HashMap<PorKey, u64>) {
    let mut entries: Vec<_> = m.iter().collect();
    entries.sort_unstable_by_key(|(k, _)| **k);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for ((replica, vid), v) in entries {
        out.extend_from_slice(replica);
        out.extend_from_slice(vid);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn read_u32_map(r: &mut Reader) -> Result<HashMap<PorKey, u32>, ReplicaError> {
    let count = r.u64()?;
    // No `with_capacity(count)`: a corrupt count must not pre-allocate; `take`
    // fails as soon as the bytes run out.
    let mut m = HashMap::new();
    for _ in 0..count {
        let key = (r.arr32()?, r.arr32()?);
        m.insert(key, r.u32()?);
    }
    Ok(m)
}

fn read_u64_map(r: &mut Reader) -> Result<HashMap<PorKey, u64>, ReplicaError> {
    let count = r.u64()?;
    let mut m = HashMap::new();
    for _ in 0..count {
        let key = (r.arr32()?, r.arr32()?);
        m.insert(key, r.u64()?);
    }
    Ok(m)
}

/// A bounds-checked forward cursor over the serialized tracker bytes.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReplicaError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ReplicaError::PorStateCorrupt("length overflow"))?;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or(ReplicaError::PorStateCorrupt("truncated"))?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ReplicaError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ReplicaError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("took exactly 4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, ReplicaError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("took exactly 8 bytes"),
        ))
    }

    fn arr32(&mut self) -> Result<[u8; 32], ReplicaError> {
        Ok(self.take(32)?.try_into().expect("took exactly 32 bytes"))
    }
}

impl Default for AuditTracker {
    fn default() -> Self {
        Self::new(
            DEFAULT_POR_INTERVAL_SECS,
            DEFAULT_POR_FAIL_LIMIT,
            DEFAULT_WIDE_EVERY,
        )
    }
}

/// Build the signed [`AuditNotice`] (type 18) an owner emits for `vid` with
/// `code` - e.g. [`AUDIT_CODE_RETENTION_LOST`] when a replica is dropped for
/// failed retention audits. Signed by the owner node key.
pub fn signed_audit_notice(owner_node: &SigningKey, vid: [u8; 32], code: u64) -> AuditNotice {
    let mut n = AuditNotice {
        vid,
        code,
        by: [0; 32],
        sig: [0; 64],
    };
    n.sign(owner_node);
    n
}

#[cfg(test)]
mod state_tests {
    use super::*;

    fn fail() -> AuditOutcome {
        AuditOutcome::Fail(AuditFailure::Missing([0u8; 32]))
    }

    /// Advance two (replica,vid) pairs through several rounds, serialize, reload,
    /// and prove the reloaded tracker resumes the *next* challenge (never a spent
    /// round) and preserves the failure streak, schedule, and config.
    #[test]
    fn round_trip_resumes_and_never_repeats_a_round() {
        let a = [0x11u8; 32]; // replica A
        let b = [0x22u8; 32]; // replica B
        let vid = [0xAAu8; 32];
        let interval = 3600u64;

        let mut t = AuditTracker::new(interval, DEFAULT_POR_FAIL_LIMIT, 4);

        // A: pass, pass, pass -> round 3, streak reset. 3 is a wide round (every 4th
        // skips 0, so is_wide is false at 3 but the state must survive regardless).
        for k in 0..3 {
            assert_eq!(
                t.record(a, vid, AuditOutcome::Pass, k * 100),
                AuditAction::Passed
            );
        }
        // B: two failures (under the default limit of 3) -> round 2, streak 2 kept.
        assert_eq!(
            t.record(b, vid, fail(), 10),
            AuditAction::Failed { consecutive: 1 }
        );
        assert_eq!(
            t.record(b, vid, fail(), 20),
            AuditAction::Failed { consecutive: 2 }
        );

        let round_a = t.round(a, vid);
        let round_b = t.round(b, vid);
        let next_a = t.next.get(&(a, vid)).copied();
        let next_b = t.next.get(&(b, vid)).copied();
        let wide_a = t.is_wide_round(a, vid);
        assert_eq!(round_a, 3);
        assert_eq!(round_b, 2);

        // Determinism: same tracker serializes to identical bytes each time.
        let bytes = t.to_bytes();
        assert_eq!(bytes, t.to_bytes());

        let t2 = AuditTracker::from_bytes(&bytes).expect("round-trips");

        // Config survived.
        assert_eq!(t2.interval, interval);
        assert_eq!(t2.fail_limit, DEFAULT_POR_FAIL_LIMIT);
        assert_eq!(t2.wide_every, 4);
        // Full map equality: round counters, streaks, and schedule all preserved.
        assert_eq!(t2.round, t.round);
        assert_eq!(t2.fails, t.fails);
        assert_eq!(t2.next, t.next);
        assert_eq!(t2.round(a, vid), round_a);
        assert_eq!(t2.round(b, vid), round_b);
        assert_eq!(t2.next.get(&(a, vid)).copied(), next_a);
        assert_eq!(t2.next.get(&(b, vid)).copied(), next_b);
        assert_eq!(t2.is_wide_round(a, vid), wide_a);

        // The core §10.1 guarantee: the NEXT challenge continues from the stored
        // round, never re-issuing a spent one. `round()` is the nonce for the next
        // build_audit; recording again must advance to round+1 for BOTH pairs.
        let mut t2 = t2;
        assert_eq!(t2.round(a, vid), 3); // next challenge uses round 3, not 0..2 again
        t2.record(a, vid, AuditOutcome::Pass, 999);
        assert_eq!(t2.round(a, vid), 4);

        // B's streak of 2 continued: one more fail hits the limit of 3 -> Lost.
        assert_eq!(t2.round(b, vid), 2);
        assert_eq!(t2.record(b, vid, fail(), 999), AuditAction::Lost);
        assert_eq!(t2.round(b, vid), 3);
    }

    #[test]
    fn empty_tracker_round_trips() {
        let t = AuditTracker::default();
        let t2 = AuditTracker::from_bytes(&t.to_bytes()).unwrap();
        assert_eq!(t2.round, t.round);
        assert_eq!(t2.fails, t.fails);
        assert_eq!(t2.next, t.next);
        assert_eq!(t2.interval, t.interval);
    }

    #[test]
    fn corrupt_input_fails_loud() {
        let good = AuditTracker::default().to_bytes();
        // Truncated.
        assert!(matches!(
            AuditTracker::from_bytes(&good[..good.len() - 1]),
            Err(ReplicaError::PorStateCorrupt(_))
        ));
        // Trailing byte.
        let mut extra = good.clone();
        extra.push(0);
        assert!(matches!(
            AuditTracker::from_bytes(&extra),
            Err(ReplicaError::PorStateCorrupt(_))
        ));
        // Wrong version tag.
        let mut bad_ver = good.clone();
        bad_ver[0] = 0xFF;
        assert!(matches!(
            AuditTracker::from_bytes(&bad_ver),
            Err(ReplicaError::PorStateCorrupt(_))
        ));
        // Empty input.
        assert!(matches!(
            AuditTracker::from_bytes(&[]),
            Err(ReplicaError::PorStateCorrupt(_))
        ));
    }
}
