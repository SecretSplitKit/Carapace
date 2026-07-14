//! carapaced: the Carapace daemon core (build-order step 1).
//!
//! A [`Daemon`] binds a carapace-net endpoint, serves its local iroh-blobs
//! store, holds one or more vaults, and runs the accept + anti-entropy loop.
//!
//! Two owner devices share the SAME user master key (`k_root`, hence the same
//! `K_manifest`/`K_content`/`K_disclose`) but hold DIFFERENT node keys, each
//! delegated by the user key (§4). Device A publishes a vault (ingest, seal
//! manifest, seal a per-chunk access grant, sign a [`VaultAnnounce`] +
//! [`FileGrant`]); device B discovers the announce over anti-entropy, fetches
//! the manifest envelope + every chunk by ChunkID, opens the grant, and
//! reconstructs the identical tree (§6, §7, §11).
//!
//! Chunk keys/nonces derive one-way from `K_content ‖ pt_hash`, so the wire
//! `Manifest` (only `{id, len}`) cannot re-derive them at reconstruct time. The
//! owner therefore ships them out of band: a det-CBOR [`GrantBody`] HPKE-sealed
//! to the user's disclosure key and carried in a signed [`FileGrant`] on the
//! control stream (the spec's §7.4 grant mechanism, reused here for the
//! same-user two-device case).

mod state;

pub use state::State;

/// Re-export so callers without an `iroh` dependency (e.g. the CLI) can parse
/// friends' relay URLs for [`Daemon::start_on`].
pub use iroh::RelayUrl;

use anyhow::{ensure, Context, Result};
use carapace_crypto::kdf::{self, INFO_DISCLOSE};
use carapace_crypto::seal::{self, HpkePrivateKey, HpkePublicKey};
use carapace_disclose::{self as disclose, DisclosureTable, Recipient};
use carapace_friend::{
    accept_friend_request, build_friend_request, build_ticket, friendship_core_bytes,
    verify_friend_accept, verify_friend_request, TicketBook,
};
use carapace_net::endpoint::ALPN;
use carapace_net::{
    authorizing_event_sender, read_frame_raw, read_msg, write_msg, CarapaceEndpoint, CarapaceRelay,
    DocStore, IrohBlobStore, PeerHints, RelayAccessPolicy,
};
use carapace_recovery::{
    build_share_grant, extend_split, share_to_json, split_root, split_vault, verify_share_grant,
    CeremonyState, PolicyWarning, RecoveryRateLimiter,
};
use carapace_replica::{
    build_audit, build_wide_audit, verify_audit_response, Audit, AuditAction, AuditTracker, Health,
    Policy, RateLimiter, DEFAULT_GRACE_SECS, DEFAULT_POR_FAIL_LIMIT, DEFAULT_POR_INTERVAL_SECS,
    DEFAULT_QUOTA_BYTES, DEFAULT_RATE_CAPACITY, DEFAULT_RATE_REFILL_PER_SEC, DEFAULT_WIDE_EVERY,
    MAX_REPLICA_BLOBS,
};
use carapace_share::{
    answer_attest_challenge, build_attest_challenge, AttestTracker, Share, ShareAction,
    ShareHealth, ShareMonitor,
};
use carapace_vault::{
    ingest_dir, merge_manifests, new_vid, open_envelope, reconstruct, seal_manifest, vv_equal,
    ChunkKeys, ChunkSecret, MemoryStore, VaultKeys,
};
use carapace_wire::messages::Message;
use carapace_wire::{
    AnnounceRef, CeremonyAbort, CeremonyApprove, CoTrustee, ContactCard, FileGrant, FriendAccept,
    FriendRequest, Friendship, GrantBody, GrantChunk, GrantFile, Hello, InviteTicket, Manifest,
    ManifestEnvelope, NodeEntry, Offers, RecoveryOpen, ReplicaAccept, ReplicaInvite, Sealed,
    ShareAttestChallenge, ShareAttestation, ShareGrant, Signed, VaultAnnounce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{EndpointAddr, EndpointId};
use iroh_blobs::BlobsProtocol;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use zeroize::Zeroizing;

/// A far-future delegation expiry for the demo (2100-01-01Z, unix seconds).
const DELEG_NOT_AFTER: u64 = 4_102_444_800;

/// Distinct chunks a wide-coverage PoR round samples in one window (§10.1): a broad
/// sweep that raises the cost of live friend-proxying. Capped at the vault's chunk
/// count by the sampler, so a small vault simply samples all of it.
const WIDE_AUDIT_COVERAGE: usize = 64;

/// Per-sample timeout for a PoR probe fetch. Bounds a stalled transfer or a
/// missing-blob fetch so one unresponsive sample cannot hang the audit round.
const POR_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the initial dial of a replica during a PoR probe. Without it an
/// unreachable peer's QUIC connect can hang for ~30 s, stalling the whole round;
/// bounding it makes an offline peer fail fast to the "unreachable" path (C1).
const POR_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// §11 filesystem-watcher debounce: after a change under a watched vault source,
/// re-ingest only once the directory has been quiet for this long. Coalesces a
/// burst of editor/copy events into one publish and avoids re-ingesting a file
/// mid-write. ponytail: fixed const; lift to `NetConfig`/`watch_vault` arg if a
/// deployment needs per-vault tuning.
pub const WATCH_DEBOUNCE: Duration = Duration::from_millis(750);

/// Tunable limits for the replica-store receive path (W1). Defaults come from the
/// replica crate: a 1 GiB default per-friend storage grant and a 256 MiB /
/// 64 MiB-per-s per-peer token bucket. Lower them (e.g. in tests) to exercise the
/// cut-offs.
#[derive(Clone, Copy, Debug)]
pub struct ReplicaLimits {
    /// Default per-friend replica-storage grant (bytes) recorded when this node
    /// ACCEPTS a friend request. Enforced later as that friend's replica quota;
    /// the initiating `befriend` path can agree a different amount explicitly.
    pub quota_bytes: u64,
    /// Per-peer rate-limit burst capacity in bytes.
    pub rate_capacity: u64,
    /// Per-peer rate-limit refill in bytes per second.
    pub rate_refill_per_sec: u64,
}

impl Default for ReplicaLimits {
    fn default() -> Self {
        Self {
            quota_bytes: DEFAULT_QUOTA_BYTES,
            rate_capacity: DEFAULT_RATE_CAPACITY,
            rate_refill_per_sec: DEFAULT_RATE_REFILL_PER_SEC,
        }
    }
}

/// Network wiring for [`Daemon::start_on`] (§6): where the endpoint binds, which
/// friend-hosted relays to consume, and whether this node runs the embedded
/// self-hosted relay a capable node offers its friends.
#[derive(Clone, Debug, Default)]
pub struct NetConfig {
    /// Endpoint bind socket. `None` picks a default: loopback:0 for a plain
    /// in-process node, or `0.0.0.0:0` when relays are involved (so the
    /// portmapper can open the port and friends can reach us).
    pub bind: Option<std::net::SocketAddr>,
    /// Friends' advertised self-hosted relay URLs to consume at startup. These
    /// form this node's usable relay set for relay fallback ("your usable relay
    /// set = relays advertised by your friends", §6).
    pub relays: Vec<RelayUrl>,
    /// Run the embedded relay bound at this socket (`Some`), so friends can relay
    /// through this node. `None` runs no relay.
    pub run_relay: Option<std::net::SocketAddr>,
    /// Host or IP to advertise in the relay URL instead of the bind IP (e.g. a
    /// public DNS name or WAN address). Ignored when `run_relay` is `None`;
    /// falls back to the relay's bound address.
    pub relay_host: Option<String>,
}

/// Cadence knobs for the background maintenance loop ([`Daemon::run_maintenance`],
/// §10.1/§10.2). Small values are injectable for bounded tests; the defaults are the
/// production cadences. Each per-concern schedule (per-replica PoR jitter, daily
/// attestation, continuous self-validation) is owned by its own injected-clock
/// tracker, so the loop only needs a wake `tick` plus the PoR interval it stamps onto
/// the audit schedule when it starts.
#[derive(Clone, Copy, Debug)]
pub struct MaintenanceConfig {
    /// How often the loop wakes and runs one [`Daemon::maintenance_round`]. Each
    /// tracker self-gates on its own cadence, so a tick finds most work not-yet-due
    /// and is cheap; it need only be at least as frequent as the shortest cadence.
    pub tick: Duration,
    /// PoR retention-audit interval for owned vaults' replicas (§10.1), per-replica
    /// jittered by the audit scheduler. Stamped onto the audit tracker when the loop
    /// starts. Default: 6 h.
    pub por_interval: Duration,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            // A minute is well under the shortest production cadence (hourly
            // self-validation) yet idle-cheap, since each round is a no-op when
            // nothing is due.
            tick: Duration::from_secs(60),
            por_interval: Duration::from_secs(DEFAULT_POR_INTERVAL_SECS),
        }
    }
}

/// What one [`Daemon::maintenance_round`] did (§10.1/§10.2). Returned for logging and
/// tests; the loop discards it.
#[derive(Clone, Debug, Default)]
pub struct MaintenanceReport {
    /// Per owned vault, the PoR audit round that ran (§10.1).
    pub por: Vec<([u8; 32], PorRound)>,
    /// Per owned recovery set, the drift decision surfaced this round (§10.2).
    pub drift: Vec<(u64, ShareAction)>,
    /// Per held share, the trustee self-validation verdict this round (§10.2).
    pub self_validated: Vec<(u64, ShareHealth)>,
    /// Recovery-set ids whose trustees' grants were re-issued with fresh announce
    /// refs this round (W3, §7.3): the owner published a new vault epoch (or a prior
    /// delivery was outstanding), so trustees were pushed current manifest pointers.
    pub refreshed_grants: Vec<u64>,
    /// Non-fatal per-item errors (one bad vault/set does not abort the round).
    pub errors: Vec<String>,
}

/// Outcome of an owner-side split-and-grant (§8, W3): which trustees were reached and
/// hold a fresh grant, plus any §8.3 issuance policy warnings.
#[derive(Clone, Debug, Default)]
pub struct GrantSplitReport {
    /// The recovery-set id the split was recorded under.
    pub rsid: u64,
    /// Trustee USER pubkeys that acknowledged storing their grant this round.
    pub delivered: Vec<[u8; 32]>,
    /// Trustee USER pubkeys that were minted a grant but could not be reached /
    /// declined; the maintenance refresh round retries them.
    pub undelivered: Vec<[u8; 32]>,
    /// §8.3 issuance policy warnings surfaced by the split.
    pub warnings: Vec<PolicyWarning>,
}

/// The W3 grant surface for one owned recovery set, for the status/`/api/recovery`
/// view: which trustees hold a grant and how fresh their announce refs are.
#[derive(Clone, Debug)]
pub struct RecoveryGrantReport {
    /// The recovery-set id.
    pub rsid: u64,
    /// The subject user whose secret is split (this owner).
    pub subject: [u8; 32],
    /// Per trustee: its user pubkey and whether its last grant delivery succeeded.
    pub trustees: Vec<([u8; 32], bool)>,
    /// The announce refs currently carried in the trustees' grants: `(vid, epoch)`
    /// per referenced vault. Advances as the owner publishes new epochs (§10.2).
    pub refs: Vec<([u8; 32], u64)>,
}

/// The §10.2 share-health surface for one owned recovery set, for the status API.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryHealthReport {
    /// The recovery-set id.
    pub rsid: u64,
    /// Distinct shares attested live within the freshness window right now.
    pub live: usize,
    /// The `M + slack` live target the §10.2 invariant requires.
    pub target: usize,
    /// The recommended action: `"healthy"`, `"extend"`, or `"resplit"` (§10.2/§8.3).
    pub recommendation: &'static str,
    /// For `"extend"`, how many replacement shares to issue; `0` otherwise.
    pub needed: usize,
}

/// The outcome of one PoR audit round over a vault's replicas ([`Daemon::por_audit_round`]).
#[derive(Clone, Debug, Default)]
pub struct PorRound {
    /// Each replica audited this round and the action its result produced.
    pub audited: Vec<([u8; 32], AuditAction)>,
    /// Replicas that crossed the consecutive-failure limit this round (confirmed
    /// retention loss, §10.1) and were fed to the repair path.
    pub lost: Vec<[u8; 32]>,
    /// Replicas that could not be reached this round (transport failure, C1). These
    /// are NOT retention failures: the audit was rescheduled and the loss streak
    /// left untouched, so a transiently-offline friend is never evicted by PoR.
    /// A peer that stays gone is handled by the reachability/grace path instead.
    pub unreachable: Vec<[u8; 32]>,
    /// Whether a repair (re-replication + re-announce) actually changed the member
    /// set as a result of this round's losses.
    pub repaired: bool,
}

/// A reconstructed vault, returned by [`Daemon::sync_from`].
pub struct Reconstructed {
    /// The vault id.
    pub vid: [u8; 32],
    /// The epoch that was reconstructed.
    pub epoch: u64,
    /// The directory the vault's files were written into.
    pub out_dir: std::path::PathBuf,
}

/// The blob source for one owned vault: the manifest-envelope digest and the
/// (unique) ChunkIDs, so the owner can push a full replica without re-ingesting.
#[derive(Clone)]
struct VaultBlobs {
    digest: [u8; 32],
    chunk_ids: Vec<[u8; 32]>,
    /// The sealed manifest (chunk `{id, len}` list) the PoR loop samples over to
    /// build unpredictable retention challenges (§10.1). Held from the last
    /// `publish_vault`; the owner already has it in hand there.
    manifest: Manifest,
}

/// The mutable document set the daemon advertises during anti-entropy, plus the
/// per-vault epoch counter and the friendship/replication state. Cloned (cheaply)
/// under a read lock at accept time; no lock is ever held across an `.await`.
#[derive(Default)]
struct Shared {
    cards: Vec<ContactCard>,
    announces: Vec<VaultAnnounce>,
    grants: Vec<FileGrant>,
    epochs: HashMap<[u8; 32], u64>,
    /// Established friendships, keyed by the *other* party's user pubkey.
    friendships: HashMap<[u8; 32], Friendship>,
    /// Each friend's newest verified `ContactCard`, keyed by user pubkey. This is
    /// the address book the control-stream gate consults (W5).
    friends: HashMap<[u8; 32], ContactCard>,
    /// Per-friend storage grant in bytes: how much replica storage THIS node
    /// grants THAT friend, keyed by the friend's user pubkey. Agreed at
    /// add-friend time (both the initiating `befriend` path and the accepting
    /// `serve_friend_accept` path) and enforced by `serve_replica_store` when the
    /// friend places a replica on us; defaults to `DEFAULT_QUOTA_BYTES` (1 GiB)
    /// when unspecified.
    ///
    /// This is LOCAL policy and is independent of what the friend advertises to
    /// us in their `ContactCard.offers.storage_bytes` (§9.1): the grant is what I
    /// enforce, the offer is what they claim to hold for me. A formal bilateral
    /// over-the-wire storage-agreement message is a possible future spec addition;
    /// the card-offer + local-grant model satisfies it for now (see spec-errata).
    ///
    /// ponytail: parallel map keyed like `friends`; there is no daemon unfriend
    /// path removing entries from `s.friends` yet, so the two cannot drift. Fold
    /// into a `FriendRecord { card, grant }` if `friends` ever gains a removal path.
    friend_grants: HashMap<[u8; 32], u64>,
    /// Tickets this daemon has issued and will honor exactly once (§6).
    tickets: TicketBook,
    /// Per-owned-vault blob source (digest + ChunkIDs) for replica placement. Holds
    /// only the CURRENT epoch's source (overwritten on republish).
    vault_blobs: HashMap<[u8; 32], VaultBlobs>,
    /// The single authoritative working directory per vault (§11): the SAME tree is
    /// the published source, the watched tree, AND the sync/reconstruct target. Set
    /// at `publish_vault` time (to the caller's source) and on a first sync (to
    /// `out_root/<vid>`), so a later sync reconstructs the merged result back into
    /// the tree the watcher observes - which makes "absent from disk => tombstone"
    /// sound (the working tree is always the full merged set, incl. conflict copies).
    working_dirs: HashMap<[u8; 32], PathBuf>,
    /// Every ChunkID ever published for a vault this daemon OWNS, mapped to that
    /// vault's vid and RETAINED across epoch bumps (unlike `vault_blobs`). The
    /// blob-read gate ([`authorize_fetch`]) consults this so a superseded-epoch
    /// chunk stays in the owner-gated set: a still-disclosed old chunk is served
    /// only to its audience, an undisclosed old chunk to no non-device. Without it,
    /// a chunk dropped from the current `vault_blobs` on republish would fall out of
    /// the owned set and be served to any dialer (W2). ponytail: grows with the
    /// distinct owned chunks over the daemon's life; bound it together with
    /// old-epoch blob eviction from the store (GC), tracked as a separate resource
    /// concern (spec-errata W2-gc).
    owned_chunks: HashMap<[u8; 32], [u8; 32]>,
    /// Owner-side replica membership: vid -> accepted replica node ids.
    members: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Owner-side replica invariant `r`, per vault.
    replica_target: HashMap<[u8; 32], usize>,
    /// Vids this daemon stores *as a replica* for some owner (blobs live in the
    /// iroh store; this records the relationship for read-serving/accounting).
    held: HashSet<[u8; 32]>,
    /// Every blob (manifest envelope + ciphertext chunk) this daemon holds *as a
    /// replica* for another owner, mapped to the vid it belongs to. The blob-read
    /// gate ([`authorize_fetch`]) consults this so a replica-held chunk is served
    /// only to that vault owner's delegated devices or a current replica-set member
    /// (§7.4 a/b), never to an arbitrary dialer (W8). Populated in
    /// [`ControlHandler::serve_replica_store`] from the pushed blob hashes.
    replica_chunks: HashMap<[u8; 32], [u8; 32]>,
    /// For each vid held as a replica, the vault owner's *user* pubkey (derived from
    /// the inviting owner node's friend card). The gate uses it to admit that owner's
    /// delegated devices (§7.4 a).
    replica_owner: HashMap<[u8; 32], [u8; 32]>,
    /// For each vid held as a replica, the current replica-set node ids from the
    /// owner-signed `VaultAnnounce` received at placement. The gate admits a member
    /// of this set so a co-replica can fetch for repair (§7.4 b).
    replica_members: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Owner-side deny-list of peer node ids this daemon refuses to place on (S4).
    replica_deny: HashSet<[u8; 32]>,
    /// Last-known dialable address per peer node id, recorded whenever this daemon
    /// dials a friend it befriended or a replica it placed (§6 "addresses are
    /// hints"). The background maintenance loop (§10.1/§10.2) resolves the node ids
    /// in `members`/`share_sets` to addresses through this map to re-audit replicas
    /// and challenge trustees without a discovery round-trip, falling back to a
    /// node-id-only `EndpointAddr` (relay/hole-punch resolution) when a peer is not
    /// recorded here. ponytail: grows one entry per distinct dialed peer; prune
    /// alongside an unfriend/teardown path when W5 adds one.
    peer_addrs: HashMap<[u8; 32], EndpointAddr>,
    /// Per-peer token buckets limiting how much a friend can push into our replica
    /// store per unit time (W1). Configured from [`ReplicaLimits`] at start.
    rate: RateLimiter,
    /// Owner-side PoR bookkeeping (§10.1): per-`(replica, vid)` audit schedule,
    /// round counter, and consecutive-failure streak against an injected clock.
    /// Single-writer per vault: only the vault owner's `por_audit_round` mutates it.
    por: AuditTracker,
    /// Owner-side share-health trackers (§10.2), keyed by recovery-set id. Each
    /// gates the daily attestation cadence and folds verified attestations into an
    /// attested-live count under a freshness window.
    share_sets: HashMap<u64, AttestTracker>,
    /// Trustee-side stored shares this daemon holds for other owners, keyed by
    /// recovery-set id, each with its continuous local CRC self-validation monitor
    /// (§10.2). Answers `ShareAttestChallenge`s from the owning friend.
    held_shares: HashMap<u64, (Share, ShareMonitor)>,
    /// Per-owned-vault chunk secrets (key/nonce per ChunkID), retained from ingest
    /// so the owner can later disclose a *subset* of files (§7.4) without
    /// re-ingesting. Owner-only, in-memory, and zeroized on drop; no weaker than
    /// already holding `k_root` (from which every content key derives) in memory.
    vault_keys: HashMap<[u8; 32], ChunkKeys>,
    /// Owner-side selective-disclosure table (§7.4 / D3): ChunkID -> audience users
    /// authorized to fetch it, recorded from every issued `FileGrant`. The
    /// blob-read gate ([`authorize_fetch`]) consults it so a granted chunk is
    /// served only to an authenticated member of that grant's audience.
    disclosure: DisclosureTable,
    /// Nodes this daemon has authenticated on its `carapace/1` control stream (via
    /// NodeID + card delegation, W5), classified as our own device or a specific
    /// friend. The blob-read gate keys on this so that a raw `iroh-blobs` dialer is
    /// served owned-vault chunks only after it proved, on the authenticated control
    /// stream, who it is — closing the §7.4/D3 gap for owner-served granted content.
    blob_auth: HashMap<[u8; 32], BlobAuth>,
    /// Owner-side recovery split-states (§8), keyed by recovery-set id. Holds the
    /// open Chela split polynomial (a secret, kept in memory beside `k_root`) so
    /// `recovery_extend` can issue further shares on the same polynomial without
    /// re-splitting. ponytail: in-memory, daemon-lifetime like the rest of daemon
    /// state; persist a sealed split-state blob if extend must survive a restart.
    split_states: HashMap<u64, RecoverySet>,
    /// Recovery ceremonies this device tracks (§8.5), keyed by ceremony id. The GUI
    /// drives approve/abort against these; `phase`/`can_release` read from them.
    ceremonies: HashMap<[u8; 16], carapace_recovery::CeremonyState>,
    /// Trustee-side: the full verified `ShareGrant`s this daemon holds for other
    /// owners (W3, §8), keyed by the subject user pubkey whose secret was split. Held
    /// verbatim (roster + recovery_delay + announce refs), so at ceremony time the
    /// quorum has the co-trustee set to reach and the latest manifest pointers to
    /// fetch - unlike a bare `Share`, which locates nothing without a live owner. The
    /// embedded share is ALSO stored in `held_shares` for the attestation cadence.
    held_grants: HashMap<[u8; 32], ShareGrant>,
    /// Owner-side: the grants this daemon minted per recovery set (W3, §8), keyed by
    /// recovery-set id. Retains each trustee's share + hints and the last-delivered
    /// announce refs so the maintenance loop can re-issue refreshed grants pointing at
    /// the latest manifest as new vault epochs publish (§10.2, §7.3).
    granted: HashMap<u64, OwnerGrants>,
}

/// Owner-side record of the [`ShareGrant`]s minted for one recovery set (§8), so the
/// maintenance loop can refresh the announce refs in each trustee's grant as the
/// owner publishes new vault epochs (§10.2, §7.3).
struct OwnerGrants {
    /// The subject user whose secret is split (this owner's user key).
    subject: [u8; 32],
    /// The owner's chosen abort window carried in every grant (§8.5, default 72 h).
    recovery_delay: u64,
    /// One entry per trustee that was minted a grant.
    trustees: Vec<GrantedTrustee>,
    /// The announce refs last delivered in these grants. The refresh round re-issues
    /// only when the current owned-vault refs differ from these (an epoch advanced).
    refs: Vec<AnnounceRef>,
}

/// One trustee holding an owner-minted grant: its identity + node hints (for the
/// co-trustee roster and delivery dial) plus its own share, re-signed into a
/// refreshed grant when the refs advance. The share is a secret kept in memory
/// beside `k_root`/`vault_keys`; no weaker than already holding the split source.
struct GrantedTrustee {
    user: [u8; 32],
    node: [u8; 32],
    relay_url: Option<String>,
    share: Share,
    /// Whether the last delivery to this trustee succeeded (surfaced on the status
    /// view so an operator sees which trustees actually hold a current grant).
    delivered: bool,
}

/// One trustee's inputs to a grant refresh: its roster entry, resolved dial address,
/// its own share (re-signed into the refreshed grant), and its prior delivery flag.
type TrusteeJob = (CoTrustee, Option<EndpointAddr>, Share, bool);

/// One recovery set's grant-refresh job, snapshotted off-lock:
/// `(rsid, subject, recovery_delay, fresh announce refs, per-trustee jobs)`.
type RefreshJob = (u64, [u8; 32], u64, Vec<AnnounceRef>, Vec<TrusteeJob>);

/// One owner-side recovery split: the scope it splits (identity `K_root` or a scoped
/// `K_vaultroot(vid)`) and the open Chela [`SplitState`] to extend from.
struct RecoverySet {
    scope: RecoveryScope,
    state: carapace_recovery::SplitState,
}

/// What a recovery split targets (§8.2). The inner circle splits `K_root` (a full
/// door to the identity); a scoped set splits `K_vaultroot(vid)` (a quorum recovers
/// that vault only, never the identity).
#[derive(Clone, Copy, Debug)]
pub enum RecoveryScope {
    /// Split the identity master key `K_root` (§8.1).
    Root,
    /// Split `K_vaultroot(vid)` for one vault only (§8.2).
    Vault([u8; 32]),
}

/// How a node authenticated itself on this daemon's `carapace/1` control stream,
/// used by the blob-read gate ([`authorize_fetch`]) to bind a raw `iroh-blobs`
/// dialer's NodeID to a verified identity.
#[derive(Clone, Copy, Debug)]
enum BlobAuth {
    /// A delegated device of our own user (the self branch of `authorize_dialer`).
    OwnDevice,
    /// A delegated device of the named established friend (the friend branch).
    Friend([u8; 32]),
    /// A delegated device of a vault OWNER we store replicas for, authenticated by a
    /// self-consistent card the dialer presented (its user is an owner in
    /// `replica_owner`). Grants nothing on our own owned chunks; only unlocks that
    /// owner's replica-held chunks (§7.4 a, W8). Used for an owner device this
    /// replica does not otherwise know (not enumerated in the stored friend card).
    ReplicaDevice([u8; 32]),
}

/// The `carapace/1` control-stream handler. It authenticates the dialer against
/// the TLS-verified remote node id, then dispatches on the first frame:
///
/// - `ContactCard` (type 2): a document pull. The dialer presents its card; the
///   handler serves cards/announces/grants **only** if that card is validly
///   self-signed, its user is this daemon's own user or an established friend,
///   and it delegates the connection's authenticated remote node id (W5). Every
///   other dialer gets nothing beyond the `Hello`.
/// - `FriendRequest` (type 3): the acceptor half of the §9.2 handshake, gated by
///   a single-use ticket this daemon issued rather than by friendship.
/// - `ReplicaInvite` (type 10): the storage-peer half of §10.1 placement, gated
///   on the inviting owner being an established friend (or self).
#[derive(Clone)]
struct ControlHandler {
    hello: Hello,
    node_key: SigningKey,
    user_key: SigningKey,
    self_user: [u8; 32],
    blobs: IrohBlobStore,
    shared: Arc<RwLock<Shared>>,
    /// Default per-friend storage grant (bytes) recorded when this node ACCEPTS a
    /// friend request (`serve_friend_accept`). The per-friend grant is what
    /// `serve_replica_store` later enforces as that friend's replica quota (W1);
    /// the initiating `befriend` path can agree a different amount explicitly.
    default_grant_bytes: u64,
    /// Injector for peer addressing hints + relay URLs into the live endpoint, so
    /// a friend's card learned on the accept path teaches this node how to dial
    /// them back by node id via hole-punch/relay (§6).
    hints: PeerHints,
    /// Shared with the owning [`Daemon`]: the rollback-guarded store of documents
    /// learned from peers (W2). `serve_docs` re-serves the third-party cards +
    /// announces here so an owner's `VaultAnnounce` reaches a friend-of-a-friend
    /// (anti-entropy store-and-forward, §6), and consults the newest stored self-card
    /// so a revoked own device presenting an old self-card is refused (W7).
    docs: Arc<Mutex<DocStore>>,
}

impl ControlHandler {
    async fn serve(&self, conn: Connection) -> Result<()> {
        let remote = *conn.remote_id().as_bytes();
        let (mut send, mut recv) = conn.accept_bi().await?;

        match read_frame_raw(&mut recv).await? {
            Some((ContactCard::TYPE, body)) => {
                let card = ContactCard::from_map(body)?;
                self.serve_docs(&card, &remote, &mut send).await?;
            }
            Some((FriendRequest::TYPE, body)) => {
                let req = FriendRequest::from_map(body)?;
                self.serve_friend_accept(req, &mut send, &mut recv).await?;
            }
            Some((ReplicaInvite::TYPE, body)) => {
                let inv = ReplicaInvite::from_map(body)?;
                self.serve_replica_store(inv, &remote, &mut send, &mut recv)
                    .await?;
            }
            Some((ShareAttestChallenge::TYPE, body)) => {
                let ch = ShareAttestChallenge::from_map(body)?;
                self.serve_attest(ch, &remote, &mut send).await?;
            }
            Some((ShareGrant::TYPE, body)) => {
                let grant = ShareGrant::from_map(body)?;
                self.serve_grant(grant, &remote, &mut send).await?;
            }
            // Unknown/legacy first frame (or a bare Hello): reveal only the Hello.
            _ => {
                write_msg(&mut send, &self.hello).await?;
                send.finish()?;
            }
        }
        conn.closed().await;
        Ok(())
    }

    /// Serve the document set iff the presented card authorizes the connection's
    /// authenticated remote node id (W5). Unauthorized dialers get only the Hello.
    ///
    /// Beyond this node's own cards/announces/grants, an authorized friend also
    /// receives the third-party cards + announces this node learned from other
    /// friends (anti-entropy store-and-forward, §6/W7): an owner's `VaultAnnounce`
    /// reaches a trustee through any mutual friend, and a returning node re-syncs the
    /// graph from any one friend. The forwarded set is version/epoch deduped and
    /// rollback-guarded per signer by the receiver's own [`DocStore`].
    async fn serve_docs(
        &self,
        card: &ContactCard,
        remote: &[u8; 32],
        send: &mut SendStream,
    ) -> Result<()> {
        write_msg(send, &self.hello).await?;

        let now = unix_now();
        // Snapshot the forwardable third-party docs + newest stored self-card under the
        // docs lock FIRST, then take the shared lock — never nested, matching
        // `sync_impl`'s docs-before-shared order (no lock held across an `.await`).
        let (fwd_cards, fwd_announces, newest_self) = {
            let d = self.docs.lock().expect("docs lock");
            (
                d.cards().cloned().collect::<Vec<_>>(),
                d.announces().cloned().collect::<Vec<_>>(),
                d.card(&self.self_user).cloned(),
            )
        };

        let (authorized, cards, announces, grants) = {
            // W5: classify the dialer against its authenticated remote node id. On
            // success, record the classification so the blob-read gate can bind this
            // node's later raw iroh-blobs fetches to a verified identity (§7.4/D3).
            let mut s = self.shared.write().expect("shared lock");
            match classify_dialer(&s, &self.self_user, card, remote, now, newest_self.as_ref()) {
                Some(auth) => {
                    s.blob_auth.insert(*remote, auth);
                    (true, s.cards.clone(), s.announces.clone(), s.grants.clone())
                }
                None => {
                    // W8/§7.4 a: even a dialer we serve no documents to may be a
                    // delegated device of an owner whose vault we replicate. Record
                    // that classification so its later raw iroh-blobs fetches of that
                    // owner's replica-held chunks are admitted - and nothing else.
                    if let Some(owner) = replica_owner_device(&s, card, remote, now) {
                        s.blob_auth.insert(*remote, BlobAuth::ReplicaDevice(owner));
                    }
                    (false, Vec::new(), Vec::new(), Vec::new())
                }
            }
        };
        if !authorized {
            send.finish()?;
            return Ok(());
        }
        // Own docs first, then the learned third-party docs we re-serve. Overlap is
        // harmless: the receiver dedups/rolls-back per signer.
        for card in &cards {
            write_msg(send, card).await?;
        }
        for card in &fwd_cards {
            write_msg(send, card).await?;
        }
        for ann in &announces {
            write_msg(send, ann).await?;
        }
        for ann in &fwd_announces {
            write_msg(send, ann).await?;
        }
        for grant in &grants {
            write_msg(send, grant).await?;
        }
        send.finish()?;
        Ok(())
    }

    /// Acceptor half of the friend handshake (§9.2). The requester drove the
    /// `FriendRequest`; here we pick `established`, run the interactive
    /// countersignature round-trip, redeem the ticket, and reply `FriendAccept`,
    /// persisting the dual-signed `Friendship` and the requester's card.
    async fn serve_friend_accept(
        &self,
        req: FriendRequest,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let now = unix_now();
        // W1: verify the request (outer node sig + embedded card + delegation).
        let requester_user = verify_friend_request(&req, now)
            .map_err(|e| anyhow::anyhow!("friend request rejected: {e}"))?;

        // Acceptor picks `established`; the requester must countersign the same
        // core over the wire (never the requester's private key locally).
        let established = now;
        write_u64(send, established).await?;
        let countersig = read_sig(recv).await?;

        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };

        // Redeem + assemble under the write lock (all synchronous, no await).
        let accept = {
            let mut s = self.shared.write().expect("shared lock");
            let (accept, friendship) = accept_friend_request(
                &req,
                &mut s.tickets,
                now,
                &self.node_key,
                &self.user_key,
                &own_card,
                established,
                |_core| countersig,
            )
            .map_err(|e| anyhow::anyhow!("friend accept failed: {e}"))?;
            s.friendships.insert(requester_user, friendship);
            s.friends.insert(requester_user, req.card.clone());
            // Agree a per-friend replica-storage grant at add-friend time. On the
            // accept path we grant this node's configured default; the initiating
            // `befriend` path can agree a different amount explicitly.
            s.friend_grants
                .insert(requester_user, self.default_grant_bytes);
            accept
        };

        // §6: learn how to reach this new friend by node id (their direct addrs
        // and self-hosted relay), so we can dial them back via hole-punch/relay.
        learn_card_hints(&self.hints, &req.card).await;

        write_msg(send, &accept).await?;
        send.finish()?;
        Ok(())
    }

    /// Storage-peer half of replica placement (§10.1). Verifies the owner's
    /// invite, requires the inviting owner to be an established friend (or self),
    /// consents per local policy, then receives the pushed envelope + chunks into
    /// the served blob store so this daemon can serve them to authorized peers.
    async fn serve_replica_store(
        &self,
        inv: ReplicaInvite,
        remote: &[u8; 32],
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let now = unix_now();
        inv.verify()
            .map_err(|e| anyhow::anyhow!("replica invite bad sig: {e}"))?;

        // Authorize the inviting owner and rate-limit its push under one write
        // lock (all synchronous; the lock is released before any `.await`). The
        // invite signer must be an established friend (or our own device) AND the
        // connection's authenticated peer, and it must have rate-budget for the
        // advertised size (W1: a single friend cannot flood the store).
        let (admitted, owner_user) = {
            let mut s = self.shared.write().expect("shared lock");
            // The inviting owner must be an established friend (or our own device);
            // resolve it to the owner's *user* pubkey so the blob-read gate can later
            // admit that owner's delegated devices (§7.4 a, W8).
            let owner_user = owner_user_of_node(&s, &self.self_user, &inv.by, now);
            let admitted = owner_user.is_some()
                && inv.by == *remote
                && s.rate.allow(*remote, now, inv.approx_bytes);
            (admitted, owner_user)
        };
        if !admitted {
            send.finish()?; // decline: no accept frame
            return Ok(());
        }

        // W1 + per-friend grant: the storage quota is the limit THIS node agreed to
        // grant the inviting friend at add-friend time (looked up by the friend's
        // user pubkey via the node that signed the invite), NOT a global default. A
        // placement larger than that friend's grant is declined outright. A node
        // with no friend record falls back to DEFAULT_QUOTA_BYTES defensively (S4
        // already gates placement on friendship, so this should not be reached).
        let grant = {
            let s = self.shared.read().expect("shared lock");
            friend_storage_grant(&s, &inv.by, now)
        };
        let Some(quota) = Policy::with_quota(grant).grant(inv.approx_bytes) else {
            send.finish()?;
            return Ok(());
        };
        let mut accept = ReplicaAccept {
            vid: inv.vid,
            quota_bytes: quota,
            by: [0; 32],
            sig: [0; 64],
        };
        accept.sign(&self.node_key);
        write_msg(send, &accept).await?;

        // The owner pushes the current owner-signed VaultAnnounce so this replica
        // learns the replica set it belongs to (§7.4 b, W8). Verify it binds the
        // inviting owner and this vault before trusting its member list.
        let announce = read_msg::<VaultAnnounce>(recv).await?;
        announce
            .verify()
            .map_err(|e| anyhow::anyhow!("replica announce bad sig: {e}"))?;
        ensure!(
            announce.vid == inv.vid,
            "replica announce named a different vault"
        );
        ensure!(
            announce.by == inv.by,
            "replica announce signer is not the inviting owner"
        );

        // Receive the pushed blobs: envelope first (verified), then each chunk.
        // W1: cap the blob count and track the running received-byte total for this
        // (peer, vid), aborting the moment it would exceed the advertised size
        // (which is <= the granted quota). The store never grows past the quota.
        let count = read_u64(recv).await?;
        ensure!(
            count <= MAX_REPLICA_BLOBS,
            "replica push declared {count} blobs, over the cap of {MAX_REPLICA_BLOBS}"
        );
        let mut received: u64 = 0;
        // S3: do not pre-reserve `count` (peer-declared, up to MAX_REPLICA_BLOBS): a
        // tiny push could force a ~32 MiB reservation. Grow as blobs arrive; the real
        // bound is the `received <= inv.approx_bytes` byte cap below.
        let mut stored: Vec<[u8; 32]> = Vec::new();
        for i in 0..count {
            let bytes = read_blob(recv).await?;
            received = received.saturating_add(bytes.len() as u64);
            ensure!(
                received <= inv.approx_bytes,
                "replica push exceeded its advertised {} bytes",
                inv.approx_bytes
            );
            if i == 0 {
                let env = ManifestEnvelope::from_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("replica envelope decode: {e}"))?;
                env.verify()
                    .map_err(|e| anyhow::anyhow!("replica envelope bad sig: {e}"))?;
            }
            // The iroh blob hash is the ChunkID (and the envelope digest for i==0);
            // record it so the fetch gate can bind it to this replica-held vault (W8).
            stored.push(self.blobs.add(&bytes).await?);
        }
        {
            let mut s = self.shared.write().expect("shared lock");
            s.held.insert(inv.vid);
            if let Some(owner) = owner_user {
                s.replica_owner.insert(inv.vid, owner);
            }
            s.replica_members.insert(inv.vid, announce.replicas.clone());
            for h in &stored {
                s.replica_chunks.insert(*h, inv.vid);
            }
        }
        // Ack: tell the owner storage is durable before it records membership.
        write_u64(send, count).await?;
        send.finish()?;
        Ok(())
    }

    /// Trustee half of the §10.2 share-health cadence: answer an owner's
    /// `ShareAttestChallenge` for a share this daemon holds. The challenge signer
    /// must be an established friend (or our own device) AND the connection's
    /// authenticated peer, so only the owning friend can probe liveness. The reply
    /// echoes label fields only (`card_number` + nonce) via
    /// [`carapace_recovery::answer_attest_challenge`] - never the share words. A
    /// daemon holding no share for the named set, or holding a corrupt one,
    /// finishes the stream with no attestation frame (a silent non-answer, which the
    /// owner counts as "not live").
    async fn serve_attest(
        &self,
        ch: ShareAttestChallenge,
        remote: &[u8; 32],
        send: &mut SendStream,
    ) -> Result<()> {
        let now = unix_now();
        ch.verify()
            .map_err(|e| anyhow::anyhow!("attest challenge bad sig: {e}"))?;

        // Copy the share out under the read lock; answer (and await the write)
        // outside it so no lock is held across `.await`.
        let share = {
            let s = self.shared.read().expect("shared lock");
            let authorized =
                node_is_authorized(&s, &self.self_user, &ch.by, now) && ch.by == *remote;
            if !authorized {
                None
            } else {
                s.held_shares.get(&ch.rsid).map(|(share, _)| share.clone())
            }
        };
        if let Some(share) = share {
            if let Ok(att) = answer_attest_challenge(&self.node_key, &ch, &share) {
                write_msg(send, &att).await?;
            }
        }
        send.finish()?;
        Ok(())
    }

    /// Trustee half of grant delivery (§8, W3): receive a `ShareGrant` an owner
    /// minted for us and, if it is authentic, store the FULL grant (roster +
    /// recovery_delay + announce refs) keyed by its subject user - not a bare share,
    /// which locates nothing without a live owner. Two independent checks must pass:
    ///
    /// - the grant's own signature verifies AND its embedded share decodes (the
    ///   words' CRC self-validates), via [`verify_share_grant`]; and
    /// - the connection's authenticated peer signed the grant (`grant.by == remote`)
    ///   and is an established friend (or our own device) - so only a friend we chose
    ///   as our owner can plant a grant on us (delegation gate, mirrors `serve_attest`).
    ///
    /// On success the embedded share is ALSO recorded in `held_shares` so the existing
    /// attestation cadence + local self-validation keep working. A grant that fails
    /// either check is dropped with no ack frame (a silent decline). The owner learns
    /// delivery succeeded from the ack.
    async fn serve_grant(
        &self,
        grant: ShareGrant,
        remote: &[u8; 32],
        send: &mut SendStream,
    ) -> Result<()> {
        let now = unix_now();
        // Signature + embedded-share (CRC) verification. A tampered grant or a
        // corrupt share is rejected here before anything is stored.
        let share = match verify_share_grant(&grant) {
            Ok(share) => share,
            Err(_) => {
                send.finish()?; // decline: no ack frame
                return Ok(());
            }
        };
        let rsid = u64::from(share.recovery_set_id);

        let stored = {
            let mut s = self.shared.write().expect("shared lock");
            // Delegation gate: the owner node that signed the grant must be the
            // connection's authenticated peer AND an established friend (or ours).
            let authorized =
                grant.by == *remote && node_is_authorized(&s, &self.self_user, remote, now);
            if !authorized {
                false
            } else {
                let subject = grant.subject;
                s.held_grants.insert(subject, grant);
                // Keep the existing share self-validation + attestation-answer path
                // working: the embedded share is the authoritative object the words
                // carry. Preserve any existing monitor's cadence state.
                s.held_shares
                    .entry(rsid)
                    .and_modify(|(sh, _)| *sh = share.clone())
                    .or_insert_with(|| (share.clone(), ShareMonitor::new()));
                true
            }
        };
        if stored {
            write_u64(send, 1).await?; // ack: the grant is held
        }
        send.finish()?;
        Ok(())
    }
}

impl std::fmt::Debug for ControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlHandler")
            .field("self_user", &hex32(&self.self_user))
            .finish()
    }
}

impl ProtocolHandler for ControlHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.serve(conn)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// A running Carapace daemon for one device.
pub struct Daemon {
    ep: CarapaceEndpoint,
    blobs: IrohBlobStore,
    shared: Arc<RwLock<Shared>>,
    node_key: SigningKey,
    user_key: SigningKey,
    k_root: Zeroizing<[u8; 32]>,
    /// Persistent per-signer document rollback state (cards by version, announces
    /// by epoch), kept across `sync_from` calls for the daemon's lifetime so a
    /// stale replica cannot roll an already-seen epoch back (W2). Held only for
    /// synchronous verification work; never locked across an `.await`.
    ///
    /// ponytail: in-memory, daemon-lifetime state. The blob store is also
    /// in-memory, so nothing survives a restart anyway; persist to disk here and
    /// in the blob store together if durable rollback across restarts is needed.
    docs: Arc<Mutex<DocStore>>,
    /// Per-vault publish serialization (§11 / MAJOR 5). A vault's whole publish -
    /// read-prev, ingest, commit - runs under its own async lock so the watcher's
    /// background `publish_vault` and a sync's `publish_merged`/baseline-persist can
    /// never interleave on the same vid (no lost update, no two digests at one
    /// epoch, no re-ingest of a half-written merged tree). The outer `Mutex` only
    /// guards the get-or-insert of the per-vid lock; it is never held across an
    /// `.await`. ponytail: grows one entry per distinct owned/synced vid over the
    /// daemon's life; prune alongside vault teardown if that is ever added.
    publish_locks: Mutex<HashMap<[u8; 32], Arc<tokio::sync::Mutex<()>>>>,
    /// Per-subject recovery-open rate limiter (§8.5): a forged/abusive `RecoveryOpen`
    /// cannot exhaust an honest subject's budget. Single long-lived limiter guarded by
    /// its own mutex so `ceremony_open` can charge it without touching `shared`.
    recovery_limiter: Mutex<RecoveryRateLimiter>,
    /// This node's own advertised relay URL, set iff it runs the embedded relay
    /// (§6). Populated into its ContactCard `NodeEntry.relay_url` and issued
    /// tickets' `relay_urls` so friends learn a relay through which to reach it.
    advertised_relay: Option<RelayUrl>,
    /// The embedded relay server, held to keep it running for the daemon's life.
    _relay: Option<CarapaceRelay>,
    _router: Router,
}

/// Handle for a live §11 filesystem watcher started by [`Daemon::watch_vault`].
///
/// Keep it alive to keep watching; drop it to stop. Drop halts the underlying
/// `notify` watcher (closing the event channel) and aborts the debounce/re-ingest
/// task, so shutdown is clean and cancel-safe (no lock is held across an `.await`
/// in that task).
pub struct VaultWatcher {
    // Field order matters for Drop: the notify watcher is dropped first (below via
    // the generated Drop glue after our explicit `drop` impl runs), closing the
    // event channel. Held to keep fs events flowing while the handle lives.
    _watcher: notify::RecommendedWatcher,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for VaultWatcher {
    fn drop(&mut self) {
        // Abort the re-ingest task; dropping `_watcher` afterwards closes the
        // channel. Abort is safe here: publish_vault holds the `shared` lock only
        // for synchronous critical sections, never across an `.await`.
        self.task.abort();
    }
}

/// Handle for the background maintenance loop started by [`Daemon::run_maintenance`]
/// (§10.1/§10.2). Keep it alive to keep the loop running; drop it (or call
/// [`MaintenanceHandle::stop`]) to tear the loop down.
///
/// The loop task holds only a [`Weak`] to the daemon and upgrades it per round, so it
/// never keeps the daemon alive: once the last `Arc<Daemon>` is dropped the loop ends
/// on its own. Drop aborts the task; this is cancel-safe because every maintenance
/// action releases its locks before each `.await` (no lock is held across a network
/// round-trip), so an abort mid-round only drops an in-flight future.
pub struct MaintenanceHandle {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MaintenanceHandle {
    /// Stop the loop and await its full teardown, so the caller can then reclaim the
    /// sole `Arc<Daemon>` (e.g. `Arc::try_unwrap` + [`Daemon::shutdown`]) with no
    /// lingering strong reference held by an in-flight round.
    pub async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for MaintenanceHandle {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Daemon {
    /// Bind the endpoint from `state`, start serving the blob store and the
    /// `carapace/1` control protocol, and publish this device's `ContactCard`
    /// (with a user-signed delegation of the node key). Uses the default
    /// [`ReplicaLimits`]; see [`Daemon::start_with_limits`] to tune them.
    pub async fn start(state: State) -> Result<Self> {
        Self::start_with_limits(state, ReplicaLimits::default()).await
    }

    /// Like [`Daemon::start`] but with explicit replica-store limits (W1). Tests
    /// use this to set a small quota or a tight rate limit and exercise the
    /// cut-offs without pushing gigabytes.
    pub async fn start_with_limits(state: State, limits: ReplicaLimits) -> Result<Self> {
        Self::start_on(
            state,
            limits,
            NetConfig {
                bind: Some(std::net::SocketAddr::from((
                    std::net::Ipv4Addr::LOCALHOST,
                    0,
                ))),
                ..NetConfig::default()
            },
        )
        .await
    }

    /// Like [`Daemon::start_with_limits`] but with full network wiring
    /// ([`NetConfig`]): a caller-chosen bind, friends' self-hosted relays to
    /// consume, and optionally running this node's own embedded relay (§6). A node
    /// that runs a relay advertises its URL in its ContactCard and issued tickets
    /// and registers on it so friends can reach it via relay fallback.
    pub async fn start_on(state: State, limits: ReplicaLimits, cfg: NetConfig) -> Result<Self> {
        let node_key = state.node_key.clone();
        let user_key = state.user_key();
        let k_root = state.k_root.clone();
        let self_user = user_key.verifying_key().to_bytes();
        let self_node = node_key.verifying_key().to_bytes();

        // The friend/replica state the relay's access gate and the daemon's
        // handlers share. Created up front so the relay can be friend-gated
        // against the live friend set (C1).
        let shared = Arc::new(RwLock::new(Shared::default()));

        // Run the embedded relay first (if requested) so its URL can be folded
        // into both the endpoint's relay set (as this node's home relay) and the
        // advertised card/tickets. C1: the relay is friend-gated - it admits only
        // this node's own devices and established friends' delegated nodes, never
        // arbitrary internet peers.
        let relay = match cfg.run_relay {
            Some(bind) => {
                let access = Arc::new(FriendRelayGate {
                    shared: Arc::clone(&shared),
                    self_user,
                    self_node,
                });
                Some(CarapaceRelay::start(bind, access).await?)
            }
            None => None,
        };
        let advertised_relay = match &relay {
            Some(r) => Some(relay_advert_url(r, cfg.relay_host.as_deref())?),
            None => None,
        };

        // The endpoint's usable relay set: friends' relays plus our own (so we
        // register on it and advertise it as our home relay).
        let mut relays = cfg.relays.clone();
        if let Some(url) = &advertised_relay {
            if !relays.contains(url) {
                relays.push(url.clone());
            }
        }

        // Default bind: loopback for a plain in-process node, but all-interfaces
        // once relays are in play so the portmapper can open our port.
        let bind = cfg.bind.unwrap_or_else(|| {
            if relay.is_some() || !relays.is_empty() {
                std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
            } else {
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0))
            }
        });

        let ep = CarapaceEndpoint::bind_on(&node_key, bind, &relays).await?;
        let blobs = IrohBlobStore::new();

        // This device's ContactCard: one node entry, user-signed delegation, and
        // (if we run a relay) our advertised relay URL so friends learn it (§6).
        let card = build_card(
            &user_key,
            &node_key,
            &k_root,
            advertised_relay.as_ref().map(|u| u.to_string()),
        );
        {
            let mut s = shared.write().expect("shared lock");
            s.cards.push(card);
            s.rate = RateLimiter::new(limits.rate_capacity, limits.rate_refill_per_sec);
        }

        // The rollback-guarded document store, shared between the daemon's own pull
        // path (`sync_from`) and the accept handler's `serve_docs` so learned docs are
        // re-served during anti-entropy (store-and-forward, §6/W7).
        let docs = Arc::new(Mutex::new(DocStore::new()));

        let hello = Hello {
            protocol: 1,
            card_version: 1,
            roles: 1,
        };
        let handler = ControlHandler {
            hello,
            node_key: node_key.clone(),
            user_key: user_key.clone(),
            self_user,
            blobs: blobs.clone(),
            shared: Arc::clone(&shared),
            default_grant_bytes: limits.quota_bytes,
            // Feed hints from friend cards learned on the accept path (§6).
            hints: ep.hints(),
            docs: Arc::clone(&docs),
        };
        // §7.4 / D3 fetch authorization (closes S5 for owned granted content): the
        // blob store no longer answers `iroh_blobs::ALPN` fetches from any dialer.
        // Every get-request is gated by `authorize_fetch` against the dialer's
        // authenticated node id and the requested ChunkID. Owner-served chunks of a
        // vault we own are released only to our own delegated devices, this vault's
        // replica-set members, or a friend authenticated as a member of a grant's
        // audience covering that chunk — so a leaked grant document alone (presented
        // by a non-audience party) authorizes nothing.
        //
        // W8/§7.4 replica gate: chunks we hold *as a replica* for another owner are
        // no longer on the inherited residual. `authorize_fetch` serves them only to
        // that vault owner's delegated devices (proved by the card the dialer
        // presents on our control stream) or a current replica-set member from the
        // owner's announce — an arbitrary dialer is refused.
        let gate_shared = Arc::clone(&shared);
        let events = authorizing_event_sender(move |node, chunk_id| {
            let s = gate_shared.read().expect("shared lock");
            authorize_fetch(&s, &node, &chunk_id)
        });
        let router = Router::builder(ep.endpoint().clone())
            .accept(
                iroh_blobs::ALPN,
                BlobsProtocol::new(blobs.mem(), Some(events)),
            )
            .accept(ALPN, handler)
            .spawn();

        Ok(Self {
            ep,
            blobs,
            shared,
            node_key,
            user_key,
            k_root,
            docs,
            publish_locks: Mutex::new(HashMap::new()),
            // §8.5: at most 5 recovery opens per subject per 24 h window.
            recovery_limiter: Mutex::new(RecoveryRateLimiter::new(24 * 3600, 5)),
            advertised_relay,
            _relay: relay,
            _router: router,
        })
    }

    /// This device's node id (= iroh endpoint id).
    pub fn node_id(&self) -> [u8; 32] {
        self.ep.node_id()
    }

    /// A directly dialable address for this daemon (localhost).
    pub fn addr(&self) -> Result<EndpointAddr> {
        self.ep.direct_addr()
    }

    /// Mint a new vault id for this user (persist the returned nonce out of band
    /// if you need to re-derive the vid later).
    pub fn new_vid(&self) -> ([u8; 32], [u8; 16]) {
        new_vid(&self.user_key.verifying_key().to_bytes())
    }

    /// The per-vid publish lock (§11 / MAJOR 5), created on first use. Held across
    /// the WHOLE of `publish_vault` and a sync's apply phase so those two paths
    /// serialize on a vid and never clobber each other's read-prev -> commit.
    fn publish_lock(&self, vid: [u8; 32]) -> Arc<tokio::sync::Mutex<()>> {
        self.publish_locks
            .lock()
            .expect("publish_locks")
            .entry(vid)
            .or_default()
            .clone()
    }

    /// Ingest `src` into vault `vid`: (re-)chunk + seal every file, load the
    /// ciphertext + manifest envelope into the served blob store, seal a
    /// per-chunk access grant, and publish a freshly signed `VaultAnnounce` +
    /// `FileGrant`. Records `src` as this vault's authoritative working directory
    /// (§11), so a later sync reconstructs the merged result back into the same
    /// tree this ingest reads.
    ///
    /// Bumps the vault's epoch and republishes ONLY when the re-ingested tree
    /// differs from the last published manifest. A no-op re-ingest (e.g. the
    /// watcher firing on the daemon's own just-applied merge, whose files and
    /// mtimes round-trip exactly) returns the current epoch WITHOUT a bump, so the
    /// per-signer announce line stays monotonic and two devices converge instead of
    /// ping-ponging epochs. Returns the vault's epoch.
    ///
    /// The whole read-prev -> ingest -> commit runs under the vid's publish lock so
    /// it serializes with a concurrent sync `publish_merged` on the same vid
    /// (MAJOR 5): no lost update, and never two different digests at one epoch.
    ///
    /// ponytail: ingest runs inline on the async worker (fine for a demo); a
    /// production daemon would `spawn_blocking` the heavy CPU/IO path.
    pub async fn publish_vault(&self, src: &Path, vid: [u8; 32]) -> Result<u64> {
        let lock = self.publish_lock(vid);
        let _publish = lock.lock().await;

        let vkeys = VaultKeys::derive(&*self.k_root, vid);
        let (cur_epoch, prev) = {
            let mut s = self.shared.write().expect("shared lock");
            // §11: this source IS the vault's authoritative working directory
            // (watched + sync target). A publish declares it, so overwrite any prior
            // (e.g. a first-sync fallback) - a later sync reconstructs merges here.
            s.working_dirs.insert(vid, src.to_path_buf());
            let cur = *s.epochs.get(&vid).unwrap_or(&0);
            // §11: carry the previously-published manifest so a re-ingest bumps
            // this device's per-file version-vector component on real changes
            // (and tombstones local deletions), making a concurrent edit on
            // another owner device detectable at merge time.
            let prev = s.vault_blobs.get(&vid).map(|vb| vb.manifest.clone());
            (cur, prev)
        };
        let epoch = cur_epoch + 1;

        // Ingest into a plain in-memory store, then mirror blobs into iroh.
        let mut mem = MemoryStore::new();
        let ingest = ingest_dir(src, &self.node_key, &vkeys, epoch, prev.as_ref(), &mut mem)?;

        // No-op guard: if the re-ingested file set is byte-for-byte identical to
        // what we last published (same paths, hashes, mtimes, per-file VVs), there
        // is nothing to propagate. Do NOT bump the epoch or republish - this is the
        // watcher re-observing the daemon's own just-written merged/reconstructed
        // tree, and republishing it would spuriously advance the announce line.
        if let Some(prevm) = &prev {
            if ingest.manifest.files == prevm.files {
                return Ok(cur_epoch);
            }
        }

        let env_digest = self.blobs.add(&ingest.envelope.to_bytes()).await?;
        ensure!(
            env_digest == ingest.digest,
            "envelope blob hash != manifestDigest"
        );
        for f in &ingest.manifest.files {
            for (id, _len) in &f.chunks {
                let ct = carapace_vault::ChunkStore::get(&mem, id)?
                    .with_context(|| "chunk missing from source store")?;
                let h = self.blobs.add(&ct).await?;
                ensure!(&h == id, "iroh blob hash != carapace ChunkID");
            }
        }

        // Seal the per-chunk access grant to the user's disclosure key.
        let grant = self.build_file_grant(&ingest.manifest, &ingest.keys, vid, epoch)?;

        // Record the blob source (digest + unique ChunkIDs) so replica placement
        // can push a full copy later without re-ingesting.
        let mut seen = HashSet::new();
        let mut chunk_ids = Vec::new();
        for f in &ingest.manifest.files {
            for (id, _len) in &f.chunks {
                if seen.insert(*id) {
                    chunk_ids.push(*id);
                }
            }
        }

        let mut s = self.shared.write().expect("shared lock");
        // Commit the bumped epoch (read-prev..commit is atomic under the vid lock).
        s.epochs.insert(vid, epoch);
        // W2: retain every published ChunkID in the owner-gated set across epoch
        // bumps, so superseded chunks keep the §7.4 owner gate (see `owned_chunks`).
        for id in &chunk_ids {
            s.owned_chunks.insert(*id, vid);
        }
        s.vault_blobs.insert(
            vid,
            VaultBlobs {
                digest: ingest.digest,
                chunk_ids,
                manifest: ingest.manifest.clone(),
            },
        );
        // Retain the per-chunk secrets so a later `disclose_files` can seal a subset
        // of files into a friend-facing grant without re-ingesting (§7.4).
        s.vault_keys.insert(vid, ingest.keys);
        let replicas = replica_list(self.node_id(), s.members.get(&vid));
        let mut ann = VaultAnnounce {
            vid,
            epoch,
            replicas,
            digest: ingest.digest,
            by: [0; 32],
            sig: [0; 64],
        };
        ann.sign(&self.node_key);
        // Replace any older announce/grant for this vid (monotonic epoch).
        s.announces.retain(|a| a.vid != vid);
        s.announces.push(ann);
        s.grants.retain(|g| g.vid != vid);
        s.grants.push(grant);
        Ok(epoch)
    }

    /// §11 / W12: start a debounced filesystem watcher over `src` that re-ingests
    /// vault `vid` (via [`Daemon::publish_vault`]) whenever files under it change,
    /// giving Dropbox-like live sync (new chunks + epoch++ manifest, pushed and
    /// announced to replicas and other owner devices).
    ///
    /// Consumes a cloned `Arc<Daemon>` and holds only a [`std::sync::Weak`] to it, so the
    /// returned [`VaultWatcher`] never keeps the daemon alive — a caller can still
    /// `Arc::try_unwrap` + [`Daemon::shutdown`]. Drop the [`VaultWatcher`] to stop
    /// watching; that halts fs events and cancels the re-ingest task.
    ///
    /// ponytail: re-ingests the *whole* vault on any change (matches the existing
    /// one-shot `publish_vault`); a large-vault deployment would want incremental,
    /// per-file re-chunking driven off the event paths.
    pub fn watch_vault(self: Arc<Self>, vid: [u8; 32], src: PathBuf) -> Result<VaultWatcher> {
        use notify::{event::EventKind, recommended_watcher, RecursiveMode, Watcher};

        // Unbounded but each item is zero-sized: an event storm costs bytes, and
        // the debounce loop collapses the whole backlog into a single re-ingest.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let mut watcher = recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                // Skip pure access/open events: only content-affecting changes
                // (create/modify/remove/rename) should trigger a re-ingest.
                if !matches!(ev.kind, EventKind::Access(_)) {
                    let _ = tx.send(());
                }
            }
        })
        .context("create filesystem watcher")?;
        watcher
            .watch(&src, RecursiveMode::Recursive)
            .with_context(|| format!("watch {}", src.display()))?;

        // Hold only a Weak so the watcher task can't block daemon shutdown.
        let weak = Arc::downgrade(&self);
        drop(self);
        let task = tokio::spawn(async move {
            loop {
                // Block until the first change of a new batch.
                if rx.recv().await.is_none() {
                    break; // watcher dropped -> channel closed
                }
                // Debounce: extend the window on every follow-up event; re-ingest
                // only once `src` has been quiet for `WATCH_DEBOUNCE`.
                loop {
                    match tokio::time::timeout(WATCH_DEBOUNCE, rx.recv()).await {
                        Ok(Some(())) => continue, // more churn, keep waiting
                        Ok(None) => return,       // channel closed
                        Err(_) => break,          // quiet period elapsed
                    }
                }
                // Re-ingest once, sequentially — no unbounded fan-out. Upgrade the
                // Weak only for the duration of the publish so shutdown can still
                // reclaim the sole Arc.
                let Some(daemon) = weak.upgrade() else {
                    break; // daemon gone
                };
                if let Err(e) = daemon.publish_vault(&src, vid).await {
                    eprintln!(
                        "carapace watch: re-ingest of {} failed: {e:#}",
                        src.display()
                    );
                }
            }
        });
        Ok(VaultWatcher {
            _watcher: watcher,
            task,
        })
    }

    /// Test-only: advertise a node-signed (hence delegation-passing) announce +
    /// grant for `vid` at `epoch` whose manifest digest is not backed by any
    /// blob, so a peer that selects it will fail to fetch it. Used to prove one
    /// poison vault does not abort reconstruction of the others (W3).
    #[doc(hidden)]
    pub fn advertise_unfetchable_for_test(&self, vid: [u8; 32], epoch: u64) {
        let mut ann = VaultAnnounce {
            vid,
            epoch,
            replicas: vec![self.node_id()],
            digest: [0xAB; 32],
            by: [0; 32],
            sig: [0; 64],
        };
        ann.sign(&self.node_key);
        let mut grant = FileGrant {
            grant_id: [0; 16],
            vid,
            epoch,
            audience: vec![],
            sealed: vec![],
            by: [0; 32],
            sig: [0; 64],
        };
        grant.sign(&self.node_key);
        let mut s = self.shared.write().expect("shared lock");
        s.announces.retain(|a| a.vid != vid);
        s.announces.push(ann);
        s.grants.retain(|g| g.vid != vid);
        s.grants.push(grant);
    }

    /// Run anti-entropy against `peer`, then reconstruct every vault for which we
    /// received both an announce and an openable grant. Each vault is written to
    /// `out_root/<hex vid>/`. Returns the vaults reconstructed. Blobs are fetched
    /// from the same `peer` that served the documents.
    pub async fn sync_from(
        &self,
        peer: EndpointAddr,
        out_root: &Path,
    ) -> Result<Vec<Reconstructed>> {
        self.sync_impl(peer.clone(), peer, out_root).await
    }

    /// Like [`Daemon::sync_from`], but pull documents (announce + grant) from
    /// `doc_peer` while fetching the ciphertext blobs from `blob_peer` (a replica
    /// that holds them). This is how a delegated device reconstructs from a
    /// surviving replica after the owner device goes away (§10.1).
    pub async fn reconstruct_from_replica(
        &self,
        doc_peer: EndpointAddr,
        blob_peer: EndpointAddr,
        out_root: &Path,
    ) -> Result<Vec<Reconstructed>> {
        self.sync_impl(doc_peer, blob_peer, out_root).await
    }

    async fn sync_impl(
        &self,
        doc_peer: EndpointAddr,
        blob_peer: EndpointAddr,
        out_root: &Path,
    ) -> Result<Vec<Reconstructed>> {
        // ---- anti-entropy pull over the control stream ----
        // Drain the whole stream into buffers first; the verification pass below
        // runs synchronously so we never hold the doc lock across an `.await`.
        let conn = self.ep.connect(doc_peer.clone(), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        // Present our own card so the peer can authorize this pull (W5). The peer
        // serves documents only if our card's user is itself or a friend and the
        // card delegates our (TLS-authenticated) node id.
        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        write_msg(&mut send, &own_card).await?;

        let mut recv_cards: Vec<ContactCard> = Vec::new();
        let mut recv_announces: Vec<VaultAnnounce> = Vec::new();
        let mut grants: HashMap<[u8; 32], FileGrant> = HashMap::new();
        while let Some((ty, body)) = read_frame_raw(&mut recv).await? {
            match ty {
                ContactCard::TYPE => recv_cards.push(ContactCard::from_map(body)?),
                VaultAnnounce::TYPE => recv_announces.push(VaultAnnounce::from_map(body)?),
                FileGrant::TYPE => {
                    let g = FileGrant::from_map(body)?;
                    // Keep the highest-epoch grant per vid within this batch.
                    match grants.get(&g.vid) {
                        Some(prev) if g.epoch <= prev.epoch => {}
                        _ => {
                            grants.insert(g.vid, g);
                        }
                    }
                }
                _ => {}
            }
        }
        send.finish()?;

        // ---- verify (C1 delegation) + rollback (W2), under the doc lock ----
        let now = unix_now();
        let self_user = self.user_key.verifying_key().to_bytes();
        let (targets, newer_cards) = {
            let mut docs = self.docs.lock().expect("docs lock");
            // Admit cards with their own version-rollback rule; a stale/duplicate
            // card is ignored, not fatal. Collect the ones that were genuinely
            // newer so the friend address book can be refreshed (W2).
            let mut newer_cards = Vec::new();
            for card in &recv_cards {
                if matches!(docs.offer_card(card), Ok(true)) {
                    newer_cards.push(card.clone());
                }
            }
            let targets = select_targets(
                &mut docs,
                &self_user,
                &recv_cards,
                &recv_announces,
                &grants,
                now,
            );
            (targets, newer_cards)
        };

        // W2: refresh `s.friends` with rollback-guarded newer cards so a friend
        // that publishes a card dropping a device actually revokes it. The update
        // is monotonic on the friend's own stored version, so a first-seen older
        // card (accepted by the empty DocStore) cannot roll the address book back.
        if !newer_cards.is_empty() {
            let mut updated: Vec<ContactCard> = Vec::new();
            {
                let mut s = self.shared.write().expect("shared lock");
                for card in &newer_cards {
                    if let Some(existing) = s.friends.get(&card.user) {
                        if card.version > existing.version {
                            s.friends.insert(card.user, card.clone());
                            updated.push(card.clone());
                        }
                    }
                }
            }
            // §6: refresh addressing hints (relay + direct addrs) from the newer
            // cards, so a friend that moves or changes relay stays reachable.
            let hints = self.ep.hints();
            for card in &updated {
                learn_card_hints(&hints, card).await;
            }
        }

        // W8/§7.4 a: when the blobs live on a different peer (a replica), first
        // authenticate to that peer's control stream so it can classify us as a
        // delegated device of the vault owner. Without it the replica's fetch gate
        // has no identity for our node id and refuses every replica-held chunk. When
        // blob and doc peer are the same node the doc pull above already did this.
        if blob_peer.id != doc_peer.id {
            self.authenticate_to(&blob_peer).await?;
        }

        // ---- per-vault: fetch, open, reconstruct ----
        // W3: one poisoned/unfetchable vault must not abort the others; collect
        // the error and move on.
        let (disclose_priv, _disclose_pub) = self.disclose_keypair();
        let mut out = Vec::new();
        for (vid, ann, grant) in &targets {
            match self
                .reconstruct_one(&blob_peer, vid, ann, grant, &disclose_priv, out_root)
                .await
            {
                Ok(r) => out.push(r),
                Err(e) => eprintln!("carapaced: skipping vault {}: {e:#}", hex32(vid)),
            }
        }
        Ok(out)
    }

    /// Fetch, open, and reconstruct a single accepted-and-delegated vault from
    /// `blob_peer` (owner or a replica). Any failure here is contained to this
    /// vault (see `sync_impl`'s loop).
    async fn reconstruct_one(
        &self,
        blob_peer: &EndpointAddr,
        vid: &[u8; 32],
        ann: &VaultAnnounce,
        grant: &FileGrant,
        disclose_priv: &HpkePrivateKey,
        out_root: &Path,
    ) -> Result<Reconstructed> {
        let vkeys = VaultKeys::derive(&*self.k_root, *vid);

        // W8: fetch into a throwaway store, NOT `self.blobs`, which the router serves
        // over `iroh_blobs::ALPN`. Fetching the owner's/replica's ciphertext into the
        // served store would re-serve it ungated from this device (the residual
        // `authorize_fetch` `true` covers any hash absent from the owned/replica maps),
        // voiding the replica fetch gate on any device that reconstructs. We only need
        // the bytes to open the manifest and write plaintext to disk. Mirrors the PoR
        // probe's `scratch` store.
        let scratch = IrohBlobStore::new();
        // Manifest envelope by digest.
        let bconn = self.ep.connect(blob_peer.clone(), iroh_blobs::ALPN).await?;
        scratch.fetch(&bconn, ann.digest).await?;
        let env_bytes = scratch.get_bytes(ann.digest).await?;
        let envelope = ManifestEnvelope::from_bytes(&env_bytes)?;
        let incoming = open_envelope(&envelope, &vkeys.k_manifest)?;
        ensure!(&incoming.vid == vid, "envelope vid mismatch");
        // S6: the AEAD aad already binds env.epoch to the manifest; also bind the
        // independently-signed announce epoch so a higher advertised epoch cannot
        // point at a lower-epoch envelope.
        ensure!(
            incoming.epoch == ann.epoch,
            "manifest epoch != announce epoch"
        );

        // Open the grant -> per-chunk secrets for the incoming manifest.
        let incoming_keys = self.open_file_grant(grant, disclose_priv, *vid)?;

        // §11 / MAJOR 5: take the vid's publish lock BEFORE reading our local
        // baseline and hold it through the reconstruct + commit below, so a
        // concurrent `publish_vault` (e.g. the watcher firing on this same tree)
        // cannot read-prev/commit in between - that would lose an update or ingest a
        // half-written merged tree. The whole apply is serialized on the vid.
        let publish_lock = self.publish_lock(*vid);
        let _apply = publish_lock.lock().await;

        // §11: if THIS device already published (or synced) a manifest for this
        // vault, MERGE the two rather than blindly reconstructing the received one -
        // otherwise the later reconstruct silently clobbers an earlier edit and
        // drops its tombstones (W1/W12, the silent-data-loss hole). A first sync (no
        // local manifest for this vid) reconstructs as-is and records a baseline.
        let local = {
            let s = self.shared.read().expect("shared lock");
            s.vault_blobs.get(vid).map(|vb| {
                (
                    vb.manifest.clone(),
                    s.vault_keys.get(vid).cloned().unwrap_or_default(),
                )
            })
        };

        let (manifest, keys, republish, first_sync) = match local {
            // First sync: reconstruct the received manifest as-is, then persist it as
            // this device's baseline (MAJOR 4) so a later local edit diffs against it.
            None => (incoming, incoming_keys, false, true),
            // Concurrent-owner sync: reconcile per §11.
            Some((local_manifest, local_keys)) => {
                let merged = merge_manifests(&local_manifest, &incoming);
                // Only re-publish when the merge produced state we did not already
                // hold; a converged (no-op) merge must not bump the epoch, or the two
                // devices would ping-pong announces forever.
                let changed = merged.files != local_manifest.files
                    || !vv_equal(&merged.vv, &local_manifest.vv);
                let epoch = if changed {
                    local_manifest.epoch.max(incoming.epoch) + 1
                } else {
                    local_manifest.epoch
                };
                let mut authors = local_manifest.authors.clone();
                for a in &incoming.authors {
                    if !authors.contains(a) {
                        authors.push(*a);
                    }
                }
                let mut keys = local_keys;
                keys.extend(incoming_keys);
                let manifest = Manifest {
                    vid: *vid,
                    epoch,
                    authors,
                    files: merged.files,
                    vv: merged.vv,
                };
                (manifest, keys, changed, false)
            }
        };

        // Materialize every referenced chunk: chunks we already own come from our
        // served store, the peer's (conflict-loser or dominant-remote) come from the
        // blob peer. On a first sync all of them come from the peer.
        let mut store = MemoryStore::new();
        for f in &manifest.files {
            if f.deleted {
                continue;
            }
            for (id, _len) in &f.chunks {
                if carapace_vault::ChunkStore::has(&store, id)? {
                    continue;
                }
                let ct = match self.blobs.get_bytes(*id).await {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        scratch.fetch(&bconn, *id).await?;
                        scratch.get_bytes(*id).await?
                    }
                };
                carapace_vault::ChunkStore::put(&mut store, *id, ct)?;
            }
        }

        // §11 (BLOCKER 1): reconstruct into the vault's ONE authoritative working
        // directory - the same tree that is published and watched - so the merged
        // set (winner at path, losers at sync-conflict names, tombstone deletions)
        // lands where the watcher will re-observe it, keeping "absent => tombstone"
        // sound. If this device has no working dir yet (a pure receiver's first
        // sync), fall back to `out_root/<vid>` and adopt it as the working dir.
        let out_dir = {
            let mut s = self.shared.write().expect("shared lock");
            s.working_dirs
                .entry(*vid)
                .or_insert_with(|| out_root.join(hex32(vid)))
                .clone()
        };
        reconstruct(&manifest, &store, &keys, &out_dir)?;
        // §11: apply tombstone deletions so a propagated delete removes a file a
        // prior reconstruct may have written into this working dir.
        for f in &manifest.files {
            if f.deleted && manifest_rel_is_safe(&f.path) {
                let _ = std::fs::remove_file(out_dir.join(&f.path));
            }
        }

        if republish {
            // Re-publish the merged state so the other device(s) converge on it
            // (eventual consistency, §7.3): this device now serves both versions and
            // announces the reconciled manifest at a bumped epoch. Skipped on a no-op
            // merge (see `changed`) to guarantee termination.
            self.publish_merged(vid, &manifest, &keys, &store).await?;
        } else if first_sync {
            // MAJOR 4: record the reconstructed manifest + keys + epoch as this
            // device's baseline WITHOUT announcing/serving, so a later local edit
            // (or watcher re-ingest) diffs against the incoming state instead of
            // re-minting every file as new and spawning a spurious conflict copy.
            self.persist_sync_baseline(vid, &manifest, &keys, ann.digest);
        }

        Ok(Reconstructed {
            vid: *vid,
            epoch: manifest.epoch,
            out_dir,
        })
    }

    /// MAJOR 4: persist a first-sync reconstruction as this device's published
    /// baseline for `vid` (manifest + per-chunk secrets + epoch) WITHOUT touching
    /// announces/grants/owned_chunks - the device is a silent receiver until it
    /// makes a local change. `publish_vault`'s prev-diff then works against the
    /// incoming state, so an unchanged re-ingest is a no-op and a real local edit
    /// bumps cleanly instead of re-minting every file as new.
    fn persist_sync_baseline(
        &self,
        vid: &[u8; 32],
        manifest: &Manifest,
        keys: &ChunkKeys,
        digest: [u8; 32],
    ) {
        let mut seen = HashSet::new();
        let mut chunk_ids = Vec::new();
        for f in &manifest.files {
            for (id, _len) in &f.chunks {
                if seen.insert(*id) {
                    chunk_ids.push(*id);
                }
            }
        }
        let mut s = self.shared.write().expect("shared lock");
        s.epochs.insert(*vid, manifest.epoch);
        s.vault_keys.insert(*vid, keys.clone());
        s.vault_blobs.insert(
            *vid,
            VaultBlobs {
                digest,
                chunk_ids,
                manifest: manifest.clone(),
            },
        );
    }

    /// §11: adopt an already-merged manifest as this device's new published
    /// baseline for `vid` so the reconciliation propagates. Adds every referenced
    /// chunk - including the peer's just fetched into `store` - to the served blob
    /// store, seals + node-signs a fresh envelope, builds a matching grant, and
    /// replaces this vault's announce/grant/blob-source at the bumped epoch.
    async fn publish_merged(
        &self,
        vid: &[u8; 32],
        manifest: &Manifest,
        keys: &ChunkKeys,
        store: &MemoryStore,
    ) -> Result<()> {
        let vkeys = VaultKeys::derive(&*self.k_root, *vid);
        let envelope = seal_manifest(manifest, &vkeys, &self.node_key)?;
        let digest = self.blobs.add(&envelope.to_bytes()).await?;

        // Load every referenced chunk into the served store so this device can serve
        // the reconciled manifest to its peers (both its own and the peer's copies).
        let mut seen = HashSet::new();
        let mut chunk_ids = Vec::new();
        for f in &manifest.files {
            if f.deleted {
                continue;
            }
            for (id, _len) in &f.chunks {
                if !seen.insert(*id) {
                    continue;
                }
                let ct = carapace_vault::ChunkStore::get(store, id)?
                    .with_context(|| "merged chunk missing from store")?;
                let h = self.blobs.add(&ct).await?;
                ensure!(&h == id, "iroh blob hash != carapace ChunkID");
                chunk_ids.push(*id);
            }
        }

        let grant = self.build_file_grant(manifest, keys, *vid, manifest.epoch)?;

        let mut s = self.shared.write().expect("shared lock");
        s.epochs.insert(*vid, manifest.epoch);
        for id in &chunk_ids {
            s.owned_chunks.insert(*id, *vid);
        }
        s.vault_keys.insert(*vid, keys.clone());
        let replicas = replica_list(self.node_id(), s.members.get(vid));
        let mut ann = VaultAnnounce {
            vid: *vid,
            epoch: manifest.epoch,
            replicas,
            digest,
            by: [0; 32],
            sig: [0; 64],
        };
        ann.sign(&self.node_key);
        s.announces.retain(|a| a.vid != *vid);
        s.announces.push(ann);
        s.grants.retain(|g| g.vid != *vid);
        s.grants.push(grant);
        s.vault_blobs.insert(
            *vid,
            VaultBlobs {
                digest,
                chunk_ids,
                manifest: manifest.clone(),
            },
        );
        Ok(())
    }

    // ---- friendship (§9.2) ---------------------------------------------

    /// This daemon's user id (shared across the user's devices).
    pub fn user_id(&self) -> [u8; 32] {
        self.user_key.verifying_key().to_bytes()
    }

    /// Whether an established friendship exists with `user`.
    pub fn is_friend(&self, user: &[u8; 32]) -> bool {
        self.shared
            .read()
            .expect("shared lock")
            .friendships
            .contains_key(user)
    }

    /// The stored dual-signed friendship with `user`, if any.
    pub fn friendship_with(&self, user: &[u8; 32]) -> Option<Friendship> {
        self.shared
            .read()
            .expect("shared lock")
            .friendships
            .get(user)
            .cloned()
    }

    /// Test/diagnostic helper: perform a document pull against `peer` and return
    /// the counts of `(cards, announces, grants)` frames the peer actually served.
    /// A peer that refuses this dialer (W5) serves only its `Hello`, so all three
    /// counts are zero; an authorized dialer sees the peer's document set.
    #[doc(hidden)]
    pub async fn pull_doc_counts(&self, peer: EndpointAddr) -> Result<(usize, usize, usize)> {
        let conn = self.ep.connect(peer, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        write_msg(&mut send, &own_card).await?;
        let (mut cards, mut announces, mut grants) = (0, 0, 0);
        while let Some((ty, _body)) = read_frame_raw(&mut recv).await? {
            match ty {
                ContactCard::TYPE => cards += 1,
                VaultAnnounce::TYPE => announces += 1,
                FileGrant::TYPE => grants += 1,
                _ => {}
            }
        }
        send.finish()?;
        Ok((cards, announces, grants))
    }

    /// Present our own card on `peer`'s `carapace/1` control stream so it can
    /// classify our node id (W5/§7.4). We discard whatever documents it serves; the
    /// side effect - the peer recording our blob-read authorization - is the point.
    /// Used before fetching replica-held blobs from a peer that is not the doc peer.
    async fn authenticate_to(&self, peer: &EndpointAddr) -> Result<()> {
        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        let conn = self.ep.connect(peer.clone(), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, &own_card).await?;
        // Drain the peer's response (Hello + any served docs) so it processes our
        // card fully before we open the blob stream.
        while (read_frame_raw(&mut recv).await?).is_some() {}
        send.finish()?;
        Ok(())
    }

    /// Issue a single-use invite ticket (§6). The ticket is signed by this user's
    /// key and names this device; hand it to a prospective friend out of band. The
    /// daemon records it and will honor exactly one matching `FriendRequest`.
    pub fn issue_ticket(&self) -> Result<InviteTicket> {
        let now = unix_now();
        // §6: advertise our self-hosted relay in the ticket's relay set, so the
        // redeemer can reach us via relay fallback without our direct address.
        let relay_urls: Vec<String> = self
            .advertised_relay
            .iter()
            .map(|u| u.to_string())
            .collect();
        let ticket = build_ticket(
            &self.user_key,
            self.node_id(),
            vec![],
            relay_urls,
            now + 3600,
        )
        .map_err(|e| anyhow::anyhow!("build ticket: {e}"))?;
        {
            let mut s = self.shared.write().expect("shared lock");
            s.tickets.prune(now); // S7: drop expired tokens before recording a new one.
            s.tickets.issue(&ticket);
        }
        Ok(ticket)
    }

    /// Drive the requester side of the §9.2 handshake against the ticket issuer at
    /// `peer`: send a `FriendRequest`, countersign the friendship core the acceptor
    /// chooses, and on a valid `FriendAccept` persist the dual-signed `Friendship`
    /// plus the acceptor's card. Returns the completed friendship.
    ///
    /// `grant_bytes` is the per-friend replica-storage limit THIS node agrees to
    /// grant the new friend (enforced later by `serve_replica_store` when they
    /// place a replica on us); `None` uses `DEFAULT_QUOTA_BYTES` (1 GiB). This is
    /// local policy, independent of the friend's advertised `offers.storage_bytes`.
    pub async fn befriend(
        &self,
        peer: EndpointAddr,
        ticket: &InviteTicket,
        grant_bytes: Option<u64>,
    ) -> Result<Friendship> {
        let now = unix_now();
        let self_user = self.user_key.verifying_key().to_bytes();
        let acceptor_user = ticket.user;
        ensure!(acceptor_user != self_user, "cannot befriend yourself");

        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        let req = build_friend_request(&self.node_key, own_card, ticket.token);

        // §6: inject the ticket's addressing hints (issuer node id + direct addrs
        // + self-hosted relay URLs) so we can dial the issuer by node id even when
        // `peer` carries no direct address (the NAT-blind, relay-only path).
        learn_ticket_hints(&self.ep.hints(), ticket).await;

        // Record the acceptor's dialable address so the maintenance loop can later
        // re-reach it (PoR probes, attestation challenges) without a discovery
        // round-trip (§6). Captured before `peer` is consumed by the dial below.
        let peer_addr = peer.clone();
        let peer_node = *peer.id.as_bytes();
        let conn = self.ep.connect(peer, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, &req).await?;

        // The acceptor picks `established`; countersign the identical core.
        let established = read_u64(&mut recv).await?;
        let (a, b) = if self_user <= acceptor_user {
            (self_user, acceptor_user)
        } else {
            (acceptor_user, self_user)
        };
        let core = friendship_core_bytes((a, b), established);
        let countersig = self.user_key.sign(&core).to_bytes();
        write_sig(&mut send, &countersig).await?;

        let accept = read_msg::<FriendAccept>(&mut recv).await?;
        send.finish()?;

        let friendship = verify_friend_accept(&accept, now, &self_user)
            .map_err(|e| anyhow::anyhow!("friend accept invalid: {e}"))?;
        // S3: the accept must actually come from the ticket's issuer, and the
        // resulting friendship must bind that same party - defense in depth against
        // a redirected/substituted acceptor.
        ensure!(
            accept_binds_ticket(&accept, &ticket.user, &friendship),
            "friend accept does not match the ticket issuer"
        );
        {
            let mut s = self.shared.write().expect("shared lock");
            s.friendships.insert(acceptor_user, friendship.clone());
            s.friends.insert(acceptor_user, accept.card.clone());
            // Agree the per-friend replica-storage grant at add-friend time.
            s.friend_grants
                .insert(acceptor_user, grant_bytes.unwrap_or(DEFAULT_QUOTA_BYTES));
            s.peer_addrs.insert(peer_node, peer_addr);
        }
        // §6: learn the acceptor's card hints (relay + direct addrs) for later
        // dials (anti-entropy, PoR probes) by node id.
        learn_card_hints(&self.ep.hints(), &accept.card).await;
        drop(conn);
        Ok(friendship)
    }

    // ---- replica placement + repair (§10.1) ----------------------------

    /// Whether this daemon currently stores `vid` as a replica for some owner.
    pub fn holds_replica(&self, vid: &[u8; 32]) -> bool {
        self.shared.read().expect("shared lock").held.contains(vid)
    }

    /// Add `node` to the owner-side replica deny-list: this daemon will never place
    /// a replica on it, even if it is an established friend (S4).
    pub fn deny_replica_peer(&self, node: [u8; 32]) {
        self.shared
            .write()
            .expect("shared lock")
            .replica_deny
            .insert(node);
    }

    /// S4 owner-side placement gate: a candidate node may be invited only if it is
    /// a trusted device (an established friend's, or one of ours) AND not on the
    /// owner deny-list.
    fn replica_candidate_ok(&self, node: &[u8; 32], self_user: &[u8; 32], now: u64) -> bool {
        let s = self.shared.read().expect("shared lock");
        !s.replica_deny.contains(node) && node_is_authorized(&s, self_user, node, now)
    }

    /// The current owner-side replica member set for `vid` (accepted peer nodes).
    pub fn replica_members(&self, vid: &[u8; 32]) -> Vec<[u8; 32]> {
        self.shared
            .read()
            .expect("shared lock")
            .members
            .get(vid)
            .cloned()
            .unwrap_or_default()
    }

    /// Invite each friend in `peers` to store a replica of `vid`, targeting
    /// invariant `r`. Each accepting peer is pushed the manifest envelope plus
    /// every ciphertext chunk and recorded as a member; the announce is re-signed
    /// to reflect the new set. Returns the node ids that accepted.
    pub async fn place_replicas(
        &self,
        vid: [u8; 32],
        peers: &[EndpointAddr],
        r: usize,
    ) -> Result<Vec<[u8; 32]>> {
        let (vb, epoch) = {
            let s = self.shared.read().expect("shared lock");
            let vb = s
                .vault_blobs
                .get(&vid)
                .cloned()
                .context("vault not published")?;
            let epoch = *s.epochs.get(&vid).context("vault has no epoch")?;
            (vb, epoch)
        };
        let blobs = self.gather_blob_bytes(&vb).await?;
        let total: u64 = blobs.iter().map(|b| b.len() as u64).sum();

        let now = unix_now();
        let self_user = self.user_id();
        let mut placed = Vec::new();
        for peer in peers {
            let node = *peer.id.as_bytes();
            // S4: only invite an established friend (or our own device) that is not
            // on the owner deny-list.
            if !self.replica_candidate_ok(&node, &self_user, now) {
                continue;
            }
            if let Some(node) = self
                .invite_and_push(peer, vid, epoch, total, &blobs)
                .await?
            {
                placed.push(node);
            }
        }
        {
            let mut s = self.shared.write().expect("shared lock");
            let members = s.members.entry(vid).or_default();
            for n in &placed {
                if !members.contains(n) {
                    members.push(*n);
                }
            }
            s.replica_target.insert(vid, r);
            reannounce(&mut s, vid, self.node_id(), &self.node_key);
        }
        Ok(placed)
    }

    /// Run the §10.1 repair loop for `vid`: drop members confirmed lost by the
    /// injected `healths` (unfriended, or unreachable past the 24 h grace), then
    /// re-replicate from `candidates` up to the invariant `r`, re-announcing the
    /// new set. Returns `true` if the member set changed.
    ///
    /// ponytail: the re-announce reuses the content epoch rather than bumping it,
    /// because `announce.epoch` is bound to the sealed manifest here (reconstruct
    /// checks `manifest.epoch == announce.epoch`). A fresh puller therefore always
    /// sees the current set; a peer that already cached the announce would not pick
    /// up a set change until the next content epoch. Decouple the replica-set
    /// version from the content epoch if in-place set propagation is required.
    pub async fn repair_vault(
        &self,
        vid: [u8; 32],
        healths: &HashMap<[u8; 32], Health>,
        candidates: &[EndpointAddr],
    ) -> Result<bool> {
        let now = unix_now();
        let (before, r, vb, epoch) = {
            let s = self.shared.read().expect("shared lock");
            let before = s.members.get(&vid).cloned().unwrap_or_default();
            let r = *s.replica_target.get(&vid).unwrap_or(&before.len());
            let vb = s
                .vault_blobs
                .get(&vid)
                .cloned()
                .context("vault not published")?;
            let epoch = *s.epochs.get(&vid).context("vault has no epoch")?;
            (before, r, vb, epoch)
        };

        let mut members = before.clone();
        members.retain(|m| {
            !healths
                .get(m)
                .is_some_and(|h| h.is_lost(now, DEFAULT_GRACE_SECS))
        });

        if members.len() < r {
            let blobs = self.gather_blob_bytes(&vb).await?;
            let total: u64 = blobs.iter().map(|b| b.len() as u64).sum();
            let self_user = self.user_id();
            for peer in candidates {
                if members.len() >= r {
                    break;
                }
                let node = *peer.id.as_bytes();
                if members.contains(&node) {
                    continue;
                }
                // S4: skip non-friends and owner-denied peers before inviting.
                if !self.replica_candidate_ok(&node, &self_user, now) {
                    continue;
                }
                if let Some(n) = self
                    .invite_and_push(peer, vid, epoch, total, &blobs)
                    .await?
                {
                    members.push(n);
                }
            }
        }

        if members == before {
            return Ok(false);
        }
        {
            // S7: merge rather than blindly overwrite, so a concurrent placement
            // that added a member while we were pushing is not clobbered. Drop the
            // members we confirmed lost, then union in the repaired set.
            let mut s = self.shared.write().expect("shared lock");
            let cur = s.members.entry(vid).or_default();
            cur.retain(|m| {
                !healths
                    .get(m)
                    .is_some_and(|h| h.is_lost(now, DEFAULT_GRACE_SECS))
            });
            for n in &members {
                if !cur.contains(n) {
                    cur.push(*n);
                }
            }
            reannounce(&mut s, vid, self.node_id(), &self.node_key);
        }
        Ok(true)
    }

    /// Fetch the envelope (index 0) plus every unique chunk from this daemon's
    /// blob store, in the order a replica expects them pushed.
    async fn gather_blob_bytes(&self, vb: &VaultBlobs) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(1 + vb.chunk_ids.len());
        out.push(self.blobs.get_bytes(vb.digest).await?);
        for id in &vb.chunk_ids {
            out.push(self.blobs.get_bytes(*id).await?);
        }
        Ok(out)
    }

    /// Dial `peer`'s control stream, send a `ReplicaInvite`, and on a valid
    /// `ReplicaAccept` push the envelope + chunks. Returns the peer node id if it
    /// accepted and stored, or `None` if it declined.
    async fn invite_and_push(
        &self,
        peer: &EndpointAddr,
        vid: [u8; 32],
        epoch: u64,
        total: u64,
        blobs: &[Vec<u8>],
    ) -> Result<Option<[u8; 32]>> {
        let node = *peer.id.as_bytes();
        let conn = self.ep.connect(peer.clone(), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        let mut inv = ReplicaInvite {
            vid,
            epoch,
            approx_bytes: total,
            by: [0; 32],
            sig: [0; 64],
        };
        inv.sign(&self.node_key);
        write_msg(&mut send, &inv).await?;

        // A declining peer finishes its stream without an accept frame.
        let accept = match read_frame_raw(&mut recv).await? {
            Some((ReplicaAccept::TYPE, body)) => ReplicaAccept::from_map(body)?,
            _ => return Ok(None),
        };
        accept
            .verify()
            .map_err(|e| anyhow::anyhow!("replica accept bad sig: {e}"))?;
        ensure!(accept.vid == vid, "replica accept named a different vault");
        ensure!(accept.by == node, "replica accept signer is not this peer");
        ensure!(
            total <= accept.quota_bytes,
            "placement exceeds granted quota"
        );

        // Send the current owner-signed announce so the replica learns the set it
        // joins and can gate later fetches on membership (§7.4 b, W8).
        let announce = {
            let s = self.shared.read().expect("shared lock");
            s.announces
                .iter()
                .find(|a| a.vid == vid)
                .cloned()
                .context("no announce for vault being placed")?
        };
        write_msg(&mut send, &announce).await?;

        write_u64(&mut send, blobs.len() as u64).await?;
        for b in blobs {
            write_blob(&mut send, b).await?;
        }
        send.finish()?;
        // Wait for the replica's ack so membership only records durable storage.
        let acked = read_u64(&mut recv).await?;
        ensure!(
            acked == blobs.len() as u64,
            "replica acked {acked} of {} blobs",
            blobs.len()
        );
        // §6: remember where this replica lives so the PoR loop can re-audit it by
        // node id without a discovery round-trip.
        {
            let mut s = self.shared.write().expect("shared lock");
            s.peer_addrs.insert(node, peer.clone());
        }
        Ok(Some(node))
    }

    // ---- PoR retention audit loop (§10.1) ------------------------------

    /// Run one Proof-of-Retention audit round for `vid` over `members`
    /// (`replica node id -> dialable address`), then repair on confirmed loss.
    ///
    /// For each member due at `now` (per the injected-clock [`AuditTracker`]) the
    /// owner derives an unpredictable sample of chunks from `K_audit(vid)` (a key
    /// only the owner holds), fetches exactly those chunks *from that replica* into
    /// a throwaway store so the transfer genuinely comes off the peer, and BLAKE3-
    /// verifies them against their ChunkIDs. A missing or wrong chunk fails the
    /// round; [`DEFAULT_POR_FAIL_LIMIT`](carapace_replica::DEFAULT_POR_FAIL_LIMIT)
    /// consecutive failures marks the replica lost, which is fed to
    /// [`Daemon::repair_vault`] as [`Health::AuditLost`] (re-replicate onto a spare
    /// from `candidates`, re-announce). Returns what happened this round.
    ///
    /// The caller ticks this (a `tokio::time::interval` in a real deployment, an
    /// injected `now` in tests); the tracker's per-replica jittered schedule decides
    /// which members are actually probed on any given tick (§10.1). No lock is held
    /// across the network fetch: audits read a manifest/schedule snapshot, probe off
    /// the lock, then record synchronously.
    pub async fn por_audit_round(
        &self,
        vid: [u8; 32],
        members: &HashMap<[u8; 32], EndpointAddr>,
        candidates: &[EndpointAddr],
        now: u64,
    ) -> Result<PorRound> {
        let (manifest, epoch) = {
            let s = self.shared.read().expect("shared lock");
            let vb = s.vault_blobs.get(&vid).context("vault not published")?;
            let epoch = *s.epochs.get(&vid).context("vault has no epoch")?;
            (vb.manifest.clone(), epoch)
        };
        // K_audit(vid) = HKDF(K_vaultroot(vid), "por") - owner-only, so the sample
        // set is unpredictable to the replica being probed.
        let vaultroot = kdf::k_vaultroot(&*self.k_root, &vid);
        let k_audit: [u8; 32] = *kdf::k_audit(&*vaultroot);

        let mut round = PorRound::default();
        for (node, addr) in members {
            let (due, r, wide) = {
                let s = self.shared.read().expect("shared lock");
                (
                    s.por.due(*node, vid, now),
                    s.por.round(*node, vid),
                    s.por.is_wide_round(*node, vid),
                )
            };
            if !due {
                continue;
            }
            let audit = if wide {
                build_wide_audit(&k_audit, vid, epoch, r, &manifest, WIDE_AUDIT_COVERAGE)
            } else {
                build_audit(&k_audit, vid, epoch, r, &manifest)
            };
            // C1: an unreachable replica (connect failed) is a transport failure,
            // not a retention answer - it must never advance the loss streak, or a
            // transiently-offline friend would be evicted without grace. Only a peer
            // that actually answered is judged on content via `record`.
            let action = match self.fetch_audit_samples(addr, &audit).await {
                None => {
                    let mut s = self.shared.write().expect("shared lock");
                    s.por.record_unreachable(*node, vid, now)
                }
                Some(responses) => {
                    let outcome = verify_audit_response(&audit, &responses);
                    let mut s = self.shared.write().expect("shared lock");
                    s.por.record(*node, vid, outcome, now)
                }
            };
            match action {
                AuditAction::Lost => round.lost.push(*node),
                AuditAction::Skipped => round.unreachable.push(*node),
                _ => {}
            }
            round.audited.push((*node, action));
        }

        if !round.lost.is_empty() {
            let mut healths = HashMap::new();
            for n in &round.lost {
                healths.insert(*n, Health::AuditLost);
            }
            round.repaired = self.repair_vault(vid, &healths, candidates).await?;
        }
        Ok(round)
    }

    /// Probe `addr` for each sampled chunk of `audit`. Returns `Some(responses)`
    /// (one `Option<Vec<u8>>` per sample: `Some` bytes if the chunk was served,
    /// `None` if the connected peer did not produce it) when the replica answered,
    /// or `None` when the replica could not be reached at all.
    ///
    /// C1: the connect-failure `None` is distinct from a per-sample `None`. An
    /// unreachable peer is a transport failure and must not be scored as a retention
    /// loss; only a peer that connected is judged on the content of its answers.
    /// Fetches into a fresh empty store so a chunk the owner already holds is still
    /// pulled from the replica; a per-sample timeout bounds a stalled/missing probe.
    async fn fetch_audit_samples(
        &self,
        addr: &EndpointAddr,
        audit: &Audit,
    ) -> Option<Vec<Option<Vec<u8>>>> {
        let scratch = IrohBlobStore::new();
        // Unreachable replica: no content answer at all -> signal transport failure.
        // The connect is time-bounded so a dead peer fails fast instead of hanging
        // the round on the QUIC handshake timeout (C1).
        let conn = match tokio::time::timeout(
            POR_CONNECT_TIMEOUT,
            self.ep.connect(addr.clone(), iroh_blobs::ALPN),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            _ => return None,
        };
        let mut out = Vec::with_capacity(audit.samples.len());
        for s in &audit.samples {
            let got =
                match tokio::time::timeout(POR_FETCH_TIMEOUT, scratch.fetch(&conn, s.chunk_id))
                    .await
                {
                    Ok(Ok(())) => scratch.get_bytes(s.chunk_id).await.ok(),
                    _ => None,
                };
            out.push(got);
        }
        Some(out)
    }

    // ---- share-health cadence (§10.2) ----------------------------------

    /// Register a recovery set this daemon owns, so [`Daemon::run_share_health_round`]
    /// tracks its attested-live count and drift. `tracker` carries the set's `M`,
    /// slack, lifetime issued-share count, and cadence (build it with
    /// [`AttestTracker::new`] for defaults, or `with_params` to tune the round /
    /// freshness intervals).
    pub fn register_recovery_set(&self, rsid: u64, tracker: AttestTracker) {
        self.shared
            .write()
            .expect("shared lock")
            .share_sets
            .insert(rsid, tracker);
    }

    /// Store a share this daemon holds as a trustee for another owner, enabling it
    /// to answer that owner's `ShareAttestChallenge`s and to run continuous local
    /// CRC self-validation (§10.2). Keyed by the share's recovery-set id.
    pub fn store_share(&self, share: Share) {
        let rsid = u64::from(share.recovery_set_id);
        self.shared
            .write()
            .expect("shared lock")
            .held_shares
            .insert(rsid, (share, ShareMonitor::new()));
    }

    /// Trustee-side continuous self-validation (§10.2): run the local CRC over the
    /// held share for `rsid` if its cadence is due at `now`, returning the current
    /// [`ShareHealth`] (or `None` if this daemon holds no share for that set).
    pub fn share_self_validate(&self, rsid: u64, now: u64) -> Option<ShareHealth> {
        let mut s = self.shared.write().expect("shared lock");
        s.held_shares
            .get_mut(&rsid)
            .map(|(share, mon)| mon.poll(share, now))
    }

    /// Owner-side share-health round (§10.2). If a round is due at `now`, challenge
    /// every `trustee` (`dialable address`) for the set `rsid` over the control
    /// stream, fold each verified attestation into the set's attested-live count,
    /// then return the drift decision: [`ShareAction::Healthy`], an
    /// [`ShareAction::Extend`] recommendation when live has drifted below `M + slack`
    /// with cap headroom, or [`ShareAction::ResplitLargerM`] at the §8.3 cap. When no
    /// round is due this just re-reads the current decision without probing.
    ///
    /// This SURFACES the recommendation; issuing the actual extend / re-split stays
    /// in [`carapace_recovery`]. No lock is held across the network round-trips.
    pub async fn run_share_health_round(
        &self,
        rsid: u64,
        subject: [u8; 32],
        trustees: &[EndpointAddr],
        now: u64,
    ) -> Result<ShareAction> {
        let due = {
            let s = self.shared.read().expect("shared lock");
            let t = s.share_sets.get(&rsid).context("unknown recovery set")?;
            t.round_due(now)
        };
        if !due {
            let s = self.shared.read().expect("shared lock");
            return Ok(s.share_sets.get(&rsid).expect("checked above").decide(now));
        }

        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("attest nonce: {e}"))?;
        let challenge = build_attest_challenge(&self.node_key, subject, rsid, nonce);

        let mut atts = Vec::new();
        for peer in trustees {
            if let Some(att) = self.challenge_trustee(peer, &challenge).await {
                atts.push(att);
            }
        }

        let action = {
            let mut s = self.shared.write().expect("shared lock");
            let t = s
                .share_sets
                .get_mut(&rsid)
                .context("unknown recovery set")?;
            // Fold only attestations that verify against this challenge; a bad or
            // mismatched one changes nothing (it simply is not counted live).
            for att in &atts {
                let _ = t.record_attestation(att, &challenge, now);
            }
            t.mark_round(now);
            t.decide(now)
        };
        Ok(action)
    }

    /// Dial `peer`'s control stream, send `challenge`, and return its
    /// `ShareAttestation` if it answers. A trustee that is unreachable, refuses, holds
    /// no share, or answers with a malformed frame yields `None`: liveness ages out
    /// through the freshness window, so a transiently-offline trustee is "not live"
    /// this round, never a round-aborting error (mirrors the C1 unreachable handling
    /// in `fetch_audit_samples`). The dial is bounded so an offline trustee fails fast
    /// instead of stalling the round on the QUIC handshake timeout.
    async fn challenge_trustee(
        &self,
        peer: &EndpointAddr,
        challenge: &ShareAttestChallenge,
    ) -> Option<ShareAttestation> {
        let conn = tokio::time::timeout(POR_CONNECT_TIMEOUT, self.ep.connect(peer.clone(), ALPN))
            .await
            .ok()?
            .ok()?;
        let (mut send, mut recv) = conn.open_bi().await.ok()?;
        write_msg(&mut send, challenge).await.ok()?;
        let att = match read_frame_raw(&mut recv).await.ok()? {
            Some((ShareAttestation::TYPE, body)) => ShareAttestation::from_map(body).ok(),
            _ => None,
        };
        let _ = send.finish();
        att
    }

    // ---- background maintenance loop (§10.1 + §10.2) -------------------

    /// Run one round of background maintenance at `now` — the unit the loop ticks and
    /// tests drive directly with an injected clock. In order:
    ///
    /// 1. PoR retention audits over each owned vault's replicas, repairing on
    ///    confirmed loss (re-replicate + re-announce, §10.1);
    /// 2. as owner, one attestation round per registered recovery set, folding
    ///    responses into the attested-live count and surfacing the drift decision
    ///    (§10.2);
    /// 3. as trustee, continuous local CRC self-validation of each held share (§10.2).
    ///
    /// Each per-concern tracker self-gates on its own cadence against `now`, so a
    /// round where nothing is due is cheap. One failing vault/set is recorded in the
    /// report and skipped, never fatal. No lock is held across any network round-trip:
    /// the work set + address book are snapshotted under a read lock, then acted on
    /// off-lock (the called methods do their own lock-drop-before-await).
    pub async fn maintenance_round(&self, now: u64) -> MaintenanceReport {
        let mut report = MaintenanceReport::default();

        let (owned_vaults, recovery_sets, held_rsids, peer_addrs) = {
            let s = self.shared.read().expect("shared lock");
            let owned: Vec<[u8; 32]> = s
                .members
                .keys()
                .filter(|vid| s.vault_blobs.contains_key(*vid))
                .copied()
                .collect();
            let sets: Vec<(u64, Vec<[u8; 32]>)> = s
                .share_sets
                .iter()
                .map(|(rsid, t)| (*rsid, t.trustees()))
                .collect();
            let held: Vec<u64> = s.held_shares.keys().copied().collect();
            (owned, sets, held, s.peer_addrs.clone())
        };

        // 1) PoR audits + repair over owned vaults with replicas (§10.1).
        for vid in owned_vaults {
            let member_ids = {
                let s = self.shared.read().expect("shared lock");
                s.members.get(&vid).cloned().unwrap_or_default()
            };
            let members: HashMap<[u8; 32], EndpointAddr> = member_ids
                .iter()
                .filter_map(|n| resolve_peer(&peer_addrs, n).map(|a| (*n, a)))
                .collect();
            // Repair candidates: known peers that are not already members of this
            // vault (repair itself re-checks friendship + deny-list per candidate).
            let candidates: Vec<EndpointAddr> = peer_addrs
                .iter()
                .filter(|(n, _)| !member_ids.contains(n))
                .map(|(_, a)| a.clone())
                .collect();
            match self.por_audit_round(vid, &members, &candidates, now).await {
                Ok(round) => report.por.push((vid, round)),
                Err(e) => report
                    .errors
                    .push(format!("por audit {}: {e:#}", hex32(&vid))),
            }
        }

        // 2) Owner attestation rounds + drift surfacing over owned recovery sets
        //    (§10.2). The subject is this owner's user key.
        let subject = self.user_id();
        for (rsid, trustee_ids) in recovery_sets {
            let trustees: Vec<EndpointAddr> = trustee_ids
                .iter()
                .filter_map(|n| resolve_peer(&peer_addrs, n))
                .collect();
            match self
                .run_share_health_round(rsid, subject, &trustees, now)
                .await
            {
                Ok(action) => report.drift.push((rsid, action)),
                Err(e) => report.errors.push(format!("attest set {rsid}: {e:#}")),
            }
        }

        // 3) Trustee self-validation over held shares (§10.2).
        for rsid in held_rsids {
            if let Some(h) = self.share_self_validate(rsid, now) {
                report.self_validated.push((rsid, h));
            }
        }

        // 4) Owner grant ref-refresh (W3, §10.2/§7.3): re-issue trustees' grants with
        //    the latest announce refs whenever a vault epoch has advanced (or a prior
        //    delivery is still outstanding), so trustees hold current manifest pointers.
        report.refreshed_grants = self.refresh_grants_round().await;

        report
    }

    /// Spawn the background maintenance loop (§10.1/§10.2) and return its handle.
    ///
    /// The loop wakes every `cfg.tick`, runs one [`Daemon::maintenance_round`] against
    /// the wall clock, and self-gates each concern on its own cadence. It holds only a
    /// [`Weak`] to the daemon (upgraded per round), so it never blocks shutdown; the
    /// returned [`MaintenanceHandle`] tears it down on drop or
    /// [`MaintenanceHandle::stop`]. Follows the same `Arc<Self>` + `Weak` pattern as
    /// [`Daemon::watch_vault`]: the production entry point ([`carapace_api`]) already
    /// holds an `Arc<Daemon>` and starts this once at boot.
    ///
    /// `cfg.por_interval` is stamped onto the audit schedule here (the loop owns the
    /// PoR cadence), so a deployment or a bounded test tunes it through the config.
    pub fn run_maintenance(self: Arc<Self>, cfg: MaintenanceConfig) -> MaintenanceHandle {
        {
            // The loop owns the PoR audit cadence: stamp it at start, before any audit
            // runs, so no accumulated per-replica schedule is discarded mid-flight.
            let mut s = self.shared.write().expect("shared lock");
            s.por = AuditTracker::new(
                cfg.por_interval.as_secs(),
                DEFAULT_POR_FAIL_LIMIT,
                DEFAULT_WIDE_EVERY,
            );
        }
        let weak: Weak<Self> = Arc::downgrade(&self);
        // Release this strong ref so the loop's Weak never keeps the daemon alive.
        drop(self);
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(cfg.tick);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(daemon) = weak.upgrade() else {
                    break;
                };
                let _ = daemon.maintenance_round(unix_now()).await;
                // Drop the strong ref between ticks so a concurrent shutdown can
                // reclaim the daemon; the loop ends once the last Arc is gone.
                drop(daemon);
            }
        });
        MaintenanceHandle { task: Some(task) }
    }

    /// The §10.2 share-health surface for the status API: per owned recovery set, its
    /// attested-live count, `M + slack` target, and drift recommendation evaluated at
    /// the current wall clock.
    pub fn recovery_health(&self) -> Vec<RecoveryHealthReport> {
        self.recovery_health_at(unix_now())
    }

    /// [`Daemon::recovery_health`] evaluated at an explicit `now` (injected clock for
    /// deterministic tests).
    pub fn recovery_health_at(&self, now: u64) -> Vec<RecoveryHealthReport> {
        let s = self.shared.read().expect("shared lock");
        s.share_sets
            .iter()
            .map(|(rsid, t)| {
                let (recommendation, needed) = match t.decide(now) {
                    ShareAction::Healthy => ("healthy", 0),
                    ShareAction::Extend { needed } => ("extend", needed),
                    ShareAction::ResplitLargerM => ("resplit", 0),
                };
                RecoveryHealthReport {
                    rsid: *rsid,
                    live: t.live_count(now),
                    target: t.target(),
                    recommendation,
                    needed,
                }
            })
            .collect()
    }

    /// The newest `VaultAnnounce` this daemon has learned for `vid` (its signer node
    /// and epoch), from the rollback-guarded document store — including third-party
    /// announces picked up via anti-entropy store-and-forward (§6/W7). `None` if none
    /// is known.
    pub fn known_announce(&self, vid: &[u8; 32]) -> Option<([u8; 32], u64)> {
        let d = self.docs.lock().expect("docs lock");
        d.announce_for_vid(vid).map(|a| (a.by, a.epoch))
    }

    /// Test-only: record `node` as a replica member of `vid` without pushing it the
    /// blobs, modeling a replica that accepted a placement but has since lost its
    /// stored copy. The PoR loop then detects the loss on audit.
    #[doc(hidden)]
    pub fn inject_lost_member_for_test(&self, vid: [u8; 32], node: [u8; 32]) {
        let mut s = self.shared.write().expect("shared lock");
        let members = s.members.entry(vid).or_default();
        if !members.contains(&node) {
            members.push(node);
        }
    }

    /// Gracefully close the endpoint.
    pub async fn shutdown(self) {
        self.ep.close().await;
    }

    // ---- grant sealing -------------------------------------------------

    fn disclose_keypair(&self) -> (HpkePrivateKey, HpkePublicKey) {
        seal::derive_keypair(&*kdf::k_disclose(&*self.k_root))
    }

    fn build_file_grant(
        &self,
        manifest: &Manifest,
        keys: &ChunkKeys,
        vid: [u8; 32],
        epoch: u64,
    ) -> Result<FileGrant> {
        let body = grant_body(manifest, keys)?;
        let (_priv, disclose_pub) = self.disclose_keypair();
        let user_pub = self.user_key.verifying_key().to_bytes();

        let mut grant_id = [0u8; 16];
        getrandom::getrandom(&mut grant_id).map_err(|e| anyhow::anyhow!("grant id: {e}"))?;

        // Prefix the encapsulated key onto the HPKE ciphertext (Sealed carries no
        // separate encap field); split it back off on open. S7: the serialized
        // body holds every chunk key in the clear, so scrub it after sealing. S2:
        // bind the seal to this exact grant (vid, epoch, grant_id), matching
        // `open_file_grant`.
        let aad = disclose::grant_aad(&vid, epoch, &grant_id);
        let body_bytes = Zeroizing::new(body.to_bytes());
        let (enc, ct) = seal::seal(&disclose_pub, INFO_DISCLOSE, &aad, &body_bytes)
            .map_err(|e| anyhow::anyhow!("grant seal: {e}"))?;
        let mut sealed_ct = enc;
        sealed_ct.extend_from_slice(&ct);

        let mut fg = FileGrant {
            grant_id,
            vid,
            epoch,
            audience: vec![user_pub],
            sealed: vec![Sealed {
                to: user_pub,
                ct: sealed_ct,
            }],
            by: [0; 32],
            sig: [0; 64],
        };
        fg.sign(&self.node_key);
        Ok(fg)
    }

    fn open_file_grant(
        &self,
        grant: &FileGrant,
        disclose_priv: &HpkePrivateKey,
        vid: [u8; 32],
    ) -> Result<ChunkKeys> {
        let user_pub = self.user_key.verifying_key().to_bytes();
        let sealed = grant
            .sealed
            .iter()
            .find(|s| s.to == user_pub)
            .context("grant has no sealed body for this user")?;
        ensure!(
            sealed.ct.len() >= 32,
            "sealed grant too short for encap key"
        );
        let (enc, ct) = sealed.ct.split_at(32);
        // S2: aad binds vid, epoch, and grant_id (matches `build_file_grant`).
        let aad = disclose::grant_aad(&vid, grant.epoch, &grant.grant_id);
        // S7: the opened plaintext carries every chunk key; scrub it on drop.
        let pt = Zeroizing::new(
            seal::open(disclose_priv, enc, INFO_DISCLOSE, &aad, ct)
                .map_err(|e| anyhow::anyhow!("grant open: {e}"))?,
        );
        let body = GrantBody::from_bytes(&pt)?;
        Ok(keys_from_grant(&body))
    }

    // ---- selective disclosure to an audience (§7.4) --------------------

    /// Disclose exactly `paths` from owned vault `vid` to `audience` (a list of
    /// established-friend user pubkeys — "reveal to all my friends" simply names the
    /// current friend list at issuance). Assembles a [`GrantBody`] from the retained
    /// per-chunk secrets, HPKE-seals it to each friend's `enc_pub`, signs a
    /// [`FileGrant`], and records the owner-side disclosure table so the blob gate
    /// will serve exactly those chunks to exactly that audience. Returns the grant to
    /// deliver directly to each member (§7.4).
    ///
    /// NORMATIVE (§7.4): the returned grant is a **snapshot** of the vault's current
    /// epoch and is **irrevocable** for the content it discloses — a later edit makes
    /// new chunk keys (hence a new grant), and "revoke" means only "issue no future
    /// version." This API never implies recall of already-disclosed content.
    pub fn disclose_files(
        &self,
        vid: [u8; 32],
        paths: &[&str],
        audience: &[[u8; 32]],
    ) -> Result<FileGrant> {
        let mut grant_id = [0u8; 16];
        getrandom::getrandom(&mut grant_id).map_err(|e| anyhow::anyhow!("grant id: {e}"))?;

        let mut s = self.shared.write().expect("shared lock");
        let epoch = *s.epochs.get(&vid).context("vault not published")?;
        let manifest = s
            .vault_blobs
            .get(&vid)
            .context("vault not published")?
            .manifest
            .clone();
        let keys = s
            .vault_keys
            .get(&vid)
            .context("vault keys missing")?
            .clone();

        // Resolve each audience member's disclosure key from their stored friend card.
        let mut recipients = Vec::with_capacity(audience.len());
        for user in audience {
            let card = s.friends.get(user).with_context(|| {
                format!(
                    "audience member {} is not an established friend",
                    hex32(user)
                )
            })?;
            recipients.push(Recipient {
                user: *user,
                enc_pub: card.enc_pub,
            });
        }

        let body = select_grant_body(&manifest, &keys, paths)?;
        let grant = disclose::build_grant(&self.node_key, vid, epoch, grant_id, &body, &recipients)
            .map_err(|e| anyhow::anyhow!("build grant: {e}"))?;
        // Authorize this audience for exactly these chunks in the blob-read gate.
        s.disclosure.record(&grant, &body);
        Ok(grant)
    }

    /// Audience side of selective disclosure (§7.4): open `grant` (addressed to this
    /// user), fetch its ciphertext chunks from `owner` over the authenticated blob
    /// path, and reconstruct exactly the granted files under `out_root/<vid>/`.
    /// Returns the written paths. Reconstructs ONLY the granted files.
    pub async fn fetch_disclosed(
        &self,
        grant: &FileGrant,
        owner: EndpointAddr,
        out_root: &Path,
    ) -> Result<Vec<PathBuf>> {
        grant
            .verify()
            .map_err(|e| anyhow::anyhow!("grant signature invalid: {e}"))?;
        // W1: `grant.verify()` only proves self-consistency (signed by whatever
        // `grant.by` claims). Authenticate the discloser too: `grant.by` must be a
        // device our own user or an established friend currently delegates, so
        // disclosed content carries verifiable provenance and an unknown party
        // cannot push us a grant to reconstruct. Mirrors C1 on the sync path.
        let now = unix_now();
        {
            let s = self.shared.read().expect("shared lock");
            ensure!(
                node_is_authorized(&s, &self.user_id(), &grant.by, now),
                "disclosure signer {} is not a delegated device of self or any \
                 established friend",
                hex32(&grant.by)
            );
        }
        let (disclose_priv, _pub) = self.disclose_keypair();
        let my_user = self.user_id();
        let body = disclose::open_grant(grant, my_user, &disclose_priv)
            .map_err(|e| anyhow::anyhow!("open grant: {e}"))?;

        // Authenticate on the owner's control stream first, so the owner's blob gate
        // binds our node id to our (friend) identity before we open a raw blob
        // connection and fetch (§7.4 / D3).
        self.present_card(&owner).await?;

        // W8: fetch into a throwaway store, NOT `self.blobs`, which the router serves.
        // Otherwise a friend that fetched disclosed files would re-serve the owner's
        // ciphertext ungated from its own node, defeating disclosure revocation. We
        // only need the bytes to write the granted plaintext to disk.
        let scratch = IrohBlobStore::new();
        let bconn = self.ep.connect(owner, iroh_blobs::ALPN).await?;
        let mut chunks: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        for f in &body.files {
            for c in &f.chunks {
                scratch.fetch(&bconn, c.chunk_id).await?;
                chunks.insert(c.chunk_id, scratch.get_bytes(c.chunk_id).await?);
            }
        }
        let out_dir = out_root.join(hex32(&grant.vid));
        disclose::write_grant(&body, &grant.vid, &out_dir, |id| chunks.get(id).cloned())
            .map_err(|e| anyhow::anyhow!("reconstruct disclosed files: {e}"))
    }

    /// Present our own card on `peer`'s control stream and drain the reply. Completes
    /// the W5 authentication handshake so `peer` records our node id in its blob-read
    /// allow-set before we open a raw blob connection (used by `fetch_disclosed`).
    async fn present_card(&self, peer: &EndpointAddr) -> Result<()> {
        let conn = self.ep.connect(peer.clone(), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let own_card = {
            let s = self.shared.read().expect("shared lock");
            s.cards.first().cloned().context("no own card")?
        };
        write_msg(&mut send, &own_card).await?;
        while read_frame_raw(&mut recv).await?.is_some() {}
        send.finish()?;
        Ok(())
    }

    /// Test/diagnostic: open `grant` as this user and return the ChunkIDs it
    /// discloses (empty if this user is not in the grant's audience or the open
    /// fails). Lets a test learn a granted ChunkID to probe the fetch gate with.
    #[doc(hidden)]
    pub fn granted_chunk_ids(&self, grant: &FileGrant) -> Result<Vec<[u8; 32]>> {
        let (disclose_priv, _pub) = self.disclose_keypair();
        let body = disclose::open_grant(grant, self.user_id(), &disclose_priv)
            .map_err(|e| anyhow::anyhow!("open grant: {e}"))?;
        Ok(disclose::granted_chunk_ids(&body).into_iter().collect())
    }

    /// Test-only: attempt a raw single-blob fetch of `chunk_id` from `peer` over the
    /// blobs ALPN WITHOUT first authenticating on the control stream — modeling a
    /// non-audience party (e.g. a leaked-grant holder) that already knows a ChunkID.
    /// The §7.4/D3 gate must refuse it.
    #[doc(hidden)]
    pub async fn try_fetch_chunk(&self, peer: EndpointAddr, chunk_id: [u8; 32]) -> Result<Vec<u8>> {
        let conn = self.ep.connect(peer, iroh_blobs::ALPN).await?;
        self.blobs.fetch(&conn, chunk_id).await?;
        self.blobs.get_bytes(chunk_id).await
    }

    // ---- read accessors (control-API status surface) -------------------

    /// The user ids of every established friendship (§9.2), for the status surface.
    pub fn friend_ids(&self) -> Vec<[u8; 32]> {
        self.shared
            .read()
            .expect("shared lock")
            .friendships
            .keys()
            .copied()
            .collect()
    }

    /// Every vault this daemon has published, as `(vid, current epoch)`.
    pub fn published_vaults(&self) -> Vec<([u8; 32], u64)> {
        let s = self.shared.read().expect("shared lock");
        s.vault_blobs
            .keys()
            .map(|vid| (*vid, s.epochs.get(vid).copied().unwrap_or(0)))
            .collect()
    }

    /// Every vault this daemon stores as a replica for some owner.
    pub fn held_replica_vids(&self) -> Vec<[u8; 32]> {
        self.shared
            .read()
            .expect("shared lock")
            .held
            .iter()
            .copied()
            .collect()
    }

    /// This device's dialable socket-address strings (best-effort). Empty if no
    /// bound socket is available. Handed to a prospective friend alongside a ticket
    /// so they can dial back without a discovery service.
    pub fn dialable_addr_strings(&self) -> Vec<String> {
        match self.addr() {
            Ok(ea) => ea.ip_addrs().map(|s| s.to_string()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// This node's own advertised relay URL as a string, iff it runs the embedded
    /// relay (§6). Surfaced on the status + ticket API so the operator can see (and
    /// share) the relay friends will use to reach this node.
    pub fn advertised_relay_url(&self) -> Option<String> {
        self.advertised_relay.as_ref().map(|u| u.to_string())
    }

    /// W4: number of distinct networks in this node's usable relay set (§6/§14) -
    /// its own advertised relay plus every relay URL in an established friend's
    /// newest card, deduplicated by host. §6 requires warning the user when this
    /// drops below 2, since a single relay network is both a single point of
    /// failure for reachability and a single metadata choke point.
    ///
    /// ponytail: "distinct network" == distinct URL host (DNS name or IP literal),
    /// lowercased. Upgrade to IP-subnet/ASN grouping if two friends behind the
    /// same host must count as one network more precisely.
    pub fn relay_network_count(&self) -> usize {
        let mut urls: Vec<String> = Vec::new();
        if let Some(u) = &self.advertised_relay {
            urls.push(u.to_string());
        }
        let s = self.shared.read().expect("shared lock");
        for card in s.friends.values() {
            for n in &card.nodes {
                if let Some(url) = &n.relay_url {
                    urls.push(url.clone());
                }
            }
        }
        distinct_relay_networks(urls.iter().map(String::as_str))
    }

    /// W4: whether to warn the user that their usable relay set spans fewer than
    /// 2 distinct networks (§6 normative MUST). Surfaced on the status API.
    pub fn relay_diversity_warning(&self) -> bool {
        self.relay_network_count() < 2
    }

    /// Wait until the endpoint has registered with at least one relay, so it is
    /// reachable via relay fallback. Never completes with no relays configured;
    /// guard with a timeout.
    pub async fn wait_online(&self) {
        self.ep.online().await;
    }

    /// Recovery-set share-health counts for the status surface:
    /// `(recovery_sets_owned, shares_held_as_trustee)`.
    pub fn share_health_counts(&self) -> (usize, usize) {
        let s = self.shared.read().expect("shared lock");
        (s.share_sets.len(), s.held_shares.len())
    }

    // ---- address-string wrappers (control-API friendly) ----------------
    // These let the loopback control API drive the network paths with a node id
    // (hex) plus dialable socket-address strings, so the API crate never has to
    // depend on iroh's `EndpointAddr` directly.

    /// [`Daemon::befriend`] against a peer named by node id + dialable addresses.
    pub async fn befriend_at(
        &self,
        node: [u8; 32],
        addrs: &[String],
        ticket: &InviteTicket,
        grant_bytes: Option<u64>,
    ) -> Result<Friendship> {
        let peer = endpoint_addr(node, addrs)?;
        self.befriend(peer, ticket, grant_bytes).await
    }

    /// [`Daemon::place_replicas`] against peers named by node id + addresses.
    pub async fn place_replicas_at(
        &self,
        vid: [u8; 32],
        peers: &[([u8; 32], Vec<String>)],
        r: usize,
    ) -> Result<Vec<[u8; 32]>> {
        let mut addrs = Vec::with_capacity(peers.len());
        for (node, a) in peers {
            addrs.push(endpoint_addr(*node, a)?);
        }
        self.place_replicas(vid, &addrs, r).await
    }

    /// [`Daemon::fetch_disclosed`] from an owner named by node id + addresses.
    pub async fn fetch_disclosed_at(
        &self,
        grant: &FileGrant,
        owner_node: [u8; 32],
        owner_addrs: &[String],
        out_root: &Path,
    ) -> Result<Vec<PathBuf>> {
        let owner = endpoint_addr(owner_node, owner_addrs)?;
        self.fetch_disclosed(grant, owner, out_root).await
    }

    // ---- recovery orchestration (§8) -----------------------------------

    /// Split a recovery secret `M`-of-`N` (§8.1/§8.2) and record the open split-state
    /// under `rsid` so it can later be extended. `scope` selects identity vs. a scoped
    /// per-vault key. Returns each share's canonical `chela.share` JSON carrier (the
    /// words the owner distributes) plus any §8.3 policy warnings. Overwrites any
    /// prior split recorded for `rsid` (this is also the "re-split" path, §8.3).
    ///
    /// SECURITY: the returned JSON carries the actual share words. This is served only
    /// over the authenticated loopback control API to the owner; it is the point of
    /// the split (the owner must distribute the words), not a leak.
    pub fn recovery_split(
        &self,
        rsid: u64,
        scope: RecoveryScope,
        m: u8,
        n: u8,
        allow_over_cap: bool,
    ) -> Result<(Vec<String>, Vec<PolicyWarning>)> {
        let (shares, state, warnings) = match scope {
            RecoveryScope::Root => split_root(&self.k_root, m, Some(n), allow_over_cap),
            RecoveryScope::Vault(vid) => {
                split_vault(&self.k_root, &vid, m, Some(n), allow_over_cap)
            }
        }
        .map_err(|e| anyhow::anyhow!("recovery split failed: {e:?}"))?;
        let jsons = shares.iter().map(share_to_json).collect();
        self.shared
            .write()
            .expect("shared lock")
            .split_states
            .insert(rsid, RecoverySet { scope, state });
        Ok((jsons, warnings))
    }

    /// Issue `count` further shares on the recorded split for `rsid` (§8.1), on the
    /// same polynomial so existing shares stay valid. Returns the new shares'
    /// `chela.share` JSON carriers. Errors if no split was recorded for `rsid`, or if
    /// issuance would exceed the §8.3 soft cap and `allow_over_cap` is false.
    pub fn recovery_extend(
        &self,
        rsid: u64,
        count: u8,
        allow_over_cap: bool,
    ) -> Result<Vec<String>> {
        let mut s = self.shared.write().expect("shared lock");
        let set = s
            .split_states
            .get_mut(&rsid)
            .context("no recovery split recorded for this recovery-set id")?;
        let secret = match set.scope {
            RecoveryScope::Root => self.k_root.clone(),
            RecoveryScope::Vault(vid) => Zeroizing::new(*kdf::k_vaultroot(&*self.k_root, &vid)),
        };
        let shares = extend_split(&mut set.state, &secret, count, allow_over_cap)
            .map_err(|e| anyhow::anyhow!("recovery extend failed: {e:?}"))?;
        Ok(shares.iter().map(share_to_json).collect())
    }

    /// Split a recovery secret `M`-of-`N` (N = `trustees.len()`) and mint + deliver one
    /// signed [`ShareGrant`] per trustee over the `carapace/1` control stream (§8, W3).
    /// Each grant wraps that trustee's `chela.share` JSON, the co-trustee roster (every
    /// OTHER trustee's user + node + relay, from its established-friend card), the
    /// owner's `recovery_delay` abort window (§8.5, default 72 h), and the latest
    /// [`AnnounceRef`]s for this owner's published vaults - so a quorum can locate the
    /// current manifest + a live replica at ceremony time without the owner present.
    ///
    /// Records the extendable split-state, an owner-side share-health tracker (§10.2),
    /// and the grant set (for the maintenance refresh + status view), all under `rsid`
    /// (overwriting any prior record - this is also the re-split path). Every trustee
    /// MUST be an established friend whose card names a node; that is where the roster
    /// identity and the delivery address come from. A trustee that is unreachable /
    /// declines is recorded as undelivered and retried by the refresh round; it does
    /// not abort the split (the words are already committed to the polynomial).
    pub async fn recovery_split_grant(
        &self,
        rsid: u64,
        scope: RecoveryScope,
        m: u8,
        trustees: &[[u8; 32]],
        recovery_delay: u64,
        allow_over_cap: bool,
    ) -> Result<GrantSplitReport> {
        ensure!(
            !trustees.is_empty(),
            "a recovery split needs at least one trustee"
        );
        let n = u8::try_from(trustees.len()).context("too many trustees (max 32)")?;
        let subject = self.user_id();

        // Resolve each trustee's roster identity (user + primary node + relay) from its
        // established-friend card, plus a dialable address for delivery. A trustee that
        // is not a friend, or whose card names no node, fails loudly - we cannot build
        // a roster entry or deliver to it.
        let resolved = {
            let s = self.shared.read().expect("shared lock");
            let mut out: Vec<(CoTrustee, Option<EndpointAddr>)> =
                Vec::with_capacity(trustees.len());
            for user in trustees {
                let card = s.friends.get(user).with_context(|| {
                    format!("trustee {} is not an established friend", hex32(user))
                })?;
                let node = card
                    .nodes
                    .first()
                    .with_context(|| format!("trustee {} card names no node", hex32(user)))?;
                let ct = CoTrustee {
                    user: *user,
                    node: node.node_id,
                    relay_url: node.relay_url.clone(),
                };
                out.push((ct, resolve_peer(&s.peer_addrs, &node.node_id)));
            }
            out
        };

        // Split M-of-N and record the extendable state. One share per trustee.
        let (shares, state, warnings) = match scope {
            RecoveryScope::Root => split_root(&self.k_root, m, Some(n), allow_over_cap),
            RecoveryScope::Vault(vid) => {
                split_vault(&self.k_root, &vid, m, Some(n), allow_over_cap)
            }
        }
        .map_err(|e| anyhow::anyhow!("recovery split failed: {e:?}"))?;
        ensure!(
            shares.len() == resolved.len(),
            "split produced {} shares for {} trustees",
            shares.len(),
            resolved.len()
        );

        // The latest announce refs over this owner's published vaults - the pointers a
        // recovering quorum follows to the current manifest + a live replica (§7.3).
        let refs = {
            let s = self.shared.read().expect("shared lock");
            current_announce_refs(&s)
        };

        // Mint one grant per trustee (roster excludes the recipient) and deliver it.
        let mut report = GrantSplitReport {
            rsid,
            warnings,
            ..Default::default()
        };
        let mut trustee_records = Vec::with_capacity(resolved.len());
        let mut roster: HashMap<[u8; 32], u64> = HashMap::new();
        for (i, (ct, addr)) in resolved.iter().enumerate() {
            let share = &shares[i];
            let cotrustees: Vec<CoTrustee> = resolved
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (o, _))| o.clone())
                .collect();
            let grant = build_share_grant(
                &self.node_key,
                subject,
                share,
                recovery_delay,
                cotrustees,
                refs.clone(),
            );
            let delivered = match addr {
                Some(a) => self.deliver_grant(a, &grant).await.unwrap_or(false),
                None => false,
            };
            if delivered {
                report.delivered.push(ct.user);
            } else {
                report.undelivered.push(ct.user);
            }
            roster.insert(ct.node, u64::from(share.x));
            trustee_records.push(GrantedTrustee {
                user: ct.user,
                node: ct.node,
                relay_url: ct.relay_url.clone(),
                share: share.clone(),
                delivered,
            });
        }

        // Record owner-side: the extendable split state, the share-health tracker
        // (§10.2 attestation cadence), and the grant set (refresh + status).
        {
            let mut s = self.shared.write().expect("shared lock");
            s.split_states.insert(rsid, RecoverySet { scope, state });
            s.share_sets
                .insert(rsid, AttestTracker::new(m, shares.len(), roster));
            s.granted.insert(
                rsid,
                OwnerGrants {
                    subject,
                    recovery_delay,
                    trustees: trustee_records,
                    refs,
                },
            );
        }
        Ok(report)
    }

    /// Dial `peer`'s control stream and send a `ShareGrant` (§8, W3). Returns `true`
    /// iff the trustee acknowledged storing it (a verified + delegated grant). A
    /// trustee that is unreachable, declines (bad delegation), or answers with no ack
    /// frame yields `false` - the caller records it undelivered and the refresh round
    /// retries. The dial is bounded so an offline trustee fails fast.
    ///
    /// Public so an owner (or a conformance test) can push a single grant directly; the
    /// trustee independently re-verifies signature + delegation on receipt.
    pub async fn deliver_grant(&self, peer: &EndpointAddr, grant: &ShareGrant) -> Result<bool> {
        let conn = tokio::time::timeout(POR_CONNECT_TIMEOUT, self.ep.connect(peer.clone(), ALPN))
            .await
            .context("grant delivery dial timed out")?
            .context("grant delivery dial failed")?;
        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, grant).await?;
        // The trustee acks with a single u64 (== 1) on success, or finishes the stream
        // with no bytes (decline). A short read is therefore a decline, not an error.
        let acked = matches!(read_u64(&mut recv).await, Ok(1));
        let _ = send.finish();
        Ok(acked)
    }

    /// Owner-side refresh round (§10.2 attestation cycle, §7.3): for each recovery set
    /// this owner minted grants for, if the current announce refs over its published
    /// vaults differ from what the trustees last received (a new epoch published),
    /// re-mint each trustee's grant with the fresh refs and re-deliver it, so trustees
    /// always hold current manifest pointers. A trustee that was previously
    /// undelivered is retried every round regardless. No lock is held across a dial.
    ///
    /// Returns the rsids whose grants were refreshed this round (for the report/tests).
    pub async fn refresh_grants_round(&self) -> Vec<u64> {
        // Snapshot the work set + current refs under a read lock, act off-lock.
        let jobs: Vec<RefreshJob> = {
            let s = self.shared.read().expect("shared lock");
            let cur_refs = current_announce_refs(&s);
            s.granted
                .iter()
                .filter_map(|(rsid, g)| {
                    let stale = g.refs != cur_refs;
                    let any_undelivered = g.trustees.iter().any(|t| !t.delivered);
                    if !stale && !any_undelivered {
                        return None;
                    }
                    let ts: Vec<TrusteeJob> = g
                        .trustees
                        .iter()
                        .map(|t| {
                            (
                                CoTrustee {
                                    user: t.user,
                                    node: t.node,
                                    relay_url: t.relay_url.clone(),
                                },
                                resolve_peer(&s.peer_addrs, &t.node),
                                t.share.clone(),
                                t.delivered,
                            )
                        })
                        .collect();
                    Some((*rsid, g.subject, g.recovery_delay, cur_refs.clone(), ts))
                })
                .collect()
        };

        let mut refreshed = Vec::new();
        for (rsid, subject, delay, refs, ts) in jobs {
            let mut new_records = Vec::with_capacity(ts.len());
            for (i, (ct, addr, share, _was)) in ts.iter().enumerate() {
                let cotrustees: Vec<CoTrustee> = ts
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, (o, _, _, _))| o.clone())
                    .collect();
                let grant = build_share_grant(
                    &self.node_key,
                    subject,
                    share,
                    delay,
                    cotrustees,
                    refs.clone(),
                );
                let delivered = match addr {
                    Some(a) => self.deliver_grant(a, &grant).await.unwrap_or(false),
                    None => false,
                };
                new_records.push(GrantedTrustee {
                    user: ct.user,
                    node: ct.node,
                    relay_url: ct.relay_url.clone(),
                    share: share.clone(),
                    delivered,
                });
            }
            // Commit the refreshed refs + delivery flags for this set.
            let mut s = self.shared.write().expect("shared lock");
            if let Some(g) = s.granted.get_mut(&rsid) {
                g.trustees = new_records;
                g.refs = refs;
            }
            refreshed.push(rsid);
        }
        refreshed
    }

    /// The W3 grant surface for the status / `/api/recovery` view: per recovery set
    /// this owner minted grants for, which trustees hold a grant and how fresh their
    /// announce refs are.
    pub fn recovery_grants(&self) -> Vec<RecoveryGrantReport> {
        let s = self.shared.read().expect("shared lock");
        s.granted
            .iter()
            .map(|(rsid, g)| RecoveryGrantReport {
                rsid: *rsid,
                subject: g.subject,
                trustees: g.trustees.iter().map(|t| (t.user, t.delivered)).collect(),
                refs: g.refs.iter().map(|r| (r.vid, r.epoch)).collect(),
            })
            .collect()
    }

    /// Trustee-side: the full [`ShareGrant`] this daemon holds for `subject` (the owner
    /// whose secret was split), if any (§8, W3). Carries the co-trustee roster, the
    /// recovery delay, and the latest announce refs - what a ceremony needs.
    pub fn held_grant(&self, subject: &[u8; 32]) -> Option<ShareGrant> {
        self.shared
            .read()
            .expect("shared lock")
            .held_grants
            .get(subject)
            .cloned()
    }

    /// Trustee-side: the subject user pubkeys this daemon holds a grant for (W3).
    pub fn held_grant_subjects(&self) -> Vec<[u8; 32]> {
        self.shared
            .read()
            .expect("shared lock")
            .held_grants
            .keys()
            .copied()
            .collect()
    }

    /// Begin tracking an inbound recovery ceremony (§8.5) from a signed `RecoveryOpen`
    /// gated by a signed `ShareGrant`. Verifies both, derives roster/`M`/delay from the
    /// grant, charges the per-subject rate limit, and records the ceremony. Returns the
    /// ceremony id and its observable phase. `now` is this observer's wall clock and
    /// anchors the abort delay (a sponsor cannot backdate it).
    pub fn ceremony_open(
        &self,
        open: &RecoveryOpen,
        grant: &ShareGrant,
        now: u64,
    ) -> Result<([u8; 16], carapace_recovery::CeremonyPhase)> {
        let state = {
            let mut limiter = self.recovery_limiter.lock().expect("recovery limiter lock");
            CeremonyState::open_from_grant(open, grant, &mut limiter, now)
                .map_err(|e| anyhow::anyhow!("ceremony open rejected: {e:?}"))?
        };
        let id = state.ceremony_id;
        let phase = state.phase(now);
        self.shared
            .write()
            .expect("shared lock")
            .ceremonies
            .insert(id, state);
        Ok((id, phase))
    }

    /// Apply a trustee's signed `CeremonyApprove` (§8.5 step 4) to a tracked ceremony.
    /// Returns the running distinct-approval count. Errors if the ceremony is unknown
    /// or the approver is not a roster trustee.
    pub fn ceremony_approve(&self, approve: &CeremonyApprove) -> Result<usize> {
        let mut s = self.shared.write().expect("shared lock");
        let cer = s
            .ceremonies
            .get_mut(&approve.ceremony_id)
            .context("unknown ceremony")?;
        cer.approve(approve)
            .map_err(|e| anyhow::anyhow!("ceremony approve rejected: {e:?}"))?;
        Ok(cer.approvals_count())
    }

    /// Abort a recovery ceremony (§8.5 step 3) by signing a `CeremonyAbort` with THIS
    /// device's user key. Only the subject user can abort; this daemon is the subject
    /// iff its own user key matches the ceremony's subject. Applies the abort to the
    /// locally tracked ceremony (if any) and returns the signed message so the GUI can
    /// broadcast it to the trustees. The abort is only *authoritative* if this device's
    /// user key is the ceremony's subject: every trustee checks `abort.by == subject`,
    /// so an abort this daemon signs for a ceremony it is not the subject of is inert
    /// (and, if the ceremony is locally tracked, `abort()` rejects it as `NotSubject`).
    pub fn ceremony_abort(&self, ceremony_id: [u8; 16]) -> Result<CeremonyAbort> {
        let mut ab = CeremonyAbort {
            ceremony_id,
            by: [0; 32],
            sig: [0; 64],
        };
        ab.sign(&self.user_key);
        let mut s = self.shared.write().expect("shared lock");
        if let Some(cer) = s.ceremonies.get_mut(&ceremony_id) {
            cer.abort(&ab)
                .map_err(|e| anyhow::anyhow!("ceremony abort rejected: {e:?}"))?;
        }
        Ok(ab)
    }
}

/// Build a `GrantBody` disclosing exactly the manifest files named in `paths`,
/// pulling each chunk's retained secret from `keys`. Errors if any requested path
/// is absent from (or deleted in) the vault, so a partial/typo'd disclosure fails
/// loudly rather than silently under-disclosing.
fn select_grant_body(manifest: &Manifest, keys: &ChunkKeys, paths: &[&str]) -> Result<GrantBody> {
    let want: HashSet<&str> = paths.iter().copied().collect();
    let mut files = Vec::with_capacity(want.len());
    for f in &manifest.files {
        if f.deleted || !want.contains(f.path.as_str()) {
            continue;
        }
        let mut chunks = Vec::with_capacity(f.chunks.len());
        for (id, len) in &f.chunks {
            let secret = keys
                .get(id)
                .with_context(|| format!("missing chunk key for {}", f.path))?;
            chunks.push(GrantChunk {
                chunk_id: *id,
                chunk_key: *secret.chunk_key,
                nonce: *secret.nonce,
                len: *len,
            });
        }
        files.push(GrantFile {
            path: f.path.clone(),
            file_hash: f.file_hash,
            size: f.size,
            chunks,
        });
    }
    ensure!(
        files.len() == want.len(),
        "disclose: {} of {} requested paths were not found in the vault",
        want.len().saturating_sub(files.len()),
        want.len()
    );
    Ok(GrantBody { files })
}

/// §7.4 / D3 blob-read gate: whether `node` (the dialer's authenticated iroh node
/// id) may fetch `chunk_id` from this daemon.
///
/// For a chunk of a vault we OWN, release it only to (a) our own delegated devices,
/// (b) this vault's replica-set members (repair), or (c) a friend authenticated on
/// our control stream whose identity an owner-signed grant names in the audience
/// covering that chunk. A dialer that never authenticated, or an authenticated
/// friend outside the audience, is refused — a leaked grant document alone (from a
/// non-audience party) authorizes nothing.
///
/// "A chunk of a vault we OWN" is any ChunkID in `owned_chunks` — every chunk ever
/// published for an owned vault, retained across epoch bumps — so a superseded
/// chunk keeps its owner gate (W2), not just the current epoch's.
///
/// A chunk we hold AS A REPLICA for another owner (any hash in `replica_chunks`,
/// envelope or ciphertext) is gated by §7.4 (a)/(b) (W8): released only to that
/// vault owner's delegated devices (proved by the card the dialer presents on our
/// control stream) or a current replica-set member from the owner's announce. Any
/// other blob (a truly foreign chunk) stays on the inherited residual.
fn authorize_fetch(s: &Shared, node: &[u8; 32], chunk_id: &[u8; 32]) -> bool {
    // Consult the RETAINED owned-chunk set, not the current-epoch `vault_blobs`, so
    // a superseded chunk stays gated instead of regressing to the residual (W2).
    if let Some(vid) = s.owned_chunks.get(chunk_id).copied() {
        return match s.blob_auth.get(node) {
            // (a) our own delegated device.
            Some(BlobAuth::OwnDevice) => true,
            // (b) replica-set member of this vault, or (c) an audience member of a
            // grant covering this chunk.
            Some(BlobAuth::Friend(user)) => {
                s.members.get(&vid).is_some_and(|m| m.contains(node))
                    || s.disclosure.is_audience(chunk_id, user)
            }
            // A device of some OTHER owner we replicate for is nobody special on our
            // own owned chunks: refused.
            Some(BlobAuth::ReplicaDevice(_)) => false,
            // Never authenticated on our control stream: refused.
            None => false,
        };
    }

    // W8/§7.4: a blob we hold AS A REPLICA for another owner. Serve it only to (a)
    // that vault owner's delegated devices, or (b) a current replica-set member (for
    // repair) - never to an arbitrary dialer, which the old residual `return true`
    // let through.
    if let Some(vid) = s.replica_chunks.get(chunk_id).copied() {
        let owner = s.replica_owner.get(&vid).copied();
        // (a) the owner's delegated device: either the owner's own node that is our
        // friend (Friend), or one of the owner's other devices proven by the card it
        // presented (ReplicaDevice).
        let owner_device = owner.is_some_and(|o| match s.blob_auth.get(node) {
            Some(BlobAuth::Friend(u)) | Some(BlobAuth::ReplicaDevice(u)) => *u == o,
            _ => false,
        });
        // (b) a current replica-set member (TLS-authenticated node id), for repair.
        let member = s
            .replica_members
            .get(&vid)
            .is_some_and(|m| m.contains(node));
        return owner_device || member;
    }

    // Not an owned-vault chunk and not replica-held: inherited residual.
    true
}

/// Resolve `node` to the *user* pubkey that delegates it: our own user (if one of
/// our cards delegates it) or an established friend whose newest card does (§4). The
/// owner-user a replica records for a placement so it can later admit that owner's
/// delegated devices (W8).
fn owner_user_of_node(
    s: &Shared,
    self_user: &[u8; 32],
    node: &[u8; 32],
    now: u64,
) -> Option<[u8; 32]> {
    if s.cards
        .iter()
        .any(|c| c.user == *self_user && card_delegates_node(c, node, now))
    {
        return Some(*self_user);
    }
    s.friends
        .iter()
        .find(|(_, c)| card_delegates_node(c, node, now))
        .map(|(user, _)| *user)
}

/// W8/§7.4 a: if the self-consistent `card` a dialer presented belongs to a vault
/// OWNER this daemon holds replicas for and delegates the dialer's `remote` node,
/// the owner-user it authenticates as. Lets an owner's device this replica does not
/// otherwise know (not enumerated in the stored friend card) fetch that owner's
/// replica-held chunks. ponytail (like the self-device gate): this trusts the
/// presented card's delegation, so a device the owner has since revoked could still
/// present an old card until a rollback-guarded owner-card store lands.
fn replica_owner_device(
    s: &Shared,
    card: &ContactCard,
    remote: &[u8; 32],
    now: u64,
) -> Option<[u8; 32]> {
    if card.verify().is_err() {
        return None;
    }
    let owner = card.user;
    if !s.replica_owner.values().any(|u| *u == owner) {
        return None;
    }
    card_delegates_node(card, remote, now).then_some(owner)
}

/// Choose which vaults to reconstruct from a pulled document batch, applying the
/// two §6 MUSTs: (C1) the announce/grant signer node must be delegated by the
/// vault-owning user in that user's newest verified `ContactCard`, and (W2) the
/// announce epoch must exceed the highest ever seen from that signer for the vid.
///
/// Phase 1 is same-user two-device sync, so the vault owner is bound to *our own*
/// user key: an announce signed by a node not delegated by our user is refused.
/// Whether a manifest-supplied relative path is safe to delete under an out dir:
/// no absolute root, no `..` escape, no backslash. Mirrors `carapace_vault`'s
/// `safe_join` guard for the tombstone-deletion path (a manifest may be hostile;
/// Phase 1 manifests are same-user-trusted, so this matches that crate's stance).
fn manifest_rel_is_safe(rel: &str) -> bool {
    if rel.is_empty() {
        return false;
    }
    rel.split('/').all(|p| p != ".." && !p.contains('\\'))
}

fn select_targets(
    docs: &mut DocStore,
    self_user: &[u8; 32],
    recv_cards: &[ContactCard],
    announces: &[VaultAnnounce],
    grants: &HashMap<[u8; 32], FileGrant>,
    now: u64,
) -> Vec<([u8; 32], VaultAnnounce, FileGrant)> {
    // The set of node ids our user delegates. The `DocStore` keeps only ONE card per
    // user, so with 3+ same-user devices that stored card alone names a single
    // sibling and every other sibling's announce would be refused - silently
    // dropping that device's edits (a §11 multi-device propagation gap). So also
    // honor the delegation carried by each card presented in THIS batch: every
    // announcing device presents its own user-signed card, and a forged card cannot
    // fake a self_user delegation (it fails `card.verify()`), so trusting any node
    // our own user validly delegates is safe. This matches the self-branch stance in
    // `classify_dialer` (own-device revocation remains a separate documented TODO).
    // Built fully before the rollback offer below borrows `docs` mutably.
    let mut delegated: HashSet<[u8; 32]> = HashSet::new();
    if let Some(card) = docs.card(self_user) {
        for n in &card.nodes {
            if card_delegates_node(card, &n.node_id, now) {
                delegated.insert(n.node_id);
            }
        }
    }
    for card in recv_cards {
        if &card.user != self_user {
            continue;
        }
        for n in &card.nodes {
            if card_delegates_node(card, &n.node_id, now) {
                delegated.insert(n.node_id);
            }
        }
    }

    let mut out = Vec::new();
    for ann in announces {
        // C1: the announce signer must be a delegated node of the vault owner.
        if !delegated.contains(&ann.by) {
            // W7 store-and-forward (§6): an announce for a vault we do not own is not
            // a reconstruction target, but store the signed doc (rollback-guarded per
            // (signer, vid)) so this node re-serves it to its own friends — an owner's
            // announce reaches a trustee through any mutual friend. A bad signature or
            // a stale epoch is simply not stored; it never aborts the batch.
            let _ = docs.offer_announce(ann);
            continue;
        }
        // A matching-epoch grant from a delegated node is required to open it.
        let grant = match grants.get(&ann.vid) {
            Some(g) if g.epoch == ann.epoch && delegated.contains(&g.by) => g,
            _ => continue,
        };
        // W2: persistent rollback — accept only an epoch strictly newer than the
        // highest ever seen from this signer for this vid (also re-verifies sig).
        if matches!(docs.offer_announce(ann), Ok(true)) {
            out.push((ann.vid, ann.clone(), grant.clone()));
        }
    }
    out
}

/// True iff `card` (self-signature valid) carries a `NodeEntry` for `node_id`
/// whose user->node delegation verifies and has not expired at `now` (§4).
fn card_delegates_node(card: &ContactCard, node_id: &[u8; 32], now: u64) -> bool {
    if card.verify().is_err() {
        return false;
    }
    let Ok(user) = VerifyingKey::from_bytes(&card.user) else {
        return false;
    };
    for n in &card.nodes {
        if &n.node_id == node_id {
            let Ok(node) = VerifyingKey::from_bytes(&n.node_id) else {
                return false;
            };
            let sig = Signature::from_bytes(&n.deleg);
            return carapace_crypto::identity::verify_delegation(
                &user,
                &node,
                n.not_after,
                &sig,
                Some(now),
            )
            .is_ok();
        }
    }
    false
}

/// W5/W2 gate for a document pull: authorize the connection's authenticated remote
/// node id. The presented `card` must be validly self-signed and name this
/// daemon's own user or an established friend. Delegation is then checked as
/// follows:
///
/// - Self branch (`card.user == self_user`, W7 `6-newest-card-delegations`): once a
///   strictly-newer self-card is known (`newest_self`, the rollback-guarded newest
///   card this user has signed, learned via anti-entropy into the [`DocStore`]), it is
///   authoritative — a node absent from it (a revoked own device presenting an old
///   self-card) is refused, per §6 "MUST NOT honor node delegations absent from the
///   signer's newest card." Until a newer self-card exists (the same-version
///   sibling-card case this build's one-node-per-device cards produce during normal
///   multi-device sync), the presented self-card's own delegation is trusted, so a
///   first-seen sibling device still authorizes.
/// - Friend branch (W2): authorization uses the STORED newest friend card
///   (`s.friends`), never the delegations in the card the dialer presents. Once a
///   friend publishes a newer card dropping a device, a dialer presenting an old
///   card that still delegates that device is refused.
fn classify_dialer(
    s: &Shared,
    self_user: &[u8; 32],
    card: &ContactCard,
    remote: &[u8; 32],
    now: u64,
    newest_self: Option<&ContactCard>,
) -> Option<BlobAuth> {
    if card.verify().is_err() {
        return None;
    }
    if card.user == *self_user {
        // A strictly-newer known self-card supersedes the presented one: honor only
        // the nodes it still delegates (revocation takes effect). Otherwise fall back
        // to the presented card, preserving same-version multi-device authorization.
        return match newest_self {
            Some(newest) if newest.version > card.version => {
                card_delegates_node(newest, remote, now).then_some(BlobAuth::OwnDevice)
            }
            _ => card_delegates_node(card, remote, now).then_some(BlobAuth::OwnDevice),
        };
    }
    match s.friends.get(&card.user) {
        Some(stored) if card_delegates_node(stored, remote, now) => {
            Some(BlobAuth::Friend(card.user))
        }
        _ => None,
    }
}

/// S3: whether a `FriendAccept` genuinely comes from the issuer of the ticket the
/// requester redeemed. The accept's embedded card must name `ticket_user`, and the
/// completed friendship must bind that same party. Signature validity is proven
/// separately by `verify_friend_accept`; this binds identity to the ticket.
fn accept_binds_ticket(accept: &FriendAccept, ticket_user: &[u8; 32], fr: &Friendship) -> bool {
    accept.card.user == *ticket_user && (fr.a == *ticket_user || fr.b == *ticket_user)
}

/// Whether `node` is a device this daemon trusts: one of our own devices (per our
/// own card) or a device delegated by an established friend's newest card. Used to
/// gate the replica-invite path on the inviting owner being a friend (or self).
fn node_is_authorized(s: &Shared, self_user: &[u8; 32], node: &[u8; 32], now: u64) -> bool {
    if s.cards
        .iter()
        .any(|c| c.user == *self_user && card_delegates_node(c, node, now))
    {
        return true;
    }
    s.friends
        .values()
        .any(|c| card_delegates_node(c, node, now))
}

/// C1: friend-gate for the embedded relay (§6/§14). Admits only this node itself,
/// its own delegated devices, and nodes delegated by an established friend's
/// newest card - never arbitrary internet peers. Reads the live friend set on
/// every connection, so a peer befriended after the relay started is admitted
/// and an unfriended one stops being admitted, with no relay restart.
///
/// The endpoint id is authenticated by the relay handshake before this runs
/// (iroh-relay), so a non-friend cannot forge a friend's id to pass the gate.
struct FriendRelayGate {
    shared: Arc<RwLock<Shared>>,
    self_user: [u8; 32],
    self_node: [u8; 32],
}

impl std::fmt::Debug for FriendRelayGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FriendRelayGate")
            .field("self_node", &hex32(&self.self_node))
            .finish_non_exhaustive()
    }
}

impl RelayAccessPolicy for FriendRelayGate {
    fn allows(&self, endpoint_id: &EndpointId, auth_token: Option<&str>) -> bool {
        let node = *endpoint_id.as_bytes();
        // Always admit ourselves: we register on our own relay as home relay,
        // independent of when our own card lands in `shared`.
        if node == self.self_node {
            return true;
        }
        let now = unix_now();
        let s = self.shared.read().expect("shared lock");
        if node_is_authorized(&s, &self.self_user, &node, now) {
            return true;
        }
        // Invite bootstrap (§6): a not-yet-friend that presents a live invite
        // ticket we issued (as its relay auth token) is admitted so it can reach
        // us to complete the friendship handshake. Without this, a friend-only
        // gate would make the very first, ticketed contact impossible over relay.
        auth_token
            .and_then(parse_ticket_auth_token)
            .is_some_and(|tok| s.tickets.admits(&tok, now))
    }
}

/// The per-friend replica-storage grant to enforce for a placement signed by
/// `node`: the byte limit agreed with the friend whose newest card delegates
/// `node`, or `DEFAULT_QUOTA_BYTES` if no grant is recorded (defensive default -
/// S4 already requires an established friendship to place at all). This is the
/// receive-side quota the storing node grants that specific friend (W1); it is
/// looked up by the placing friend, never a global constant.
fn friend_storage_grant(s: &Shared, node: &[u8; 32], now: u64) -> u64 {
    for (user, card) in &s.friends {
        if card_delegates_node(card, node, now) {
            return s
                .friend_grants
                .get(user)
                .copied()
                .unwrap_or(DEFAULT_QUOTA_BYTES);
        }
    }
    DEFAULT_QUOTA_BYTES
}

/// The latest [`AnnounceRef`]s over this owner's published vaults (W3, §7.3): one
/// `(vid, epoch, digest)` per owned-vault announce, sorted by vid so the set is
/// order-stable (a refresh only re-issues on a real epoch change, not on map
/// iteration order). Third-party announces live in the doc store, not `s.announces`,
/// so this is exactly the owner's own vaults.
fn current_announce_refs(s: &Shared) -> Vec<AnnounceRef> {
    let mut refs: Vec<AnnounceRef> = s
        .announces
        .iter()
        .map(|a| AnnounceRef {
            vid: a.vid,
            epoch: a.epoch,
            digest: a.digest,
        })
        .collect();
    refs.sort_by_key(|r| r.vid);
    refs
}

/// The announce `replicas` list: this device first, then the accepted members.
fn replica_list(self_node: [u8; 32], members: Option<&Vec<[u8; 32]>>) -> Vec<[u8; 32]> {
    let mut v = vec![self_node];
    if let Some(m) = members {
        for n in m {
            if !v.contains(n) {
                v.push(*n);
            }
        }
    }
    v
}

/// Re-sign the announce for `vid` reflecting the current member set (same content
/// epoch + digest). Replaces any prior announce for the vid.
fn reannounce(s: &mut Shared, vid: [u8; 32], self_node: [u8; 32], node_key: &SigningKey) {
    let Some(vb) = s.vault_blobs.get(&vid).cloned() else {
        return;
    };
    let epoch = *s.epochs.get(&vid).unwrap_or(&0);
    let replicas = replica_list(self_node, s.members.get(&vid));
    let mut ann = VaultAnnounce {
        vid,
        epoch,
        replicas,
        digest: vb.digest,
        by: [0; 32],
        sig: [0; 64],
    };
    ann.sign(node_key);
    s.announces.retain(|a| a.vid != vid);
    s.announces.push(ann);
}

/// Cap on a single pushed replica blob (envelope or ciphertext chunk): the vault
/// max chunk is 4 MiB plus sealing overhead, so 16 MiB is a generous ceiling that
/// still bounds a hostile length prefix.
const MAX_REPLICA_BLOB: usize = 16 * 1024 * 1024;

async fn write_u64(send: &mut SendStream, v: u64) -> Result<()> {
    send.write_all(&v.to_be_bytes()).await?;
    Ok(())
}

async fn read_u64(recv: &mut RecvStream) -> Result<u64> {
    let mut b = [0u8; 8];
    recv.read_exact(&mut b)
        .await
        .map_err(|e| anyhow::anyhow!("read u64: {e}"))?;
    Ok(u64::from_be_bytes(b))
}

async fn write_sig(send: &mut SendStream, sig: &[u8; 64]) -> Result<()> {
    send.write_all(sig).await?;
    Ok(())
}

async fn read_sig(recv: &mut RecvStream) -> Result<[u8; 64]> {
    let mut b = [0u8; 64];
    recv.read_exact(&mut b)
        .await
        .map_err(|e| anyhow::anyhow!("read sig: {e}"))?;
    Ok(b)
}

async fn write_blob(send: &mut SendStream, data: &[u8]) -> Result<()> {
    write_u64(send, data.len() as u64).await?;
    send.write_all(data).await?;
    Ok(())
}

async fn read_blob(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let len = read_u64(recv).await? as usize;
    ensure!(
        len <= MAX_REPLICA_BLOB,
        "replica blob length {len} exceeds cap"
    );
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow::anyhow!("read blob: {e}"))?;
    Ok(buf)
}

/// Build a dialable [`EndpointAddr`] from a node id and zero or more socket-address
/// strings (e.g. `"127.0.0.1:52345"`). An empty `addrs` yields an id-only address
/// (usable only with a discovery service). A malformed node id or socket string is a
/// hard error rather than a silently-dropped address.
/// Resolve a peer node id to a dialable [`EndpointAddr`] for the maintenance loop:
/// the last-known address if this node recorded one (from a prior befriend/placement
/// dial), else a node-id-only addr that iroh resolves through injected hints and relay
/// fallback (§6 "addresses are hints, not identities"). Returns `None` only if the
/// node id is not a valid endpoint key.
fn resolve_peer(
    peer_addrs: &HashMap<[u8; 32], EndpointAddr>,
    node: &[u8; 32],
) -> Option<EndpointAddr> {
    if let Some(addr) = peer_addrs.get(node) {
        return Some(addr.clone());
    }
    EndpointId::from_bytes(node).ok().map(EndpointAddr::new)
}

fn endpoint_addr(node: [u8; 32], addrs: &[String]) -> Result<EndpointAddr> {
    let id = EndpointId::from_bytes(&node)
        .map_err(|e| anyhow::anyhow!("bad node id {}: {e}", hex32(&node)))?;
    let mut ea = EndpointAddr::new(id);
    for a in addrs {
        let sock: std::net::SocketAddr = a
            .parse()
            .with_context(|| format!("bad socket address {a:?}"))?;
        ea = ea.with_ip_addr(sock);
    }
    Ok(ea)
}

/// Build the relay URL to advertise for a running embedded relay: `relay_host`
/// (a public DNS name or WAN IP) on the relay's bound port, or the relay's own
/// bound `http://addr` when no host override is given (§6).
fn relay_advert_url(relay: &CarapaceRelay, host: Option<&str>) -> Result<RelayUrl> {
    match host {
        Some(h) => format!("http://{}:{}", h, relay.http_addr().port())
            .parse::<RelayUrl>()
            .map_err(|e| anyhow::anyhow!("advertised relay url for host {h:?}: {e}")),
        None => Ok(relay.relay_url()),
    }
}

/// Feed a friend's ContactCard addressing hints into the live endpoint (§6): for
/// each node entry, inject an `EndpointAddr` (id + direct addrs + relay url) so it
/// can be dialed by node id, and add its relay to our usable relay set. A
/// malformed entry is skipped rather than failing the whole learn.
async fn learn_card_hints(hints: &PeerHints, card: &ContactCard) {
    let now = unix_now();
    for n in &card.nodes {
        // W1: only inject a hint for a node the card's user actually delegates,
        // with a delegation that has not expired. `card.verify()` at the call
        // sites covers only the card's self-signature, not the per-node
        // user->node delegations, so without this gate a card could inject an
        // address hint for a node_id it never delegated.
        //
        // ponytail (known ceiling): this enforces the card's own trust model but
        // does not fully stop cross-friend hint poisoning - delegations are
        // user-signed only, so a malicious friend can self-delegate an arbitrary
        // node_id (including a third friend's) with attacker-chosen addrs. That
        // residual is bounded (no impersonation; QUIC is node-id-authenticated;
        // hints merge, not replace) and closing it needs source-keyed hints, out
        // of scope here.
        if card_delegates_node(card, &n.node_id, now) {
            // No relay auth token: an established friend's relay admits us via the
            // friend branch of its gate, not via an invite ticket.
            inject_hint(hints, n.node_id, &n.addrs, n.relay_url.as_deref(), None).await;
        }
    }
}

/// Like [`learn_card_hints`] but from an [`InviteTicket`] (issuer node id + direct
/// addrs + advertised relay URLs). "Your usable relay set = relays advertised by
/// your friends" (§6). The ticket's token is attached to the issuer's relays as
/// the relay auth token so the issuer's friend-gated relay admits us for the
/// (not-yet-friend) bootstrap handshake.
async fn learn_ticket_hints(hints: &PeerHints, ticket: &InviteTicket) {
    let auth = ticket_auth_token(&ticket.token);
    inject_hint(
        hints,
        ticket.node,
        &ticket.addrs,
        ticket.relay_urls.first().map(String::as_str),
        Some(&auth),
    )
    .await;
    // Any further advertised relays join our usable set too, with the same token.
    for url in ticket.relay_urls.iter().skip(1) {
        if let Ok(u) = url.parse::<RelayUrl>() {
            hints.add_relay_with_token(u, auth.clone()).await;
        }
    }
}

/// Inject one peer's `{node_id, direct addrs, relay}` hint into the endpoint.
/// Unparseable node ids, socket strings, or relay URLs are dropped (best effort:
/// addresses are hints, §6). When `auth_token` is set, the relay is added with
/// that client auth token (the invite bootstrap, §6); otherwise it is added plain.
async fn inject_hint(
    hints: &PeerHints,
    node: [u8; 32],
    addrs: &[String],
    relay: Option<&str>,
    auth_token: Option<&str>,
) {
    let Ok(id) = EndpointId::from_bytes(&node) else {
        return;
    };
    let mut ea = EndpointAddr::new(id);
    for a in addrs {
        if let Ok(sock) = a.parse::<std::net::SocketAddr>() {
            ea = ea.with_ip_addr(sock);
        }
    }
    if let Some(url) = relay {
        if let Ok(u) = url.parse::<RelayUrl>() {
            ea = ea.with_relay_url(u.clone());
            match auth_token {
                Some(t) => {
                    hints.add_relay_with_token(u, t.to_string()).await;
                }
                None => {
                    hints.add_relay(u).await;
                }
            }
        }
    }
    hints.add_peer(ea);
}

/// Hex-encode a 16-byte invite-ticket token for use as a relay auth token (§6
/// bootstrap). Lowercase, unpadded, 32 chars.
fn ticket_auth_token(token: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in token {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a relay auth token back to a 16-byte invite-ticket token, or `None` if
/// it is not exactly 32 hex chars. Inverse of [`ticket_auth_token`].
fn parse_ticket_auth_token(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Current unix time in seconds (for delegation-expiry checks).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a `GrantBody` carrying every non-deleted chunk's secret. Errors (rather
/// than panicking — S3) if a manifest chunk id is absent from `keys`; both come
/// from the same ingest, so this is an owner-local invariant, but fail loudly.
fn grant_body(manifest: &Manifest, keys: &ChunkKeys) -> Result<GrantBody> {
    let mut files = Vec::new();
    for f in &manifest.files {
        if f.deleted {
            continue;
        }
        let mut chunks = Vec::with_capacity(f.chunks.len());
        for (id, len) in &f.chunks {
            let s = keys
                .get(id)
                .with_context(|| format!("missing chunk key for {}", f.path))?;
            chunks.push(GrantChunk {
                chunk_id: *id,
                chunk_key: *s.chunk_key,
                nonce: *s.nonce,
                len: *len,
            });
        }
        files.push(GrantFile {
            path: f.path.clone(),
            file_hash: f.file_hash,
            size: f.size,
            chunks,
        });
    }
    Ok(GrantBody { files })
}

/// Rebuild the `ChunkKeys` map from an opened `GrantBody`.
fn keys_from_grant(body: &GrantBody) -> ChunkKeys {
    let mut m = HashMap::new();
    for f in &body.files {
        for c in &f.chunks {
            m.insert(
                c.chunk_id,
                ChunkSecret {
                    chunk_key: Zeroizing::new(c.chunk_key),
                    nonce: Zeroizing::new(c.nonce),
                },
            );
        }
    }
    m
}

/// This device's ContactCard: display name, disclosure enc key, and a single
/// node entry whose delegation is user-signed (§4). `relay_url` is this node's
/// advertised self-hosted relay (§6), or `None` when it runs no relay.
fn build_card(
    user_key: &SigningKey,
    node_key: &SigningKey,
    k_root: &[u8; 32],
    relay_url: Option<String>,
) -> ContactCard {
    let (_priv, disclose_pub) = seal::derive_keypair(&*kdf::k_disclose(k_root));
    let enc_pub: [u8; 32] = disclose_pub
        .to_bytes()
        .try_into()
        .expect("X25519 pubkey is 32 bytes");
    let node_pub = node_key.verifying_key();
    let deleg =
        carapace_crypto::identity::sign_delegation(user_key, &node_pub, DELEG_NOT_AFTER).to_bytes();

    let mut card = ContactCard {
        user: user_key.verifying_key().to_bytes(),
        display: "carapace-device".into(),
        enc_pub,
        nodes: vec![NodeEntry {
            node_id: node_pub.to_bytes(),
            deleg,
            not_after: DELEG_NOT_AFTER,
            addrs: vec![],
            relay_url: relay_url.clone(),
        }],
        offers: Offers {
            storage_bytes: 0,
            relay: relay_url.is_some(),
            trustee: false,
        },
        version: 1,
        by: [0; 32],
        sig: [0; 64],
    };
    card.sign(user_key);
    card
}

/// W4: count distinct relay networks among a set of relay URLs, keyed by host
/// (DNS name or IP literal, lowercased). Unparseable URLs and URLs with no host
/// are ignored. Two relays on the same host (any port) count as one network.
fn distinct_relay_networks<'a>(urls: impl Iterator<Item = &'a str>) -> usize {
    let mut hosts: HashSet<String> = HashSet::new();
    for url in urls {
        if let Ok(u) = url.parse::<RelayUrl>() {
            if let Some(h) = u.host_str() {
                hosts.insert(h.to_ascii_lowercase());
            }
        }
    }
    hosts.len()
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000; // well before DELEG_NOT_AFTER

    fn kp(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn announce(node: &SigningKey, vid: [u8; 32], epoch: u64) -> VaultAnnounce {
        let mut a = VaultAnnounce {
            vid,
            epoch,
            replicas: vec![],
            digest: [7; 32],
            by: [0; 32],
            sig: [0; 64],
        };
        a.sign(node);
        a
    }

    fn grant(node: &SigningKey, vid: [u8; 32], epoch: u64) -> FileGrant {
        let mut g = FileGrant {
            grant_id: [0; 16],
            vid,
            epoch,
            audience: vec![],
            sealed: vec![],
            by: [0; 32],
            sig: [0; 64],
        };
        g.sign(node);
        g
    }

    fn one_grant(node: &SigningKey, vid: [u8; 32], epoch: u64) -> HashMap<[u8; 32], FileGrant> {
        let mut m = HashMap::new();
        m.insert(vid, grant(node, vid, epoch));
        m
    }

    // C1: an announce is honored only if its signer node is delegated by the
    // vault-owning user's newest card; a rogue/undelegated node is refused.
    #[test]
    fn c1_only_delegated_signer_is_accepted() {
        let user = kp(1);
        let node = kp(3);
        let card = build_card(&user, &node, &[9; 32], None);
        let self_user = user.verifying_key().to_bytes();
        let vid = [0x55; 32];

        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[],
            &[announce(&node, vid, 1)],
            &one_grant(&node, vid, 1),
            NOW,
        );
        assert_eq!(targets.len(), 1, "delegated signer must be accepted");

        // A rogue node, not present in the user's card, is refused even though it
        // self-signs a valid announce + grant.
        let rogue = kp(0x42);
        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[],
            &[announce(&rogue, vid, 1)],
            &one_grant(&rogue, vid, 1),
            NOW,
        );
        assert!(
            targets.is_empty(),
            "undelegated signer must be refused (C1)"
        );

        // 3+ device propagation: a second sibling node our SAME user delegates -
        // proven by the card that sibling presents in this batch - is accepted even
        // though the stored card names only `node`. This is what lets a third
        // device's edits reach us instead of being silently dropped.
        let node2 = kp(0x77);
        let card2 = build_card(&user, &node2, &[9; 32], None);
        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap(); // stored card delegates `node`, not node2
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[card2],
            &[announce(&node2, vid, 1)],
            &one_grant(&node2, vid, 1),
            NOW,
        );
        assert_eq!(
            targets.len(),
            1,
            "a sibling our own user delegates (card in batch) must be accepted"
        );

        // A card signed by a DIFFERENT user cannot smuggle a delegation into our set
        // (its user != self_user), so a rogue presenting one stays refused.
        let rogue_user = kp(0x99);
        let rogue_card = build_card(&rogue_user, &rogue, &[9; 32], None);
        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[rogue_card],
            &[announce(&rogue, vid, 1)],
            &one_grant(&rogue, vid, 1),
            NOW,
        );
        assert!(
            targets.is_empty(),
            "a foreign-user card cannot delegate into our trusted set"
        );
    }

    // C1: a valid announce survives even when a poison undelegated announce is in
    // the same batch (this is also the selection half of W3's isolation).
    #[test]
    fn c1_poison_announce_does_not_starve_valid_vault() {
        let user = kp(1);
        let node = kp(3);
        let rogue = kp(0x42);
        let card = build_card(&user, &node, &[9; 32], None);
        let self_user = user.verifying_key().to_bytes();
        let good = [0x11; 32];
        let bad = [0x22; 32];

        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();
        let mut grants = one_grant(&node, good, 1);
        grants.insert(bad, grant(&rogue, bad, 1));
        let targets = select_targets(
            &mut docs,
            &self_user,
            &[],
            &[announce(&rogue, bad, 1), announce(&node, good, 1)],
            &grants,
            NOW,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, good);
    }

    #[test]
    fn c1_expired_or_unknown_delegation_refused() {
        let user = kp(1);
        let node = kp(3);
        let card = build_card(&user, &node, &[9; 32], None);
        let node_id = node.verifying_key().to_bytes();
        assert!(card_delegates_node(&card, &node_id, NOW));
        assert!(
            !card_delegates_node(&card, &node_id, DELEG_NOT_AFTER + 1),
            "expired"
        );
        assert!(
            !card_delegates_node(&card, &[0x42; 32], NOW),
            "unknown node id"
        );
    }

    /// A self-signed card for `user` delegating exactly `node`, at `version`.
    fn card_with(user: &SigningKey, node: &SigningKey, version: u64) -> ContactCard {
        let node_pub = node.verifying_key();
        let deleg =
            carapace_crypto::identity::sign_delegation(user, &node_pub, DELEG_NOT_AFTER).to_bytes();
        let mut card = ContactCard {
            user: user.verifying_key().to_bytes(),
            display: "x".into(),
            enc_pub: [0; 32],
            nodes: vec![NodeEntry {
                node_id: node_pub.to_bytes(),
                deleg,
                not_after: DELEG_NOT_AFTER,
                addrs: vec![],
                relay_url: None,
            }],
            offers: Offers {
                storage_bytes: 0,
                relay: false,
                trustee: false,
            },
            version,
            by: [0; 32],
            sig: [0; 64],
        };
        card.sign(user);
        card
    }

    // W2: friend-device revocation takes effect. A friend delegates node N in card
    // v1, then publishes v2 dropping N. Once v2 is the stored newest card, a dialer
    // presenting the old v1 card for node N is refused - authorization uses the
    // stored card, not the presented one.
    #[test]
    fn w2_friend_revocation_refused_after_newer_card() {
        let friend_user = kp(0x50);
        let node_n = kp(0x51);
        let node_m = kp(0x52);
        let friend = friend_user.verifying_key().to_bytes();
        let n_id = node_n.verifying_key().to_bytes();
        let self_user = kp(0x01).verifying_key().to_bytes();

        let v1 = card_with(&friend_user, &node_n, 1); // delegates N
        let v2 = card_with(&friend_user, &node_m, 2); // drops N, delegates M

        let mut s = Shared::default();
        s.friends.insert(friend, v1.clone());
        // While v1 is newest, a dialer presenting v1 for node N is authorized.
        assert!(classify_dialer(&s, &self_user, &v1, &n_id, NOW, None).is_some());

        // Friend publishes v2 (drops N). A dialer still presenting v1 for N loses.
        s.friends.insert(friend, v2);
        assert!(
            classify_dialer(&s, &self_user, &v1, &n_id, NOW, None).is_none(),
            "node N is revoked once the newer card dropping it is known (W2)"
        );
    }

    // W7 (6-newest-card-delegations): own-device revocation takes effect once a newer
    // self-card is known. This user's device X is delegated by self-card v1; the user
    // then publishes v2 (a newer self-card) that drops X. Once v2 is the newest known
    // self-card, X presenting its old v1 self-card is refused — §6 "MUST NOT honor
    // node delegations absent from the signer's newest card." A device still present
    // in v2 authorizes, and before any newer card exists the presented card is
    // trusted (preserving same-version multi-device sync).
    #[test]
    fn w7_own_device_revocation_refused_after_newer_self_card() {
        let self_user = kp(0x01);
        let device_x = kp(0x02);
        let device_y = kp(0x03);
        let self_uid = self_user.verifying_key().to_bytes();
        let x_id = device_x.verifying_key().to_bytes();
        let y_id = device_y.verifying_key().to_bytes();

        let v1 = card_with(&self_user, &device_x, 1); // self-card delegating X
        let v2 = card_with(&self_user, &device_y, 2); // newer self-card: drops X, adds Y

        let s = Shared::default();
        // No newer self-card known yet: X presenting its own valid self-card is trusted
        // (the same-version multi-device path this build relies on).
        assert!(
            classify_dialer(&s, &self_uid, &v1, &x_id, NOW, None).is_some(),
            "own device authorizes on its own self-card before any newer card exists"
        );

        // Once v2 is the newest known self-card, X (absent from v2) is refused even
        // though its old v1 card still delegates it.
        assert!(
            classify_dialer(&s, &self_uid, &v1, &x_id, NOW, Some(&v2)).is_none(),
            "a revoked own device presenting an old self-card must NOT authorize (W7)"
        );
        // A device still present in the newest self-card authorizes.
        assert!(
            classify_dialer(&s, &self_uid, &v2, &y_id, NOW, Some(&v2)).is_some(),
            "a device in the newest self-card still authorizes"
        );
    }

    // W1: `fetch_disclosed` authenticates the discloser (its `grant.by`) via
    // `node_is_authorized` before reconstructing. A device of our own user or of an
    // established friend passes; an unknown node (the `grant.by` of an unsolicited
    // grant sealed to us by a stranger) is refused, so only established friends can
    // push us disclosed content.
    #[test]
    fn w1_discloser_must_be_self_or_friend() {
        let self_user = kp(0x01);
        let self_node = kp(0x02);
        let friend_user = kp(0x50);
        let friend_node = kp(0x51);
        let stranger = kp(0x77);
        let self_uid = self_user.verifying_key().to_bytes();

        let mut s = Shared::default();
        s.cards
            .push(build_card(&self_user, &self_node, &[9; 32], None));
        s.friends.insert(
            friend_user.verifying_key().to_bytes(),
            card_with(&friend_user, &friend_node, 1),
        );

        assert!(
            node_is_authorized(&s, &self_uid, &self_node.verifying_key().to_bytes(), NOW),
            "our own delegated device may disclose"
        );
        assert!(
            node_is_authorized(&s, &self_uid, &friend_node.verifying_key().to_bytes(), NOW),
            "an established friend's delegated device may disclose"
        );
        assert!(
            !node_is_authorized(&s, &self_uid, &stranger.verifying_key().to_bytes(), NOW),
            "an unknown discloser (stranger-signed grant) is refused (W1)"
        );
    }

    // W2: a superseded-epoch chunk keeps its §7.4 owner gate. Once a republish drops
    // the old chunk from `vault_blobs`, `owned_chunks` still holds it, so an
    // unauthenticated dialer and a non-audience friend are both refused, while the
    // grant's audience is still served - the chunk never regresses to the residual.
    #[test]
    fn w2_superseded_chunk_stays_owner_gated() {
        let vid = [0x55; 32];
        let old_chunk = [0x11; 32];
        let audience_user = [0xBB; 32];
        let friend_node = [0xCC; 32];

        let mut s = Shared::default();
        // Published under an old epoch, then superseded: gone from vault_blobs but
        // retained in owned_chunks.
        s.owned_chunks.insert(old_chunk, vid);

        // Record a grant that disclosed this old chunk to `audience_user`.
        let owner = kp(0x03);
        let mut fg = FileGrant {
            grant_id: [0; 16],
            vid,
            epoch: 1,
            audience: vec![audience_user],
            sealed: vec![],
            by: [0; 32],
            sig: [0; 64],
        };
        fg.sign(&owner);
        let body = GrantBody {
            files: vec![GrantFile {
                path: "f1".into(),
                file_hash: [0; 32],
                size: 1,
                chunks: vec![GrantChunk {
                    chunk_id: old_chunk,
                    chunk_key: [0; 32],
                    nonce: [0; 24],
                    len: 1,
                }],
            }],
        };
        s.disclosure.record(&fg, &body);

        // Unauthenticated dialer: refused (pre-fix this fell through to the residual
        // `return true` because the chunk was no longer in any current vault_blobs).
        assert!(
            !authorize_fetch(&s, &[0x99; 32], &old_chunk),
            "unauthenticated dialer refused a superseded owned chunk (W2)"
        );
        // A friend outside the audience: refused.
        s.blob_auth
            .insert(friend_node, BlobAuth::Friend([0xDD; 32]));
        assert!(
            !authorize_fetch(&s, &friend_node, &old_chunk),
            "non-audience friend refused a superseded owned chunk"
        );
        // The grant's audience: still served.
        s.blob_auth
            .insert(friend_node, BlobAuth::Friend(audience_user));
        assert!(
            authorize_fetch(&s, &friend_node, &old_chunk),
            "the audience of a grant covering the chunk is still served"
        );
        // A genuinely foreign chunk (never owned) stays on the inherited residual.
        assert!(
            authorize_fetch(&s, &[0x99; 32], &[0xAB; 32]),
            "a non-owned chunk keeps the residual (AEAD + ChunkID secrecy)"
        );
    }

    // W8/§7.4: a chunk held AS A REPLICA is served only to the vault owner's
    // delegated devices or a current replica-set member - never to an arbitrary
    // dialer, which the old residual `return true` let through.
    #[test]
    fn w8_replica_held_chunk_is_gated() {
        let vid = [0x77; 32];
        let chunk = [0x22; 32];

        // The vault owner (a friend of this replica) with two devices.
        let owner_user = kp(0x50);
        let owner_dev1 = kp(0x51); // owner node enumerated in the stored friend card
        let owner_dev2 = kp(0x52); // owner's OTHER device, not in that card
        let owner_uid = owner_user.verifying_key().to_bytes();
        let dev1 = owner_dev1.verifying_key().to_bytes();
        let dev2 = owner_dev2.verifying_key().to_bytes();

        let member = [0xEE; 32]; // a current replica-set peer
        let stranger = [0x99; 32];

        let mut s = Shared::default();
        // This daemon holds `chunk` (and its envelope) as a replica of owner's vault.
        s.replica_chunks.insert(chunk, vid);
        s.replica_owner.insert(vid, owner_uid);
        s.replica_members.insert(vid, vec![member]);
        // It holds the owner's card (owner is its friend); the card delegates dev1.
        s.friends.insert(
            owner_uid,
            build_card(&owner_user, &owner_dev1, &[0x50; 32], None),
        );

        // Unauthorized dialer (never authenticated, not a member): refused. This is
        // exactly the leak the pre-W8 residual `return true` allowed.
        assert!(
            !authorize_fetch(&s, &stranger, &chunk),
            "an arbitrary dialer is refused a replica-held chunk (W8)"
        );

        // (a) the owner's known device, classified Friend(owner) via the control
        // stream: served.
        s.blob_auth.insert(dev1, BlobAuth::Friend(owner_uid));
        assert!(
            authorize_fetch(&s, &dev1, &chunk),
            "the owner's delegated device is served (§7.4 a)"
        );

        // (a) the owner's OTHER device, authenticated by the card it presented
        // (replica_owner_device -> ReplicaDevice): served.
        let dev2_card = build_card(&owner_user, &owner_dev2, &[0x50; 32], None);
        assert_eq!(
            replica_owner_device(&s, &dev2_card, &dev2, NOW),
            Some(owner_uid),
            "owner's other device authenticates via its presented card"
        );
        s.blob_auth.insert(dev2, BlobAuth::ReplicaDevice(owner_uid));
        assert!(
            authorize_fetch(&s, &dev2, &chunk),
            "the owner's other delegated device is served (§7.4 a)"
        );

        // (b) a current replica-set member, by TLS-authenticated node id: served for
        // repair, no control-stream handshake required.
        assert!(
            authorize_fetch(&s, &member, &chunk),
            "a current replica-set member is served for repair (§7.4 b)"
        );

        // A device of a DIFFERENT owner (ReplicaDevice for another user) is refused.
        s.blob_auth
            .insert(stranger, BlobAuth::ReplicaDevice([0xAB; 32]));
        assert!(
            !authorize_fetch(&s, &stranger, &chunk),
            "a device of another owner is refused a replica-held chunk"
        );

        // A ReplicaDevice classification authorizes nothing on a chunk we OWN.
        let owned = [0x33; 32];
        s.owned_chunks.insert(owned, vid);
        assert!(
            !authorize_fetch(&s, &dev2, &owned),
            "a replica-owner device is nobody on our own owned chunk"
        );

        // replica_owner_device only fires for an owner we actually replicate for.
        let other_user = kp(0x60);
        let other_node = kp(0x61);
        let other_card = build_card(&other_user, &other_node, &[0x60; 32], None);
        assert_eq!(
            replica_owner_device(&s, &other_card, &other_node.verifying_key().to_bytes(), NOW),
            None,
            "no replica held for this user -> no replica-device authentication"
        );
    }

    // S3: a friend accept is bound to the ticket's issuer - both the accept's card
    // user and the friendship's parties must match the ticket user.
    #[test]
    fn s3_accept_must_bind_ticket_issuer() {
        let issuer_key = kp(0x60);
        let issuer = issuer_key.verifying_key().to_bytes();
        let me = kp(0x62).verifying_key().to_bytes();
        let stranger = kp(0x64).verifying_key().to_bytes();

        let friendship = |x: [u8; 32], y: [u8; 32]| {
            let (a, b) = if x <= y { (x, y) } else { (y, x) };
            Friendship {
                a,
                b,
                established: 1,
                sig_a: [0; 64],
                sig_b: [0; 64],
            }
        };
        let accept = FriendAccept {
            card: card_with(&issuer_key, &kp(0x63), 1),
            friendship: friendship(issuer, me),
            by: [0; 32],
            sig: [0; 64],
        };

        // Correct issuer: card user and friendship party both match.
        assert!(accept_binds_ticket(&accept, &issuer, &accept.friendship));
        // Wrong ticket issuer: the card names someone else.
        assert!(!accept_binds_ticket(&accept, &stranger, &accept.friendship));
        // Card matches the ticket but the friendship binds a different pair.
        let mismatched = friendship(stranger, me);
        assert!(!accept_binds_ticket(&accept, &issuer, &mismatched));
    }

    // W2: the highest-seen epoch persists across sync calls (shared DocStore), so
    // a genuinely-signed but older/equal announce is refused on a later sync.
    #[test]
    fn w2_rollback_persists_across_syncs() {
        let user = kp(1);
        let node = kp(3);
        let card = build_card(&user, &node, &[9; 32], None);
        let self_user = user.verifying_key().to_bytes();
        let vid = [0x55; 32];

        let mut docs = DocStore::new();
        docs.offer_card(&card).unwrap();

        // sync 1: accept epoch 2 (delegation comes from the stored card)
        let t = select_targets(
            &mut docs,
            &self_user,
            &[],
            &[announce(&node, vid, 2)],
            &one_grant(&node, vid, 2),
            NOW,
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].1.epoch, 2);

        // sync 2: a real, signed epoch-1 announce (stale replica) is refused
        let t = select_targets(
            &mut docs,
            &self_user,
            &[],
            &[announce(&node, vid, 1)],
            &one_grant(&node, vid, 1),
            NOW,
        );
        assert!(t.is_empty(), "epoch-1 rollback refused after epoch 2 (W2)");

        // equal epoch is not newer either
        let t = select_targets(
            &mut docs,
            &self_user,
            &[],
            &[announce(&node, vid, 2)],
            &one_grant(&node, vid, 2),
            NOW,
        );
        assert!(t.is_empty(), "equal epoch is refused");
    }

    // C1: the embedded relay's friend-gate admits only this node itself and nodes
    // delegated by an established friend's newest card - never arbitrary peers -
    // and it tracks the live friend set (a peer befriended after start is
    // admitted with no relay restart).
    #[test]
    fn c1_relay_gate_admits_only_self_and_friends() {
        let self_user_key = kp(1);
        let self_node_key = kp(2);
        let self_user = self_user_key.verifying_key().to_bytes();
        let self_node = self_node_key.verifying_key().to_bytes();

        let friend_user = kp(10);
        let friend_node = kp(11);
        let friend_card = build_card(&friend_user, &friend_node, &[0xAA; 32], None);

        let shared = Arc::new(RwLock::new(Shared::default()));
        let gate = FriendRelayGate {
            shared: Arc::clone(&shared),
            self_user,
            self_node,
        };
        let eid = |k: &SigningKey| {
            EndpointId::from_bytes(&k.verifying_key().to_bytes()).expect("valid endpoint id")
        };

        // Self is always admitted (it registers on its own relay as home relay).
        assert!(gate.allows(&eid(&self_node_key), None));
        // Before the friendship exists, the friend's node and any stranger are
        // denied - the relay is not an open forwarder.
        assert!(!gate.allows(&eid(&friend_node), None));
        assert!(!gate.allows(&eid(&kp(99)), None));

        // Invite bootstrap: a stranger presenting a live invite-ticket token we
        // issued (as its relay auth token) is admitted so it can reach us to
        // complete the handshake; a bogus/unknown token is not.
        let ticket = build_ticket(&self_user_key, self_node, vec![], vec![], NOW + 3600).unwrap();
        let good = ticket_auth_token(&ticket.token);
        shared.write().unwrap().tickets.issue(&ticket);
        assert!(
            gate.allows(&eid(&kp(99)), Some(&good)),
            "a stranger with a live issued ticket token is admitted for bootstrap"
        );
        assert!(
            !gate.allows(&eid(&kp(99)), Some(&ticket_auth_token(&[0xAB; 16]))),
            "an unknown ticket token is not admitted"
        );
        assert!(
            !gate.allows(&eid(&kp(99)), Some("not-hex")),
            "a malformed auth token is not admitted"
        );

        // Establishing the friendship admits their delegated node, live.
        shared
            .write()
            .unwrap()
            .friends
            .insert(friend_user.verifying_key().to_bytes(), friend_card);
        assert!(
            gate.allows(&eid(&friend_node), None),
            "established friend's delegated node is admitted"
        );
        // An unrelated stranger with no token is still denied.
        assert!(!gate.allows(&eid(&kp(99)), None));
    }

    // W1: a card injects an addressing hint only for a node it validly delegates.
    // `card.verify()` covers the card self-signature but not the per-node
    // user->node delegations, so an entry carrying an invalid delegation must not
    // be injected even when the card itself is validly signed.
    #[test]
    fn w1_hint_gate_rejects_undelegated_node() {
        let user = kp(5);
        let node = kp(6);
        let mut card = build_card(&user, &node, &[1; 32], None);
        assert!(card_delegates_node(
            &card,
            &node.verifying_key().to_bytes(),
            NOW
        ));

        // Append a third party's node_id with a bogus (all-zero) delegation, then
        // re-sign the card so its self-signature is valid (a malicious friend
        // controls their own card). The bogus entry must be rejected by the gate.
        let victim = kp(7);
        card.nodes.push(NodeEntry {
            node_id: victim.verifying_key().to_bytes(),
            deleg: [0u8; 64],
            not_after: DELEG_NOT_AFTER,
            addrs: vec!["9.9.9.9:9".to_string()],
            relay_url: None,
        });
        card.sign(&user);
        assert!(card.verify().is_ok(), "card self-signature is still valid");
        assert!(
            !card_delegates_node(&card, &victim.verifying_key().to_bytes(), NOW),
            "an entry with an invalid user->node delegation is not injected"
        );
    }

    // W4: distinct relay networks are counted by host, so a diversity warning
    // (set < 2 networks) reflects real redundancy, not just relay-URL count.
    #[test]
    fn w4_distinct_relay_networks_dedup_by_host() {
        // Same host, different ports = one network.
        assert_eq!(
            distinct_relay_networks(
                ["http://relay.example:9991", "http://relay.example:80"].into_iter()
            ),
            1
        );
        // Distinct hosts = distinct networks.
        assert_eq!(
            distinct_relay_networks(["http://a.example:9991", "http://b.example:9991"].into_iter()),
            2
        );
        // Unparseable or hostless URLs are ignored.
        assert_eq!(
            distinct_relay_networks(["not a url", "http://c.example"].into_iter()),
            1
        );
        // No relays at all = zero networks (diversity warning fires).
        assert_eq!(distinct_relay_networks(std::iter::empty()), 0);
    }
}
