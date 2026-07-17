# Durable persistence + self-sufficient manifest (Option B) — design (v2, hardened)

Status: hardened per security review (fable/max), ready for implementation.
Date: 2026-07-17.
Guiding principle: **a really solid tool, not a fast one.** Zero committed-loss
durability, every secret sealed, crash-safety by construction, default-deny.

> v2 folds in a full security review. The load-bearing lessons: (1) persisting
> blobs turns the `authorize_fetch` default-*allow* residual into a public leak —
> flip it to **default-deny** and persist the gate maps; (2) categorization must be
> **exhaustive and compile-enforced**, because the reboot test can only exercise
> listed fields; (3) retire **only** the recovery `FileGrant`, not the serve path
> that authorizes a fresh claimant device; (4) **commit redb before any external
> effect**; (5) GC roots come only from persisted tables; (6) bound the durable
> abort map. Details inline.

## 1. Problem

Blob store is `MemStore` (RAM); the whole `Shared` struct + `DocStore` are
in-memory. Identity (`root.key`/`node.key`) already persists with optional
Argon2id at-rest sealing via `CARAPACE_PASSPHRASE`. On restart everything else is
lost: a replica drops the ciphertext it safeguards and its record of what it
holds; a trustee drops shares (`held_shares`/`held_grants`) and owner recovery
material (`split_states`/`granted`); and **three security properties silently
reopen** — §6 rollback protection (DocStore high-water marks), §8.5 abort
durability (`aborted_ceremonies`), and §10.1 PoR unpredictability (per-(replica,
vid) round counters). Separately, recovery (§8.4) is self-sufficient only via the
Option-A workaround (replica stores + serves the `FileGrant`).

## 2. Goals / non-goals

Goals: blobs + all durable runtime state survive restart, zero committed-loss,
every secret sealed; rollback/abort/PoR unpredictability survive restart; recovery
reconstructs from `K_root` + the sealed manifest alone (Option B); **no owned blob
becomes fetchable-by-anyone after reboot** (default-deny).

Non-goals: multi-writer vaults, erasure cold tier (deferred); on-disk migration
(nothing deployed — pay the manifest/vector rev once, now); persisting transient
network caches.

## 3. Part 1 — Durable persistence

### 3.1 Blob store: `MemStore` → `FsStore`

`IrohBlobStore` wraps `FsStore::load(<state_dir>/blobs).await` (iroh-blobs
0.103.0, confirmed). Same `Store` trait, so `add`/`fetch`/`get_bytes`/`ChunkStore`
are unchanged; construction becomes async. Blobs are already ciphertext
(AEAD chunks; `K_manifest`-sealed manifest envelopes), so no extra sealing.
**Keep the two deliberate scratch stores as `MemStore`** — ingest scratch
(`publish_vault`) and the W8 disclose/reconstruct re-serve scratch
(lib.rs ~2495-2501, whose comment is the reason: fetched third-party ciphertext
must NOT enter the served store because of the fetch-gate residual). `blobs/` gets
0600-equivalent perms (dir 0700).

### 3.2 Runtime state: redb, source of truth on disk

`redb` v4.1.0 (already transitive via `FsStore`; pin the direct dep to 4.1.0) at
`<state_dir>/state.redb`. Chosen over snapshots for **zero committed-loss +
corruption-safety by construction** (ACID/fsync). In-RAM `Shared` stays the hot
read path; each persistent map is a redb table, **written through in a
transaction at the mutation-function boundary**.

Non-negotiable integration rules (from D1/A1):

1. **Exhaustive, compile-enforced categorization.** One funnel that does
   `let Shared { field_a, field_b, .. NO GLOB } = &*s;` naming **every** field, each
   either written through or explicitly `let _ = discard;`. Adding a `Shared`
   field then fails to compile until categorized. This is the only mechanical
   guarantee against a silently-unpersisted category, and it makes the §6 reboot
   test's coverage equal to the field list.
2. **One transaction per compound mutation.** `teardown_unfriended_state` (+ the
   caller's `pending_delete_sends` push), `serve_grant`, `serve_share_destroy`,
   `register_completed_resplit`, and the `publish_vault` commit each commit their
   whole multi-map change in a single redb txn. A crash cannot half-apply.
3. **Commit before any externally visible one-shot effect.** Commit the redb txn
   *before* sending an ack or acting on the network. Sharp cases: `serve_share_destroy`
   commits the share removal before `write_msg(ack)` (else a crash resurrects a
   "destroyed" share and violates §9.3 stranding); `serve_friend_accept` commits
   consumed-ticket + friendship before `FriendAccept`; `drive_resplit` commits
   received delivered-grants / destroy-acks before treating them as done.
4. **RAM and redb mutate under the same `Shared` write-lock critical section**, so
   the only crash divergence is "process died" (self-erasing). No lock release
   between the RAM mutation and the commit.
5. **Fail loud.** A redb commit failure crashes the daemon (never continue with RAM
   ahead of disk). A sealed row that fails AEAD-open on load aborts startup with an
   unmissable error (never skip-and-continue — that is silently losing a share).

### 3.3 Exhaustive state categorization (source of truth)

Legend: **SEAL** = XChaCha20-Poly1305 under `HKDF(K_root,"carapace/v1/state-seal")`
(§3.4). **PLAIN** = plaintext (signed/public/metadata; no secret). **EPH** = never
persisted, rebuilt on reconnect. **DERIVE** = not stored; recomputed at load.

| Field (lib.rs) | Disp | Note |
|---|---|---|
| `held_shares` (Share) | **SEAL** | others' shares; `ShareMonitor` cadence reset (EPH part) |
| `held_grants` (ShareGrant.share_json) | **SEAL** | embeds the raw share |
| `granted` (OwnerGrants.trustees[].share) | **SEAL** | all N owner-held shares |
| `split_states` (RecoverySet/SplitState) | **SEAL** | polynomial coeffs |
| `resplits` (OpenResplit) | **SEAL** | new shares + SplitState |
| `epochs` | PLAIN | vault versions |
| `friendships`, `friends`(cards), `friend_grants` | PLAIN | signed / quota policy |
| `working_dirs` | PLAIN | local config |
| `held`, `replica_owner`, `replica_members`, `replica_chunks`, `replica_announce`, `replica_target`, `replica_deny` | PLAIN | replica bookkeeping + S4 policy |
| `held_share_subjects` | PLAIN | rsid→subject; lockstep with `held_shares` |
| `owned_chunks` | **PLAIN (F1)** | ChunkID→vid; **required** for the fetch gate (§3.5) + GC roots (F2) |
| `members` | PLAIN (F1) | vault→member set; friend arm of the gate |
| `disclosure` (FileGrant audiences, pubkeys) | PLAIN (F1) | audience arm of the gate |
| `vault_blobs` | **DERIVE (A1)** | persist only `{vid → digest, chunk_ids}` PLAIN; re-derive the decrypted `Manifest` at load by fetching the envelope from FsStore and opening with `K_manifest`. **Never persist the decoded Manifest** (paths + pt_hash) in clear |
| `cards`(own), `announces`(own) | PLAIN + counter | persist; **own-card version counter persisted (F3)**: on boot version = `max(unix_now(), persisted+1)`. Re-mint announces from `epochs`+`vault_blobs.digest` if simpler |
| `grants` (own FileGrants, HPKE bodies) | PLAIN | sealed bodies; safe |
| `por` (round counters/schedule) | **PLAIN (F4)** | persist counters; loss = PoR challenge replay |
| `share_sets` (AttestTracker) | PLAIN (F4) | persist or rebuild from `granted` at load |
| `ceremonies` (TrackedCeremony) | PLAIN | pubkeys+sigs only, no share bytes; persist so the E4 delay anchor survives |
| `ceremony_alarms` | PLAIN + bound | persist so the "is this you?" alarm survives the 72h window; bound like C1 |
| `aborted_ceremonies` | **PLAIN + bound (C1)** | **persist only aborts whose signer ∈ (held_grants subjects ∪ friends ∪ self)**; stranger aborts stay RAM-only (dispatch is unauthenticated → durable disk-fill DoS otherwise). Keep all qualifying signers per id (crowding property) |
| `pending_resplits`, `pending_delete_sends`, `unfriended_nodes` | PLAIN | prompts / obligations / queues survive restart |
| `tickets` | PLAIN, **hashed** | if persisted, store `BLAKE3(token)` not the token, and persist `issued`+`consumed` in one txn (else single-use replay). Ephemeral-with-`TicketUnknown` also acceptable |
| `vault_keys` (ChunkKeys) | **EPH (A1)** | never persist; rebuilt from `K_content`+`pt_hash` on demand. An accidental write-through is a key dump — the funnel prevents it |
| `peer_addrs`, `peer_last_seen`, `relay_health`, `rate`, `blob_auth`, `test_now` | **EPH** | address/liveness caches, rate limiter, per-session auth (must NOT persist), test clock (must NOT persist) |
| `DocStore` (cards-by-version, announces-by-epoch) | **PLAIN** | the §6 high-water marks; persist the signed docs |

`replica_grants` (the Option-A field) is **removed** (§4.3).
Verify before coding: `RateLimiter` and `AttestTracker` internals hold no
nonce/secret (treat as counters/rosters); `ChunkKeys` is key/nonce-per-ChunkID.

### 3.4 At-rest sealing

Two layers: (1) passphrase→`root.key` via Argon2id `atrest` (exists, unchanged);
(2) `K_root`→SEAL rows: XChaCha20-Poly1305 under
`HKDF(K_root,"carapace/v1/state-seal")` (distinct from `"carapace/v1/split-state"`;
independent key). Requirements:

- **Fresh random 24-byte nonce on every seal AND every re-seal** (mirror
  `carapace-recovery::state_seal`). **Counter nonces are forbidden** — a restored
  `state.redb` rewinds a counter into catastrophic nonce reuse under one HKDF key;
  XChaCha's 192-bit nonce makes random collision-safe.
- `aad = format_version ‖ table_name ‖ canonical_redb_key_bytes` (stops row
  relocation / cross-table / cross-rsid swap; the version byte enables future
  format changes). Per-row aad gives relocation integrity, not state-level
  rollback — state that lives (see below).
- Decrypted plaintext buffers are `Zeroizing`.
- **Fail loud** on any sealed-row open failure (abort startup).
- `state.redb` gets 0600 (unix) / the same non-unix caveat `write_secret` carries.
- **Honesty:** without `CARAPACE_PASSPHRASE`, the state seal adds nothing against
  theft of the whole state dir (the attacker opens plaintext `root.key`, derives
  the seal key); it only defends a misdirected backup of `state.redb` alone. Doc
  this plainly (updates §14 note).
- **Consolidate SplitState sealing:** the redb row-seal supersedes the unused
  `seal_split_state`; retire `seal_split_state`/`open_split_state` (and the §8.1
  spec language) OR store a `SealedSplitState` in the row. One mechanism only.

### 3.5 Startup, gate, GC, reconciliation

Startup order (C): load `root.key`/`node.key` → open `FsStore` → open `state.redb`
→ load `Shared`/`DocStore` (decrypt SEAL rows; rebuild EPH; re-derive `vault_blobs`
manifests) → **reconcile with FsStore** → **only then** `Router::spawn`/accept
connections. Accepting before load lets a peer replay a card against an empty
store and legitimize it.

**Fetch gate → default-deny (F1, MUST).** Flip `authorize_fetch`'s terminal
`return true` for unknown hashes to `return false`. With a durable store,
"unknown blob → serve anyone" has no justification, and default-deny turns any
future gate-map omission from a leak into a visible availability failure. The gate
now relies on persisted `owned_chunks` (own devices), `replica_chunks` (replica
serving), `members` (friend arm), and `disclosure` (audience arm) — all persisted
per §3.3.

**GC roots from persisted tables only (F2, MUST).** GC-eligible = blobs in none of
`vault_blobs.chunk_ids` ∪ `vault_blobs.digest` ∪ `owned_chunks` ∪ `replica_chunks`
∪ `replica_announce[].digest`. **Gate GC until startup reconciliation completes**,
or the first post-reboot pass deletes every owned blob.

Reconciliation: a manifest-referenced chunk absent from FsStore → mark vault
needs-refetch (repair/anti-entropy fetches it); an orphan blob → GC-eligible.
Content-addressing + verify-on-read (`blobs.rs:69-80`) make orphan-or-refetch the
only representable outcomes; a needs-refetch mark grants no access. **Tripwire:**
if `blobs/` or the key files exist but `state.redb` is absent, fail/warn loudly
rather than silently starting fresh (which would re-open all three vectors).

## 4. Part 2 — Self-sufficient manifest (Option B)

### 4.1 Change

`FileEntry` chunk list `(ChunkID, len)` → `(ChunkID, pt_hash, len)`
(carapace-wire). `pt_hash` is already computed at ingest; record it.

### 4.2 Reconstruct/recovery from the manifest alone

For each chunk derive `chunk_key`+`nonce` from `K_content`+`pt_hash`, fetch by
`ChunkID`, decrypt, verify `BLAKE3(P)==pt_hash` (free integrity oracle). No grant,
no owner liveness. Incremental-ingest bonus: skip re-encrypting chunks whose
`pt_hash` is unchanged.

**Confidentiality (corrected):** `pt_hash = BLAKE3(plaintext)` is a
guess-confirmation oracle *to anyone who holds it*. It is safe **only** because
every party who can open the `K_manifest`-sealed manifest already holds
`K_vaultroot` → `K_content` (siblings, kdf.rs:50-57). **Spec invariant: never
grant `K_manifest` to a party without `K_content`** (§7.4 disclosure hands explicit
`GrantChunk` keys, never `K_manifest`). And per A1, `pt_hash`'s only unsealed home
is RAM — persisted `vault_blobs` re-derives the manifest, never stores it plain.

### 4.3 Retire ONLY the recovery grant (E, MUST — do not over-retire)

Remove: `Shared.replica_grants`; the grant push in `invite_and_push`; the grant
read/verify/store in `serve_replica_store`; the `grants.push` inside the
ReplicaOwner branch of `serve_docs` (lib.rs ~1054-1056).

**KEEP:** `replica_owner_device` classification, the `BlobAuth::ReplicaDevice`
insert, and the ReplicaOwner branch serving the **owner card + `replica_announce`**
(lib.rs ~1041-1059). This is the claimant's ONLY authorization + announce path:
`CeremonyShare` carries no announce refs (messages.rs:1364-1373), `AnnounceRef`
has no replica list (messages.rs:329-336), and `classify_dialer` admits a fresh
device nowhere else (lib.rs:5560-5588). Deleting it bricks recovery even with
`K_root`. Serving the replica's epoch-fresh `replica_announce` also feeds
`max_epoch_refs` the newest epoch, so the claimant recovers the latest replicated
epoch. The dead-owner-decrypt gap is closed by pt_hash-in-manifest; this fix is
about *reaching* the bytes, not decrypting them. `FileGrant`/`GrantChunk` remain,
used only for §7.4 disclosure.

### 4.4 Golden vectors

Regenerate the §4/§5 cross-client golden vectors + Appendix B manifest vector
(W11) for the new `FileEntry`. Bump the manifest format version tag. cbor_vectors.py
oracle regenerates KDF/chunk vectors; the manifest vector from the new encoder.

## 5. Security requirements (implementation must satisfy)

1. Seal completeness: every SEAL row encrypted before touching redb; the funnel
   (§3.2.1) makes this exhaustive by construction. No Share / SplitState / K_root /
   chunk-or-manifest key ever hits disk in the clear (with a passphrase, not even
   under K_root-in-the-clear).
2. Default-deny fetch gate (F1); gate maps persisted.
3. GC roots from persisted tables only, GC gated on reconciliation (F2).
4. Rollback (§6): DocStore marks persist + committed in the acceptance txn; router
   accepts only after load.
5. Abort (§8.5): `aborted_ceremonies` persists, bounded to qualifying signers (C1).
6. PoR (§10.1): `por` round counters persist (F4).
7. Commit-before-external-effect + fail-loud + one-critical-section (§3.2.3-5).
8. Nonces random per (re)seal; aad binds version‖table‖key; forbid counters (§3.4).
9. Own-card version counter persists (F3) — `max(unix_now(), persisted+1)`.
10. Startup tripwire on missing `state.redb` beside surviving blobs.

## 6. Testing

- **Reboot-survival** (new, exhaustive): exercise **every persisted category** —
  publish a vault, place a replica for a friend, accept a replica, split K_root,
  receive a grant as trustee, open a ceremony, record a (qualifying) abort, take a
  PoR round, issue+partially-consume a ticket, queue a pending delete/resplit —
  then **drop the daemon and reload from the same state-dir**. Assert each survives:
  blobs served, trust/replica/share/split intact, the abort still blocks a release,
  a replayed old card is still rejected, PoR does not re-issue the same challenge,
  own-card version strictly increases across the restart. The §3.2.1 funnel makes
  the field list == the tested list.
- **Default-deny after reboot** (new, F1): restart, then a non-owner dialer
  requesting an owned ChunkID by hash is **refused**.
- **GC-does-not-eat-the-vault** (new, F2): restart, run GC, assert owned +
  still-disclosed old-epoch chunks survive.
- **Recovery-from-manifest** (update `recovery_reconstruct`): owner splits, places
  a replica, **shuts down**; fresh claimant recovers K_root and reconstructs
  byte-exact content with **no grant** — assert the replica served blobs + its
  announce + the owner card, **never a grant**.
- **At-rest sealing**: with a passphrase, dump `state.redb`; assert no share /
  polynomial plaintext; wrong/absent passphrase fails to open sealed rows (loud).
- **Crash consistency**: kill between blob-add and state-commit → reload → vault is
  needs-refetch, not corrupt.
- **Golden vectors**: regenerated vectors round-trip + match the oracle.
- Full existing suite green (fmt, clippy -D warnings, workspace tests).

## 7. Sequencing (two phases, one spec)

1. **Phase B** — manifest `pt_hash`, reconstruct/recovery from it, retire only the
   grant (keep the serve path per §4.3), regen golden vectors. Finalizes the
   on-disk manifest shape before persistence.
2. **Phase persistence** — FsStore blobs; redb state with the funnel, sealing,
   compound-txn + commit-before-effect ordering, default-deny gate, persisted
   gate/GC/rollback/abort/PoR/card-version state, startup load + reconciliation;
   the reboot/default-deny/GC/at-rest tests.

## 8. Spec / errata updates

- Replace the Option-A errata note with Option B (manifest `pt_hash`; grant
  disclosure-only; keep the `ReplicaDevice` serve path).
- Update the §14 in-memory-state deferral: state persists; secrets sealed under
  `HKDF(K_root,…)`; residual is only the no-passphrase K_root posture; add the
  whole-dir-theft honesty line.
- Note the default-deny fetch-gate change (supersedes the W2/W8 residual note).
- Note the manifest format version bump + regenerated W11 vectors + the
  never-grant-K_manifest-without-K_content invariant.
- Retire the `seal_split_state` mechanism (consolidated into the row seal).
