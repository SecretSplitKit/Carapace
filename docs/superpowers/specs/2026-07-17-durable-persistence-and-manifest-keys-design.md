# Durable persistence + self-sufficient manifest (Option B) — design

Status: draft for review (hardener + user), pre-implementation.
Date: 2026-07-17.
Guiding principle: **a really solid tool, not a fast one.** Prefer zero-loss
durability, explicit sealing of every secret at rest, and crash-safety by
construction over expedient shortcuts.

## 1. Problem

The daemon's blob store is `iroh_blobs::store::mem::MemStore` (RAM), and the
entire `Shared` runtime struct + `DocStore` live only in memory. Identity
(`root.key`/`node.key`) already persists, with optional Argon2id at-rest sealing
via `CARAPACE_PASSPHRASE` (`carapace-crypto::atrest`). Everything else evaporates
on restart:

- A **replica** that reboots drops every ciphertext chunk it was safeguarding
  for a friend, and its record of *what* it holds for *whom* — the durability
  promise of the whole system.
- A **trustee** that reboots drops the shares it safeguards for others
  (`held_shares`, `held_grants`) and its owner-side recovery material
  (`split_states`, `granted`), i.e. the recovery layer.
- Rollback-protection high-water marks (`DocStore`) and the durable
  abort-ceremony set (`aborted_ceremonies`, the §8.5 fix) reset — silently
  reopening two security properties across a reboot (see §5).

Separately, recovery (§8.4) is only self-sufficient because of a workaround
(Option A): the per-chunk decryption keys live only in the `FileGrant`, so a
replica has to store and serve that grant to a recovering owner. The cleaner
design (Option B) stores what recovery needs in the (already-encrypted) manifest,
retiring that workaround.

## 2. Goals / non-goals

**Goals**
- Blobs (chunks + manifest envelopes) survive restart, crash-safe.
- All durable runtime state survives restart, **zero committed-loss**, with every
  secret sealed at rest.
- Rollback protection (§6) and abort durability (§8.5) survive restart.
- Recovery reconstructs file content from `K_root` + the sealed manifest alone
  (Option B); the `FileGrant` reverts to third-party disclosure only (§7.4).

**Non-goals**
- Multi-writer shared vaults, erasure-coded cold tier (spec-deferred).
- Cross-version on-disk migration: nothing is deployed and there are no other
  implementations, so we pay the manifest-format / golden-vector rev once, now.
- Persisting transient network caches (addresses, liveness, relay health) — those
  rebuild on reconnect by design.

## 3. Part 1 — Durable persistence

### 3.1 Blob store: `MemStore` → `FsStore`

`IrohBlobStore` (crates/carapace-net/src/blobs.rs) currently wraps
`MemStore::new()`. Change it to wrap `FsStore::load(<state_dir>/blobs).await`
(iroh-blobs 0.103.0, confirmed present). `FsStore` is content-addressed,
crash-safe (redb-backed metadata + on-disk data), integrity-verifying on read,
and dedup/resumable — the same `Store` trait, so the `add`/`fetch`/`get_bytes`/
`ChunkStore` surface is unchanged. Blobs are already ciphertext (chunks are AEAD
output; manifest envelopes are sealed under `K_manifest`), so no additional
at-rest sealing is needed for the blob store.

`IrohBlobStore::new()` becomes async (or takes a path); construction sites
(`Daemon` build, the `scratch` store in reconstruct/publish) get the state dir or
keep an in-memory scratch store where a throwaway is intended (ingest scratch,
W8 disclose re-serve scratch stay `MemStore` — they are deliberately ephemeral).

### 3.2 Runtime state: redb (source of truth on disk)

Add `redb` (already a transitive dep via `FsStore`) at `<state_dir>/state.redb`.
Rationale over snapshots: **zero committed-loss and corruption-safety by
construction** (ACID, fsync-durable) — the product is durable backup, so we buy
the strongest durability. The cost is integration discipline (§3.5), which the
reboot-survival test (§6) and the hardener review are designed to catch.

Model: keep the in-RAM `Shared` as the hot read path; make each persistent map a
redb table and **write through inside a transaction at the mutation-function
boundary**. Compound mutations (e.g. `teardown_unfriended_state`, `serve_grant`,
`register_completed_resplit`, `publish_vault` commit) each run as **one** redb
transaction so a crash can never leave a half-applied multi-map mutation. On
startup, load every table into `Shared`.

### 3.3 State categorization (the load-bearing table)

| Field | Disposition | Notes |
|---|---|---|
| `epochs` | persist, plaintext | your vault versions |
| `friendships` | persist, plaintext | signed records |
| `friends` (cards) | persist, plaintext | public, wire-shared |
| `working_dirs` | persist, plaintext | local config |
| `held` / `replica_owner` / `replica_members` / `replica_chunks` | persist, plaintext | what I replicate for whom |
| `replica_announce` | persist, plaintext | signed announce |
| `held_share_subjects` | persist, plaintext | rsid→subject binding, kept in lockstep with `held_shares` |
| `aborted_ceremonies` | **persist, plaintext** | signed aborts — MUST survive restart (§5, §8.5) |
| `ceremonies` | persist, plaintext | in-flight ceremony state; persist so a reboot during the recovery delay does not reset approvals/clock. Contains only pubkeys + signatures, no share bytes |
| `pending_resplits` | persist, plaintext | suggested sets + ex-trustee (pubkeys) |
| `pending_delete_sends` | persist, plaintext | outstanding §9.3.1 delete obligations should survive restart |
| `unfriended_nodes` | persist, plaintext | re-placement queue must complete after restart |
| `held_shares` (`Share`) | **persist, SEALED** | others' secret shares I safeguard. `ShareMonitor` cadence is reset on load (ephemeral) |
| `held_grants` (`ShareGrant`) | **persist, SEALED** | contains the embedded share |
| `split_states` (`RecoverySet`) | **persist, SEALED** | recovery polynomials — §14 MUST seal |
| `granted` (`OwnerGrants`) | **persist, SEALED** | owner's copies of ALL N trustee shares — the material to rebuild `K_root` |
| `resplits` (`OpenResplit`) | **persist, SEALED** | in-flight new-set shares + `SplitState` |
| `DocStore` (cards-by-version, announces-by-epoch) | **persist, plaintext** | rollback high-water marks — MUST survive restart (§5, §6) |
| `peer_addrs` | ephemeral | last-known address hints; rebuild on reconnect |
| `peer_last_seen` | ephemeral | liveness cache; re-probe |
| `relay_health` | ephemeral | re-probe on start |

`replica_grants` (the Option-A field) is **removed** by Part 2 — see §4.3.

### 3.4 At-rest sealing (two layers, reuse what exists)

1. **Passphrase → `root.key`** (already implemented): `CARAPACE_PASSPHRASE`
   Argon2id-seals `root.key`/`node.key` via `carapace-crypto::atrest`. Unchanged.
2. **`K_root` → secret state** (new): the SEALED rows in §3.3 are encrypted with
   `XChaCha20-Poly1305` under `HKDF(K_root, "carapace/v1/state-seal")`, mirroring
   the existing split-state seal (`carapace-recovery::state_seal`, which uses
   `HKDF(K_root, "carapace/v1/split-state")`), **not** the Argon2id `atrest` path
   (that layer is only for the passphrase→root.key step). Each secret value is
   sealed individually (det-CBOR body → AEAD), with `aad` binding it to its table
   + key so a value can't be moved between rows.

Result: with a passphrase, a stolen `state.redb` + `blobs/` + `*.key` yields only
ciphertext — the secret rows need `K_root`, which needs the passphrase. Without a
passphrase, the secret rows are still `K_root`-sealed (K_root sits plaintext in
`root.key`, the documented demo posture), so `state.redb` alone never exposes
shares/polynomials in the clear regardless. Public rows are plaintext but
integrity-protected by their existing signatures.

### 3.5 Startup, consistency, reconciliation

On `run`: load `root.key`/`node.key` (existing) → open `FsStore` → open
`state.redb` → load `Shared` (decrypt sealed rows with `K_root`; drop/rebuild
ephemeral fields) → **reconcile with `FsStore`**:

- A chunk referenced by a held manifest but absent from `FsStore` → mark the vault
  needs-refetch (the existing repair/anti-entropy path fetches it); do not treat
  as loss.
- A blob in `FsStore` referenced by nothing → GC-eligible (iroh-blobs GC, gated so
  in-flight/owned blobs are protected).

Cross-store crash consistency: `FsStore` and `state.redb` are independent
durability domains (this is true of any two-store design). Because blobs are
content-addressed and every reference is verified on read, a crash between "blob
written" and "state committed" is always safe: worst case is an orphan blob (GC)
or a needs-refetch reference (repair). No corruption is representable.

**Integration-correctness guard (the redb risk).** The failure mode is a mutation
site that forgets to write through, silently not persisting a category. Mitigation:
(a) funnel all persistent mutations through a small set of named functions;
(b) the reboot-survival test (§6) mutates *every* category, hard-restarts, and
asserts each survives — a missed write-through fails it; (c) the hardener review
checks coverage.

## 4. Part 2 — Self-sufficient manifest (Option B)

### 4.1 The change

Chunks use convergent encryption: `chunk_key = HKDF(K_content, pt_hash)`,
`pt_hash = BLAKE3(plaintext)`, `ChunkID = BLAKE3(ciphertext)`. The manifest stores
`ChunkID` (to fetch) but not `pt_hash` (to derive the key), so a `K_root` holder
alone cannot decrypt — hence the `FileGrant` workaround. Fix: **store `pt_hash`
per chunk in the manifest.**

`FileEntry` chunk list `(ChunkID, len)` → `(ChunkID, pt_hash, len)`
(`carapace-wire`). `pt_hash` is already computed during ingest; record it.

### 4.2 Recovery + reconstruct from the manifest alone

`reconstruct` / recovery: for each chunk, derive `chunk_key` + `nonce` from
`K_content` + `pt_hash` (both already in hand: `K_content` from `K_root`,
`pt_hash` from the decrypted manifest), fetch the blob by `ChunkID`, decrypt,
verify `BLAKE3(plaintext) == pt_hash` (free integrity check). No grant, no owner
liveness, no special replica serving.

Confidentiality is unchanged: `pt_hash` rides inside the `K_manifest`-sealed
manifest, visible only to a `K_root` holder, and it reveals nothing `ChunkID`
(already public to storage peers) does not.

Incremental ingest bonus: `pt_hash` in the previous manifest is the dedup key, so
re-ingest can skip re-encrypting any chunk whose `pt_hash` is unchanged.

### 4.3 Retire Option A

Recovery no longer needs the replica to store/serve the `FileGrant` or the
announce. Remove: `Shared.replica_grants`; the grant-push in `invite_and_push`;
the grant read/verify/store in `serve_replica_store`; the recovery-serve branch in
`serve_docs` that returns owner card/announce/grant to a `ReplicaDevice` dialer.
The claimant instead learns the vault's latest announce from the **trustee
grants** it collected during the ceremony (ShareGrants already carry announce
refs, §8), then fetches manifest + chunks from any replica as a normal
owner-device blob read (existing `authorize_fetch` path). `FileGrant` +
`GrantChunk` remain, used only for §7.4 selective disclosure to third parties (who
lack `K_content` and so still need explicit keys).

Net simplification: the replica returns to being a pure blob store; a whole
inbound serve branch and two `Shared` fields disappear.

### 4.4 Golden vectors

Regenerate the §4/§5 cross-client golden vectors and the Appendix B manifest
vector (W11) for the new `FileEntry` shape. Bump the manifest format version tag
(and, if the digest domain changed, note it in errata). The cbor_vectors.py
oracle (scratchpad venv) regenerates the KDF-tree / chunk vectors; the manifest
vector is regenerated from the new encoder.

## 5. Security requirements (call out for the hardener)

- **Seal completeness:** every field marked SEALED in §3.3 must be encrypted
  before it touches redb; no share bytes or polynomial coefficients ever hit disk
  in the clear (with a passphrase, not even under `K_root`-in-the-clear). Verify
  `held_grants` (embeds a share) and `granted` (embeds all N shares) are sealed.
- **Rollback survival (§6):** `DocStore` high-water marks persist, so after a
  restart a peer still cannot replay a card/announce version ≤ the highest already
  seen. Losing these on restart would reopen the rollback attack.
- **Abort durability (§8.5):** `aborted_ceremonies` persists, so a subject abort
  seen before a restart still blocks a share release after it. The prior audit
  flagged the restart vector explicitly; this closes it.
- **AEAD `aad` binding:** sealed values bind table + key in `aad` so a value can't
  be relocated between rows/owners.
- **Compound atomicity:** multi-map mutations commit in one redb transaction; a
  crash cannot leave, e.g., a destroyed old share with the new set unregistered.
- **Reconciliation cannot fabricate access:** a needs-refetch reference never
  yields plaintext without the real chunk; an orphan blob is inert.

## 6. Testing

- **Reboot-survival integration** (new): stand up a daemon, exercise *every*
  persistent category — publish a vault (blobs + epoch + working_dir), place a
  replica for a friend, accept a replica from a friend, split `K_root` (granted +
  split_states), receive a grant as trustee (held_shares/held_grants), open a
  ceremony, record an abort, queue a pending delete/resplit — then **drop the
  daemon and reload from the same state-dir**. Assert: blobs still served,
  friend/replica/share/split state intact, the abort still blocks a release, a
  rollback (replay old card) is still rejected. A missed write-through fails this.
- **Recovery-from-manifest** (update `recovery_reconstruct`): owner splits, places
  a replica, **shuts down**, fresh claimant recovers `K_root` and reconstructs
  byte-exact content **with no grant path** (prove the replica served only blobs).
- **At-rest sealing** (extend the `atrest` test pattern): with a passphrase, dump
  `state.redb` and assert no share/polynomial plaintext appears; wrong/absent
  passphrase fails to open sealed rows.
- **Crash consistency**: kill between blob-add and state-commit; on reload the
  vault is needs-refetch, not corrupt.
- **Golden vectors**: the regenerated vectors round-trip and match the oracle.
- Full existing suite stays green (fmt, clippy -D warnings, workspace tests).

## 7. Sequencing

One spec, implemented in two phases so each lands verified:

1. **Phase B first** — manifest `pt_hash`, reconstruct/recovery from it, retire
   Option A, regen golden vectors. Finalizes the on-disk manifest shape before we
   persist it.
2. **Phase persistence** — `FsStore` blobs, redb state with sealing, startup
   load + reconciliation, reboot-survival test.

Rationale: Phase B changes the manifest content that Phase 2 persists; doing B
first means we never persist-then-reformat.

## 8. Spec / errata updates

- Remove the Option-A errata note; replace with Option B (manifest carries
  `pt_hash`; `FileGrant` disclosure-only).
- Update the §14 in-memory-state deferral: state now persists; `split_states`/
  shares sealed under `HKDF(K_root, …)`; the residual is only the
  passphrase-vs-plaintext `K_root` posture, which is the documented demo fallback.
- Note the manifest format version bump + regenerated W11 vectors.
