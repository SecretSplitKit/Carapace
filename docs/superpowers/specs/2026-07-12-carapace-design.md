# Carapace Reference Implementation — Design & Build Program

Status: approved scope, phased build. Target: full reference daemon + CLI,
cross-platform (Linux/macOS/Windows), Chela extendable-split profile
implemented in `chela/`, each phase adversarially reviewed.

Normative sources (do not restate, cite): `carapace-protocol.md` (v0.10),
`carapace-appendix-b-cbor.md` (wire), `chela-extendable-splits.md` (rev 3),
`cbor_vectors.py` (vector oracle), sibling `chela/` workspace.

## Decisions

- Language: Rust, edition 2021, latest stable toolchain. Cargo workspace at
  `Carapace/`.
- iroh: latest 1.x, adapt to API drift at Phase 1.
- Chela consumed as a path/git-rev dependency; extendable-split added inside
  `chela/` at Phase 2 (separate audited workspace, no new Chela deps).
- "Clients" = daemon (`carapaced`) + CLI (`carapace`) as native binaries on
  the three desktop OSes, built/tested in CI matrix.
- GUI = a local web app served by the daemon: SvelteKit static build embedded
  in the daemon binary (`rust-embed`), opened in the user's browser. The
  daemon exposes a loopback control API (`carapace-api`) bound to `127.0.0.1`
  only, guarded by a per-session bearer token (written to a local file the GUI
  reads) and strict Origin/Host checks (localhost CSRF defense); WebSocket for
  live status push, JSON for actions. This API fronts a process holding
  `K_root` and vault plaintext, so it is a trust boundary: opus + auditor
  treatment, no action without token, no external bind ever. Phase 6.
- Definition of done, per phase: `cargo test` green, phase-specific
  conformance/behavior verified against a real oracle or harness, adversarial
  `auditor` pass folded in. No upper layer is claimed working without a test
  that exercises it.

## Crate map (bottom-up; phase in brackets)

```
carapace-wire      det-CBOR codec, 23 msg types + 4 docs, carapace-sig-v1   [0]
carapace-crypto    HKDF tree, Ed25519 identity+delegation, XChaCha20 chunks,
                   BLAKE3 addressing, FastCDC, HPKE, Argon2id at-rest        [0]
carapace-vault     vid, Manifest/Envelope, chunk store, content model        [1]
carapace-net       iroh endpoint, ALPN framing, pairwise anti-entropy, relay [1]
chela-engine       split_extendable/extend/SplitState (rev-3, in chela/)     [2]
carapace-recovery  ShareGrant, split-state sealing, attestation, ceremony    [2]
carapace-friend    contact cards, friendships, tickets, unfriend/re-split    [3]
carapace-replica   placement, repair, PoR retention audit                  [3-4]
carapace-share     share health, attestation cadence                         [4]
carapace-disclose  FileGrant selective disclosure                            [5]
carapace-api       loopback control API (127.0.0.1 + token + WS), grows/phase [1+]
carapace-gui       SvelteKit static web app, embedded in daemon (rust-embed)  [6]
carapaced (bin)    daemon      carapace (bin)  CLI client                  [1+]
```

Dependencies flow strictly downward. Each phase is its own spec → plan →
implement → audit cycle; this document details Phase 0 and sketches the rest.

## Phase 0 — Foundation (detailed)

### carapace-wire

The conformance floor (Appendix B §B.9). Provides:

- **Deterministic CBOR codec** under the restricted profile (B.1): unsigned
  shortest-form ints; definite lengths only; map keys unsigned `<24` or byte
  strings, sorted bytewise on encoded form; floats/tags/bignums/other simples
  rejected; UTF-8 (NFC for paths). Decoder rejects every non-canonical form.
- **Framing** (B.2): `len(4B BE) ‖ det_cbor([msg_type:uint, body:map])`,
  1 MiB cap, drop on oversized/non-deterministic.
- **Message registry** (B.5): all 23 frame types + 4 bare documents as typed
  Rust structs with encode/decode; `by`=key 22, `sig`=key 23 conventions.
- **Signing discipline** (B.3): `sig = Ed25519(k, "carapace-sig-v1" ‖
  det_cbor([msg_type, body_without_23]))`; verify by **re-encode and compare**,
  never splice. Doc-type ids for bare docs (0=Friendship, 24=ManifestEnvelope).

**Done =** byte-reproduces all 24 §B.8 vectors (embedded as golden hex),
verifies every §B.8 signature, and passes §B.9 negatives: reject
indefinite-length, float, unknown map key, unsorted keys, non-shortest int,
and a frame whose sig was computed over a non-deterministic encoding.

### carapace-crypto

Suite `0x01` (§2) behind clean, testable interfaces:

- HKDF-SHA-256 derivation tree with the exact §4 `info` strings
  (`carapace/v1/...`); K_root → vault/content/manifest/audit/userid/disclose.
- Ed25519 user + node keys; delegation `Ed25519(user, "carapace/v1/deleg" ‖
  node_id ‖ not_after)` and chain verification.
- XChaCha20-Poly1305 per-chunk seal; BLAKE3-256 ChunkID; convergent
  chunk_key/nonce derivation (§5). FastCDC params (256K/1M/4M, Gear).
- HPKE (RFC 9180, X25519 + XChaCha20-Poly1305) seal/open.
- Argon2id at-rest sealing helper.

**Done =** per-primitive self-checks (assert-based), plus cross-pins against
Appendix B: the delegation in the ContactCard vector reproduces, and KDF
`info` strings match the spec byte-for-byte. Uses vetted RustCrypto crates;
no hand-rolled primitives.

### Phase 0 workflow (orchestration)

1. Build `carapace-wire` to green (opus engineer): iterate code → `cargo test`
   until all vectors + negatives pass.
2. Build `carapace-crypto` to green (opus engineer), after wire exists so the
   delegation/KDF pins resolve.
3. Adversarial audit both crates (opus xhigh auditor): canonicalization
   escapes, sig malleability, splice/offset verification, nonce/AEAD misuse,
   zeroization, delegation-chain bypass.
4. Fold confirmed findings, re-green (opus engineer).

## Phases 1–5 (sketch, each its own cycle)

- **1 Content + net:** vault identity, Manifest/ManifestEnvelope, local chunk
  store; iroh endpoint + ALPN `carapace/1` framing + pairwise anti-entropy;
  relay self-election. Demo: two owner devices sync a vault over iroh.
  Multi-node behavior verified with a local N-node integration harness.
- **2 Recovery + Chela:** implement `split_extendable`/`extend`/`SplitState`
  in `chela-engine` (rev-3, engine-only, zero new Chela deps, drop-wipe,
  versioned `to_bytes`, cap logic, wrong-secret check, subset round-trip
  tests). Carapace seals split-state under
  `HKDF(K_root,"carapace/v1/split-state")`; ShareGrant, attestation, recovery
  ceremony (sponsor/delay/alarm/abort/HPKE share delivery).
- **3 Friendship + replication:** contact cards, friendships, tickets,
  unfriend + re-split flow with old-share destroy sequence; replica placement
  to `r`, repair after grace.
- **4 Audit + share health:** PoR retention audits, share attestation cadence,
  drift-driven extend/re-split prompts.
- **5 Disclosure + polish:** FileGrant selective disclosure with
  audience-authenticated fetch; cross-platform CI matrix; release binaries.
- **6 GUI:** SvelteKit static app embedded in the daemon and served on
  loopback; live status dashboard (vaults, replicas, trustees/share health,
  relay reachability, ceremonies) over WebSocket, plus action flows for every
  daemon capability (create vault, friend/unfriend, invite tickets, replica
  grants, split/extend/re-split, recovery ceremony, file grants). The
  `carapace-api` crate (token-auth loopback control surface) is built
  incrementally from Phase 1 onward as each capability lands, so Phase 6 is
  mostly frontend over an API that already exists. `frontend-design` skill
  applies here. Auditor pass focuses on the loopback trust boundary.

## Cross-cutting

- CI: GitHub Actions matrix (ubuntu/macos/windows-latest) `cargo test` +
  `cargo clippy` from Phase 0; release binaries from Phase 5.
- Licensing: Apache-2.0 OR MIT (matches iroh + Chela).
- Every phase ends with an `auditor` pass; crypto/protocol code never below
  opus.
```
