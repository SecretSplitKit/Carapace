# Carapace conformance-gap ledger

Driving doc for reaching full §-conformance. From a systematic clause-to-code
sweep (157 normative clauses mapped; 49 open, deduped to 15 work items). Root
cause across most recovery/social gaps: **library primitives are written and
unit-tested but never wired to the daemon control stream or a background loop**
(same class as the §6 relay that shipped green). Status updated as items land.

**STATUS: all 15 work items DONE + committed. A full-spec re-sweep (§2-§14, 186
normative clauses) then ran as the capstone; the real MUST-level gaps it found are
also fixed (see "Full-spec sweep" below); defensible residuals are in
`spec-errata.md`.**

| # | Item | Sev | Crates | Status |
|---|------|-----|--------|--------|
| W1 | §11 version vectors + conflict-keep + tombstones + manifest merge (silent data loss today) | BLOCKER | vault, wire, net/sync, daemon | DONE |
| W2 | Recovery ceremony wired end-to-end (§8.5/§8.4: transport, fan-out/alarm, delay-gated release, claimant recover+re-sign, max-epoch fetch) | BLOCKER | recovery, daemon, api | DONE |
| W3 | ShareGrant minting/delivery/ref-refresh (§8, §7.3 propagate to trustees) | MAJOR | recovery, daemon | DONE |
| W4 | Background maintenance loops (§10.1 PoR+repair, §10.2 attestation cadence, self-validate, drift) | MAJOR | daemon, share, recovery | DONE |
| W5 | Unfriend + trustee re-split flow wired (§9.3: FriendshipEnd, delete reqs, gated destroy sequence, re-split prompt) | BLOCKER | friend, daemon, api, replica, gui | DONE |
| W6 | Relay reachability lifecycle: dialback verify, advertise-on-success/withdraw-on-loss, self-elect, relay-TCP port mapping (§6) | BLOCKER | net, daemon | DONE |
| W7 | Anti-entropy store-and-forward of third-party docs; newest-card own-device rollback; attestations in reconciliation (§6) | MAJOR | net/sync, daemon | DONE |
| W8 | Replica blob-read authorization for held chunks (§7.4 MUST) | MAJOR | net, daemon | DONE |
| W9 | Suite/version rejection: validate Hello.protocol==1, drop mismatch (§2 MUST) | MAJOR | net/sync, wire | DONE |
| W10 | Relay diversity warning surfaced in GUI (§6 MUST warn <2 networks) | MAJOR | gui, daemon | DONE |
| W11 | Cross-client golden vectors (KDF tree, chunk-boundary, (vid,P)→ct+ChunkID) + pin FastCDC normalization (§4/§5) | MAJOR | content, kdf, docs, wire | DONE |
| W12 | §11 filesystem watcher for Dropbox-like live sync | MAJOR | daemon | DONE |
| W13 | IPv6 bind/verify (unverifiable — may already dual-stack) | MINOR | net | DONE (non-gap: iroh 1.0.2 dual-stacks) |
| W14 | Default initial split N0 = M+1 when caller doesn't override (§12) | MINOR | recovery | DONE |
| W15 | Paper-card export/print route + GUI action (§10.2 backstop) | MINOR | api, gui | DONE |

No-action (spec-deferred per §13): shared multi-writer vaults, iroh-docs revisit,
erasure-coded cold tier, K_root at-rest policy.

## Execution order (each phase: workflow → verify → commit → next)

- **P0 hardening+interop** (independent, low-risk): W9, W8, W11, W14, W10.
- **P-data §11** (blocker, disjoint crates): W1, then W12.
- **P1 recovery spine**: W7, W3, W4 (stand up the daemon background loop +
  control-stream dispatch — the highest-leverage move; most "missing" items
  become integration wiring after this).
- **P2 ceremony e2e**: W2, W15.
- **P3 lifecycle**: W5 (needs W4 counts + W3 grants), W6 relay lifecycle.
- **P4 polish**: W13, GUI copy verification for §7.4 snapshot/irrevocable wording.

## Full-spec sweep (capstone)

After W1-W15 landed, an independent clause-by-clause sweep of the entire spec
(§2-§14, 186 normative clauses, one auditor per section + a completeness critic
against the §13 profiles and §12 defaults) ran to catch anything missed or
regressed. Every §12 default constant was correct and no §13 profile obligation was
unimplemented. It surfaced one security blocker and several MUST-level gaps, now all
fixed and committed:

- **§8.5 (BLOCKER, security):** recovery-ceremony abort was not durable against
  message reordering — a subject `CeremonyAbort` arriving before the `RecoveryOpen`
  was dropped, so a later open could release a share despite a valid abort. Fixed
  with a durable per-signer abort set consulted at open time.
- **§8.4:** recovery stopped at `K_root` and never fetched the user's data. Now
  replicas retain + serve the (HPKE-sealed) `FileGrant` to a recovering owner-device
  (Option A), and recovery reconstructs actual file content — proven by the new
  `recovery_reconstruct` ceremony→replica→reconstruct e2e. Option B (chunk keys in
  the manifest) deferred as a spec-level wire-format decision.
- **§11:** a routine edit did not push the new epoch to enrolled replicas (they
  served stale content); `publish_vault` now pushes the new manifest+chunks.
- **§8.3:** the over-cap *extend* path dropped the mandated warning + re-split
  recommendation; now surfaced consistently across split and extend.

Defensible divergences, SHOULD-level items, physical advisories, and superseded
wire messages (§4 node-key manifest authorship, §6/§10 SHOULDs, §9 fallbacks, §10.2
drift surface-not-auto, §14 at-rest sealing + single-root, §12 Hello/ManifestOffer/
AuditNotice) are documented in `spec-errata.md`, not code-changed.
