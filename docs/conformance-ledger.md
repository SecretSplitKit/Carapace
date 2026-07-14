# Carapace conformance-gap ledger

Driving doc for reaching full §-conformance. From a systematic clause-to-code
sweep (157 normative clauses mapped; 49 open, deduped to 15 work items). Root
cause across most recovery/social gaps: **library primitives are written and
unit-tested but never wired to the daemon control stream or a background loop**
(same class as the §6 relay that shipped green). Status updated as items land.

| # | Item | Sev | Crates | Status |
|---|------|-----|--------|--------|
| W1 | §11 version vectors + conflict-keep + tombstones + manifest merge (silent data loss today) | BLOCKER | vault, wire, net/sync, daemon | TODO |
| W2 | Recovery ceremony wired end-to-end (§8.5/§8.4: transport, fan-out/alarm, delay-gated release, claimant recover+re-sign, max-epoch fetch) | BLOCKER | recovery, daemon, api | TODO |
| W3 | ShareGrant minting/delivery/ref-refresh (§8, §7.3 propagate to trustees) | MAJOR | recovery, daemon | TODO |
| W4 | Background maintenance loops (§10.1 PoR+repair, §10.2 attestation cadence, self-validate, drift) | MAJOR | daemon, share, recovery | TODO |
| W5 | Unfriend + trustee re-split flow wired (§9.3: FriendshipEnd, delete reqs, gated destroy sequence, re-split prompt) | BLOCKER | friend, daemon, api, replica, gui | TODO |
| W6 | Relay reachability lifecycle: dialback verify, advertise-on-success/withdraw-on-loss, self-elect, relay-TCP port mapping (§6) | BLOCKER | net, daemon | TODO |
| W7 | Anti-entropy store-and-forward of third-party docs; newest-card own-device rollback; attestations in reconciliation (§6) | MAJOR | net/sync, daemon | TODO |
| W8 | Replica blob-read authorization for held chunks (§7.4 MUST) | MAJOR | net, daemon | DONE |
| W9 | Suite/version rejection: validate Hello.protocol==1, drop mismatch (§2 MUST) | MAJOR | net/sync, wire | DONE |
| W10 | Relay diversity warning surfaced in GUI (§6 MUST warn <2 networks) | MAJOR | gui, daemon | DONE |
| W11 | Cross-client golden vectors (KDF tree, chunk-boundary, (vid,P)→ct+ChunkID) + pin FastCDC normalization (§4/§5) | MAJOR | content, kdf, docs, wire | DONE |
| W12 | §11 filesystem watcher for Dropbox-like live sync | MAJOR | daemon | TODO |
| W13 | IPv6 bind/verify (unverifiable — may already dual-stack) | MINOR | net | TODO |
| W14 | Default initial split N0 = M+1 when caller doesn't override (§12) | MINOR | recovery | DONE |
| W15 | Paper-card export/print route + GUI action (§10.2 backstop) | MINOR | api, gui | TODO |

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
