# Carapace spec errata

Divergences found during implementation where the code follows the correct
resolution and the normative prose needs reconciling. Each was surfaced by the
Phase 0 adversarial audit.

## E1 — Friendship signing construction (protocol §9.2 vs Appendix B)

`carapace-protocol.md` §9.2 says the Friendship signatures are over
`"carapace/v1/friend" ‖ a ‖ b ‖ established`. Appendix B (§B.3/§B.6, the
normative wire spec) and `cbor_vectors.py` sign
`"carapace-sig-v1" ‖ det_cbor([0, {0:a, 1:b, 2:established}])` (doc-type 0).
These disagree. **Resolution: the Appendix B doc-type-0 discipline wins**
(it is the designated wire authority and the test vectors encode it); the
implementation follows it. protocol §9.2 updated to point at the appendix
discipline rather than restate a conflicting byte string.

## E2 — HPKE AEAD in suite 0x01 (protocol §2 / §7.4)

Suite `0x01` mandates HPKE with **XChaCha20-Poly1305**. RFC 9180 registers no
XChaCha20 AEAD, so the suite as written is unsatisfiable by a conformant
RFC 9180 implementation, and the `hpke` crate cannot express it. HPKE derives
its per-message nonce from a counter, so XChaCha20's 24-byte random-nonce
advantage is irrelevant here. **Resolution: HPKE uses ChaCha20-Poly1305
(RFC 9180 AEAD id 0x0003).** Chunk sealing and at-rest sealing keep
XChaCha20-Poly1305 as specified (they are not HPKE). No golden vector is
affected — Appendix B treats HPKE ciphertext as an opaque `0xEE` placeholder.
Spec §2 table and §7.4 updated. **Impl note (Phase 1):** the `hpke` crate is
pinned to `0.13` (not `0.14`), because iroh 1.0.x exact-pins the RustCrypto
release-candidate stack (`curve25519-dalek 5.0.0-rc`, `aead 0.6.0-rc`) and
`hpke 0.14` forces the final `curve/aead` majors, which Cargo cannot co-resolve.
`0.13` keeps carapace-crypto on the 4.x/0.5.x line that coexists with iroh. Same
ChaCha20-Poly1305 construction; no vector affected. Revisit when iroh moves to
the released RustCrypto stack.

## Note — iroh version

The spec said iroh "v1.0.0-rc". At Phase 1 the released line is **iroh 1.0.2 /
iroh-blobs 0.103** (there is a 1.x). API renames adopted: `NodeId→EndpointId`,
`NodeAddr→EndpointAddr`, blob fetch via `store.remote().fetch(conn, hash)`.
`iroh_blobs::Hash::new == blake3::hash`, so Carapace ChunkID == iroh blob hash
holds by construction.

## E4 — Recovery delay must anchor to local first-observation, not sponsor `opened_at` (protocol §8.5 step 5)

§8.5 step 5 says "No share moves before `opened_at + recovery_delay`", where `opened_at`
is a field of the sponsor-signed `RecoveryOpen`. Taken literally this is exploitable: the
sponsor is a free-choosing party, so a malicious sponsoring trustee sets `opened_at = 0`
(or any past time) and the `opened_at + recovery_delay` gate is already satisfied - the
abort/alarm window the delay exists to create is removed the instant `M` approvals land.
**Resolution: each observing party gates on `max(opened_at, first_seen) + recovery_delay`,
where `first_seen` is that party's own wall clock when it began tracking the ceremony.** A
backdated `opened_at` can no longer shorten the delay (the local `first_seen` floor holds);
a future-dated `opened_at` only pushes release later, which is safe. The implementation
(`carapace-recovery::ceremony::CeremonyState`) records `first_seen` at `open`/`open_from_grant`
and `can_release` uses the max. §8.5 step 5 should be reworded to specify the local-clock anchor.

## E5 — `recovery_delay` has no floor (protocol §8.5 step 5)

§8.5 gives `recovery_delay` a default (72 h) "chosen at split time" but no minimum. A grant
with `recovery_delay = 0` collapses the abort window to just "M approvals", removing the
slow-takeover defense even when `opened_at` is honest (E4). It is the owner's own signed
choice, so the implementation accepts it verbatim rather than hard-rejecting a spec-sanctioned
value. **Recommendation: the spec SHOULD state a floor (e.g. reject `recovery_delay < 24 h`
unless an explicit override is set) and clients SHOULD warn below it.** Tracked as advisory;
`build_share_grant` documents the risk at the call site.

## E-blob-authz — replica blobs are served without per-peer read authorization (protocol §10.1, S5)

A replica daemon answers `iroh_blobs::ALPN` fetches from any dialer: the blob
transport has no per-peer read gate. Confidentiality therefore rests entirely on
(a) every chunk being AEAD-sealed and (b) ChunkIDs being unguessable BLAKE3 hashes
revealed only inside the W2/W5-gated manifest+grant on the `carapace/1` control
stream. A peer that never learns a ChunkID cannot request it; a peer that does
(e.g. a former replica, or one that saw a manifest) can still fetch the sealed
bytes even after it should have lost read access. This is an inherited design
limitation, not a Phase-3 code bug. **Owed: a per-peer blob-read authorization hook
on the blobs protocol** (gate `fetch` on the same friend-graph/delegation check
`authorize_dialer` applies to documents). Until then the sealing + ChunkID secrecy
are the only confidentiality boundary. Flagged at the `BlobsProtocol` accept site
in `carapaced::Daemon::start_with_limits`. **Resolved by W8** — see the W8 note
below; the owed per-peer read gate now ships as `authorize_fetch`.

## E3 — FastCDC variant/params unpinned (protocol §5)

§5 names "FastCDC" with MIN 256 KiB / AVG 1 MiB / MAX 4 MiB but not the
variant, normalization level, or gear table, and shipped no chunk-boundary
vector. Different variants (e.g. v2016 vs v2020) and normalization levels cut
differently, breaking cross-client convergent dedup. **Resolution: pin FastCDC
v2016, standard Gear table, Normalization Level 1**, matching the
implementation. The level is now passed EXPLICITLY in code
(`content::NORMALIZATION` / `FastCDC::with_level`), not left to the crate
default. §5 updated with the level; the owed chunk-boundary golden vector now
ships as Appendix B §B.10.2 (with the KDF-tree §B.10.1 and convergent-seal
§B.10.3 vectors), pinned by the `carapace-crypto` `appendix_b_pins` tests.

## Note — per-friend replica-storage grant is local (protocol §9, §10.1)

The storage limit a node grants a friend for replicas is agreed PER-FRIEND at
add-friend time and stored locally (the daemon's `friend_grants`, keyed by the
friend's user pubkey); `serve_replica_store` enforces that friend's agreed limit
as its replica quota (W1), never a global default. This is kept independent of
the counterpart's advertised `ContactCard.offers.storage_bytes` (§9.1): the
offer is what they claim to hold for me, the grant is what I enforce for them.
No wire message or Appendix B vector changes - the advertised offer travels in
the card, the grant is local policy. A formal bilateral over-the-wire
storage-agreement message is a possible future spec addition; the card-offer +
local-grant model satisfies it for now.

## Note — PoR round counter is in-memory; unreachable is not retention loss (§10.1)

Phase 4 audit findings C1/S2. Two related PoR (§10.1) points settled in code:

- **C1 (fixed): transport failure is not a retention failure.** A replica the
  owner cannot dial is fed to `AuditTracker::record_unreachable` (yielding
  `AuditAction::Skipped`), which reschedules the next audit without touching the
  consecutive-failure streak. Only a peer that *answered* with a missing or
  hash-mismatched sampled chunk advances the streak toward `AuditAction::Lost`.
  A transiently-offline friend is therefore never evicted by PoR; a peer that
  stays gone is handled by the separate reachability/grace path
  (`Health::UnreachableSince`, 24 h grace). The daemon's `fetch_audit_samples`
  distinguishes the two: a bounded-timeout connect failure returns `None`
  (unreachable), a connected-but-empty answer returns per-sample `None`
  (content loss).

- **S2 (accepted, not fixed): the per-replica round counter is in-memory.** The
  entire daemon runtime state (members, epochs, vault blob refs, the PoR tracker)
  lives in `Shared` and is not persisted; only the node/root keys are on disk.
  On restart the round counter reseeds at 0 and re-arms every member's audit, so
  a restart re-issues the `(epoch, round=0)` challenge and bursts audits at
  startup - a marginal aid to a pre-staging proxy. Persisting only the round
  counter while the rest of the set state stays ephemeral would be inconsistent;
  this is deferred until the daemon grows a runtime-state store, at which point
  the round counter is persisted alongside the member set.

## Note — attestation liveness binds to the enrolled roster (§10.2)

Phase 4 audit finding W1. `AttestTracker` now carries the set's enrolled roster
(trustee signing-key -> its issued `card_number`/share `x`). `record_attestation`
counts an attestation toward the live count only if its signer is on the roster
(`RecoveryError::NotATrustee` otherwise) and it echoes that signer's own card
number (`RecoveryError::ChallengeMismatch` otherwise), and it keys liveness by the
validated `card_number` so duplicate answers for one share collapse to a single
live entry. The count is thus "distinct enrolled shares whose holder cooperated
and self-validated," not "distinct online signers." This cannot prove *possession*
over the label-only §10.2 channel (the words never transmit): an enrolled trustee
that discarded its words but stays online is caught only by its own
`answer_attest_challenge` self-validation failing (silent non-answer -> ages out of
the freshness window), never by the owner-side count. Attestation proves
liveness/cooperation and roster/share binding, not retained possession.

## Note — PoR sampled-range fidelity (§10.1, audit S1)

The PoR module samples a per-chunk `offset..offset+len` range, but the wired
adapter fetches the whole content-addressed chunk and BLAKE3-verifies it against
the sampled ChunkID; a full valid chunk always covers the range, so
`AuditFailure::ShortRange` is unreachable on the wired path and the per-sample
range is a focus record, not a bytes-on-the-wire boundary. The anti-proxy cost
therefore rests on randomized per-replica timing and occasional wide-coverage
rounds, not on range minimality. Production SHOULD narrow this to bao
verified-range streaming so only the sampled bytes cross the wire; the module
docs were softened to state the current property rather than the aspirational one.

## Note — selective-disclosure fetch gate residuals (§7.4 / D3, Phase 5 audit)

Phase 5 audit dispositions for the owner-side blob-read gate (`authorize_fetch`).

- **W2 (fixed): superseded-epoch chunks stay owner-gated.** `Shared.owned_chunks`
  now retains every ChunkID ever published for an owned vault across epoch bumps
  (the current-epoch `vault_blobs` is overwritten on republish). The gate keys on
  `owned_chunks`, so a chunk dropped from `vault_blobs` by an edit keeps its §7.4
  gate: a still-disclosed old chunk is served only to its audience, an undisclosed
  old chunk to no non-device - it no longer regresses to the residual and is not
  served to any dialer.

- **W2-gc (accepted, not fixed): old-epoch blobs are not GC'd.** Superseded chunk
  blobs remain in the in-memory store and their ChunkIDs remain in `owned_chunks`,
  so both grow with the distinct chunks published over the daemon's life. This is a
  resource concern, not a confidentiality or gate one (the gate is retained above).
  Bounded eviction of old-epoch blobs under a retention policy - dropping the blob
  and its `owned_chunks` entry together - is deferred until the daemon grows a
  runtime-state/blob store with a GC pass; the two must be evicted in lockstep so
  the gate never outlives, or is outlived by, the blob.

- **S4 (accepted, not fixed): the manifest envelope digest is outside the gate.**
  `authorize_fetch` gates chunk ChunkIDs, not the per-vault manifest-envelope blob
  (`VaultBlobs.digest`), so the envelope is served to any dialer on the inherited
  residual. It is AEAD-sealed under `K_manifest`, which friends never hold, so only
  its ciphertext and size leak - acceptable. Folding the envelope digest into
  `owned_chunks` (gated to own devices + replica set) would tighten it if envelope
  metadata size/among-friends exposure ever matters.

## Note — self-hosted NAT-traversal audit dispositions (§6, §14)

Phase-N audit of the embedded relay + endpoint wiring. C1 (open unauthenticated
relay) and W1 (undelegated hint injection) are fixed in code (`carapace-net::relay`
friend-gate + per-client rate cap; `carapaced::learn_card_hints` delegation gate),
W4 (relay-diversity warning) is implemented on the status surface
(`relay_network_count` / `relay_diversity_warning`). The two below are settled
here rather than in code.

- **W2 (accepted metadata exposure): the embedded relay is plain HTTP.** The
  `/relay` WebSocket is served over `ws://` (no TLS, no cert - the "zero
  third-party infrastructure" relay). The relayed QUIC payload stays
  end-to-end-encrypted, so content is safe, but the relay routing header carries
  source/destination endpoint ids in the clear, so any passive on-path observer
  (ISP, wifi, transit), not only the relay operator, sees which of your friends'
  NodeIDs are talking and the packet timing/sizes. §14 scopes metadata exposure to
  "friends' relays" (the operator); plain HTTP widens that to arbitrary on-path
  networks. **Resolution: this on-path metadata exposure is accepted for Phase N.**
  iroh's relay client speaks TLS only to an `https://` URL with a
  handshake-valid cert, so closing this needs ACME or a pinned-cert scheme on
  stable-named relays (§6 anticipates DDNS). §14 should state that a plain-HTTP
  self-hosted relay exposes routing metadata to on-path observers, and that TLS is
  recommended once a relay has a stable name.

## Note — W8 replica blob-read gate + reconstruct/disclose re-serve (§7.4, Phase 5 audit)

W8 lands the per-peer blob-read gate the E-blob-authz note owed: `authorize_fetch`
serves an owned chunk only to the owner's own devices, the vault's replica-set
members, or a grant-audience friend, and a replica-held chunk only to that owner's
devices or a current replica-set member. The verified-clean gate logic is not
attacker-spoofable (owner/vid→chunk associations all trace to an owner-signed,
`verify()`'d card/announce). Two completion points from the adversarial review:

- **W8-reserve (fixed): reconstructing/disclosing a vault no longer re-serves the
  ciphertext.** `reconstruct_one` and `fetch_disclosed` previously fetched the
  owner's/replica's ciphertext into `self.blobs` - the *same* `MemStore` the router
  serves over `iroh_blobs::ALPN`. Because `authorize_fetch` ends in a residual
  `true` for any hash absent from the owned/replica maps, any device that
  reconstructed A's vault (a delegated device pulling from a replica) or fetched A's
  disclosed files (an audience friend) would then re-serve that ciphertext to any
  dialer knowing the ChunkID - voiding the W8 gate one hop over and defeating
  disclosure revocation. Both paths now fetch into a throwaway `IrohBlobStore` (the
  PoR probe's `scratch` pattern); the bytes are used to write plaintext to disk and
  never enter the served store. Regression-tested in `friend_replica`
  (reconstructing device A2 refuses a stranger) and `selective_disclosure`
  (audience B refuses a stranger a chunk it got only via `fetch_disclosed`).

- **Residual `true` retained by design.** The gate's default-serve residual is left
  in place: it covers only the manifest-envelope digest (S4 note above, AEAD-sealed)
  and, previously, reconstructed/disclosed blobs (now removed from the served store).
  The fix is at the population site, not the gate, so no owned/replica association
  and no legitimate serve path changes.

## Note — W9 suite/version rejection is module-scoped, not daemon-wide (§2, Phase 5 audit)

W9 validates `Hello.protocol == PROTOCOL_VERSION` on **both** directions of
`carapace-net`'s anti-entropy module (`SyncHandler::serve` inbound and
`pull_documents` outbound), rejecting a mismatch **before** any document is written
and dropping a connection whose `Hello` fails to decode (no panic). This hardens the
standalone anti-entropy/sync module, which is exercised only by carapace-net's own
integration tests. The **daemon** does not register `SyncHandler`; it registers
`ControlHandler`, which dispatches on the first frame type and never reads a peer
`Hello.protocol`. Daemon-side suite binding is purely the ALPN string `carapace/1`
(a mismatched suite never negotiates the ALPN), which is consistent with the
"suite bound to ALPN" design. So W9 is real and clean within its module but is NOT a
daemon handshake check - stated here so the ledger's DONE is not mistaken for
daemon-wide `Hello.protocol` enforcement.

- **W3 (deferred feature): advertised relay is not dialback-verified.** A node run
  with `--relay` advertises its relay URL in its ContactCard and issued tickets
  unconditionally at startup; §6's "peer-dialback verification; advertise on
  success, withdraw on loss" is not implemented, and there is no card re-issue when
  the relay dies. Compounding it, iroh's portmapper maps only the single iroh
  **endpoint UDP port**, never the relay's HTTP/TCP port, so a home-NAT node's
  advertised relay is unreachable from the WAN unless the operator manually
  port-forwards or fronts it with DDNS. **Resolution: documented, implementation
  deferred.** Full dialback needs a cooperating external prober and an
  event-driven advertise/withdraw + card-bump path (a new subsystem), out of scope
  for this pass. Until then: a home node's relay port needs a manual
  port-forward/DDNS, and friends may waste dials on an unreachable advertised
  relay (bounded - the relay is a fallback hint, direct/hole-punched paths and
  other friends' relays still work). §6 should note the portmapper does not open
  the relay's TCP port.

## E6 — §11 conflict-file identity uses content hash, not `<dev>` (winner tie-break too)

§11 says a losing concurrent write is renamed `path.sync-conflict-<ts>-<dev>.<ext>`
and the winner is chosen "by `(mtime, deviceID)`". Deriving `<dev>`/the deviceID
tie-break from the (post-merge, joined) version vector is **order-dependent**: with
3+ concurrent devices, different pairwise merge fold orders yield different winners
and different conflict filenames, so devices permanently diverge (proven in the
§11 audit: 3 concurrent edits produced different file sets per device). **Resolution:
identity is derived from order-independent, content-intrinsic data instead** — the
loser's `file_hash` gives the conflict suffix (`path.sync-conflict-<ts>-<hash>.<ext>`)
and the winner tie-break is `(mtime, file_hash, size)`, `mtime` still primary per the
spec. This converges identically on every device regardless of merge order. The
literal `<dev>` (the device that authored the losing edit) is satisfiable via the
loser's *original single-device attribution captured before any VV join*; the content
hash was chosen as the simpler order-independent key. Conflict filenames are local
artifacts (the manifests/VVs are what sync), so this does not affect cross-client
data interop. §11 should specify an order-independent conflict identity.
