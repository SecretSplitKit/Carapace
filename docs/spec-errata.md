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
(`relay_network_count` / `relay_diversity_warning`), and W6 (relay reachability
lifecycle: health-gated advertise/withdraw with monotonic card re-issue, TCP
port-mapping, and peer-dialback confirmation) is implemented in code - the W6 bullets
below record what landed and the residuals that remain errata. W2 (below) is settled
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

- **W6 (implemented): relay reachability lifecycle - advertise on health, withdraw
  on loss, with monotonic card re-issue.** §6's "advertise on success, withdraw on
  loss" is now a real subsystem, not a startup one-shot. The relay is NO longer
  advertised unconditionally at startup: the own card is built relay-less, and
  the relay URL is folded in only after a liveness probe confirms the listener is up
  (`CarapaceRelay::is_alive`, an active TCP connect to the relay's own loopback
  socket - the iroh-relay `Server` handle exposes no non-blocking task-liveness
  accessor, only a blocking `join`, the bound address, and metrics). The maintenance
  loop (`maintenance_round`) probes every round and reconciles: on a health loss the
  own card is re-issued WITHOUT the relay URL, on recovery WITH it; every such change
  BUMPS the monotonic card version (§6 rollback rule) and propagates through the
  existing anti-entropy doc path (`serve_docs` re-serves `shared.cards`; a peer's
  `DocStore::offer_card` accepts the higher version and rejects a replay). `W4`
  diversity counting and issued tickets track the *current* advertised state, so a
  withdrawn relay stops counting and is not handed out as a dead hint. Covered by
  `w6_relay_advertise_withdraw_reissues_card_monotonically`.
  - **Probe hysteresis (implemented).** `is_alive` is a 2 s loopback TCP connect;
    under load a single connect can time out on a perfectly healthy relay, and
    each spurious withdraw costs two card re-issues (withdraw + re-advertise).
    `drive_relay_health` now requires `RELAY_PROBE_FAILURE_THRESHOLD` (3)
    consecutive failed probes before withdrawing - the first two are tentative
    and do not re-issue - and resets the streak on the first success (which
    re-advertises). Covered by `w6_relay_probe_hysteresis`.
  - **Own-card version rollback survival across restart (implemented, with a
    residual).** All daemon state (including the own card and its flap-bumped
    version) is in-memory, so a naive restart would re-issue the card at v1;
    friends who already hold a higher-versioned card from the prior run's relay
    flaps would reject the fresh one as a rollback (`DocStore`), stranding the
    node. The own card's *initial* version is therefore seeded from a wall-clock
    floor (`unix_now()`, unix seconds) rather than 1, and the existing
    `version += 1` re-issue logic rides on top. A later restart's base (a larger
    timestamp) exceeds the prior run's flap-bumped versions in the common case
    (elapsed seconds >> number of flaps). **Residual:** a pathological
    rapid-restart under heavy flapping (elapsed wall-clock seconds < number of
    flaps in the prior run) can still re-issue below a version a friend holds.
    The complete fix is a persisted monotonic counter, folded into the same
    in-memory-state persistence deferral as the rest of `Shared` (the maintenance
    round counter, the friend/replica set, etc.; see the persistence note above):
    when `Shared` gains on-disk durability, persist the own card's last-issued
    version alongside it and seed from `max(persisted + 1, unix_now())`.

- **W6 (implemented): the relay's TCP/HTTP port is now NAT-mapped.** The earlier
  errata that "iroh's portmapper maps only the endpoint UDP port, never the relay's
  TCP port" is resolved: `CarapaceRelay` drives its own `portmapper::Client` (the
  same crate iroh uses, `Protocol::Tcp`, UPnP/NAT-PMP/PCP) for the relay's TCP listen
  port on a routable bind, and advertises the mapped WAN address
  (`external_addr`) - precedence: configured relay host (DDNS) > mapped external
  address > local/bound URL. Registration stays on the loopback URL (never the WAN
  URL, which a home router may not hairpin) so our own endpoint always remains a
  client of its own relay, which is what lets friends relay *to* us. **Residual
  errata:** port-mapping is best effort - with no UPnP/NAT-PMP/PCP-speaking gateway
  the mapping never establishes and a home node still needs a manual port-forward or
  a stable relay host (`--relay-host` / DDNS), exactly as before. iroh's endpoint UDP
  portmapper is unchanged and independent.
  - **Only globally-routable addresses are advertised (implemented).** Three
    guards close the "signed card advertises an unreachable relay" gap: (1)
    `external_addr` filters the port-mapper's reported WAN address through
    `is_globally_routable_v4`, rejecting a mapping in RFC1918 private, CGNAT
    (100.64.0.0/10), loopback, link-local, unspecified, broadcast, or
    documentation space (a double-NAT / carrier-grade-NAT gateway can hand back
    such an "external" address). (2) `advertised_url_for` no longer falls back to
    the loopback-substituted `local_url` for a `0.0.0.0`/private-LAN bind - that
    fallback is used only for an EXPLICIT loopback bind (the same-host / test
    case); with the default `0.0.0.0` home-relay bind and no routable host or
    mapping the node stays withdrawn rather than fold `http://127.0.0.1:PORT` (or
    a LAN `192.168`/`10.x` address) into the card and inflate the diversity count.
    (3) The composed URL (including a `--relay-host` value) must parse as an iroh
    `RelayUrl` before it is folded into the card; a malformed relay host yields no
    advertised relay rather than a signed card with a garbage `relay_url`.
  - **Port-mapper skipped when a relay host is configured (implemented).** With a
    stable `--relay-host` (DDNS/WAN name) and a manual port-forward, UPnP/NAT-PMP/
    PCP is redundant, so `CarapaceRelay::start` takes a `skip_portmap` flag (set
    when `relay_host` is present) and does not spawn `portmapper::Client` there -
    avoiding the SSDP/PCP traffic and firewall prompts. Loopback binds skip it as
    before.

- **W6 (partial - external-prober dialback remains errata): peer-dialback confirms,
  it does not gate/withdraw.** iroh *does* expose the path a connection arrived on
  (`Connection::paths()` -> `Path::is_relay()` + `remote_addr()` =
  `TransportAddr::Relay(url)`; an inbound relayed datagram is labelled with the relay
  URL we received it on), so when a friend reaches us through our own relay we record
  it (`relay_health.verified_at`, surfaced via `relay_verified_at`) as genuine
  external-reachability proof. But advertising is gated on *local* liveness, not on
  dialback, for two honest reasons: (1) gating the initial advertise on dialback
  deadlocks - a friend can only reach us via the relay after learning it from our
  card; (2) dialback silence cannot be distinguished from "no friend has dialed
  lately," so it must not withdraw a live relay. **Resolution: dialback is
  confirmation, not a gate.** Actively withdrawing a relay that is up locally but
  unreachable from the WAN needs a cooperating external prober (a third party that
  dials our relay URL from outside our NAT and reports back), which is out of scope
  for this pass. Consequence (bounded): a relay that is locally healthy but
  WAN-unreachable (e.g. no port-forward, no working port-mapper) stays advertised, so
  friends may waste dials on it - direct/hole-punched paths and other friends' relays
  still carry the connection. A second honest ceiling: iroh upgrades a relayed path
  to direct as soon as hole-punching succeeds, so `note_relay_dialback` (checked at
  accept time) catches connections that are still-or-only relayed - which is exactly
  the population the relay serves.

- **W6 (known ceilings, out of scope for this pass).** Two smaller residuals are
  documented rather than fixed: (1) `is_alive` proves the relay's TCP *listener
  accepts a connection*, not that the relay's forwarding/registration logic is
  actually healthy - a wedged server that still accepts would probe alive. A true
  liveness check would register a client and round-trip a relayed datagram; the
  active-connect probe is the concrete signal the iroh-relay `Server` handle
  makes available. (2) `Hello.card_version` is hardcoded to `1` on the control
  handshake and no reader consumes it (card freshness is reconciled via the
  versioned `DocStore`/anti-entropy path, not the `Hello` field), so it carries no
  meaning today; wire it to the real own-card version if a reader ever needs it.

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

## Note — attestations use a direct request/response channel, not versioned anti-entropy (§6, §10.2, W7)

§6 lists "attestations (§10.2)" among the signed documents two friends "exchange
and reconcile … by version number — simple anti-entropy," alongside contact cards
and vault announces. In the implementation attestations are **not** folded into the
versioned document store-and-forward. They are a live challenge/response liveness
probe with per-round freshness, not a monotonic document:

- The owner mints a `ShareAttestChallenge` carrying a fresh random nonce each round
  and dials each trustee directly (`Daemon::run_share_health_round` →
  `challenge_trustee`); the trustee answers with a `ShareAttestation` echoing that
  nonce (`ControlHandler::serve_attest`). The owner verifies the echoed nonce and
  folds the response into a per-recovery-set **freshness window** (`AttestTracker`):
  liveness means "answered a recent challenge," which a stored, re-served,
  version-deduped document cannot express (a replayed old attestation would forge
  liveness; the nonce binding is exactly what prevents that).
- Attestations therefore have no monotonic version/epoch line to reconcile and are
  never rollback-guarded or forwarded like cards/announces. Store-and-forward
  (W7) applies to cards and announces only.

**Resolution: attestations legitimately use a direct request/response channel; §6's
inclusion of them in the anti-entropy document list is the divergence.** Cards and
announces are the versioned documents that flow (and now store-and-forward) across
friendship edges; the attestation cadence is a separate §10.2 liveness protocol that
must stay nonce-fresh. §6 should scope its anti-entropy list to cards + announces and
cross-reference §10.2 for the attestation challenge/response cadence.

## Note — W2 ceremony roster is reconstructed at the daemon, not read from `grant.by` (§8.5)

The ceremony crate's `CeremonyState::open_from_grant` derives the trustee roster as
`grant.by` (the grant signer) plus each `cotrustee.user`. That is correct for the crate's
own model, where each trustee holds a grant it signed itself (`grant.by` == the holder).
But a **W3 owner-minted grant is signed by the OWNER's node key** (`recovery_split_grant`
uses `build_share_grant(&self.node_key, …)`) and its `cotrustees` list **excludes the
holder** - so `grant.by` is the subject-owner (not a trustee at all) and the holder is
absent from the derived roster. Feeding such a grant to `open_from_grant` yields a roster
that both **omits the holding trustee** and **wrongly admits the owner**, breaking every
downstream check (`RecoveryOpen.by ∈ roster`, `CeremonyApprove.by ∈ roster`).

**Resolution: the daemon reconstructs the ceremony roster itself** as `{this trustee's
own user key} ∪ {each grant cotrustee.user}` (`carapaced::track_from_grant`), using the
lower-level `CeremonyState::open` rather than `open_from_grant`. The holder is exactly the
missing roster entry, so `{self} ∪ cotrustees` is the full N-trustee set on every observer;
the owner-subject (who aborts, never approves) is correctly excluded. Opens, approvals, and
aborts are signed with the **user** key (roster membership is by user key; node keys are
dial hints + the §10.2 attestation roster only). Per-subject rate limiting stays on the
sponsor path (`ceremony_sponsor_open`), matching §8.5 "rate-limited per subject" (the
opener); the fan-out receive path relies on ceremony-id dedup + roster-gated tracking.
The share-release transport reuses the signed `RecoveryOpen` as the claimant's request
frame: a trustee whose gate is open (it approved AND `≥ M` approvals AND `max(opened_at,
local first_seen)+recovery_delay` elapsed AND no abort) replies with its `CeremonyShare`
HPKE-sealed to `ceremony_enc`; otherwise it replies with nothing. The spec prose is
unaffected (it does not prescribe the grant's signer); this is an implementation
reconciliation between the W3 grant format and the ceremony primitives.

## Note — W13 IPv6 bind is a non-gap: iroh 1.0.2 is dual-stack by construction (§6)

W13 asks that a node be reachable over IPv6. `CarapaceEndpoint::bind_on` hands its
caller-chosen `SocketAddr` straight to iroh's `Endpoint::builder(...).bind_addr(bind)`
(`crates/carapace-net/src/endpoint.rs`), and the `--bind` CLI flag parses its value with
`str::parse::<SocketAddr>` - which accepts `[::]:port` and `[::1]:port` - so an IPv6 bind
already flows through unmodified. The question was whether iroh actually binds an IPv6
socket.

It does, in **both** directions, because iroh 1.0.2's builder is dual-stack by default:

- `Builder::empty()` (the base every preset, including `presets::Minimal`, is built on)
  pre-loads *two* IP transports:
  `TransportConfig::default_ipv4()` (bind `0.0.0.0:0`, `is_required: true`) and
  `TransportConfig::default_ipv6()` (bind `[::]:0`, `is_required: false`).
  Evidence: `iroh-1.0.2/src/endpoint.rs:341-346` (`empty()`), and
  `iroh-1.0.2/src/socket/transports.rs:123-153` (`default_ipv4`/`default_ipv6`).
- `bind_addr(addr)` does **not** clear the whole transport list; it only pushes a
  user-defined transport for `addr`'s address family. The resolver in
  `Transports::bind` (`iroh-1.0.2/src/socket/transports.rs:190-221`) drops a
  pre-configured default *only* when a user-defined default of the **same family**
  exists (`has_ipv4_default` / `has_ipv6_default`). Evidence: the skip guard
  `!is_user_defined && (is_ipv4 && has_ipv4_default || is_ipv6 && has_ipv6_default)`.

Consequences:

- Passing an **IPv4** bind (carapace's default `0.0.0.0:port` / loopback) replaces only
  the IPv4 default; the pre-configured `[::]:0` IPv6 socket is still bound (its
  `is_required: false` means it degrades gracefully to silent skip on hosts without IPv6,
  rather than failing the endpoint). The node is IPv6-reachable regardless.
- Passing an **IPv6** bind (`[::]:port`) replaces the IPv6 default and keeps the
  `0.0.0.0:0` IPv4 default - full dual-stack, IPv6-preferred.

**Resolution: W13 is a non-gap; no behavior change.** The dual-stack guarantee is pinned
by a unit test, `carapace_net::endpoint::tests::binds_ipv6`
(`crates/carapace-net/src/endpoint.rs`), which binds `[::1]:0` through `bind_on` and
asserts an IPv6 socket appears in `Endpoint::bound_sockets()`.

## Note — W5 §9.3.4 re-split prompt flow (implemented)

§9.3.4's prompt flow is implemented. Unfriending a trustee does **not** auto-start a
re-split: `Daemon::unfriend` records a **pending** re-split (`pending_resplits`) for every
recovery set the ex-friend was a trustee of, surfaced via `pending_resplit_statuses` (and
`/api/status`) with the suggested new set (old set minus the ex-friend) and per-friend live
reachability. Nothing stands up until the user acts: `POST
/api/recovery/{rsid}/resplit-start` (`Daemon::start_pending_resplit`, optional trustee-set
override) is the **only** path that opens a re-split, after which the maintenance loop drives
it under the destroy gate. The destroy-gating invariant is unaffected: the old shares are
destroyed only once the new set is proven live (`≥ M + slack`), routed solely through
`Resplit::share_destroy`.

The trustee-side receiver of that destroy (§9.3 step 3c) binds the instruction to the
share's owner: `ControlHandler::serve_share_destroy` requires the signer node to map to the
**subject** owner (`owner_user_of_node(ds.by) == ds.subject`) AND the named `rsid` to be one
held **for that subject** (`held_share_subjects`), so no current friend can destroy an
unrelated owner's share by naming its rsid. The `FriendshipEnd` receiver likewise honors an
end only when it names **us** (`end.user == self_user`) and rides the signer's own
connection (`end.by == remote`). Regression coverage: `crates/carapaced/tests/unfriend.rs`.

## Note — full-spec conformance sweep: residual dispositions

A clause-by-clause sweep of the whole spec (§2-§14, 186 normative clauses) against the
code produced code fixes for the real MUST-level gaps it found (§8.5 abort durability,
§8.3 over-cap extend warning, §11 push-to-replicas on publish, §8.4 recovery manifest/chunk
fetch) and one security fix (§8.5). The following residuals are deliberate divergences,
SHOULD-level items, physical-world advisories, or wire-schema entries superseded by other
mechanisms. Each is documented here rather than code-changed.

- **§4 manifest authorship is node-key-signed, not user-key-signed.** The spec says the user
  key signs manifest authorship; the impl signs each `ManifestEnvelope` with the per-device
  **node** key (`carapace-vault` `seal_manifest`), tied to the user through the node
  delegation chain (§4). Same rationale as E1 (friendship signing): per-device attribution
  is revocable without touching identity, and a lost device is revoked by dropping its
  delegation rather than rotating `K_root`. Authorship still resolves to the user, just
  indirectly. Deliberate.
- **§6 "≥1 stable-named relay per friend cluster" (SHOULD).** The capability exists
  (`--relay-host`/`cfg.relay_host` for a DDNS or static-IP relay), but whether a given friend
  cluster actually contains one is a cross-node deployment property no single daemon can
  observe or enforce. Left to operators; the `< 2 distinct networks` warning (W10) is the
  in-app nudge.
- **§9.3 FriendshipEnd "learned via the sender's next card version" fallback.** Only the
  direct-receipt path is a distinct mechanism (`serve_friendship_end`, best-effort send). An
  offline ex-friend is not chased with an explicit end-signal folded into a re-fetched card;
  it simply stops appearing once contact lapses, and the teardown is idempotent on eventual
  receipt. The card-version fallback is descriptive, not a separate code path.
- **§9.3.4 "old paper cards should be physically destroyed and replaced" (physical SHOULD).**
  Paper-card printing exists (W15); the specific reminder to physically destroy superseded
  cards as each new one is delivered is a real-world action the software cannot enforce and
  is not surfaced as a per-card prompt in the re-split UI.
- **§10.1 "owners SHOULD watch response-time distributions" (anti-proxy heuristic).** Not
  implemented at runtime; anti-proxy rests on jittered audit timing and occasional
  wide-coverage rounds, as §10.1 itself allows. Residual friend-proxying is an availability
  risk explicitly accepted by the trust model.
- **§10.2 drift-toward-M extend/re-split is surfaced, not auto-executed.** `decide()` computes
  `Extend{needed}` (below M+slack, with cap headroom) or `ResplitLargerM` (at the §8.3 soft
  cap) and the daemon reports it via `recovery_health`, but attestation-liveness drift does
  not autonomously start an extend or re-split (only the unfriend path auto-drives a re-split,
  under the destroy gate). This matches the §9.3.4 decision to prompt the owner rather than
  act unattended: the recommendation is surfaced, the owner starts it via the recovery API.
- **§14 split-state at-rest sealing is correct but not exercised.** The seal primitive is
  `HKDF(K_root, "carapace/v1/split-state")` + XChaCha20-Poly1305 with `aad = rsid‖M`
  (`state_seal`), unit-tested, but the daemon holds split-state only in memory (all daemon
  runtime state is in-memory, no persistence yet), so nothing is ever written unsealed. When
  persistence lands, seal on write. Endpoint compromise of an owner device is out of scope
  (§14).
- **§14 weakest-split rule "K_root split once" (SHOULD) is not enforced.** `recovery_split`
  accepts more than one root split; nothing rejects a second `K_root` door. The scope
  distinction (`RecoveryScope::Root` vs `Vault`) exists and the default flow splits once, but
  a guard/warning against a second root split is a candidate future hardening, not present.
- **§12 `Hello` is sent but not consumed for negotiation.** `Hello` (card versions +
  capabilities) is emitted as the stream preamble and the W9 suite/version-mismatch refusal,
  and `Hello.protocol == 1` is checked (W9), but no daemon reader consumes an inbound
  `Hello`'s `card_version`/`roles` for capability negotiation; version reconciliation runs on
  the anti-entropy card/announce exchange (§6) instead. `card_version`/`roles` are hardcoded.
- **§12 `ManifestOffer` and `AuditNotice` are defined and golden-vectored but not wired at
  runtime.** Both are superseded by mechanisms the spec describes elsewhere: the manifest
  flows as an iroh blob addressed by `VaultAnnounce.manifestDigest` (§7.2/§7.3), so a separate
  offer message is redundant; and PoR issues direct BLAKE3-verified `iroh-blobs` range
  requests (§10.1), so no separate audit-notice frame is needed. Retained in `carapace-wire`
  with their Appendix B vectors for wire-schema completeness and possible future use.

## Note — §8.4 recovery data-fetch: replicas retain and serve the FileGrant (Option A)

§8.4 ("recover K_root, then fetch the latest manifest + chunks from any replica") requires the
recovering, key-less claimant to obtain the per-chunk decryption keys, which live only in the
`FileGrant` (`GrantChunk { chunk_key, nonce }`), not in the manifest. Previously the grant was
served only by the live owner, so a dead-owner claimant could fetch ciphertext but not decrypt
it. Implemented as **Option A**: on replica placement/repair/epoch-push the owner now pushes the
epoch-matched `FileGrant` alongside the announce; the replica verifies it (`grant.verify()`,
`vid`/`by`/`epoch` bound to the placement) and retains it (`replica_grants`, `replica_announce`);
and a dialer classified `ReplicaDevice(owner)` (which requires presenting an owner-user-key-signed
card delegating its node - unforgeable without `K_root`) is served that one owner's card, announce,
and grant so it can drive `select_targets` and reconstruct. Confidentiality is unchanged: the grant
body is HPKE-sealed to the owner's `K_disclose` (derived from `K_root`), so serving it to anyone
lacking `K_root` yields nothing, and anyone holding `K_root` could derive the content keys directly.
End-to-end regression: `crates/carapaced/tests/recovery_reconstruct.rs`.

Two dispositions: (1) the placement push now carries one extra `FileGrant` frame between the
announce and the blob count - a coordinated in-repo protocol addition, fail-closed against a pre-
change pusher (placement aborts, no partial state), no mixed-version compat guarantee. (2)
Deferred **Option B** (carry the per-chunk keys in the sealed manifest so recovery needs no grant
at all): cleaner long-term, but it revs the core `Manifest`/`FileEntry` wire format and the §4/§5
cross-client golden vectors (W11), so it is left as a future spec-level decision rather than folded
in here. (3) Multi-source max-epoch reconciliation across trustees + replicas (§8.4) remains
unit-tested (`max_epoch_refs`); the live claimant fetch uses a single replica, which is sufficient
for content recovery - wiring trustee-served announce refs into the live fetch is additive.
