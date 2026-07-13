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
in `carapaced::Daemon::start_with_limits`.

## E3 — FastCDC variant/params unpinned (protocol §5)

§5 names "FastCDC" with MIN 256 KiB / AVG 1 MiB / MAX 4 MiB but not the
variant, normalization level, or gear table, and ships no chunk-boundary
vector. Different variants (e.g. v2016 vs v2020) cut differently, breaking
cross-client convergent dedup. **Resolution: pin FastCDC v2016 with the
standard Gear table**, matching the implementation. A chunk-boundary test
vector is owed (tracked for Phase 1, when the chunker is exercised
end-to-end).

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
