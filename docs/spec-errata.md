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

## E3 — FastCDC variant/params unpinned (protocol §5)

§5 names "FastCDC" with MIN 256 KiB / AVG 1 MiB / MAX 4 MiB but not the
variant, normalization level, or gear table, and ships no chunk-boundary
vector. Different variants (e.g. v2016 vs v2020) cut differently, breaking
cross-client convergent dedup. **Resolution: pin FastCDC v2016 with the
standard Gear table**, matching the implementation. A chunk-boundary test
vector is owed (tracked for Phase 1, when the chunker is exercised
end-to-end).
