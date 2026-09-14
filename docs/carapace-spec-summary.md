# Carapace - Protocol Spec (Summary)

Carapace is a peer-to-peer protocol for encrypted, live-syncing, friend-to-friend
file storage with social key recovery, built on [iroh](https://github.com/n0-computer/iroh).
Vault plaintext lives only on your own devices. Friends hold encrypted replicas
and threshold recovery shares, never keys. This is the condensed spec; the
normative source is `carapace-protocol.md` (v0.10), with `docs/spec-errata.md`
for accepted deviations and `docs/conformance-ledger.md` for implementation status.

## Model

A user owns **vaults** (folder trees) and maintains **friendships**: bilateral,
mutually-signed relationships. From among their friends a user selects, and each
friend individually accepts, two independent per-friend grants:

- **Storage peer** - holds `r` encrypted replicas of a vault, serves ciphertext
  blobs, answers retention audits, holds no keys.
- **Recovery trustee** - holds one Chela share of the root secret, attests
  possession, helps recover.

Changes propagate live and are eventually consistent. Losing the root secret is
survivable as long as any `M` trustees, or `M` paper cards, survive.

Axioms:

- **Everything is pairwise.** There is no membership beyond friendship, and no
  action by two people can obligate or expose a third. A friend of a friend is a
  stranger: no data, metadata, or relay service crosses a non-edge.
- **Peers are ciphertext-only.** iroh is the substrate. The only threshold
  primitive is Chela; no bespoke crypto.
- **Grants, not people.** Storage and trusteeship are separate grants; the
  recovery threshold `M` is chosen independently of the replica count `r`.

## Identity and keys

One long-term secret, `K_root` (256-bit CSPRNG, rendered as a 24-word BIP-39
mnemonic). Everything else derives from it by HKDF-SHA-256 with fixed info strings:

```
K_vaultroot(vid) = HKDF(K_root, "carapace/v1/vault/" ‖ vid)
K_content(vid)   = HKDF(K_vaultroot(vid), "content")           # chunk encryption
K_manifest(vid)  = HKDF(K_vaultroot(vid), "manifest")          # manifest sealing
K_audit(vid)     = HKDF(K_vaultroot(vid), "por")               # retention audits
K_userid         = HKDF(K_root, "carapace/v1/user-identity")   # Ed25519 identity
K_disclose       = HKDF(K_root, "carapace/v1/disclosure")      # X25519 / HPKE
```

`K_root` never leaves owner devices except as Chela shares. The **user key**
(from `K_userid`) is permanent identity, recoverable via Chela, and signs contact
cards, friendships, and manifests. The **node key** is a per-device iroh endpoint
key, not derived from `K_root`, so a lost device is revoked without touching
identity; it is certified by a signed user-key delegation. Peers verify the
delegation chain before treating a node as acting for a user.

## Content

Files split with FastCDC v2016 (Normalization Level 1; 256 KiB / 1 MiB / 4 MiB
min/avg/max), so any two clients chunk a file identically. Each chunk is
convergently encrypted, vault-scoped:

```
pt_hash   = BLAKE3(plaintext)
chunk_key = HKDF(K_content(vid), "chunk-key"  ‖ pt_hash)
nonce     = HKDF(K_content(vid), "chunk-nonce" ‖ pt_hash)[:24]
C         = XChaCha20-Poly1305(chunk_key, nonce, plaintext, aad = vid)
ChunkID   = BLAKE3(C)          # this is the iroh blob hash
```

Ciphertext chunks are iroh blobs, so peers get keyless BLAKE3-verified streaming
and resumable transfer natively. Dedup is intra-vault only; `K_content` is never
shared across vaults, so ciphertext carries no cross-vault correlation. A vault's
**manifest** lists its files and, per chunk, `(ChunkID, pt_hash, len)`. The
manifest is self-sufficient: any holder of `K_content` (an owner device, or a
claimant who has just recovered `K_root`) re-derives every chunk key from the
manifest alone, so recovery needs only the sealed manifest plus the ciphertext,
no separate key delivery.

## Storage and durability

Owner devices are the only decryption locus and the only place plaintext exists.
Everything else a node persists is on disk and survives reboot: ciphertext blobs
in a content-addressed store, and runtime state (friendships, epochs, grants,
recovery state, audit counters) in an ACID key-value store with secret-bearing
rows sealed under `K_root`. State is committed before any externally visible
effect, and a commit failure is fatal rather than letting memory run ahead of disk.

Blob serving is **default-deny**: a node answers a fetch only for a hash it can
prove the dialer is entitled to read (own device, current replica-set member, or
an authenticated disclosure audience). A leaked reference alone authorizes nothing.

Redundancy is `r` replicas plus **proof-of-retention** audits: the owner
periodically challenges each storage peer for randomly sampled chunks (sampling
keyed by `K_audit`, answers verified by content address, no owner copy needed). An
unreachable peer is not a lost one; only a peer that answers with missing or wrong
content advances toward eviction and repair.

## Social recovery (Chela)

Recovery is `M`-of-`N` threshold over the root secret using **Chela**, the sole
threshold component. A user splits `K_root` into shares held by chosen trustees;
any `M` reconstruct it. Paper cards are an offline backstop at the same threshold.
Trustees self-validate their shares and periodically attest possession, so the
owner sees recovery health without exposing the secret. Recovery is delay-gated
and abortable: an owner, or their surviving devices, can cancel an in-flight
recovery within the window, and a valid abort consulted at share-release time
overrides a later open.

**Selective disclosure** grants a specific friend read access to a subset of
files without sharing `K_root`: the per-chunk keys for that subset are sealed to
the friend's disclosure key with HPKE (X25519 + ChaCha20-Poly1305).

## Networking

Every node is an iroh endpoint (QUIC, TLS 1.3, dialed by NodeID). There is no
third-party infrastructure: **relays are friends' relays**, self-electing and
dialback-verified, advertised on success and withdrawn on loss; your usable relay
set is whatever your friends advertise. Clients warn when the reachable relay set
falls below two distinct networks. Addresses are hints, not identities - a stale
hint is one failed dial, NodeIDs are permanent.

There is no gossip. On each friend-to-friend connection the two nodes reconcile
their latest signed documents (contact cards, vault announces, attestations) by
version number - pairwise anti-entropy. Documents flow only across friendship
edges. Versions are monotonic per signer, and a peer rejects any card or announce
at or below the highest already seen from that signer, which blocks rollback. The
one out-of-band step is a friend-request **ticket** (a compact string or QR)
exchanged over a channel the two people already trust; acceptance is the mutual
signing of a friendship.

## Live sync and conflicts

A vault's working directory is watched; on change the owner re-chunks, updates the
manifest, and republishes a new **epoch** to the replica set. Concurrent edits
across two owner devices reconcile with per-file version vectors: non-conflicting
changes merge, real conflicts are kept side by side rather than silently dropped,
and deletions tombstone so they do not resurrect.

## Cryptographic suite (id `0x01`)

| Purpose | Algorithm |
|---|---|
| Root secret | 256-bit CSPRNG, 24-word BIP-39 |
| Key derivation | HKDF-SHA-256, fixed info strings |
| Content encryption | XChaCha20-Poly1305, per-chunk keys |
| Hash / address | BLAKE3-256 (ChunkID = iroh blob hash) |
| Signatures | Ed25519 |
| Sealed disclosure | HPKE: X25519 + ChaCha20-Poly1305 |
| Root at rest | Argon2id (local sealing only) |
| Transport | iroh endpoint (QUIC, TLS 1.3) |
| Threshold recovery | Chela v1.0.0 + extendable-split |
| Serialization | Deterministic CBOR (RFC 8949) |

Unknown suite ids are rejected, never negotiated down.

## Status

Reference implementation in Rust: a workspace of crypto, vault, wire, net,
recovery, replica, friend, disclose, share, and daemon crates on iroh, with Chela
for threshold recovery. Normative source is `carapace-protocol.md` v0.10; accepted
deviations and conformance status live in `docs/spec-errata.md` and
`docs/conformance-ledger.md`.
