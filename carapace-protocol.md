# The Carapace Protocol — Specification (v0.10, draft)

Carapace is an **open peer-to-peer protocol** for encrypted, live-syncing
**friend-to-friend** storage with social key recovery, built on the **iroh**
networking stack (`github.com/n0-computer/iroh`, Apache-2.0/MIT). Your files
sync across your own devices like Dropbox; friends' machines hold your data
only as encrypted, content-addressed blobs they can store and serve but not
read. A threshold of trustees can reconstruct your key via **Chela**
(`github.com/SecretSplitKit/Chela`), used with one proposed extension
(extendable splits — companion design doc).

## What changed from v0.8

**The group is gone.** v0.9 replaces group membership, rosters, and
quorum-voted admission with a **reciprocal friend graph**: every relationship
is a bilateral, mutually-signed friendship, and every capability (storage,
relay, trusteeship) is granted pairwise. Nothing is transitive; nobody can
obligate anyone by adding a third party. This deletes v0.8's §9
roster/voting machinery and the multi-group section (overlapping friend-sets
are now the default topology, not a feature). iroh-gossip is dropped —
pairwise sync covers all propagation.

**Split lifecycle is two-tier.** Chela splits become *extendable*: the split
polynomial can issue additional shares later (new friend, lost-card
replacement) without touching existing shareholders — the routine operation.
Full **re-split** (new polynomial, new `recovery_set_id`) remains the
escalation for raising `M`, suspected compromise, or periodic hygiene. A soft
cap **`N ≤ 3M − 1`** bounds extension (§8.3).

## Status, licensing, compatibility

Draft, intended for Apache-2.0 OR MIT. All dependencies permissive (iroh,
Chela). A compatible client on any platform embeds the iroh core natively or
via **iroh-ffi** (Swift/iOS, Kotlin/Android, Python, Node.js); this spec
defines everything above iroh precisely enough that independent clients
interoperate. Conformance language per RFC 2119.

---

## 1. Overview

A **user** owns **vaults** (folder trees). Vault plaintext exists only on the
user's **owner devices**. Each user maintains **friendships** — bilateral,
mutually-signed relationships. From among their friends, a user *selects* (and
each friend individually *accepts*): **storage peers** holding `r` encrypted
replicas of a vault, and **recovery trustees** holding Chela shares of a
secret. Changes propagate live (eventually-consistent). Losing the root secret
is survivable while any `M` trustees (or `M` paper cards) survive.

Axioms:

- **Everything is pairwise.** No membership beyond friendship; no action by
  two people can obligate or expose a third. A friend-of-a-friend is a
  stranger: no data, metadata, or relay service crosses a non-edge.
- **Ciphertext-only peers**; **iroh substrate** (endpoint + blobs); **no
  bespoke crypto** — the sole threshold component is Chela.
- **Separate grants, not separate people**: storage and trusteeship are
  independent per-friend grants; `M` is chosen independently of `r`.

---

## 2. Cryptographic suite (normative, suite id `0x01`)

| Purpose | Algorithm |
|---|---|
| Root secret | 256-bit CSPRNG; rendered as BIP-39 24 words (== Chela `kind 0x05`, the no-length-ambiguity path, SPEC §4.6) |
| Key derivation | HKDF-SHA-256, fixed `info` strings (§4) |
| Content encryption | XChaCha20-Poly1305 (24-byte nonce), per-chunk keys — never bare AES-GCM |
| Hashing / addressing | BLAKE3-256 (ChunkID = iroh blob hash) |
| Signatures | Ed25519 (user keys, device delegations, documents) |
| Sealed disclosure | HPKE (RFC 9180): X25519 + XChaCha20-Poly1305 |
| Root-at-rest KDF | Argon2id (local sealing only) |
| Transport | iroh endpoint (QUIC, TLS 1.3, dial-by-NodeID) |
| Threshold recovery | **Chela** SPEC v1.0.0 (+ extendable-split profile, companion doc) |
| Serialization | Deterministic CBOR (RFC 8949) |

Unknown suite ids MUST be rejected, never negotiated down.

---

## 3. Roles (per-friendship grants)

- **Owner device** — holds vault plaintext; the only decryption locus.
- **Storage peer** — a friend's node holding encrypted replicas; serves blobs,
  answers retention audits; never holds keys.
- **Recovery trustee** — a friend holding one Chela share; self-validates it,
  attests possession, participates in recovery.
- **Relay** — a friend's publicly-reachable node offering rendezvous (§6).

Each grant exists only inside a signed friendship (§9) and each is
individually offered, accepted, and revocable. One friend may hold all four
roles; the stores (`replicas/`, `chela-shares/`) remain separate.

---

## 4. Keys and identity

```
K_root   = CSPRNG(32)                      # the one long-term secret; 24-word mnemonic
K_vaultroot(vid) = HKDF(K_root, "carapace/v1/vault/" ‖ vid)
K_content(vid)   = HKDF(K_vaultroot(vid), "content")
K_manifest(vid)  = HKDF(K_vaultroot(vid), "manifest")
K_audit(vid)     = HKDF(K_vaultroot(vid), "por")
K_userid   = HKDF(K_root, "carapace/v1/user-identity")   # Ed25519 seed: USER key
K_disclose = HKDF(K_root, "carapace/v1/disclosure")      # X25519 seed: HPKE key (§7.4)
```

`K_root` MUST NOT leave owner devices except as Chela shares. **User key**
(from `K_userid`): permanent identity, recoverable via Chela; signs contact
cards, friendships, manifest authorship. **Node key**: the iroh endpoint key,
per device, NOT derived from `K_root` (lost devices are revoked without
touching identity); certified by a user-key **delegation**
`Ed25519(user_key, "carapace/v1/deleg" ‖ node_id ‖ not_after)`. NodeID = the
key peers dial. Peers MUST verify the delegation chain before treating a node
as acting for a user.

---

## 5. Content model (unchanged from v0.5)

**Chunking:** FastCDC, MIN 256 KiB / AVG 1 MiB / MAX 4 MiB, standard Gear hash
(normative for cross-client dedup).

**Encryption & addressing:**

```
pt_hash   = BLAKE3(P)
chunk_key = HKDF(K_content(vid), "chunk-key"  ‖ pt_hash)
nonce     = HKDF(K_content(vid), "chunk-nonce" ‖ pt_hash)[0:24]
C         = XChaCha20-Poly1305(chunk_key, nonce, P, aad = vid)
ChunkID   = BLAKE3-256(C)          # = the iroh blob hash
```

Ciphertext chunks are iroh blobs: storage peers get keyless integrity
verification (BLAKE3-verified streaming) and resumable transfer natively.
Convergent encryption is vault-scoped: intra-vault dedup, no cross-vault
correlation (`K_content` never shared across vaults). Peers MUST NOT retain a
blob whose hash mismatches its ChunkID.

---

## 6. Networking

- **Endpoint.** Every node runs an iroh endpoint (NodeID = its Ed25519 key);
  QUIC + TLS 1.3, dial-by-key; hole-punching with relay fallback.
- **Relays are friends' relays.** Zero third-party infrastructure: every node
  capable of inbound connections SHOULD run the embedded, self-electing relay
  (UPnP/NAT-PMP/PCP + IPv6 + **peer-dialback verification**; advertise on
  success, withdraw on loss). Your usable relay set = relays advertised by
  your friends. `relay_url`/`addrs` MAY be DNS names and SHOULD be for
  rotating residential IPs; each friend cluster SHOULD include ≥1 stable-named
  relay (group-owned DDNS domain the daemon keeps current, or a static-IP VPS
  running the same daemon). Clients MUST warn a user whose reachable relay
  set falls below 2 distinct networks.
- **Addresses are hints, not identities.** Stale = one failed dial; NodeIDs
  are permanent. A returning node tries every cached hint (all friends'
  relays, then direct addrs); reaching any one friend re-syncs the rest.
- **Pairwise sync replaces gossip.** There is no broadcast topic. On each
  connection between friends, the two nodes exchange and reconcile their
  latest signed documents (contact cards §9.1, announces §7.3, attestations
  §10.2) by version number — simple anti-entropy. Offline friends catch up on
  next contact. Documents flow only across friendship edges. **Rollback
  protection:** versions are monotonic per signer; a peer MUST reject any
  card/announce with version ≤ the highest already seen from that signer,
  and MUST NOT honor node delegations absent from the signer's newest card.
- **Friend-request tickets.** The one out-of-band moment: a compact string /
  QR (`carapace:<base32-CBOR>`) = `{user_pubkey, node hints, relays: [...],
  token, expires}`, sent over any channel the two people already trust.
  Acceptance is the mutual signing of a Friendship (§9.2); a ticket alone
  grants only the ability to ask. Existing friends whose hints all went stale
  re-bootstrap the same way ("rejoin ticket" — the human channel is the one
  rendezvous that cannot rotate).
- **Custom streams.** Carapace messages (§12) are length-prefixed
  deterministic-CBOR frames on ALPN `carapace/1` over iroh QUIC streams.
- **Not used:** iroh-gossip (nothing to broadcast), iroh-docs/willow (manifest
  is Carapace-defined; docs layer still in flux).

---

## 7. Vault data structures

### 7.1 Vault identity

`vid = BLAKE3-256(user_pubkey ‖ creation_nonce)`, `creation_nonce = CSPRNG(16)`.

### 7.2 Manifest

As v0.5: plaintext `Manifest` (entries: path, mode, mtime, size, ordered
`ChunkRef`s, `fileHash`, per-file version vector, tombstones) encrypted into a
`ManifestEnvelope` (XChaCha20-Poly1305 under `K_manifest(vid)`, aad =
`vid ‖ epoch`, node-signed), stored and moved **as an iroh blob**; its blob
hash is the manifest digest. Peers verify the signature + delegation, cannot
read the contents.

### 7.3 Announce

```
VaultAnnounce = { vid, epoch, replicas: [NodeID...], manifestDigest, sig, by }
```

Sent (pairwise, §6) to: all storage peers of the vault, all trustees of the
owner, and any friends the owner designates. Trustees receiving announces is
what lets a recovering user or heir locate the latest manifest and a live
replica without the owner.

### 7.4 FileGrant (selective disclosure)

Chunk keys derive one-way from `K_content(vid)` + plaintext hash, so an owner
can disclose exactly chosen files by handing out exactly those chunks' keys:

```
FileGrant = { grant_id, vid, epoch, audience: [user_pubkey...],
              sealed: [{to, ct: HPKE(enc_pubkey_to, CBOR(GrantBody))}...], sig, by }
GrantBody = { files: [{path, fileHash, size, chunks: [{id, key, nonce, len}...]}...] }
```

Audiences are explicit user lists (a "reveal to all my friends" is a client
convenience that names the current list at issuance). Delivery is direct to
each audience member. **Fetch authorization:** a storage peer MUST serve a
chunk blob only to (a) the owner's delegated devices, (b) replica-set members
for repair, (c) a requester presenting a valid owner-signed grant covering
that ChunkID **and authenticated (NodeID + delegation) as a member of that
grant's audience** — a leaked grant document alone authorizes nothing. **Normative notes:** grants are *snapshots by construction*
(edits ⇒ new plaintext ⇒ new chunk keys; a grant never extends to future
content) and *irrevocable for disclosed content* (recipients may hold copies;
"revoke" = "no future versions", and UX MUST NOT imply more).

---

## 8. Key recovery via Chela

Chela is the normative threshold layer; shares travel as the documented
`chela.share` JSON carrier (SPEC §6.2), parsed only by a conformant Chela
decoder (SPEC §7) — `words` authoritative, label fields advisory and
cross-checked. A `ShareGrant` wraps the share together with what a quorum
needs to act when the owner is gone: the **co-trustee roster** (pubkeys +
node hints) for this recovery set, the ceremony **recovery delay** chosen at
split time, and refs to the latest `VaultAnnounce`s — all refreshed on the
attestation cycle (§10.2). Trustees store grants at
`chela-shares/<user_pubkey>`. Owners MUST also print **paper cards**
(`chela-cli … --paper`), which recover from words alone, offline, no Carapace
software (SPEC §5) — and by hand via `MANUAL_RECOVERY.md` if every copy of
Chela vanished. Paper is the out-of-band backstop; the in-app path is the
**recovery ceremony** (§8.5).

### 8.1 Two-tier split lifecycle

**Extendable split (the routine tier).** The initial split of a secret uses
Chela's **extendable-split profile** (companion design doc): the CSPRNG-drawn
polynomial coefficients — unchanged from standard Chela, so below-threshold
shares keep their information-theoretic guarantee — are *returned* by
`chela-engine` as an in-memory split-state instead of discarded. **Sealing is
Carapace's job, with Carapace's crypto stack:** the daemon AEAD-encrypts the
state bytes under `HKDF(K_root, "carapace/v1/split-state")` (XChaCha20-
Poly1305, aad = `rsid ‖ M`) before persisting, and zeroizes plaintext
buffers. Chela is consumed as a pinned library dependency (crates.io or git
rev) and gains no dependencies of its own. The sealed state is tiny
(`body_len × (M−1)` bytes). Extension = unseal + `extend()` at a fresh x.
Later, the owner can:

- **Add a trustee:** issue one new share at a fresh CSPRNG-drawn unused
  `x ∈ 1..32` on the *same* polynomial (same `recovery_set_id`, same `M`).
  Existing shareholders are untouched — no re-delivery, no re-printing of
  paper cards. Extended shares are wire-identical to original shares;
  decoders need no changes.
- **Replace a lost share:** same operation. The lost share remains
  *valid-if-found* (nothing can revoke a Shamir share); it therefore stays in
  the issued-count (§8.3) and its loss is a standing exposure on this
  polynomial until a re-split.

**Re-split (the escalation tier).** A fresh split — new polynomial, new
`recovery_set_id` (Chela draws one per split, SPEC §4.2, so old and new
shares cannot be mixed) — is REQUIRED on suspected share compromise and to
change `M`, and RECOMMENDED periodically (2–3 years) and when replacements
accumulate: extension never refreshes exposure, so shares leaked years apart
on one polynomial still combine. After a re-split, old paper cards MUST be
destroyed (and are harmless if `M` of them can no longer be assembled).

### 8.2 What to split for whom (scoped splits)

Every split of `K_root` is an independent door to the whole identity —
overall collusion-resistance equals the weakest split's `M`. Therefore:
`K_root` is split **once**, to the inner circle. Additional or outer-circle
trustee sets receive **scoped splits** of `K_vaultroot(vid)` (32 bytes ⇒ also
a 24-word `kind 0x05` payload): a quorum there recovers *that vault only*,
never the identity, `K_disclose`, or other vaults.

### 8.3 Thresholds and the extension cap

Chela enforces `2 ≤ M ≤ N ≤ 32` and rejects `M = 1`. Additionally:

- **Initial issuance SHOULD be `N₀ ≥ M + 1`** (never `N₀ = M`: zero slack —
  one lost share ends recoverability during the window before it's noticed).
- **Soft cap: `N ≤ 3M − 1`**, where `N` counts **every share ever issued on
  the polynomial** — including lost and replaced ones, which remain
  combinable. Rationale: the cap guarantees a recovering coalition always
  needs **more than ⅓ of all outstanding shares** (`M / (3M−1) > ⅓`);
  beyond it, a fixed `M` gets cheap relative to circulating shares
  (M=2→cap 5, M=3→8, M=4→11, M=5→14).
- Clients MUST warn and require explicit override to extend past the cap, and
  MUST surface "re-split with a larger `M`" as the recommended alternative.
  Reaching the cap via replacements is itself a re-split signal.

### 8.4 Recovery (mechanics)

A recovering client collects `M` shares — via the ceremony (§8.5) and/or
transcribed paper cards — and calls Chela `recover` → mnemonic → `K_root`
(or a vault key, for scoped splits) → re-derive keys → fetch the latest
manifest + chunks from any replica in the latest announce (trustees hold
announces, §7.3), taking the **max epoch across all reachable trustees and
replicas** → decrypt. Chela's integrity tag + CRC guarantee recovery never
silently yields a wrong secret (SPEC §5). The restored user key re-signs
delegations for the new device; existing friendships and cards remain valid.

### 8.5 The recovery ceremony (normative)

The in-app path for total key loss (or inheritance). **No protocol can
cryptographically verify that a key-less claimant is the real owner** — the
requester holds nothing by definition — so the ceremony's job is to
structure human verification and make silent takeover loud and slow:

1. **Sponsor.** Only a trustee of the subject can open a ceremony
   (`RecoveryOpen { ceremony_id, subject_user_pubkey, claimant: {display,
   ceremony_enc_pubkey (fresh X25519 from the new device), new_node_id},
   reason, opened_at, sig, by }`). Strangers cannot; rate-limited per
   subject. For inheritance, the sponsoring trustee acts for the heir.
2. **Fan-out + alarm.** The sponsor relays the request to every co-trustee
   (roster carried in the `ShareGrant`, §8) — and to **every known device of
   the subject and their friends**: clients MUST surface it prominently
   ("Recovery of your account has been started — is this you?").
3. **Owner abort.** Any device holding the subject's user key MAY sign
   `CeremonyAbort { ceremony_id }` — authoritative and unforgeable by an
   impostor. Trustees seeing a valid abort MUST cancel permanently and flag
   the ceremony as an attempted takeover.
4. **Per-trustee verification.** Each trustee MUST verify the claimant
   out-of-band (video, in person) before approving in-app. Approval is a
   signed `CeremonyApprove`; rejection is reported to all parties.
5. **Delay, then release.** No share moves before `opened_at +
   recovery_delay` (default **72 h**, chosen at split time, recorded in
   every `ShareGrant`). After the delay AND ≥ `M` approvals, each approving
   trustee sends its share **HPKE-sealed to `ceremony_enc_pubkey`** — no
   trustee ever sees another's share.
6. **Recover + hygiene.** The new device recovers locally (§8.4). Afterwards
   a **re-split is RECOMMENDED** (shares just moved; trusteeship may be
   re-chosen). Full `K_root` rotation — which means re-encrypting everything
   derived from it — is REQUIRED only when *compromise* (not mere loss) is
   suspected.

Scoped (vault-key) splits run the identical ceremony against their own
recovery set. Paper cards bypass the ceremony entirely by design — they are
the offline backstop when no software or no quorum of daemons survives; card
holders should understand the same delay-and-verify discipline applies
socially.

---

## 9. Friendship (replaces membership)

### 9.1 Contact card

Each user maintains one self-signed, versioned document describing themselves:

```
ContactCard = {
  user_pubkey, display: text, enc_pubkey: bytes(32),      # X25519, from K_disclose
  nodes: [{node_id, delegation, addrs: [text], relay_url: text/null}, ...],
  offers: { storage_bytes: uint, relay: bool, trustee: bool },
  version: uint, sig,
}
```

Card updates (new device, new address, changed offer) are pushed to all
friends on next contact (§6 pairwise sync). The set of your friends' current
cards **is** your address book.

### 9.2 Friendship record

```
Friendship = {
  a: user_pubkey, b: user_pubkey, established: uint,
  sig_a, sig_b,                    # both USER keys over ("carapace/v1/friend" ‖ a ‖ b ‖ established)
}
```

Created by ticket exchange (§6) + mutual signature. A friendship enables
*offering* — it grants nothing by itself. Every concrete arrangement is a
separate explicit exchange between the two: `ReplicaInvite`/`ReplicaAccept`
(storage), `ShareGrant` acceptance (trusteeship), relay usage (implied by the
friend's advertised `relay_url`). **No two users can create any obligation or
data placement on a third**; this property replaces v0.8's admission votes.

### 9.3 Unfriending

Either side MAY terminate unilaterally (signed `FriendshipEnd`, effective
for the sender on send; carried to the other side on receipt or learned via
the sender's next card version). The flow:

1. **Deletion requests.** Each side's client sends `DeleteRequest`s for
   everything it placed on the other (replicas, shares, queued grants) and
   deletes everything it holds *of* the other. The ex-friend's client SHOULD
   comply and reply with signed `DeleteAck`s — which are **bookkeeping, not
   proof**: deletion is unprovable in any system that ever handed out bytes.
   Everything they held was ciphertext; shares are neutralized by step 3.
2. **Re-placement.** Replicas the ex-friend held are re-placed onto other
   accepting friends immediately (§10.1), independent of any ack.
3. **Trustee removal = re-split, never extension.** If the ex-friend was a
   trustee, their share cannot be revoked and extension cannot remove it —
   only a full re-split neutralizes it, and only *indirectly*: (a) generate
   the new split (new `recovery_set_id`) and deliver `ShareGrant`s to the
   chosen trustee set; (b) collect attestations until the new set is live
   (≥ `M` + slack); (c) then instruct remaining old-set trustees to destroy
   their old shares (`ShareDestroy` → signed `ShareDestroyAck`). The
   ex-friend's retained share is stranded **because the honest holders
   destroyed theirs** — the old set can no longer reach `M` anywhere. During
   (a)–(c) both sets briefly coexist: two doors, each still requiring its
   own full quorum; the client tracks and displays completion.
4. **The re-split prompt.** The client MUST prompt the user to re-split when
   an unfriended party was a trustee, and MUST show **live reachability of
   the remaining friends** (who is online now, who will get their new share
   / destroy-instruction queued) — so the user knows whether the re-split
   completes immediately or progressively as friends come online. Old paper
   cards held by remaining friends should be physically destroyed and
   replaced as each new card is delivered.
5. Outstanding FileGrants to the ex-friend remain disclosed-forever (§7.4).

---

## 10. Redundancy and resilience

### 10.1 Replicas — invariant `r` (default 3)

Per vault: `r` accepted storage peers hold the current manifest + all chunks.
Placement is consent-based both directions (owner selects; peer explicitly
accepts; local private policies and deny-lists on both sides). Offline ≠
failure: repair only after the grace window (default 24 h); on confirmed loss
(unfriended, unreachable past grace, failed audits) the owner re-replicates
to another accepting friend and re-announces. Reads succeed while ≥1 current
replica or owner device is reachable; beyond the loss budget data is
*unavailable, not lost*.

**Retention audit (PoR):** owner derives unpredictable chunk/offset samples
from `K_audit(vid)` + epoch and issues BLAKE3-verified iroh-blobs range
requests; a correct response is the retention proof. 3 consecutive failures ⇒
treated as lost. **Stated limitation:** this proves retrievability *through*
the audited peer, not exclusive storage — a peer could proxy audits to
another replica. Owners SHOULD randomize audit timing per replica, issue
occasional wide-coverage audits (large random subsets in one window), and
watch response-time distributions; residual friend-proxying is an
availability risk only, accepted by the trust model.

### 10.2 Shares — invariant "attested live shares ≥ M + slack"

- Trustee daemons MUST periodically self-validate their stored share with a
  Chela decoder (a single share is validatable alone — CRC over its words,
  SPEC §4.6) — catches bit-rot.
- Trustees answer signed challenges with `ShareAttestation`
  `{user_pubkey, recovery_set_id, card_number, epoch, sig, by}` — label
  fields only, never words.
- Owners MUST verify a fresh split round-trips (sample of `M`-subsets) before
  trusting it; MUST track attested-live count per set; on drift toward `M`:
  **extend** to replace lost shares (§8.1) and/or re-split; the issued-count
  cap (§8.3) applies.
- Paper cards are the backstop that never goes offline.

---

## 11. Live sync and conflicts (unchanged from v0.5)

New local change ⇒ new chunks + manifest (epoch+1) ⇒ push to replicas ⇒
announce; other owner devices fetch manifest then missing chunks.
Eventually-consistent. Per-file version vectors detect concurrency;
conflicting concurrent writes are BOTH kept (winner by `(mtime, deviceID)`
keeps the path; loser renamed `path.sync-conflict-<ts>-<dev>.<ext>`);
tombstones carry VVs (delete-vs-edit resolves as conflict, edit survives).
No CRDT/real-time merge.

---

## 12. Wire messages and defaults

| Channel | Messages |
|---|---|
| pairwise sync (on connect) | `ContactCard`, `VaultAnnounce`, `ShareAttestChallenge`/`ShareAttestation` |
| `carapace/1` streams | `Hello` (card versions + capabilities), `FriendRequest`/`FriendAccept`, `FriendshipEnd`, `DeleteRequest`/`DeleteAck`, `ManifestOffer`, `ReplicaInvite`/`ReplicaAccept`, `ShareGrant`, `ShareDestroy`/`ShareDestroyAck`, `FileGrant`, `AuditNotice`, `RecoveryOpen`/`CeremonyApprove`/`CeremonyAbort`/`CeremonyShare` |
| iroh-blobs | chunk blobs, `ManifestEnvelope` blobs, PoR verified range requests |

Byte-exact deterministic-CBOR schemas + per-message test vectors: Appendix B
(remaining work; Chela SPEC §8.3 discipline).

| Parameter | Default |
|---|---|
| Replicas `r` | 3 |
| Initial split | `M` per circle size; `N₀ ≥ M + 1` |
| Extension soft cap | `N ≤ 3M − 1` (ever-issued count; override ⇒ explicit warning) |
| Re-split triggers | suspected compromise (REQUIRED), change `M` (REQUIRED), periodic 2–3 y (RECOMMENDED), cap reached via replacements (RECOMMENDED) |
| Offline repair grace | 24 h |
| PoR cadence / fail count | 6 h / 3 |
| Share health | daily attestation + continuous local CRC |
| Relays | friends' self-electing embedded relays; ≥1 stable-named per cluster; warn < 2 distinct networks |

---

## 13. Conformance profiles

**Owner-capable** (any platform, incl. phones as thin owner devices): §§4–8,
§9, §11. **Storage peer:** §5 verification, §7 envelope handling without
keys, §10.1 serving + PoR. **Trustee:** §8 share handling, §10.2. **Relay:**
§6 self-election + forwarding. A homelab node typically implements all four.

Open items: shared multi-writer vaults (current model: personal vaults +
FileGrants; true shared vaults need multi-author manifests — deferred);
iroh-docs revisit post-1.0; erasure-coded cold tier trigger (Appendix A);
`K_root` at-rest policy.

---

## 14. Security considerations

- **Trustee collusion:** any `M` shares reconstruct at any time — no
  liveness condition exists in Shamir sharing. Inherent to social recovery;
  mitigated only by trustee choice, `M`, and the §8.3 cap.
- **Cumulative polynomial exposure:** extension never refreshes randomness;
  shares (including lost-then-found cards) leaked years apart combine.
  Re-split is the only reset. §8.1/§8.3 encode this.
- **Split-state:** CSPRNG coefficients returned by `chela-engine`, sealed by
  *Carapace* under `HKDF(K_root, …)` — never a separate password, never
  persisted unsealed, zeroized after use. A leaked sealed blob reveals
  nothing beyond AEAD security; an attacker with the owner device already
  has `K_root`, so the state adds nothing. Shares retain classic Shamir
  information-theoretic security below threshold (coefficients are standard
  CSPRNG draws, merely retained).
- **Weakest-split rule:** `K_root` split once (inner circle); scoped vault
  splits elsewhere (§8.2).
- **Disclosure is forever** for granted content (§7.4).
- **Metadata:** friends' relays and storage peers see sizes, timing,
  NodeIDs/IPs, who-talks-to-whom — all inside your chosen friend edges;
  nothing crosses a non-edge. Content and paths are always encrypted.
- **Deletion is unprovable** (§9.3): unfriended peers should delete, may not;
  they only ever held ciphertext.
- **Endpoint compromise** of an owner device is out of scope (plaintext and
  `K_root` live there).

---

## 15. Reference stack and build order (non-normative)

| Layer | Component | License |
|---|---|---|
| Threshold recovery | Chela (`chela-engine` as a pinned crates.io/git-rev dependency; `chela-wasm` for non-Rust embedders; `chela-cli` for paper) + extendable-split profile; Chela itself stays dependency-free — sealing crypto lives in Carapace | Apache-2.0/MIT |
| Networking + blobs | iroh, iroh-blobs (+ iroh-ffi: Swift/Kotlin/Python/Node) | Apache-2.0/MIT |
| Primitives | BLAKE3, XChaCha20-Poly1305, Ed25519, HKDF-SHA-256, HPKE, Argon2id, FastCDC, CBOR | permissive, all major languages |

Build order (each step demoable): (1) keys + chunking + manifest; two owner
devices syncing over iroh. (2) Chela split/recover incl. paper cards +
extendable-split profile in Chela itself. (3) friendship handshake + replica
placement to `r` + repair. (4) PoR + share-health + attestation. (5)
FileGrants + polish. The Rust daemon is the reference client; iroh-ffi
carries the same core to mobile/desktop UIs.

---

## Appendix A — Deferred: erasure-coded cold tier

Unchanged from v0.5: age-based demotion into encrypted archives,
Reed–Solomon `(k,n)` fragments across friends (e.g. (6,10) = 1.67× overhead,
4-loss tolerance), rebuild-on-access. Needs a new suite id + fragment
messages. Prior art: Tahoe-LAFS.

## Appendix B — Wire schemas (separate document)

The byte-exact encoding is specified in **`carapace-appendix-b-cbor.md`**
(normative): the restricted deterministic-CBOR profile, 4-byte-BE-length
framing on ALPN `carapace/1`, the `"carapace-sig-v1"` signing discipline
(sig over the re-encoded body with key 23 removed; verification MUST
re-encode, never splice), the full message-type registry (23 types) with
CDDL schemas for every message and document, and generated,
signature-verified test vectors from fixed Ed25519 test keys
(`cbor_vectors.py` is the vector source of truth).

---

*Draft v0.10 (v0.9 + adversarial-review fixes: §8.5 recovery ceremony,
§9.3 unfriend/re-split flow with old-share destroy sequence, audience-
authenticated grant fetches, monotonic-version rollback protection, PoR
proxy limitation stated — see `carapace-adversarial-review.md`). Chela
references verified against SPEC.md in workspace `SecretSplitKit/chela`
(v1.0.0-beta.1); extendable-split profile in `chela-extendable-splits.md`
(rev 3, engine-only). iroh (v1.0.0-rc, Apache-2.0/MIT, iroh-ffi:
Swift/Kotlin/Python/Node) verified 2026-07-12.*
