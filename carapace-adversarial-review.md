# Carapace v0.9 — Adversarial Review

*Method: enumerate attacker goals per subsystem, attempt each attack against
the spec as written, classify the outcome. Verdicts: **BLOCKED** (design
stops it), **FIXED→v0.10** (hole found, spec change made), **ACCEPTED**
(residual risk, stated in the spec, out of scope by trust model).*

---

## A. Key recovery / ceremony

### A1. Impersonation recovery ("I'm Tyler, I lost everything")
Attacker asks trustees for shares while posing as a key-less friend.
**The fundamental attack on all social recovery** — no protocol can
cryptographically distinguish "real owner, lost keys" from an impostor,
because the claimant by definition holds nothing.
**Verdict: FIXED→v0.10 (ceremony design).** Mitigation stack: (1) ceremony
must be *sponsored* by a trustee; (2) each approving trustee MUST verify the
claimant out-of-band (video/in-person — app enforces explicit per-trustee
approval, provides a verification checklist); (3) **mandatory delay window**
(default 72 h, set at split time) before any share transmits; (4) **recovery
alarm**: the request is pushed to every known device of the subject and all
their friends; (5) any surviving owner device holds the user key and can sign
an authoritative `CeremonyAbort` — an impostor cannot forge it; an abort also
flags the ceremony as a takeover attempt. Residual: an attacker who fools `M`
humans out-of-band *and* the subject cannot abort for the whole window —
that is the trust model's floor, not a protocol gap.

### A2. Fake-death recovery against a living owner
Special case of A1 where the owner is alive but inattentive.
**Verdict: BLOCKED** (by the same delay + alarm: owner devices dial friends
routinely for sync/attestation, so a live device learns of the ceremony well
inside 72 h and aborts).

### A3. Trustee collusion (M shares assembled without any ceremony)
**Verdict: ACCEPTED** — inherent to Shamir sharing (no liveness condition
exists); mitigated only by trustee choice, `M`, the `3M−1` cap, and scoped
splits (vault-key-only for outer circles). Already stated in §14.

### A4. Share sniffing during ceremony
**Verdict: BLOCKED.** Shares transit HPKE-sealed to a fresh X25519 ceremony
key generated on the recovering device; no trustee sees another trustee's
share; transport is additionally QUIC/TLS.

### A5. Stale-state rollback against a recovering user
Colluding replicas + trustees present an old epoch to the heir.
**Verdict: ACCEPTED (narrow).** Recovering client takes the max epoch across
all reachable trustees' stored announces and all replicas; only a *complete*
eclipse (every consulted party colluding) can roll back — below-threshold
subsets cannot forge announces (owner-signed).

### A6. Ceremony spam / harassment
**Verdict: FIXED→v0.10.** Ceremonies are trustee-sponsored (a stranger
cannot open one), rate-limited per subject, and every rejection is reported
to the subject's devices and trustees.

## B. Split lifecycle

### B1. "Replacing" an unfriended trustee by extension
Extension adds shares; it cannot remove the ex-friend's share from the old
polynomial — treating extension as removal leaves a live share outstanding.
**Verdict: FIXED→v0.10.** §9.3/§8.1 now state: trustee *removal* REQUIRES
re-split; extension is only for adding trustees or replacing *lost* shares.
The unfriend flow never offers extension as the remedy.

### B2. Re-split doesn't invalidate old shares
Subtle and easy to get wrong: a new polynomial does not revoke the old one —
`M` old shares still reconstruct `K_root`.
**Verdict: FIXED→v0.10.** The re-split flow now has an explicit completion
sequence: (1) deliver + attest new shares to the new trustee set; (2) then
instruct remaining old-share holders to destroy old shares (signed
`ShareDestroyAck`); the ex-friend's retained share is stranded *because*
honest holders destroy theirs, dropping the old set permanently below `M`.
Both sets briefly coexist (two doors, each still needing its own quorum;
transient, monitored). Ex-friend collusion with `M−1` dishonest retainers is
A3 again — accepted.

### B3. Split-state theft
**Verdict: BLOCKED / ACCEPTED.** Sealed under `HKDF(K_root)`-derived AEAD;
thief without `K_root` gets nothing; thief with the owner device has `K_root`
already. (The PRF-salt design that would have leaked against low-entropy
payloads was rejected in the Chela companion doc rev 3.)

### B4. Wrong-secret extension producing incompatible shares
**Verdict: BLOCKED.** AEAD unseal fails first; `chela-engine::extend`
additionally cross-checks body against constant terms; post-extend subset
round-trip verification is mandatory.

## C. Friendship & membership

### C1. Contact-card rollback (feeding a peer an old card)
Old cards contain stale addresses/offers — could redirect placement to a
since-revoked device.
**Verdict: FIXED→v0.10.** Explicit rule: cards and announces carry monotonic
versions; peers MUST reject any version ≤ the highest seen (per signer) and
MUST NOT act on delegations absent from the newest card.

### C2. Unfriend-message suppression (ex-friend pretends not to receive)
**Verdict: ACCEPTED (bounded).** `FriendshipEnd` is effective for the sender
on send; the owner's repair loop re-places replicas regardless of ack, and
other friends learn via the owner's next card version (which drops the
ex-friend from trustee/replica hints). The ex-friend keeps only what they
already had: ciphertext and one stranded-after-B2 share.

### C3. Deletion theater (acking deletion, keeping data)
**Verdict: ACCEPTED — stated.** Deletion is unprovable in any system that
ever handed out bytes. Everything held is ciphertext; shares are stranded by
B2's destroy sequence. `DeleteAck` is bookkeeping, not proof, and the spec
says so.

### C4. Two users obligating a third
**Verdict: BLOCKED** (structural, the v0.9 redesign's point): no shared
membership object exists; every grant is a bilateral signed exchange.

## D. Storage & audit

### D1. PoR proxy attack (replica answers audits by fetching from another replica)
A "replica" stores nothing and proxies range requests to a peer that does —
audits pass, de-facto `r` silently drops.
**Verdict: FIXED→v0.10 (partial) + ACCEPTED (residual).** Spec now notes the
limitation honestly (PoR proves retrievability-*through*-the-peer, not
exclusive storage) and adds cheap frictions: owners SHOULD randomize audit
timing per replica, occasionally issue wide-coverage audits (large random
subset in one window — expensive to proxy live), and compare response-time
distributions. Residual proxying among *friends* is a social failure with an
availability cost only, tolerated by the trust model.

### D2. Selective serving (replica serves the owner, stonewalls the heir)
**Verdict: BLOCKED-ish.** Any single honest current replica suffices for
recovery (`r = 3`, plus owner devices); a stonewalling replica is
indistinguishable from an offline one and gets repaired around.

### D3. FileGrant replay by a non-audience member
Spec said "presenting a valid owner-signed grant" — but a grant could leak
and be presented by anyone.
**Verdict: FIXED→v0.10.** Fetch authorization now requires the connection to
be *authenticated (NodeID + delegation) as a member of the grant's audience*,
in addition to the grant covering the ChunkID.

### D4. Chunk-size fingerprinting
FastCDC boundaries + blob sizes leak file-structure metadata to storage
peers.
**Verdict: ACCEPTED — stated** (§14 metadata bullet; padding is future work).

### D5. Malicious blob injection
**Verdict: BLOCKED.** ChunkID = BLAKE3(ciphertext) verified by iroh-blobs on
transfer and storable-side; manifests are owner-signed; AEAD authenticates
plaintext under vault keys.

## E. Networking

### E1. Relay abuse (a friend's relay reads/correlates traffic)
**Verdict: ACCEPTED — stated.** Relays see ciphertext QUIC + who-talks-to-
whom, inside the chosen friend edge set. That is the design's privacy floor
and its selling point versus third-party relays.

### E2. Ticket theft (invite/rejoin ticket intercepted)
**Verdict: BLOCKED (bounded).** Tickets are single-use, short-lived, and
grant only reach + the ability to *ask*; friendship requires the mutual
signature, and a thief cannot produce the expected human on the out-of-band
channel the ticket traveled through.

### E3. Total relay loss
**Verdict: ACCEPTED (bounded).** New introductions between double-NAT nodes
stall until any relay returns; existing connections and LAN discovery
survive; ≥2-relay warning + stable-named relay guidance bound the window.

---

## Summary of spec changes carried into v0.10

1. **§8.5 Recovery ceremony** (new): sponsor-gated, OOB-verified, delayed,
   alarmed, owner-abortable; HPKE-sealed share delivery; post-recovery
   hygiene (re-split RECOMMENDED after any ceremony; `K_root` rotation —
   i.e. full re-encryption — REQUIRED only if compromise, not loss, is
   suspected).
2. **§9.3 Unfriending** rewritten: delete requests + non-probative acks;
   re-split prompt with live per-friend connectivity display; extension
   explicitly invalid for trustee removal; old-share destroy sequence (B2).
3. **§7.4** fetch authorization requires audience authentication (D3).
4. **§6** monotonic-version rejection rule for cards/announces (C1).
5. **§10.1** PoR proxy limitation stated + audit-diversity guidance (D1).
6. **§8/§10.2** `ShareGrant` enriched: co-trustee roster + recovery delay +
   latest announce refs (so a quorum can run a ceremony with the owner gone);
   refreshed on the attestation cycle.
7. **§12** message set: ceremony + deletion messages.
