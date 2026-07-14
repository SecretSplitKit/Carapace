# Designing Carapace: a planning session with Claude

*A reconstruction of the working session (July 12–13, 2026) in which the
Carapace protocol went from a group-chat idea to an implementable spec.
AtHeartEngineer's messages appear verbatim as block quotes; Claude's responses are
condensed to their substance (the originals ran longer). The artifacts this
session produced are listed at the end. For a word-for-word record, use the
Claude app's conversation share feature — this document is optimized for
reading.*

---

## How it started

**AtHeartEngineer** pasted a group chat — Alex vibe-coding a docker-deployed intranet
("our own cloud"), talk of YouTube auto-rip, fail2ban, GPU tuning — ending
with his own proposal:

> What do you think of basically doing this like a raid? where each of us
> gets an even amount of storage (let's say 10g for arguments sake) and our
> data is replicated to some other set of peers... We could even add the
> master password library that I published (Chela) for the encryption key.
> If you pictured this like Dropbox... the password is split using chela
> between the other members of the network, so if anything happened to you,
> they could get together and decrypt your stuff

**Claude** fetched the Chela repo, then pushed back on four things: (1) the
design conflates *encrypting so peers can't read* with *splitting so peers
can recover* — "any M peers can collude to decrypt your stuff at any time,
whether or not anything happened to you; Shamir shares don't know if you're
alive." Proposed separating storage peers from recovery trustees. (2)
Mirroring is the expensive redundancy primitive; erasure coding gets the
same durability at ~1.6× instead of 3–5×. (3) "It's backup, not Dropbox" —
consumer peers are offline half the time. (4) The killers of P2P storage
projects: free-riding/silent data loss (needs proof-of-retrievability
audits) and repair under churn. Plus crypto footguns: AES-GCM nonce reuse,
use XChaCha20-Poly1305, don't roll the backup layer (restic/borg), study
Tahoe-LAFS.

**AtHeartEngineer:**

> Yes, exactly, we can have two separate roles; but most of the time you
> would want to only backup your data with your friends anyway. Like I
> understand we should keep these roles separately, but practically, at
> least in my friend group, they would be the same thing.

**Claude** conceded the humans are the same, and reframed: **"Separate the
grants, not the humans."** The threshold protecting your key (M) must stay
an independent knob from the number convenient for storage — same five
friends, different math. This became the load-bearing principle of the
whole design.

## Becoming a spec

**AtHeartEngineer** (connecting the SecretSplitKit workspace folder):

> Can you turn this into a spec (make sure we use the actual Chela code in
> it, I spent a lot of time on that)

**Claude** read Chela's SPEC.md, README, and Cargo workspace, then wrote
**Carapace v0.1**: five layers (restic backup → Reed–Solomon → placement/
repair → PoR audits → membership), with Chela used unmodified — the
256-bit root secret rendered as a 24-word mnemonic *because that is exactly
Chela's `kind 0x05`, the no-length-ambiguity path*, `chela-cli --paper`
cards as the inheritance backstop.

**AtHeartEngineer** answered the open questions in one message:

> 1. This should be live sync like dropbox yes
> 2. yep agreed
> 3. Sounds good
> 4. yep
> 5. 5-20 people I'd say.
>
> We should be able to handle nodes going offline, losing data/secret
> splits, etc pretty well too.

**Claude** flagged the hard tension — *erasure coding and live sync pull in
opposite directions* — and resolved it with hot/cold tiering (v0.2:
replicated hot working set, erasure-coded cold archive, Syncthing's
encrypted-untrusted-device mode for live sync).

Mid-rewrite, **AtHeartEngineer:**

> Also, the working title is great, lets stick with it.
>
> I think we should stick with the "hot tier" all together, for simplicity

**Claude** named the cost being accepted (3× storage for everything — "the
store 30 GB to protect 10 GB cost from the original RAID discussion"),
called it the right trade for homelab disk, kept erasure as a deferred
appendix, and shipped v0.3.

## The license fork and the spec pivot

**AtHeartEngineer:**

> Is syncthings clients open source too? I only want to use their stuff if
> its MIT/Apache

**Claude** checked: Syncthing is MPL-2.0 — out. Then, mid-check, **AtHeartEngineer**
raised the stakes:

> I also think our goal should be to write a *spec* of this protocol so
> anyone else can make their own custom client if they want, like for
> android, windows, mac, iphone, whatever. Anyone should be able to easily
> build a compatible client/peer.

**Claude** rewrote the document as an actual protocol specification (v0.4):
RFC-2119 conformance language, pinned crypto suite (XChaCha20-Poly1305,
BLAKE3, Ed25519, HKDF, FastCDC, deterministic CBOR), libraries demoted to
reference implementations.

**AtHeartEngineer:**

> Oh, hmmm, tell me about iroh more and how it would fit here, and if it
> works on multiple OSs

**Claude** laid out iroh (dial-by-public-key QUIC, NAT traversal, relay
fallback, Apache-2.0/MIT, Swift/Kotlin/Python/Node bindings) and two
options: iroh as optional transport (purist spec) vs iroh as substrate
(ship faster, everyone embeds the Rust core via FFI).

**AtHeartEngineer:**

> Option 2, iroh sounds awesome and is exactly what we need

**Claude** shipped v0.5, noting the happy accident: the spec had already
defined ChunkID = BLAKE3(ciphertext), and iroh-blobs addresses blobs by
BLAKE3 — so encrypted chunks simply *are* iroh blobs, and retention audits
collapse into verified range-requests. Deliberately excluded iroh-docs
(still in flux) for the manifest.

## Owning the infrastructure

**AtHeartEngineer**, probing the network model across several messages:

> So using Iroh, it wouldn't be a network of my friends right, it would be
> a global network, where I only actually communicate with my friends

> like, how do they do the mesh/peer network, there has to be a rendevous
> server somewhere right? or we write that?

> I would prefer no 3rd party infrastructure, could we each host a relay
> server by default? That way no one is fully responsible for that role and
> we have fallbacks

> Whats the easiest way for people that dont know that much to have the
> relay just magically work, and whats the best magic way to share the
> relays between each other

> We basically need to send our friends: here is my public key, here is my
> relay address.
>
> But that relay address can't be a residential IP address because those
> rotate.

**Claude**, across v0.6–v0.7: iroh is a connection library, not a global
DHT — "a phone system with cryptographic phone numbers." The relay *is* the
rendezvous server; you run one, you don't write one. Every capable node
runs an embedded, **self-electing** relay (UPnP/NAT-PMP + IPv6 + verify by
peer dialback), advertised through the roster, which doubles as the address
book. Invite tickets (QR/string over the group chat) cover the one cold-
start moment. Addresses are *hints, not identities* — the permanent thing is
the public key; one stable DNS name (a $10/yr domain the daemon keeps
updated, or a $5 VPS) makes total staleness impossible, and the group chat
is "the one rendezvous that cannot rotate."

## Governance — and then the better idea

**AtHeartEngineer:**

> Dope ok, ya that is great, I like that plan. Now, we need a way to "vote
> in" people. Because right now anyone can invite anyone to the collective
> and effectively sign me up for saving other peoples data when I may be
> limited on storage space; also I may not want them even having my
> encrypted data.
>
> Someone should be able to join more than 1 friend group also, and be able
> to share the same data, with different chela splits. I should also be
> able to reveal files to the group, or to specific individuals.

**Claude** built v0.8: quorum-voted roster changes, consent-based placement
(admission grants zero storage rights), multi-group with *scoped* Chela
splits (K_root only in the home group — "your key is only as collusion-
resistant as your weakest group's M"), and FileGrants — the per-chunk key
derivation meant files could be revealed by handing out exactly those
chunks' keys, no re-encryption, with grants being snapshots by construction.

Then **AtHeartEngineer** replaced the premise:

> Or, what about instead of thinking of this like a group all shares
> between each other and splits between each other, we should think of this
> as each user has friends they add and share with in a reciprocal form,
> and when we generate the secret split, we should do it with the minimum
> number of people in order to reconstruct, and *save* the polynomial
> coefficients, that way if we want to add more friends to the same
> polynomial for the secret split we can (up to some sane limit).
>
> What do you think about that?

**Claude** adopted the friend-graph immediately — "it also deletes the
voting machinery I just built, which is a point in its favor" — everything
becomes bilateral, nothing transitive, no two users can obligate a third.
On saving the polynomial: cryptographically sound, killer benefit (new
friend gets card N+1; nobody re-prints), two real costs stated plainly —
**M is frozen forever**, and **exposure is cumulative** (shares stolen years
apart still combine; a lost-then-found card is live until a full re-split).
Verdict: extension as the routine tier, re-split as the escalation.

**AtHeartEngineer:**

> ok, yeah lets do that, sounds good. We should set soft caps (that can be
> overridden, but not without a warning) at how much of a difference there
> is between m and n. 3 of 7 is fine, 3 of 9 starts to get worrying, 3 of
> 15 is clearly scaring. I think 3 of 8 is probably the limit, or 4 of 11.
> Lets go with triple minus 1 as the formula

**Claude** encoded N ≤ 3M−1 with the rationale (a recovering coalition
always needs >⅓ of outstanding shares) and one sharpening: the cap counts
shares *ever issued*, including lost and replaced ones. Shipped v0.9 plus a
Chela companion doc.

## AtHeartEngineer catches the over-engineering

The first Chela design derived coefficients from a PRF over the secret plus
a salt, so the saved state would be "secret-free."

**AtHeartEngineer:**

> What is the benefits of doing the extension instead of the coefficients,
> is it much smaller? to me it sounds like unnecessary complication

**Claude** conceded — and found, under pressure, that the clever design was
actually *broken* for a case Chela explicitly supports: for low-entropy
passwords, salt + one share enables a dictionary attack, destroying classic
Shamir's entropy-independent security. Rev 2: keep CSPRNG coefficients,
seal them with AEAD.

**AtHeartEngineer:**

> Why wouldn't we just store the coefficients with the same password that
> we use for the data encryption, theres no reason to have *another*
> password

Agreed — the sealing key derives from the secret you must already hold to
extend; zero new credentials anywhere.

**AtHeartEngineer:**

> Why can't we make another "build" of chela that also produces a library
> that can be imported into Carapace, or we can publish chela to crates.io
> and then use chela as a dependency in Carapace; then we can import
> Argon2id + XChaCha20-Poly1305 into Caparace and Chela stays pristine

> Ya thats fine, we can make the change only to the chela-engine and not
> touch the CLI or TUI or anything

**Claude:** exactly right — math in Chela (zero new dependencies, the
no-deps auditability claim survives), sealing in the embedder. Final scope:
`chela-engine` gains `SplitState`/`split_extendable`/`extend`; every
user-facing artifact stays byte-identical. The rejected designs stayed in
the doc with the attacks written out.

## Hardening and finishing

**AtHeartEngineer:**

> Deterministic cbor sounds good, we should flesh that out after we do the
> adversarial review.
>
> For "heir with paper cards" - chelas paper card usage, and this file
> backup/syncing usage are completely separate. Someone doing the file
> backup *could* do recovery the same way as the paper card usage, but we
> should really just make it part of the Carapace app, where the friends
> that want to do recovery can start a "recovery ceremony" through the app.
>
> Unfriending someone should ask the other persons client to delete the
> shares and data, and the user should be prompted to resplit if they want
> (and they should be shown if their client can talk to their other friends
> so they know if they can do the resplit live or not).

**Claude** ran an 18-attack adversarial review. Four real holes found and
fixed: leaked FileGrants would have authorized anyone (now audience-
authenticated); contact-card rollback could resurrect revoked devices (now
monotonic-version rejection); extension-as-trustee-removal is a trap
(extension can't remove a share — removal requires re-split, and even that
works only because remaining honest trustees destroy their old shares); and
PoR proxying (a "replica" passing audits by fetching from another replica).
The ceremony went in with the honest floor stated: *no protocol can verify
a key-less claimant is the real owner* — hence sponsor-gating, out-of-band
verification, a 72-hour delay, a recovery alarm to every device, and an
unforgeable owner-abort. v0.10.

**AtHeartEngineer:**

> Ok, yeah lets work on the CBOR

Appendix B: a restricted deterministic-CBOR profile, framing, signing
discipline, CDDL for all 23 message types + 4 documents — with every test
vector *generated and machine-verified* by a reference script rather than
hand-written.

**AtHeartEngineer**, mid-build:

> Does Iroh use ed25519 by default?

Yes — confirmed against iroh's docs (EndpointID is the public half of an
Ed25519 keypair), so the entire stack runs on one signature primitive.

**AtHeartEngineer:**

> Cool, I liked ed25519

> lets do the other 16 message vectors

The completion audit caught exactly one error in the whole set: two bytes
dropped in a vector Claude had transcribed *by hand* — the failure mode the
generator exists to prevent. The ShareGrant vector embeds Chela SPEC §8.3's
own worked example share, tying the two specs' test suites together.

**AtHeartEngineer:**

> Are all these saved into the SecretSplitKit folder? We should make a
> Carapace folder in there and add those files

All artifacts committed to `SecretSplitKit/Carapace/` on AtHeartEngineer's machine.

---

## The decision ledger (v0.1 → v0.10)

| # | Decision | Driven by |
|---|---|---|
| 1 | Separate grants (storage vs trustee), not people | Claude's push; AtHeartEngineer's "same friends" reality |
| 2 | Live sync, not backup-only | AtHeartEngineer |
| 3 | Replication only; erasure deferred to appendix | AtHeartEngineer ("simplicity"), cost stated by Claude |
| 4 | MIT/Apache only → Syncthing out, iroh in | AtHeartEngineer's license bar |
| 5 | Write a *protocol spec*, not an app design | AtHeartEngineer |
| 6 | iroh as substrate (Option 2) | AtHeartEngineer, after Claude laid out the trade |
| 7 | Zero third-party infrastructure; member-hosted self-electing relays | AtHeartEngineer |
| 8 | Addresses are hints; one stable DNS name per cluster | AtHeartEngineer's rotating-IP observation |
| 9 | Friend graph replaces groups (and deletes voting) | AtHeartEngineer's reframe |
| 10 | Extendable splits + re-split escalation; cap N ≤ 3M−1 | AtHeartEngineer's idea + formula; Claude's exposure analysis |
| 11 | Sealed CSPRNG coefficients, no PRF derivation, no second password | AtHeartEngineer's simplicity challenge (which exposed a real attack) |
| 12 | Chela stays pristine; engine-only change; sealing lives in Carapace | AtHeartEngineer |
| 13 | In-app recovery ceremony; deletion-request unfriending | AtHeartEngineer's design, Claude's threat-model framing |
| 14 | Everything Ed25519/Curve25519; deterministic CBOR with generated vectors | joint |

## Artifacts produced (in `SecretSplitKit/Carapace/`)

- **carapace-protocol.md** — the protocol spec, v0.10
- **carapace-appendix-b-cbor.md** — wire encoding, 23 message types + 4
  documents, 27 verified test vectors
- **cbor_vectors.py** — reference encoder + vector generator (source of truth)
- **carapace-adversarial-review.md** — 18 attacks: blocked / fixed / accepted
- **chela-extendable-splits.md** — the scoped `chela-engine` feature design
  (rev 3, with two rejected designs documented)
