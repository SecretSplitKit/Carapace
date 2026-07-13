# Chela: Extendable Splits — Design Sketch (rev 3)

*Proposed feature for `SecretSplitKit/Chela`. Written against SPEC.md
v1.0.0-beta.1. Status: design for discussion, not implemented.*

*Rev history: rev 1 derived coefficients by PRF (rejected, §7). Rev 2 sealed
coefficients inside Chela with Argon2id+XChaCha (rejected: forces
dependencies or hand-rolled KDF crypto into a deliberately dependency-free
repo). Rev 3 splits responsibility: **Chela does the math, the embedder does
the sealing.** Chela stays pristine — zero new dependencies.*

## 1. Motivation

Today a split draws its polynomial coefficients from the CSPRNG and discards
them (SPEC §3.2). Adding a shareholder later therefore requires a full
re-split: new polynomial, new `recovery_set_id`, and — the real cost —
**re-delivering fresh cards to every existing holder**. For paper cards in
safes, that is the dominant operational burden.

An **extendable split** retains the polynomial state so the splitter can
later issue *additional* shares on the *same* polynomial (same
`recovery_set_id`, same `M`): a new shareholder gets card `N+1` while every
existing card stays where it is; a holder who lost a card gets a replacement
at a fresh `x`, touching nobody else.

Extended shares are **wire-identical** to original shares. Share format,
recovery algorithm, and all decoder conformance rules (SPEC §5, §7) are
unchanged — a decoder cannot tell, and never needs to tell, when a share was
issued.

## 2. Design principle: math in Chela, sealing in the embedder

The coefficients are drawn from the CSPRNG **exactly as today** — shares
keep their information-theoretic below-threshold guarantee (SPEC §3.1),
unconditionally, with no mode split in the security claim.

What changes: `chela-engine` (the library crate — already published/badged
for crates.io) *returns* the polynomial state to the caller instead of
discarding it, and accepts it back to issue further shares. **Chela never
persists, encrypts, or sees a state file.** How the state is stored is the
embedding application's responsibility, with the embedder's crypto stack —
the same line SPEC §10 already draws for zeroization and display discipline:
implementation concern, not wire format.

Consequences:

- **Zero new dependencies in the Chela workspace.** No Argon2id, no AEAD, no
  serialization format decisions. The repo's "everything from scratch, every
  line checkable" property is untouched.
- The embedder brings sealing it already has. Carapace seals under
  `HKDF(K_root, "carapace/v1/split-state")` → XChaCha20-Poly1305 (both
  already in its normative suite; no password KDF needed — `K_root` is
  256-bit).
- Standalone `chela-cli` does **not** grow an `extend` subcommand in the
  core repo (it would need sealing crypto). Paper-first users re-split, as
  today; if demand exists, a thin companion crate (`chela-extend`, outside
  the pristine workspace) can wrap `chela-engine` plus vetted RustCrypto
  sealing for a file-based workflow.

## 3. API sketch (`chela-engine`)

```rust
/// Secret-equivalent: the coefficient matrix pins the polynomial, and the
/// constant terms ARE the body bytes. Wipes on drop (same hand-rolled
/// discipline as chela-tui's SecretString). Deliberately NOT Serialize:
/// persisting it is the caller's act, via explicit `to_bytes()`.
pub struct SplitState {
    recovery_set_id: u16,      // 11-bit rsid (word 1)
    threshold: u8,             // M
    issued_x: Vec<u8>,         // every x ever issued, 1..=32, no duplicates
    coeffs: CoeffMatrix,       // body_len × (M−1) bytes, zeroized on drop
}

impl SplitState {
    /// Serialize for sealing. Caller MUST encrypt before persisting.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>>;
    pub fn from_bytes(b: &[u8]) -> Result<Self, StateError>;
    pub fn issued_count(&self) -> usize;
}

/// As `split`, but also returns the retained polynomial state.
pub fn split_extendable(secret: &Secret, m: u8, n: u8)
    -> Result<(Vec<Share>, SplitState), SplitError>;

/// Issue `count` new shares on the same polynomial, at fresh CSPRNG-drawn
/// x coordinates from 1..=32 \ issued_x (rejection-sampled; error when
/// exhausted). Verifies the supplied secret matches the state's polynomial
/// (recompute body; check constant terms) before issuing.
pub fn extend(state: &mut SplitState, secret: &Secret, count: u8)
    -> Result<Vec<Share>, ExtendError>;
```

Notes:

- `extend` takes the **secret** as well as the state: it recomputes `body`
  (SPEC §4.3) and checks it against the constant terms, so a
  wrong-secret/wrong-state pairing is a clean error, never incompatible
  shares. (The embedder's AEAD will usually catch this first; the engine
  check is defense in depth and serves unsealed in-memory callers.)
- New shares are produced by the *existing* encoding path (word 0 layout,
  rsid in word 1, CRC-11) — byte-for-byte what split time would have
  emitted for that `x`.
- The soft cap lives in the engine: `extend` returns a distinguishable
  `Warning`/requires an `allow_over_cap` flag once
  `issued_count() > 3·M − 1` (see §5), and hard-errors at 32.
- `to_bytes`/`from_bytes` define a stable little byte layout (versioned) so
  sealed blobs survive Chela upgrades; the *container* around it (nonce,
  AAD, ciphertext framing) is embedder-defined and out of scope.
- Non-Rust embedders would reach this via `chela-wasm` exports — deferred
  until needed (§9); Carapace links `chela-engine` directly.

## 4. Embedder contract (normative for embedders, one paragraph)

> `SplitState` bytes are secret-equivalent (state + nothing else ⇒ the
> secret, from the constant terms). An embedder MUST encrypt them with an
> AEAD under a key at least as protected as the secret itself before any
> persistence, MUST bind `rsid ‖ M` as associated data, and MUST zeroize
> plaintext buffers after sealing/use. Losing the sealed state loses only
> the ability to extend — recovery from existing shares and full re-split
> are unaffected.

Reference sealings: **Carapace** — `HKDF(K_root, "carapace/v1/split-state")`
→ XChaCha20-Poly1305, stored beside the daemon's other state.
**File-based companion tool** (if built) — Argon2id over the re-entered
secret → XChaCha20-Poly1305; no new password, ever.

## 5. Issuance cap

`x ∈ 1..=32` hard-caps lifetime issuance at 32 (SPEC §3.3). The engine
additionally enforces a **soft cap `N_issued ≤ 3M − 1`** — warn / require
explicit override beyond — where `N_issued = len(issued_x)`: **every share
ever issued, including lost and replaced ones.** A lost card, if found,
still combines; replacement revokes nothing. The cap keeps any recovering
coalition above ⅓ of outstanding shares (`M/(3M−1) > ⅓`): M=2→5, M=3→8,
M=4→11, M=5→14. Override messaging SHOULD name the correct response to cap
pressure: a fresh split with a larger `M`.

## 6. Security notes

- **Shares are classic Shamir, full stop.** Same CSPRNG coefficients,
  merely returned instead of discarded; SPEC §3.1's information-theoretic
  claim needs no qualification.
- **No proactive refresh.** Extension never re-randomizes: shares leaked
  years apart combine; a lost-then-found card is live forever on this
  polynomial. Suspected compromise ⇒ full re-split (new rsid) + destroy old
  cards. Extension is the routine tier; re-split remains the escalation.
- **Replacement ≠ revocation** (repeat in user-facing docs).
- **Zeroization:** retaining coefficients means secret-equivalent material
  lives longer in memory. `SplitState` wipes on drop; `to_bytes` returns a
  self-zeroizing buffer; the existing `panic = unwind` choice (Drop runs on
  panic) already covers the unwind path.

## 7. Rejected alternatives

**PRF-derived coefficients** (rev 1): state = a public salt; coefficients =
`PRF(HKDF(body, salt), i‖j)`. Rejected: (1) breaks the headline guarantee
for low-entropy payloads — Chela splits "any short password," and classic
Shamir protects even weak passwords perfectly below threshold, but under
PRF derivation an attacker with salt + **one** share can dictionary-attack
(guess password → derive coefficients → predict the share at that x →
compare); (2) downgrades SPEC §3.1 to computational security in all cases;
(3) buys nothing — state shrinks ~100→32 bytes, UX identical.

**In-Chela sealing** (rev 2): Argon2id + XChaCha inside the repo. Rejected:
forces either external dependencies (breaking the no-deps auditability
claim — Cargo.lock is ~1 KB today) or hand-rolling a memory-hard KDF, the
one primitive in this design genuinely risky to reimplement. Sealing is
storage policy, not wire format; SPEC §10 already places that outside
Chela's scope.

## 8. SPEC.md amendment sketch

Add as §7-bis "Extendable splits (optional profile)":

> An encoder MAY support an *extendable* split mode. In this mode the
> polynomial coefficients are drawn from the CSPRNG exactly as in §3.2 and
> retained by the calling application as *split-state*, together with the
> set of all `x` coordinates ever issued. Extension issues further shares
> on the same polynomial at fresh CSPRNG-drawn `x` coordinates, drawn
> without replacement across the lifetime of the split; such shares MUST be
> byte-identical to those the same polynomial would have produced at split
> time. Decoder behavior is unchanged; decoders cannot distinguish the
> modes. Split-state is secret-equivalent: implementations MUST NOT persist
> it unencrypted — sealing is the embedding application's responsibility
> (see § 10). An encoder SHOULD warn when lifetime issuance exceeds
> `3M − 1` and MUST fail beyond 32.

Plus: test vectors (fixed body + fixed coefficient matrix → known shares at
known x's, including one issued "later"), and one line added to §10's
out-of-scope list: "split-state storage and sealing."

## 9. Implementation map

**Scope decision: engine-only.** The public feature surface lives entirely
in `chela-engine`. Every binary and user-facing artifact — `chela-cli`,
`chela-tui`, `chela-wasm`, `chela-bundle`, the release HTML — is untouched
and remains byte-identical.

- `chela-sss`: only if its current API doesn't expose the polynomial to the
  caller, add the **minimal additive** internal API the engine needs (a
  `Polynomial` handle with `evaluate_at(x)`, or a `split_with_coefficients`
  variant). No behavior change to existing functions; do NOT duplicate the
  SSS math in the engine — one implementation, one audit target.
- `chela-engine`: `SplitState` (drop-wipe, versioned `to_bytes`),
  `split_extendable`, `extend` (+ cap logic, wrong-secret check);
  round-trip verification reused after every extend.
- `chela-wasm`: **deferred** — Carapace's daemon is Rust and links the
  engine directly; add wasm exports only when a non-Rust embedder wants
  extension (state crosses as bytes under the §4 contract when it does).
- `chela-cli`/`chela-tui`: no change (no sealing available in the pristine
  workspace); optionally a later companion crate outside the workspace for
  file-based extension.
- Tests: mixed original+extended recovery; exhaustive subset round-trips
  post-extension (`round_trip_for_every_subset_…` pattern); x-exhaustion;
  cap warning/override; state round-trip via `to_bytes`/`from_bytes`; fuzz
  `from_bytes` (`chela-share/fuzz` pattern).
- `AUDITORS.md`: one new section — "what `SplitState` contains and why it
  must be sealed."

---

*Companion to the Carapace Protocol spec (v0.9+): Carapace consumes
`chela-engine` as a pinned crates.io (or git-rev) dependency, calls
`split_extendable`/`extend`, and seals the returned state under
`HKDF(K_root, "carapace/v1/split-state")` with its own crypto stack. Chela
gains no dependencies.*
