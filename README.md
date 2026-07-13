# Carapace

Carapace is an open peer-to-peer protocol for encrypted, live-syncing
friend-to-friend storage with social key recovery, built on the
[iroh](https://github.com/n0-computer/iroh) networking stack. Files sync
across your own devices like Dropbox; friends' machines store your data only
as encrypted, content-addressed blobs they can hold and serve but not read.
Every relationship is a bilateral, mutually-signed friendship (no groups, no
transitive trust), and a threshold of trustees can reconstruct your key via
[Chela](https://github.com/SecretSplitKit/Chela), using an extendable-split
profile that lets the owner add or replace trustees without a full re-split.
See `carapace-protocol.md` for the normative spec.

## Crate map

| Crate | Purpose |
| --- | --- |
| `carapace-wire` | Deterministic-CBOR codec, signing discipline, and the typed message/document registry (Appendix B). |
| `carapace-crypto` | Cryptographic suite `0x01`: HKDF key tree, Ed25519 identity/delegation, FastCDC + XChaCha20-Poly1305 content sealing, HPKE sealed disclosure, Argon2id at-rest sealing. |
| `carapace-vault` | Vault identity, directory ingest into a sealed manifest + content-addressed chunk store, and reconstruction back to plaintext. Network-independent. |
| `carapace-net` | iroh integration: endpoint/ALPN binding, control-frame transport, `Hello` + anti-entropy sync, an iroh-blobs-backed chunk store. |
| `carapace-recovery` | Recovery-via-Chela orchestration: sealed split state, `K_root`/vault-root splitting and extension, share grants, the recovery ceremony. |
| `carapace-friend` | The friendship graph: contact cards, invite tickets, the ticket -> request -> accept handshake, unfriending. |
| `carapace-replica` | Consent-based replica placement and repair: an owner's replica set, a friend's replica-peer role, health/repair policy. |
| `carapace-share` | Share-health cadence on top of `carapace-recovery`'s attestation primitives: trustee self-validation loop, owner attestation loop. |
| `carapace-disclose` | Selective disclosure (§7.4): build/open a `FileGrant` that hands out exactly chosen files' chunk keys to an explicit audience, and the owner-side fetch-authorization table. |
| `carapaced` | The daemon: binds an endpoint, serves the blob store + control protocol, holds vaults, runs the daemon-side disclosure/replica/PoR loops. Ships the `carapaced` binary. |

## Building

Requires a stable Rust toolchain (edition 2021).

Carapace depends on `chela-engine`, `chela-bip39`, and `chela-share` via path
dependencies (`../../../chela/...` from `crates/carapace-recovery`), so the
[Chela](https://github.com/SecretSplitKit/Chela) repository must be checked
out as a **sibling** of this repository:

```
some-parent-dir/
  Carapace/   <- this repo
  chela/      <- github.com/SecretSplitKit/Chela, branch main
```

```sh
mkdir some-parent-dir && cd some-parent-dir
git clone https://github.com/SecretSplitKit/Carapace.git Carapace
git clone https://github.com/SecretSplitKit/Chela.git chela
cd Carapace
cargo build --release
```

### Verify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Running the daemon

```sh
carapaced run --state-dir <PATH> [--publish <DIR> --vid <64-hex>]
```

`--state-dir` holds the daemon's persisted identity/state and is required.
On start it binds the endpoint, serves the blob store and control protocol,
and prints this device's node id and dialable address. With `--publish
<DIR>`, it ingests and publishes that directory as a vault (generating a new
vault id, or reusing one passed via `--vid`). It then idles, serving peers,
until Ctrl-C.
