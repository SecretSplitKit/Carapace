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

Requires Rust 1.95.0, Node.js 24.18.0, and npm 11.16.0.

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
git -C ../chela checkout "$(cat chela-revision.txt)"
cd gui && npm ci && npm run build && cd ..
cargo build --release --locked
```

### Verify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Running on a desktop or laptop

Launch `carapaced` with no arguments to use the platform data directory and open
the interface in your default browser. Production identities use protected local
key storage. Saved folders resume watching when the daemon restarts.

The default data directory is `%LOCALAPPDATA%\Carapace` on Windows,
`~/Library/Application Support/Carapace` on macOS, and
`${XDG_DATA_HOME:-~/.local/share}/carapace` on Linux. The automatic launch uses
loopback API port `43821`. Use `carapaced --help` for command options.

For scripts, use an explicit state directory; add `--open` to open the browser:

```sh
carapaced run --state-dir <PATH> [--publish <DIR> --vid <64-hex>]
```

`--state-dir` holds the daemon's persisted identity/state and is required.
On start it binds the endpoint, serves the blob store and control protocol,
and prints this device's node id, API URL, and dialable address. With `--publish
<DIR>`, it ingests and publishes that directory as a vault (generating a new
vault id, or reusing one passed via `--vid`). The daemon watches saved folders and syncs enrolled devices until Ctrl-C.
The HTTP control API stays on loopback; the peer endpoint listens on the local
network. Use `--bind` to select a specific address. The explicit development-only
`--insecure-plaintext-keys` mode remains loopback-only.


## Protecting your account

Add friends with invite tickets, choose a folder, and select friends to hold its
encrypted replicas. Under Recovery, choose trustees and the recovery threshold.
The overview distinguishes delivered and verified shares; a newly created split
alone is not proof of recovery. Replica membership alone does not prove that every
current file is available. Rehearse a restore before depending on Carapace.

Use **Account and devices** to transfer an account to another computer. Create an
encrypted package, send its passphrase separately, import into a new state folder,
and return the new device card to the original computer. Restart using the new
state folder. This does not switch the running account automatically.

For recovery after losing devices, start `carapaced claimant --state-dir <PATH>`
and open the printed local URL. Give its public request to a trustee, confirm the
account identifier independently, and follow the approval and restart steps.
Keep the claimant state folder so an interrupted attempt can resume. Connections
across separate networks need reachable peers or configured relays.

See [key storage](docs/key-storage.md), [claimant recovery](docs/claimant-recovery-boundary.md),
and [supported platforms](docs/supported-platforms.md) for operational details.

The current restore limits are 4 GiB per file, 64 GiB per folder operation, and
100,000 file entries. Publication checks these limits too. Folders with names
that collide under supported case/Unicode rules or contain unsupported paths
are rejected explicitly; Carapace does not silently rename them.
