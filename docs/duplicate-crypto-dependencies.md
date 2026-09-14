# Duplicate cryptographic dependencies

The locked graph has two cryptographic dependency families. Carapace and Chela use the
stable Ed25519 Dalek 2 family. Iroh 1.0.2 uses the Ed25519 Dalek 3 release-candidate
family. This split also duplicates Curve25519 Dalek, SHA-2, digest, signature,
`crypto-common`, random-number traits, and ChaCha20 support crates.

| Family | Carapace and Chela | Iroh and its current support crates |
| --- | --- | --- |
| `ed25519-dalek` | 2.2.0 | 3.0.0-rc.0 |
| `curve25519-dalek` | 4.1.3 | 5.0.0-rc.0 |
| `sha2` | 0.10.9 | 0.11.0 |
| `digest` | 0.10.7 | 0.11.3 |
| `signature` | 2.2.0 | 3.0.0 |
| `chacha20` | 0.9.1 | 0.10.1 |

The duplicate families use separate Rust types. Carapace does not convert secret keys
between them. Direct Carapace signing uses the stable family. Iroh owns its network
identity operations and the release-candidate family. A forced dependency override could
change Iroh protocol behavior and is not safe.

Keep the duplicate-version lint at warning level only for this reviewed transitive split
until Iroh moves to a stable compatible family. Wildcard dependency requirements fail
the cargo-deny gate. Review this file and the lock file with each Iroh upgrade. New direct
cryptographic dependency families need explicit review.
