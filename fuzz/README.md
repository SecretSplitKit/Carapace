# Carapace fuzz targets

Install `cargo-fuzz` and use a nightly Rust toolchain. Run one target at a time:

```sh
cargo +nightly fuzz run wire
cargo +nightly fuzz run recovery_messages
cargo +nightly fuzz run manifests_grants
cargo +nightly fuzz run restore_paths
cargo +nightly fuzz run state_database
```

CI runs every target with 1,000 deterministic smoke iterations:

```sh
scripts/check-fuzz-targets.sh --smoke
```

## Local sustained campaign

On 2026-08-01, all five targets ran with `cargo-fuzz 0.13.1`,
`nightly-2026-06-01` (`rustc 1.98.0-nightly`), libFuzzer seed `424242`, and exactly
10,000 runs per target. All 50,000 runs completed without a crash or sanitizer artifact.
The state-database target completed at 114 executions per second and used 218 MB peak
RSS. The other four targets completed their 10,000-run budgets in less than one reported
second each.

The resulting corpora were minimized with `cargo fuzz cmin`. The corpus digest is the
SHA-256 of the sorted `shasum -a 256` listing for all files in that target directory.

| Target | Runs | Minimized inputs | Bytes | Corpus digest |
| --- | ---: | ---: | ---: | --- |
| `manifests_grants` | 10,000 | 83 | 929 | `2ddba383bcd5c593a3d3710c3ae072c184e9a82d2cdca4051e88b7466421dfac` |
| `recovery_messages` | 10,000 | 95 | 1,231 | `b7c71103b619c1034c6e8392b6f4c4cc171611d2085ac5eb7c9c09f80aae7ae3` |
| `restore_paths` | 10,000 | 73 | 753 | `2b79463528c2774397f62c366fb9d967491ad7c6e34ab5b7387c2b70d6c9d1b5` |
| `state_database` | 10,000 | 3 | 11 | `09f3d84c5f4bed15b33757ad530d3eacfab831b766789e5b79d2e41bc27dc4d7` |
| `wire` | 10,000 | 105 | 523 | `21d050067849eb38910782f10b31be5add840c5a7c88f906a5d1a3d4e3770e06` |

The state target writes each input to a new temporary directory and calls the public,
read-only database inspection boundary. It does not use a production state directory.
Keep crash artifacts and minimized regression inputs that expose a defect. Do not commit
inputs that contain real user data or secrets.
