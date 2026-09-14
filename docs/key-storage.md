# Key storage and state recovery

Carapace stores production root and node seeds in the operating-system credential store.
The state directory contains `credential.id`, which is a non-secret lookup identifier. A
production start refuses legacy `root.key` or `node.key` files.

## Interactive protected-local mode

The operating-system credential store remains the default. An operator can instead open an
existing passphrase-protected local identity with:

```sh
carapaced run --state-dir PATH --terminal-passphrase
```

This mode reads the passphrase from the controlling terminal with echo disabled. It does not
accept a passphrase in an argument, environment variable, pipe, or redirected standard input.
It refuses an empty passphrase and refuses to create a new identity. It is separate from the
development-only plaintext mode.

Back up both protected key files with `state.redb` and `blobs`. Test the backup with the same
passphrase. Loss of the passphrase makes the protected identity unusable. An unattended restart
leaves Carapace locked until an operator enters the passphrase. While it is locked, it cannot
enforce the recovery takeover delay or send recovery alarms. Use the operating-system credential
store when these controls must resume without operator attendance.

## Backups

Back up these items together:

- The operating-system credential entries for the Carapace credential identifier.
- `state.redb`.
- The `blobs` directory.
- `credential.id`.

The database contains sealed recovery and authorization state that cannot be derived from
the root key. The encrypted blobs do not replace the database. A backup is valid only after
the credential entries and all state files are present and verified on a test restore.

Use `carapaced inspect-state --state-dir PATH` to authenticate an existing database without
starting the network router. Use `restore-backup` with matching `--state-dir` and
`--confirm-state-dir` values to stage, verify, and activate a database backup. The command
preserves the old database for rollback.

## Legacy-key migration

First stop the daemon and make a full state-directory backup. Then run:

```sh
carapaced migrate-keys --state-dir PATH --confirm-state-dir PATH
```

The command validates both legacy key files, creates a protected `legacy-key-backup`, stores
and reopens both seeds through the operating-system credential store, writes `credential.id`,
and removes the legacy files only after verification. Keep the backup offline until a restart
and a recovery drill pass.

If `CARAPACE_PASSPHRASE` protected the legacy key files, set it only for this stopped-daemon
migration. The production credential-store mode does not use an inherited passphrase.

## Legacy state-schema migration

Normal daemon startup refuses an unversioned or schema-1 database. First inspect it, then
run the explicit confirmed migration while the daemon is stopped:

```sh
carapaced inspect-state --state-dir PATH
carapaced migrate-legacy-state --state-dir PATH --confirm-state-dir PATH
```

The migration validates the legacy database without changing it, creates the protected
`state.redb.before-schema-2` backup, writes every required schema-2 category and the sealed
identity in one transaction, and verifies the strict result. Keep the backup until normal
startup and recovery-state checks succeed.

## Loss cases

- Loss of only `state.redb`: restore the database backup. Do not initialize empty state.
- Loss of only the credential entries: restore the credential backup. The sealed database
  cannot open without the original root seed.
- Loss of only encrypted blobs: restore the blob backup or fetch retained replicas.
- Loss of the passphrase for legacy sealed key files: those files cannot be recovered from
  the database.
- Loss of all owner devices: use the tested trustee recovery process. Do not use a security
  reset as account recovery.

`reset-security-state` clears rollback, replay, authorization, friendship, replica, and
recovery history. It requires the canonical state path twice and the exact reset phrase. It
moves the previous database and blobs to a recoverable backup and writes an operator audit
record.

## Development-only plaintext mode

`--insecure-plaintext-keys` stores key files in the state directory. Carapace refuses this
mode with non-loopback or relay operation and prints a persistent warning. Do not use it for
production data or backups.
