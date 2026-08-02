# Recovery Ceremony Lifecycle

Recovery ceremony safety state is durable plain metadata. It does not contain a recovery share or a root key, so it is not a sealed category. The state schema version is independent of the state-seal format version.

Carapace stores two sliding-window histories for accepted recovery opens:

- A per-subject history.
- A per-sponsor history.

Each history permits five new opens in 24 hours. A repeated ceremony ID does not consume another event. Each map has at most 4,096 keys, and each key has at most five events. A full map fails closed.

One subject can have at most eight active tracked ceremonies. One fan-out operation contacts at most 128 distinct peers. These limits are independent of the durable 24-hour rate histories. They bound concurrent state and network work even when many trusted peers are available.

The release clock uses `max(opened_at, local first_seen) + recovery_delay`. A backward wall-clock change cannot make a share release early. A forward wall-clock change can pass the gate only when the observed time is at least the full configured delay after the local anchor. The daemon enforces a minimum configured delay of 72 hours.

An active ceremony remains available for safe share-response retries. After a trustee sends a share, it records the release but keeps the ceremony until the recovery delay plus a seven-day retry period ends. Maintenance then removes the full ceremony and creates a compact completed tombstone. A ceremony that did not release a share gets an expired tombstone. A valid subject abort gets an aborted tombstone.

A tombstone contains only the ceremony ID, subject, sponsor, terminal time, and terminal state. A replay with that ceremony ID cannot create an alarm, consume rate history, recreate active state, or release a share. Tombstones have a hard limit of 4,096 records. Carapace does not evict an older replay record to admit a newer one. If the table is full, terminal active state remains in its safe state and new cleanup fails closed.

The durable categories are:

- `ceremony_subject_rate`: PLAIN security metadata.
- `ceremony_sponsor_rate`: PLAIN security metadata.
- `ceremony_tombstones`: PLAIN replay metadata.
- `ceremony_released`: PLAIN retry and terminal-classification metadata.

State schema version 2 adds these categories. Normal startup requires every schema-2 category and the sealed identity row. It does not treat missing legacy rows as empty security state. Read-only inspection can decode schema-1 or unversioned state. The sealed-row key derivation and AAD version do not change.

The explicit schema-1-to-2 migration validates the legacy state, creates a protected backup, and writes the complete schema-2 state in one transaction. This operation can re-seal rows with new nonces, but it keeps the existing sealed-row AAD format. If the transaction does not commit, normal startup continues to refuse the legacy database. The operator can restore the protected backup before another migration attempt.
