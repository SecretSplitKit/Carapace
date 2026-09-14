# Legacy state fixture

`legacy-rich-v1.redb.gz.b64` is a frozen, gzip-compressed, base64-encoded redb
database. It has the legacy unversioned `state` table and no schema or identity row. It
contains sealed `held_shares`, `split_states`, and owner grants. It also contains test
cards, epochs, replica state, working-directory metadata, vault blob sources, and document
state. The decoded database is 1,056,768 bytes. Its SHA-256 digest is
`bdd54a5e2959a14914002fe7e298cdb0976702dff9dbed3bb5e16b34835420f8`.
`MANIFEST.tsv` records both the tracked encoded-file digest and this decoded database
digest, with its data classification.

The fixture contains no keys, shares, personal data, or other secret data. The migration
test uses fixed test-only root and node seeds.

To regenerate the fixture from the full persistence test for an intentional legacy-format
update:

```sh
CARAPACE_LEGACY_FIXTURE_OUTPUT=/tmp/legacy.redb \
  cargo test --locked -p carapaced persist_load_roundtrips_all_categories
gzip -n -9 -c /tmp/legacy.redb | base64
```

Do not replace this fixture only because a new redb release writes different bytes.
Replace it only when support for a reviewed legacy format changes.

## Generated fixture matrix

Generate the full synthetic state matrix into a caller-selected directory:

```sh
scripts/state-fixtures.sh generate /tmp/carapace-state-fixtures
```

The tool creates empty schema-2, rich schema-2, schema-1, unversioned legacy, active
ceremony/rate/tombstone, split/held-share, replica/GC, corrupt, and truncated database
classes. It writes `MANIFEST.tsv` with a SHA-256 digest and the synthetic-data
classification for each file. Sealed rows use fresh nonces, so database hashes can change
between runs. The logical contents and required class names are deterministic.

The check mode regenerates the matrix, verifies complete class coverage, and checks the
tracked frozen fixture's encoded-file digest:

```sh
scripts/state-fixtures.sh check
```

Only `legacy-rich-v1.redb.gz.b64` is reviewed and tracked. Generated files contain fixed
test-only material and no production secrets. Do not commit generated databases.
