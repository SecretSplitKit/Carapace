# Blob Garbage Collection

Carapace keeps encrypted blobs until durable state no longer needs them. The daemon runs a retention reconciliation during maintenance. The filesystem blob store then removes unprotected blobs on a five-minute schedule.

Replica pushes first enter a private state-local `.replica-ingress` directory. Startup removes
only this exact stale staging root. Each completed or rejected push removes its owned
subdirectory. The served blob store receives data only after the complete push validates.

If a served-store add or sync operation fails, replica authorization and durable protocol state
remain unchanged. Content-addressed blobs that an earlier add completed can remain physically
present without authorization. They stay default-deny and the normal garbage collector can
remove them. This behavior does not promise byte-identical physical storage after an I/O failure.

The live set includes:

- The digest and chunks for each current vault epoch.
- Blobs that a restart must fetch again.
- Blobs that this device stores as a replica.
- All blobs in a permanent disclosure.

The reconciliation removes stale owner authorization rows before it publishes the smaller live set to the blob collector. The state commit is durable first. If the process stops between these operations, old ciphertext can remain for one more cycle, but current or disclosed data is not removed.

Filesystem writes and fetches use temporary public-store tags to protect new blobs until daemon
state can name them. After the daemon publishes a complete durable live set, it removes these
write-time tags through the public store API and synchronizes that change. The state-derived roots
then become the only long-term retention authority. A restart before the smaller root set is
published starts with no roots, so the collector aborts and retains extra ciphertext conservatively.

The daemon serializes served-store mutations and collection with one mutation guard. A publisher
holds the guard from before its first blob add through the state transaction that names every new
hash. Collection takes the guard before it reads durable state. It then publishes that complete
root snapshot before it removes write-time tags. Thus, collection cannot use a root snapshot from
before an add and remove that add's tag after the add starts. Scratch stores do not use this guard
because they do not feed the served filesystem store or its durable protocol state.

The collector does not run until the daemon publishes its first complete live set. If the live set has more than 1,000,000 entries, reconciliation stops and maintenance reports an error. This limit bounds memory use and prevents a partial live set.

Operators must not delete files from the blob directory. A maintenance error can delay deletion, but it does not permit the collector to use an incomplete live set. Keep the state database and blob directory together when you copy or recover daemon state.

Production collection remains on a five-minute interval. Tests use a private short interval with
bounded five-second waits to prove physical deletion and retention against a real filesystem store.
