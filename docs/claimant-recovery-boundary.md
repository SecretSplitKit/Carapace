# Claimant Recovery Boundary

Carapace uses a separate local server while a new device has no identity. This
server does not construct a normal `Daemon`, and it cannot route to the normal
control handlers.

## Lifecycle

1. Run `carapaced claimant --state-dir <PATH>`. Add `--api-port <PORT>` only
   when a fixed loopback port is necessary. The command starts only the claimant
   server. It prints the loopback URL and the `claimant-api-token` path.
2. Read `GET /api/claimant/status` with the bearer token from
   `claimant-api-token`. Copy the version 1 `carapace.claimant-handoff` package as
   one text block. It contains only the public ceremony key and new node identifier.
3. Give the package to a trusted sponsor through an authenticated out-of-band
   channel. The sponsor imports it in the normal recovery view. Advanced manual
   fields remain available for expert use.
4. The sponsor exports one version 1 `carapace.sponsor-ceremony` package. It contains
   the signed `RecoveryOpen`, the roster and address hints from the verified held grant,
   and its public announce references. Import this package. Manual fields are Advanced.
   The shell calls `POST /api/claimant/preview` to verify the open signature and session
   binding. Confirm the displayed subject identity through a trusted channel.
5. The server confirms that the open names the exact public values from this local
   claimant session. It then collects sealed shares from trustees and reconstructs
   the root key in process memory.
6. The server confirms that the reconstructed user identity matches the subject in
   the open. It stores the recovered root key and the new node seed in the operating
   system credential store. It also creates and verifies an empty, identity-bound
   state database.
7. The server saves a versioned public restart handoff with trustee hints and announce
   references. It contains no key, share, or decrypted vault data.
8. Press Ctrl-C, or send SIGTERM on Unix, to stop the claimant server. The command
   shuts down the claimant API and exits. Start the normal daemon from the same state
   directory.
9. In the normal recovery view, select a restore directory and run retained-vault
   recovery. The normal router reads the handoff and contacts each trustee hint. It
   accepts only rollback-checked, maximum-epoch announces that match the signed grant
   references by vault, epoch, and digest. It then contacts each replica node from the
   accepted owner-signed announce as a separate blob peer.

The completion response contains only the recovered user identifier, the new node
identifier, and `restart_required: true`.

## Security Properties

- The server binds only to IPv4 loopback.
- The Host, Origin, and constant-time bearer-token checks protect both routes.
- The token file has mode `0600` on Unix and refuses a pre-planted symbolic link.
- The browser never receives the ceremony private key, node seed, root key, opened
  shares, or plaintext share words.
- One in-process claimant session can run at a time. A second completion request is
  refused while the first request is active.
- Activation refuses to replace an existing credential identifier, legacy key file,
  state database, or blob store.
- A successful activation needs a normal daemon restart. The claimant server does
  not turn into a privileged normal server.
- A trustee admits the recovered node only after it released a share for a verified
  ceremony that binds the subject to that exact node. This bounded proof survives a
  trustee restart and expires with the ceremony.
- Cancellation drops the current claimant device, replaces both fresh key pairs, clears
  browser attempt data, and leaves a new retry session.

## Test Boundary

Unit and browser tests cover package import, subject confirmation, cancellation,
key replacement, restart-handoff permissions, and router separation. A loopback
integration test covers real trustee quorum, trustee restart, rollback-checked document
discovery, and content restore from a distinct replica. A full HTTP process restart with
a real platform credential store remains in the external integration environment.
