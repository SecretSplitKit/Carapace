# Desktop quality review

Carapace has a substantial security and recovery foundation, but reliable daily
use also requires automatic synchronization, safe retries, understandable status,
and native operating-system tests. This work is integrated into PR #1.

| Criterion | Changes in this review | Acceptance still needed |
| --- | --- | --- |
| Works | Automatic folder watching and own-device synchronization; durable device addresses; protected account transfer; recovery handoff persistence | Native tests on all six release targets and a real two-computer setup on each operating system |
| Reliable | Streaming ingestion; restore-limit preflight; safe Windows replacement; overlapping-folder rejection; interrupted-restore backups; retained-baseline repair; bounded peer retries | Long-running tests across sleep, network changes, low disk space, and removable-drive disconnects |
| Easy to use | Default launch and account location; folder browsing; visible sync errors and backup locations; status based on verified recovery shares; device-transfer guidance | Usability sessions with new users; native installers and application signing |

## Local verification

The integrated macOS run passed 434 Rust tests with none ignored, 15 GUI unit and
component tests, and 14 headless Firefox browser checks. Svelte reported no errors
or warnings. The daemon startup and authenticated control-client smoke test passed.
Native CI results remain separate from this local evidence.

## Required before a general release

- [ ] All native CI jobs pass for Windows, macOS, and Linux on x86-64 and ARM64.
- [ ] Exercise protected credential creation, restart, migration, and recovery on
  clean machines, including Linux with a working credential service.
- [ ] Verify two-device edits, conflicts, deletes, offline recovery, sleep/wake,
  network changes, and interrupted restores on each supported operating system.
- [ ] Run packaged daemon and control-client smoke checks on all release targets.
- [ ] Configure release signing credentials; produce and test native installers
  and macOS notarization before claiming a normal desktop installation experience.
- [ ] Observe new users adding a folder, adding a second computer, choosing
  trustees, and restoring files; remove steps that require developer knowledge.

Current archives have explicit platform and file-size limits. See
[supported platforms](supported-platforms.md) and the README. Support for every
historical desktop operating system, 32-bit machine, filesystem, or Linux variant
is not established by a successful build.

Interrupted-restore backups stay in the private account directory under
`restore-backups`. The interface shows their location. They are retained for
manual review so edits made during an interruption can be recovered. Repeated
failed retries can consume disk space; deletion should follow review of the saved
files, never run automatically before the user has recovered needed edits.
