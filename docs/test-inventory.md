# Requirement-to-test inventory

This inventory maps protocol and product requirements to executable regression tests.
`Pass` means that the named test directly checks the requirement. `Partial` means that the
test checks an important part but does not close the full requirement. `Gap` means that no
adequate automated test exists. A gap is not evidence that the implementation is safe.

| ID | Status | Requirement | Test file | Test function |
| --- | --- | --- | --- | --- |
| PR-01 | Pass | Deterministic CBOR has stable golden encodings. | crates/carapace-wire/tests/vectors.rs | b8_24_manifest_envelope_doc |
| PR-02 | Pass | The wire parser rejects indefinite lengths. | crates/carapace-wire/tests/vectors.rs | reject_indefinite_length |
| PR-03 | Pass | The wire parser rejects oversized frames. | crates/carapace-wire/tests/vectors.rs | reject_oversized_frame |
| PR-04 | Pass | The wire parser rejects excessive nesting. | crates/carapace-wire/tests/vectors.rs | reject_deeply_nested_frame |
| PR-05 | Pass | HKDF derivation contexts produce distinct keys. | crates/carapace-crypto/src/kdf.rs | tree_is_deterministic_and_distinct |
| PR-06 | Pass | Content encryption detects tampered recovered content. | crates/carapace-vault/tests/roundtrip.rs | reconstruct_from_manifest_pt_hash_and_tamper_detected |
| PR-07 | Pass | A threshold of trustees can recover the root key. | crates/carapaced/tests/ceremony.rs | full_ceremony_recovers_k_root |
| PR-08 | Pass | Fewer than the threshold do not release recovery material. | crates/carapaced/tests/ceremony.rs | sub_m_never_releases |
| PR-09 | Pass | A non-trustee cannot start recovery. | crates/carapaced/tests/ceremony.rs | non_trustee_cannot_open |
| PR-10 | Pass | Unknown recovery signers cannot grow ceremony state. | crates/carapaced/tests/ceremony.rs | unknown_signer_cannot_grow_ceremony_state |
| PR-11 | Pass | Oversized recovery text is refused. | crates/carapaced/tests/ceremony.rs | oversized_ceremony_text_is_refused |
| PR-12 | Pass | Inbound recovery opens are rate-limited before alarm insertion. | crates/carapaced/tests/ceremony.rs | inbound_recovery_open_is_rate_limited_before_alarm |
| PR-13 | Pass | Missing durable state causes startup to fail closed. | crates/carapaced/tests/reboot_survival.rs | missing_state_database_fails_closed |
| PR-14 | Pass | Existing state inspection does not start networking. | crates/carapaced/tests/state_inspection.rs | inspection_validates_existing_state_without_network_startup |
| PR-15 | Pass | Inspection does not create a missing state database. | crates/carapaced/tests/state_inspection.rs | inspection_never_creates_a_missing_database |
| PR-16 | Pass | Two authorized devices can synchronize a vault. | crates/carapaced/tests/two_device_sync.rs | two_device_sync |
| PR-17 | Pass | Three concurrent devices converge to the same file set. | crates/carapaced/tests/three_device_convergence.rs | three_device_concurrent_edit_converges_identically |
| PR-18 | Pass | Concurrent same-path edits do not silently lose data. | crates/carapaced/tests/sync_conflict.rs | concurrent_edit_same_path_keeps_both_no_loss |
| PR-19 | Pass | Rollback rules reject stale and equal document versions. | crates/carapace-net/tests/integration.rs | rollback_rule_rejects_stale_and_equal_versions |
| PR-20 | Pass | Unfriending removes peer access over the wire. | crates/carapaced/tests/unfriend.rs | unfriend_tears_down_the_peer_over_the_wire |
| PR-21 | Pass | Forged friendship-end and share-destroy messages are refused. | crates/carapaced/tests/unfriend.rs | forged_friendship_end_and_share_destroy_are_rejected |
| PR-22 | Pass | Replica placement enforces friendship and deny lists. | crates/carapaced/tests/replica_hardening.rs | s4_placement_gates_on_friend_and_deny_list |
| PR-23 | Pass | Replica writes enforce quotas and rate limits. | crates/carapaced/tests/replica_hardening.rs | w1_quota_and_rate_limit_cut_off_pushes |
| PR-24 | Pass | Proof-of-retrievability rejects corrupt stored bytes. | crates/carapace-replica/tests/por.rs | corrupt_bytes_fail_content_verification |
| PR-25 | Pass | Proof rounds do not replay after restart. | crates/carapaced/tests/por_reboot_replay.rs | por_round_never_replays_across_reboot |
| PR-26 | Pass | Selective disclosure enforces audience and chunk authorization. | crates/carapaced/tests/selective_disclosure.rs | selective_disclosure_and_fetch_authorization |
| PR-27 | Pass | Local API access requires its bearer token. | crates/carapace-api/tests/integration.rs | status_requires_the_bearer_token |
| PR-28 | Pass | Cross-origin API requests are refused. | crates/carapace-api/tests/integration.rs | cross_origin_is_rejected_even_with_token |
| PR-29 | Partial | API token files are owner-only. The named test is Unix-only. | crates/carapace-api/tests/integration.rs | token_file_is_written_owner_only |
| PR-30 | Partial | Release jobs produce both executables. The workflow gate checks layout, but the full matrix must run in GitHub. | scripts/check-release-workflow.sh | main |
| PR-31 | Pass | A frozen unversioned legacy state fixture opens, remains unchanged during inspection, migrates, and binds its identity. | crates/carapaced/tests/legacy_fixture.rs | frozen_unversioned_fixture_opens_and_binds_identity |
| PR-32 | Gap | Native Windows tests cover ACLs, reparse points, alternate data streams, and atomic replacement. | - | - |
| PR-33 | Pass | Unix restore uses descriptor-relative, no-follow traversal. Temporary plaintext is private from creation. Injected stops at each file commit stage leave one complete old or new file. Vault and disclosure restores keep a synced whole-operation journal until all output files commit, so an interrupted mixed tree is tracked and a restart safely rewrites the full operation. | crates/carapace-restore/src/lib.rs | restore_journal_tracks_interruption_and_clean_restart |
| PR-34 | Pass | An independent Python implementation verifies every normative wire frame and document without changing the worktree. | cbor_vectors.py | check_vectors |
| PR-35 | Partial | Real cargo-fuzz targets and retained minimized corpora cover wire CBOR, recovery messages, persisted-state inspection, manifests, grants, and restore paths. Continuous long-running campaigns remain external. | scripts/check-fuzz-targets.sh | main |
| PR-36 | Pass | Rendered alerts expose live error text and a working keyboard-native dismissal. | gui/tests/error-banner.component.test.ts | renders an accessible alert and dismisses it |
| PR-37 | Pass | Clipboard success and rejection produce truthful visible state. | gui/tests/runtime.component.test.ts | reports success only after the clipboard accepts the value |
| PR-38 | Pass | A deliberate WebSocket stop cancels retries, while an unexpected close retries. | gui/tests/runtime.component.test.ts | retries an unexpected close and does not retry a deliberate stop |
| PR-39 | Pass | Real Chromium checks keyboard navigation, destructive confirmation, and axe rules. | gui/tests/browser/ui.spec.ts | keyboard navigation, destructive confirmation, and accessibility work |
| PR-40 | Pass | Real mobile and desktop Chromium viewports do not overflow and keep focused controls in view. | gui/tests/browser/ui.spec.ts | the narrow viewport has no horizontal overflow and keeps focus visible |
| PR-41 | Pass | The claimant shell verifies the subject, completes activation, and moves focus to restart guidance. | gui/tests/browser/ui.spec.ts | claimant workflow verifies the subject and moves focus after activation |
| PR-51 | Pass | Streaming restore verifies bounded plaintext length and BLAKE3 before atomic activation and preserves the old file on failure. | crates/carapace-restore/src/lib.rs | streaming_verification_preserves_old_file_on_failure |
| PR-52 | Pass | Distinct restore destinations cannot name existing hard-link aliases. | crates/carapace-restore/src/lib.rs | rejects_existing_hard_link_aliases_before_writing |
| PR-53 | Pass | File, chunk, total-byte, path-component, duplicate, case, and Unicode restore limits have direct boundary tests. | crates/carapace-restore/src/lib.rs | rejects_direct_resource_boundaries_and_layout_mismatch |
| PR-54 | Pass | A signature-valid oversized inbound RecoveryOpen from a real co-trustee causes no ceremony growth or durable database change. | crates/carapaced/tests/ceremony.rs | inbound_oversized_recovery_open_has_no_state_or_commit_amplification |
| PR-55 | Pass | Signature-valid unauthenticated RecoveryOpen flooding causes no ceremony growth or durable database change. | crates/carapaced/tests/ceremony.rs | unauthenticated_recovery_open_flood_has_no_state_or_commit_amplification |
| PR-56 | Pass | CeremonyAbort flooding from an unknown signer causes no ceremony growth or durable database change. | crates/carapaced/tests/ceremony.rs | unknown_signer_cannot_grow_ceremony_state |
| PR-42 | Pass | A real child restore is killed after temporary-file sync. Restart removes the exact stale private temp through held directory descriptors, preserves the old file, and completes idempotently. | crates/carapace-restore/src/lib.rs | child_process_kill_cleans_stale_temp_and_resumes_idempotently |
| PR-43 | Pass | An owner device stays offline across several vault epochs, restarts from durable state, resynchronizes, and restores the latest bytes. | crates/carapaced/tests/two_device_sync.rs | long_offline_owner_reboots_and_resyncs_latest_vault |
| PR-44 | Pass | The production replica ingress stager bounds count, per-blob length, and advertised total before activation. It validates the signed envelope binding and hash from private state-local files, removes rejected or stale staging, and changes authorization only after served-store sync. An add or sync failure can leave untagged content-addressed blobs for GC, but it cannot expose or authorize them. | crates/carapaced/src/lib.rs | authenticated_malformed_blob_transport_is_atomic_and_bounded |
| PR-45 | Pass | A fake credential store injects failures at both credential writes, verification, credential-ID activation, and both legacy-file removals. A child-process barrier proves that a kill after backup sync leaves the original pair usable and that restart completes migration without mixed state. | crates/carapaced/src/state.rs | backup_activation_survives_child_process_kill |
| PR-46 | Pass | Replica receive-side disk quotas and rate limits reject excess data without partial store growth. | crates/carapaced/tests/replica_hardening.rs | w1_quota_and_rate_limit_cut_off_pushes |
| PR-47 | Pass | Two conflicting documents signed by one valid signer at the same epoch are treated as equivocation: the second is rejected and the first remains authoritative. | crates/carapace-net/tests/integration.rs | valid_signer_equivocation_at_same_epoch_is_rejected_and_first_value_remains |
| PR-57 | Pass | A wall-clock rollback does not release a recovery share, and a forward change must cross the full delay floor. | crates/carapace-recovery/src/ceremony.rs | wall_clock_changes_do_not_reduce_the_recovery_delay_floor |
| PR-58 | Pass | Active recovery ceremony state has an independent per-subject cap. | crates/carapaced/src/lib.rs | ceremony_active_subject_cap_is_independent_for_each_subject |
| PR-59 | Pass | Daemon and API library code cannot add free-form operational log calls outside the structured event modules. | scripts/check-operational-logs.sh | main |
| PR-60 | Pass | Restore and security reset record durable start and completion events, and interrupted operations do not record false completion. | crates/carapace-api/src/bin/carapaced/state_ops.rs | restore_and_reset_interruption_leave_start_without_completion |
| PR-61 | Pass | Authenticated metrics are bounded, identity-free, and include maintenance, GC, migration, and ceremony capacity state. | crates/carapace-api/tests/integration.rs | metrics_are_authenticated_bounded_and_identity_free |
| PR-62 | Pass | The synthetic durable-state fixture matrix covers all required classes and verifies the frozen legacy fixture digest. | scripts/state-fixtures.sh | main |
| PR-63 | Pass | A recovered node uses signed grant references to obtain a rollback-checked announce from a restarted trustee, then restores exact file bytes from a distinct announce-named replica. | crates/carapaced/tests/recovery_reconstruct.rs | ceremony_then_reconstruct_recovers_file_content |
| PR-68 | Pass | A real filesystem blob collector aborts before durable roots, physically removes an unprotected stale blob, and retains current-vault and permanent-disclosure blobs. | crates/carapace-net/src/blobs.rs | filesystem_collector_removes_only_unprotected_physical_blobs |
| PR-69 | Pass | A restart between durable authorization pruning and publication of a smaller GC root set conservatively retains stale ciphertext until the complete roots are republished. | crates/carapace-net/src/blobs.rs | restart_before_root_shrink_keeps_the_old_live_set_conservative |
| PR-48 | Pass | Claimant cancellation replaces session keys and leaves a safe retry state. | crates/carapace-api/src/claimant.rs | cancellation_replaces_keys_and_leaves_a_safe_retry_session |
| PR-49 | Pass | The public restart handoff is versioned, secret-free, and owner-only on Unix. | crates/carapace-api/src/claimant.rs | restart_handoff_is_public_versioned_and_private_on_unix |
| PR-50 | Partial | Browser automation covers sponsor-package claimant activation and cancellation. Real process restart with platform credential storage remains external. | gui/tests/browser/ui.spec.ts | claimant workflow verifies the subject and moves focus after activation |
| PR-64 | Pass | Every cargo-fuzz target has a minimized non-empty corpus and runs in a deterministic bounded CI smoke campaign. | scripts/check-fuzz-targets.sh | main |
| PR-66 | Pass | Unix terminal-passphrase mode requires a controlling terminal, never reads redirected input, and fails before networking. | crates/carapace-api/tests/terminal_passphrase_process.rs | terminal_passphrase_without_a_controlling_terminal_fails_before_networking |
| PR-67 | Partial | Unix process evidence keeps the terminal passphrase out of argv, environment, and output. Native Windows console-process coverage remains external. | crates/carapace-api/tests/terminal_passphrase_process.rs | terminal_passphrase_is_absent_from_process_inputs_and_output |
| PR-65 | Pass | Explicit terminal-passphrase mode opens only an existing sealed identity, rejects empty or wrong input, and keeps prompt input behind a testable source abstraction. | crates/carapaced/src/state.rs | protected_local_identity_opens_only_with_the_supplied_passphrase |
| PR-70 | Pass | PoR uses ChunkID-bound Bao ranges with exact response lengths, and its bounded latency window detects a proxy-like shift and survives restart. | crates/carapace-replica/src/por.rs | latency_shift_is_bounded_and_survives_restart |
| PR-72 | Pass | A live loopback provider observes a partial Bao range request for a boundary-crossing sample, transfers materially less payload than the multi-megabyte blob, and returns exact verified bytes. | crates/carapace-net/tests/integration.rs | live_bao_range_fetch_excludes_unrelated_blocks |
| PR-71 | Pass | A deterministic mutation guard test holds collection across a served-store add and state commit, then proves that the new blob survives the first complete root publication and is removed only after its durable root is deleted. | crates/carapace-net/src/blobs.rs | concurrent_add_holds_gc_until_the_durable_root_commit |

Run `scripts/check-test-inventory.sh` after a test rename or move. The script confirms
that each `Pass` and `Partial` row points to a file and function that still exist. It also
requires at least one explicit `Gap` row so that incomplete assurance cannot disappear
from this document by omission.
