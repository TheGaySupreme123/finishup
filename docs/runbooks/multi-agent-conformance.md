# Multi-agent conformance and native acceptance

This is the scenario map for [issue #509](https://github.com/TheGaySupreme123/finishup/issues/509),
including its [2026-09-15 capture acceptance comment](https://github.com/TheGaySupreme123/finishup/issues/509#issuecomment-5686714958).
Use it when changing delegation, project grouping, observation, or source selection on `0.3`.
Test names identify executable coverage; their presence is not a claim that a particular revision,
host, operating system, or installed package passed. Record exact commands and results in the owning
issue/PR. Keep transcripts and temporary packets outside the repository.

## Evidence levels

- **Composed fixture:** production components with synthetic inputs and isolated state. The
  `builders.multi_agent` fixture uses real encrypted vaults, catalogs, objects, ledgers, and READY
  routing. It substitutes the clock and singleton generation store. It does not launch a native
  host, MCP process, or network reviewer.
- **Boundary fixture:** the named adapter, policy, or fault seam is tested in isolation. It supports
  that boundary only; joining independent green tests in prose is not composed coverage.
- **Native execution:** an exact installed candidate and host process perform actual ordinary work,
  delivery, selection, and any claimed reviewer calls. Each operating system and host is a separate
  cell. A successful fixture does not pass a native cell.

## Increment A: delegation and rollup

Paths below are relative to `tests/conformance/observation/` unless otherwise stated.

| Issue row | Executable scenario | Evidence limit |
| --- | --- | --- |
| Mixed clean, actionable-dirty, informational, pending, live, written-off children and grandchild | `test_parent_lineage_workflow.py::test_parent_receipt_rolls_up_mixed_real_child_states_and_one_hop_grandchild` | Composed fixture; semantic outcomes in this lineage test are controlled inputs. |
| Contact lost, recovery window, abandonment and late evidence | `test_lineage_receipt_acceptance.py::test_contact_lost_abandoned_child_late_evidence_is_incomplete_gap` | Injected clock; late evidence cannot erase incomplete work. |
| Delayed or duplicate host evidence renews from its receipt time, not its delivery (#837) | `test_native_liveness_recovery.py::test_delayed_host_evidence_restores_contact_from_its_own_time` | Injected clock; evidence is offered through the production renewal hook, not a native hook process. |
| Parent waiting on a native subagent past lease plus window stays live and can delegate; the stop releases the hold (#837) | `test_native_liveness_recovery.py::test_native_subagent_run_holds_parent_contact_until_its_stop` | Injected clock with real registry rows. **Open native acceptance:** re-run the Claude structural-profile sequence on a pinned instance. |
| Host dies mid-subagent: the bounded hold still ends contact and abandons honestly | `test_native_liveness_recovery.py::test_host_child_without_a_stop_is_released_by_the_hold_bound` | Injected clock; bound is service policy. |
| Cooperative publications keep hookless long work open; explicit close is never abandoned and refuses resume atomically | `test_native_liveness_recovery.py::test_cooperative_publications_keep_long_hookless_work_open`; `test_explicit_close_is_never_abandoned_and_refuses_resume_atomically` | Injected clock; resume refusal leaves route and sessions unchanged. |
| Abandoned parent: delegation refused with a successor continuation, history and old receipts preserved, successor delegates and receipts independently | `test_native_liveness_recovery.py::test_abandoned_parent_continues_through_a_successor_with_receipts` | Composed fixture; successor inherits no children, findings, or receipts. |
| Delegation crash at every phase, exact retry identity | `test_delegation_phase_matrix.py::test_public_delegation_retries_every_phase_boundary_without_duplicates` | Phase fault injection, including committed reply loss. |
| New manifest after check prevents clean wording; recheck evaluates it | `test_lineage_receipt_acceptance.py::test_later_child_manifest_is_cleared_by_qualifying_parent_recheck` | Composed fixture; old receipt is immutable. |
| Grandchild changes propagate one hop | `test_parent_lineage_workflow.py::test_parent_receipt_rolls_up_mixed_real_child_states_and_one_hop_grandchild` | Parent consumes recorded child manifest, not arbitrary grandchild state. |
| Unobserved freshness remains unknown | `test_parent_lineage_workflow.py::test_parent_receipt_keeps_old_manifest_immutable_after_new_recorded_child_facts` | Does not infer freshness from liveness. |
| Accepted child cannot become rejected | `test_lineage_receipt_acceptance.py::test_accepted_child_cannot_be_rejected_through_public_parent_event` | Public operation refusal. |
| Rejected unaccepted child annotates the parent receipt | `test_lineage_receipt_acceptance.py::test_rejected_unaccepted_child_annotates_parent_receipt` | Composed fixture. The kernel matrix locks `not_authorized` annotation against accepted-child unavailability. |
| Explicit sibling create, observe/check/receipt without contamination | `test_multi_agent_composition.py::test_two_sibling_tasks_complete_isolated_observe_check_receipt_cycles`; `test_multi_agent_public_workflow.py::test_explicit_siblings_have_independent_public_checks_receipts_and_work_state` | Worker cycle and public task cycle are separate fixtures. |
| Restart mid-delegation, parent and child reattach | `test_service_lineage_lifecycle.py::test_fresh_ready_service_preserves_siblings_and_lineage_after_restart` | Recomposes the service over the same synthetic encrypted installation. |
| Upgrade while lineage is live | Same lifecycle scenario covers restart and retained state only | **Open native acceptance:** execute a real older-to-newer installed package upgrade; same-version recomposition is not upgrade proof. |
| Cross-repository parent refusal in A | `test_delegation_phase_matrix.py::test_parent_reference_failures_are_typed_and_do_not_mint_children` | Later explicitly authorized cross-repository grants have their own integration tests. |

## Host qualification rows

These three names are the #509 child-registration rows. Each executable scenario is a composed
fixture under `tests/conformance/observation/`. A green fixture does not pass a native host cell.
Record this run's native result in the acceptance table below, separately from the fixture.

| Qualification row | Executable scenario | Evidence limit |
| --- | --- | --- |
| Delegated-attach | `test_multi_agent_public_workflow.py::test_real_delegation_attach_publication_and_child_receipt_preserve_parent_lane` | Composed READY fixture. Parent `mode=delegate` mints `origin=parent_minted` and `acceptance=accepted`. The child attaches with the handle, uses a distinct session and writer, publishes, checks, and receipts. `work_closed` is a later child publication; the receipt does not close work, and the parent task stays open. |
| Self-registration, acceptance, and rollup | `test_self_registration_public_workflow.py::test_self_registration_pending_acceptance_closure_and_receipt_rollup` | Composed real-SQLite fixture. `parent_session_id` starts `origin=self_registered` and `acceptance=pending` (lineage annotation, not yet a blocking dependency). Parent `child_accepted` keeps that origin and sets `acceptance=accepted`. The child receipt leaves work open; `work_closed` plus a later parent check and receipt is the rollup. The parent conclusion stays coverage-bounded. |
| Unregistered-helper and independent-root | `test_multi_agent_public_workflow.py::test_late_subagent_stop_after_parent_reattach_keeps_registry_annotation`; `test_multi_agent_public_workflow.py::test_explicit_siblings_have_independent_public_checks_receipts_and_work_state` | Composed fixtures. A host start/stop without cooperative registration leaves `children` empty and at most a pending `host_observed` annotation; advice may name that correlation and still does not grant child ownership. Two `mode=create` tasks in one workspace are independent roots: proximity is not lineage. |

## Increment B: admission and project coordination

| Issue row | Executable scenario | Evidence limit |
| --- | --- | --- |
| New host session resumes stored predecessor and delivers its pending rows | `test_host_admission_continuity.py::test_persisted_predecessor_pending_row_drains_after_successor_attach` | Local host-admission/outbox fixture; not a native host restart. |
| Dormant unbound task does not select new work | `test_admission_decision_table.py::test_dormant_unbound_task_does_not_select_or_group_new_work` | Composed READY fixture. |
| Concurrent same pair yields one task; distinct pairs yield two tasks and one project | `test_multi_agent_public_workflow.py::test_concurrent_create_or_attach_pairs_are_resolved_atomically` | Concurrent application requests. |
| Disagreeing selectors refuse before mutation | `test_admission_decision_table.py::test_disagreeing_public_selectors_refuse_before_child_mutation` | Public schema/application boundary. |
| Two worktrees, consent on only one, live-only implicit grouping | `test_worktree_consent_composition.py::test_worktrees_share_live_project_but_require_independent_source_consent` | Actual Git worktrees, resolved common-root identity, READY admission, independent source consent, dormant/resumed sessions and live member filtering; in-process fixture. |
| Revocation refuses queued delivery before any sweep | `test_project_recovery_matrix.py::test_public_queued_generation_revocation_records_refusal_without_advice`; `test_coordination_consent_generation.py::test_consent_refusal_irreversibly_invalidates_queued_detection` | Generation invalidation remains effective after reconsent. |
| Overlap advice to both; finding only for declared coordination obligation; disposition and recheck | `test_project_recovery_matrix.py::test_public_structured_plan_overlap_declaration_disposition_and_recheck` | Composed READY fixture. |
| Warm and cold task runtimes yield the same coordination input (#839) | `test_coordination_cold_runtime_inputs.py`: same resources (`test_cold_inputs_match_warm_and_a_publish_after_reopen_still_detects`), distinct resources, cold duplicate-finding advice, advice-first until an explicit declaration, revocation, structural leases without payload, one unreadable task isolated as coverage, recorded post-publish sweep failure | Composed READY fixture recomposed with `relock_and_reopen_multi_agent_service` for every cold phase. **Open native acceptance:** a fresh Codex and Claude Code live pair has not been rerun against this repair. |

| Superseded generation closes a declared finding without reviving authority (#842) | `test_project_coordination_superseded_generation.py`: opt-out, opt-out then opt-in, consent revoke with and without re-consent, grant revoke and re-grant, a later link, unlink of recipient or counterpart, dissolve, plan overlap, and successor isolation, each through refused disposition, check, status and receipt | Composed READY fixture; no native host restart or UI. |
| Crash after first delivery recovers exactly two deliveries | `test_project_recovery_matrix.py::test_public_crash_after_first_ledger_delivery_restarts_and_redelivers_exact_pair` | Receipt/ledger-driven crash recovery. |
| Opt-out stops grouping and preserves accepted delegation | `test_project_recovery_matrix.py::test_public_optout_preserves_accepted_delegation_and_rejects_second_general_link` | Grouping and lineage remain distinct. |
| Fairness across N live tasks, bounded scheduling work | `test_multi_agent_bounded_lifecycle.py::test_ready_supervisor_fairness_has_bounded_work_per_live_task`; `test_three_live_siblings_survive_maintenance_relock_and_gc` in the same module | Scheduler work bounds and three live task lifecycle coverage. **Open native measurement:** total hook latency under N concurrent hosts. |

## Host observation and capture

| Issue row | Executable scenario or required evidence | Evidence limit |
| --- | --- | --- |
| Post-only Claude/Cursor do not invent missing pre; paired Codex detects orphan | `tests/unit/cli/test_observe_hooks.py::test_issue_607_native_post_only_hooks_do_not_create_false_pairing_gaps`; `test_missing_codex_post_identity_is_retained_as_orphan_evidence` | Host-shaped fixtures; installed profile execution remains separate. |
| Ordinary command/edit/read outcomes, failures and generic/specialized deduplication | Codex normalizer/capture integration below; `tests/unit/cli/test_claude_observe_hooks.py` and `test_cursor_observe_hooks.py` lock current structural profiles | **Partial:** expanded ordinary Claude/Cursor content profiles are not implemented by this repair. Preserve #608/#609 ownership. |
| Validated child owns activity; missing child records gap; parent lanes stay independent | `test_multi_agent_public_workflow.py::test_codex_shared_host_child_alias_routes_observation_to_attached_child`; `test_host_lineage_attribution.py::test_missing_child_identity_is_one_explicit_gap_without_an_annotation` | Composed Codex fixture and attribution boundary fixture. |
| Codex normalizer to encrypted retained evidence and selected packet, contentless retry | `tests/integration/application/test_native_capture_pipeline.py::test_codex_normalizer_retains_encrypted_output_and_replays_without_chunks` | Synthetic `Bash` and `functions.exec_command` payloads through real READY ingest, frozen case, authenticated resolver and prepared packet. No native hook process, socket or actual provider call. |
| Incomplete multipart never earns evidence | `test_native_capture_pipeline.py::test_incomplete_multipart_ingress_retains_explicit_gap_without_evidence` | Composed fixture; explicit unavailable gap is required. |
| Deleted/unreadable objects, conflicting parts, replay and secret scanning | `tests/unit/application/test_observation_secret_persistence.py::test_observation_capture_binds_inner_bytes_and_deleted_object_weakens`, `test_unreadable_multipart_object_weaken_all_parts`, `test_conflicting_multipart_source_commitments_weaken_new_materialization`, `test_coordinator_replays_content_commit_after_reply_is_lost`, `test_observation_capture_secret_scans_before_digest_binding` | Fault seams; not native interrupted transport. |
| Wrong session or revoked source consent | `test_native_capture_pipeline.py::test_capture_ingress_refuses_wrong_session_or_revoked_consent_before_storage` | Public READY ingress refuses before changing the task ledger. |
| Input and locator data excluded from native evidence | `test_native_capture_pipeline.py::test_excluded_content_kind_never_enters_captured_evidence_or_packet` | Excluded retained kinds remain explicit `content_unselected`. |
| Valid excerpt beside oversized and missing items; denied selection | `test_native_capture_pipeline.py::test_selected_packet_preserves_valid_item_beside_oversized_and_missing_objects` | Exact synthetic encrypted object removed; per-item omissions and valid selected bytes inspected in prepared packet. No provider call. |
| Resolution bound to frozen frontier | `test_native_capture_pipeline.py::test_captured_resolution_cannot_be_reused_after_a_new_ledger_event` | New ledger event rejects stale resolved content; captured snapshots do not assert current working-file state. |
| Wrong source/correlation, session stream and stale pre-regrant capture | `test_native_capture_pipeline.py::test_captured_packet_rejects_non_native_or_mismatched_source_authority` | Native source qualification and authority timestamp boundary through READY capture plus packet construction. |
| Missing sibling in previously complete multipart group | `test_native_capture_pipeline.py::test_missing_multipart_sibling_omits_every_part_from_selected_packet` | Removes one exact synthetic encrypted object and requires omission of its readable sibling too. |
| Captured selection across READY restart and contentless replay; later deletion | `test_native_capture_pipeline.py::test_captured_selection_survives_ready_restart_and_preserves_deleted_object_gap` | Reopens the same synthetic encrypted installation twice; valid neighboring excerpt remains selected after one object is removed. This does not exercise native transport FIFO blocking. |
| Restart, reattach, replay, revocation, bounded drain on exact native profiles | Native procedure below | **Open per host/OS:** portable, local CLI, cloud, macOS and Linux results are not interchangeable. |

## Native acceptance procedure

Use the [Codex isolation and authority procedure](codex-dogfood.md#1-isolation-and-authority)
and [ADR-026](../adr/ADR-026-isolated-root-runtime-identity.md). Pin the candidate commit, wheel digest, installed
executable, host version/process, instance root, effective observation authority and reviewer route.
The comment's historical `main` test counts and packet probes do not establish a `0.3` result.

1. Obtain a successful explicit start before evaluating ordinary capture. Exercise busy attach
   independently through the #744 diagnostic scenario; a skipped source-work phase cannot pass.
2. In a tiny synthetic repository, read/edit a recognizable defect and run a passing/failing test
   through the actual native host. Preserve bounded correlation and task/session identities. Do not
   inject source markers into an evidence description and label that native capture.
3. Trace a matching item through normalized hook identity, authenticated delivery, encrypted
   retained object and manifest, structural evidence, current availability, and selected excerpt.
   Record each boundary independently. Missing bytes before durable staging remain unavailable.
4. Run the authorized explicit `semantic_required` check. At an approved diagnostic boundary,
   establish whether actual provider input includes the selected source/test bytes. Record exact
   provider/model/effort, selection, state, attempt identity, terminal status, and coverage.
5. Exercise revoked/stale authority, wrong task/source/correlation, incomplete multipart, excluded
   input/locator/session-stream content, an oversized item and an unavailable item among valid
   excerpts. Check per-item omissions and retained valid excerpts. Aggregate success is insufficient.
6. Record actual follow-through for each finding: repair, evidence improvement, narrower claim,
   justified disagreement, or unresolved blocker. An edit already planned before review does not
   establish causal reviewer influence.
7. Record native receipt/frontier, work outcome, explicit semantic check, background advisory jobs,
   physical calls/retries/cancellations, usage and observation pending/loss/quarantine separately.
   Missing counters mean unknown. Cached and reasoning token subsets are not added twice.

The owning PR/issue must maintain separate rows for **native local macOS Codex**, **native Modal
Linux Codex**, **Claude Code**, and **Cursor**, each with its actual candidate and evidence. Keep a
row open or blocked until executed; a fixture or another host's success cannot close it. This
runbook itself certifies no native cell. Any first broken boundary is assigned from evidence to
its existing owner (#678 transport/content loss, #691 drain diagnostics, #695/#690 inventory and
pressure, #618 evidence interpretation, #744 startup); do not infer transport failure from an empty
packet or infer a pressure cause from a pending counter.

## Per-host acceptance table

Fixture rows above are source evidence only. Native cells below summarize the local macOS run
on 2026-09-27 against candidate `3654c3d612aefcdf4bb53515c752e44ce12bdb90`. The coordinator
integrated the three hosts' final records after their native receipts. Source guidance repairs
were not installed into that candidate during the run. `passed` means that host actually launched
the relationship, and the child ledger shows its own plan, publication, check, receipt, and `work_closed`. A text summary is not
a receipt. Linux and WSL stay `untested` for these rows; installation success in
[cursor-integration.md](cursor-integration.md#linux-and-wsl) does not admit a session cell (#722).
#689 capture contention and #841 Codex rollout reconciliation stay separate owners when they recur.

| Host | OS | Qualification row | Source fixture | This run's native evidence | Result |
| --- | --- | --- | --- | --- | --- |
| Cursor | macOS | Delegated-attach | Composed fixture named above | Parent `mode=delegate` minted an accepted `parent_minted` child. The child attached, published, checked with `semantic_required` (`succeeded` / `semantic_completed`), receipted, and published `work_closed`. That receipt's conclusion was `unresolved_findings_remain`, with capture gaps. Parent lineage later showed the child closed, `contact_lost`, rollup unavailable, and no host annotation. The parent had already recorded `work_abandoned`, so this session does not treat the child receipt as a parent rollup. | partial |
| Cursor | macOS | Self-registration, acceptance, and rollup | Composed fixture named above | The start against the abandoned parent returned `SESSION_CONFLICT` / `lineage_parent_work_terminal` and created no child. On the successor, a child self-registered, was `child_accepted` with origin unchanged, published, checked (`succeeded` / `semantic_completed`), receipted with `unresolved_findings_remain`, and published `work_closed`. Parent lineage then showed that child closed, `contact_lost`, rollup unavailable, and no host annotation. | partial |
| Cursor | macOS | Unregistered-helper and independent-root | Composed fixtures named above | One read-only helper was told not to call FinishUP and returned only the runbook title and the three evidence-level names. Lineage at sequence 36 had no annotation and no extra child. An independent-root native `mode=create` beside the parent was not launched. | partial |
| Codex | macOS | Delegated-attach; self-registration, acceptance, and rollup | Composed fixtures named above | Both registered children had distinct identities, accepted relationships, publications, successful bounded semantic review, receipts, and explicit `work_closed`. Child receipts retained two and one blockers; host correlation remained unproven. The parent receipt retained one blocker and one open obligation. Engine-written check records caused three final publication previews to conflict, so no parent `work_closed` was accepted. | partial |
| Codex | macOS | Unregistered-helper and independent-root | Composed fixtures named above | The unregistered native helper returned without a FinishUP ledger or receipt. A separate native independent-root control was not run. | partial |
| Claude Code | macOS | Delegated-attach; self-registration, acceptance, and rollup | Composed fixtures named above | Both registered children published, checked, receipted, and explicitly closed. Self-registration changed from pending to accepted while preserving its origin. Child reviews reported insufficient coverage and limited receipts. Host correlation was unproven in the ordinary observation profile. The parent final review succeeded at high effort; its receipt retained four blockers with all seven obligations resolved. The parent had already recorded `work_abandoned`; later review and receipt did not reopen it. | partial |
| Claude Code | macOS | Unregistered-helper and independent-root | Composed fixtures named above | Read-only and neutral-write helpers stayed off the ledger. A separate native independent-root control was not run. | partial |
| Cursor, Codex, Claude Code | Linux and WSL | All three rows | None for native session qualification | Not executed | untested |

### Same-workspace coordination boundary

The same run recorded one automatically grouped repository project, a plan overlap between the
Claude and Codex parents, and three physical overlaps among the Cursor predecessor, successor
and self-registered child. Eight delivery records were corroborated by coordination-context
ledger events. The plan detection carried unobservable coverage; the physical detections carried
complete detection coverage. These five participating tasks do not qualify every retained route.

All four detections were advisory, with no declared, addressed or resolved coordination
obligation. Native display/consumption and the declaration-to-resolution workflow were not
qualified. The operator's disjoint ownership prompts and shared coordination files are not
FinishUP detection evidence. The bounded outcome and remaining cells are recorded in the
[issue #509 qualification report](https://github.com/TheGaySupreme123/finishup/issues/509#issuecomment-5855208779).
