# ADR-033 — Deterministic task facts, explicit blockers, and the Stop-time closure gate

**Status:** Accepted for [issue #977](https://github.com/TheGaySupreme123/yoetz/issues/977). The
owner requested this design-gated work explicitly in the 2026-10-06 session that reviewed TB4 run
tb4f1; the issue records that acknowledgement. It covers host hook behaviour, the control-request
structural fields, the work-integrity policy-pack version, and the change to "Yoetz is not an
enforcement system". It grants no runtime, credential, disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/kernel/task_facts.py`, `src/yoetz/kernel/closure_readiness.py`,
`src/yoetz/kernel/policies/work_integrity.py`, `src/yoetz/kernel/deterministic_checks.py`,
`src/yoetz/kernel/observed_failures.py`, `src/yoetz/application/check.py`,
`src/yoetz/application/check_change.py`, `src/yoetz/adapters/git_change_capture.py`,
`src/yoetz/adapters/memory/ledger.py`, `src/yoetz/application/observation_materialize.py`,
`src/yoetz/cli/runtime_facts.py`, `src/yoetz/cli/closure_gate.py`, `src/yoetz/cli/observe_hooks.py`,
`src/yoetz/kernel/policies/observation_advice.py`, `src/yoetz/service/ready_composition.py`,
`src/yoetz/domain/observation.py`, `src/yoetz/domain/receipts.py` (`TASK_FACT_GAP_SENTENCES`),
`src/yoetz/cli/hook_diagnostics.py`, `src/yoetz/mcp/summaries.py` (rejected-outcome hint),
`src/yoetz/protocol/policy_packs.py`, `src/yoetz/kernel/finding_resolution.py`, the control-request
2.9.0 structural payload, and the work-integrity 0.3.0 pack identity.
**Relates to:** ADR-019 (completion scope), ADR-022 (observation authorship), ADR-031 (check-time
change capture), ADR-032 (closure readiness), and issues #909, #910, #913.

## Context

In TB4 run tb4f1 the deterministic arm received no task information. Of 160 unique deterministic
findings, none concerned the task: 137 were `requested_item_never_attempted` raised against a
fresh plan before any work, and that finding meant only "no published action names this item", so
atrx-vep-crispr cleared it by publishing an attempt and never wrote its report. Nothing stopped
an agent with work left: pretrain-shard-corruption stopped with three open obligations and
`closure_readiness.state = action_required`, while guidance let it "record the blocker" and the
result enum had no `blocked` outcome to record. Meanwhile the hooks already saw facts that matter
for delivery: packages installed into Yoetz's own interpreter, files written outside the
workspace, verification run only as root.

The owner's direction: deterministic Yoetz makes few judgments but must calculate and surface facts
the agent can act on; self-generated evidence stays admissible (that is a deliberate difference
from AI-powered review); blockers are acceptable only when outside the agent's control; and the
agent must not be able to stop silently with known work left.

## Decisions

1. **Task facts are closed gap codes derived from hook observations and the ledger.**
   `kernel.task_facts.task_fact_signals(projection, records)` reads only service-stamped hook
   observations (ADR-022) and the effective plan, and returns closed codes, each classified exactly
   once in `GAP_CLASSIFICATION`:
   - `planned_verification_not_observed`, `planned_verification_failed`,
     `planned_verification_stale` (agent-actionable): an effective obligation's requested item of
     kind `command` was never observed run, failed on its latest observed run, or last ran before
     the latest observed edit. The match uses the installation-keyed command commitment the hook
     already computes (#909): the requested value gets the same light normalization and keyed
     HMAC, so no command text is compared, stored or shown. A wrapped or reformatted variant is a
     different identity; the remedy is to run the command as recorded or correct the requested
     item. The service registers the key at composition; a process without it computes no planned
     fact rather than claiming a command never ran.
   - `planned_verification_outcome_unknown` and `planned_verification_unobservable` (standing): a
     matching run stated no outcome, or no keyed observed command exists to match against.
   - `edited_after_last_verification` (agent-actionable): an observed edit after the latest
     observed run the hook classified as `test`, `lint`, `typecheck` or `build`.
   - `install_into_yoetz_runtime`, `install_into_private_env`, `write_outside_workspace`,
     `verification_only_as_root` (standing): recorded history classified at the host boundary.
   - `obligation_blocked_outside_agent_control` (standing): decision 4.

   Ledger-only codes enter the frozen deterministic case (with the obligation as subject) and the
   compact status gaps, exactly like plan-drift signals, so status, check, closure preparation,
   receipts and the TUI share one answer. Standing task facts are advisory for the check verdict,
   the receipt conclusion and the scoped local verdict; no task fact vetoes a local absence proof.
2. **Requested outputs are read at check time.** For every effective obligation's requested item of
   kind `file`, the check (every mode) asks the change-capture adapter for a metadata-only probe
   through the ADR-011/031 hardened Git runner, after the structural change capture already passed
   the repository fence: the path is located under the validated root lexically, reached without
   following a link and only `stat`-ed, and `git check-ignore -q` answers whether Git would add
   it (honouring `.gitignore`, `.git/info/exclude`, a repository excludes file and the owner's
   global ignore file); for an ignored path a second `git check-ignore -v` names the rule's source.
   A file that does not exist, and is not a tracked file the change deletes, raises
   `requested_item_never_attempted` with the fact `requested_output_absent`, whatever was
   published: naming a file in `attempted_items` does not create it. An output excluded by
   `.git/info/exclude` (a local exclude) or by a `.gitignore` the task's own change created is
   `requested_output_git_ignored` (agent-actionable: diff-based delivery omits it; in shadow-relay
   the agent added the exclude); one ignored by a pre-existing `.gitignore`, even one the task
   edited, or by a global excludes file is the
   standing `requested_output_ignored_by_repository`; an unread one is the standing
   `requested_output_unverified`. A `file` item names any file the request names, read-only
   inputs included, and an existing file the change leaves untouched or a path outside the
   repository is exactly what an input looks like. So `requested_output_unchanged` and
   `requested_output_outside_workspace` are standing disclosures only for an item the record
   asserts was written: an `edit` action whose `attempted_items` names that exact value (attributed
   to obligations as `attempted_items_for_obligation` does). Validation run tb4v1 reported both
   for task inputs (`/app/data` files tracked and unchanged; `/app/packet` inputs outside a
   `/workspace` repository); requested items carry no input/output role, and the record's edit
   assertion is the narrowest existing signal. The cost is accepted: an output written only by a
   `command` action (a script writing a report) is not checked for these two codes, because a
   command that reads an input looks the same; the value match is exact, as for
   `requested_item_never_attempted`, so a differently spelled path marks nothing. Both failures
   are silence on a standing disclosure, never a false fact; an absent output is still found. No path is stored, returned
   or sent. The same check's AI-powered review packet (including the closing review, ADR-006)
   carries these requested-output codes, and `requested_output_absent` when a requested file is
   missing, in its coverage `known_gaps`, so the reviewer judges the work beside them.
3. **The plan is not an omission.** `requested_item_never_attempted` for an unattempted item waits
   until the agent has started acting: an observed edit, an observed run the hook classified as
   `test`, `lint`, `typecheck` or `build`, or any published action. Investigation commands
   (exploration, version control, and the unclassified `other`/`compound` shells) are not acting. Its repair text no longer
   offers "or revise its obligation" as the default exit; an absent output's text asks for a
   best-effort artifact and names the blocker form. These rule changes move the work-integrity pack
   to `0.3.0`; earlier versions stay decodable and form one lineage.
4. **Blockers are explicit and closed.** A readable, unsuperseded `decision_recorded` whose
   statement holds the exact line `yoetz-blocker:<kind>`, for a kind in `authority`, `consent`,
   `credential`, `dependency_unavailable`, records that the obligations in its
   `affected_obligation_ids` are blocked by something outside the agent's control. No event schema
   changes (the same marker pattern as `yoetz-no-material-work`). Yoetz cannot verify the claim:
   it honours it and discloses it. Readiness reports open obligations that are all so named as the
   standing `obligation_blocked_outside_agent_control` instead of `obligations_open`; their
   requested items raise no never-attempted or absent-output finding; the Stop gate does not list
   them as work, but re-asks each recorded blocker once (see the 2026-10-06 amendment).
   A blocker never waives the closing review (ADR-006, #976): the receipt is the final
   step after a final review, recording the blocker is itself a material change, and running
   `check` with `final_review: true` stays within the agent's control, so
   `closing_review_required` stays agent-actionable and keeps the gate armed until that review
   is current. Missing data the task says is recoverable, an inconsistent input, or a failing test
   are not blocker kinds. The result `outcome` enum stays `success|failure|partial|unknown`.
5. **The Stop-time closure gate continues the agent once per ledger frontier.** At a mapped
   session's Stop hook, the hook reads the service's compact `status` and continues the agent when
   `closure_readiness.state` is `action_required` and `agent_actionable` holds any of
   `obligations_open`, `receipt_findings_unresolved`, `closing_review_required` (the closing
   AI-powered review the checklist requires after the last material change; its repair is
   `check` with `final_review: true`), `planned_verification_failed`,
   `planned_verification_not_observed`, `planned_verification_stale` or
   `requested_output_git_ignored`. The message names what remains with counts and closed tokens
   only, and how to record a genuine blocker. Loop safety:
   - the host loop guard is honoured first (`stop_hook_active` on Codex and Claude Code; Cursor's
     `loop_count > 0`), so an agent is continued at most once per host turn;
   - an owner-only memory (`observation/closure-gate.json`, opaque session and frontier ids)
     suppresses a second gate at the same session and frontier;
   - planned-verification items are ignored while the session's observation outbox is still
     draining, because a run the service has not ingested would read as never observed. Since
     #994 the Stop pass first drains the task's rows toward the current frontier (ADR-022
     amendment of 2026-10-07), so this applies only to rows that remain after that bounded
     drain, and only to rows that can change this task's facts;
   - any read failure, or less than five seconds of the Stop budget left, lets the agent stop.

   Every outcome is a bounded hook diagnostic (`closure_gate_continued`,
   `closure_gate_blocker_rechecked`, `closure_gate_memory_unwritten` (amendment),
   `closure_gate_not_required`, `closure_gate_repeat_suppressed`, `closure_gate_loop_guard`,
   `closure_gate_budget_exhausted`, `closure_gate_unavailable`) visible in `yoetz observe status`,
   beside the Stop drain's own `stop_drain_complete` / `stop_drain_incomplete` (#994).
6. **Per-host delivery.** Codex: `decision: block` with `reason` (its only model-visible Stop
   channel). Claude Code: `hookSpecificOutput.additionalContext` at Stop, the documented non-error
   feedback that continues the conversation under the same `stop_hook_active` guard. Cursor:
   `followup_message` at `stop`, used for the gate only (ordinary advice still never auto-submits).
   Each host's runbook records this decision.
7. **Runtime facts are closed tokens classified in the hook.** For a tool event the hook adds
   `install_target` (`yoetz_runtime`, `workspace_env`, `private_env`, `system`, `unresolved`),
   `write_scope` (`outside_workspace`) and `effective_user` (`root`, `non_root`) to the structural
   payload; the control-request 2.9.0 schema and the domain envelope admit exactly these values.
   `write_scope` is not claimed for a scratch write into a temporary directory (`/tmp`,
   `/var/tmp`, `/dev/shm`, their macOS `/private` aliases, the per-user macOS
   `/var/folders/<a>/<b>/T`, or the hook process's own temporary directory unless that is `/` or
   contains the home directory); paths are normalized lexically first, so `/tmp/../etc/x` still
   counts (tb4n1 E6: 28 of 33 flagged attempts were `/tmp` logs only).
   Interpreter resolution uses the hook process's `PATH` and never follows links; an interpreter
   under the hook's own `sys.prefix` is Yoetz's runtime. Materialization appends them to the
   observed action description in a fixed closed suffix order, which is how the ledger carries
   them. Observation advice delivers `install_into_yoetz_runtime`, `install_into_private_env` and
   `write_outside_workspace` once each at the next advice-bearing event (advice only, never a
   ledger finding); observation-advice moves to `0.1.8`.
8. **"Not an enforcement system" is narrowed, not reversed.** Yoetz still blocks no tool call and
   gates no receipt; a check is still not correctness. The one active behaviour is the Stop
   continuation above, bounded to once per frontier and per host turn, honouring declared
   blockers, and never claiming work is incorrect.

## Consequences

- The deterministic arm now tells the agent, at check time, at status and at Stop, whether its own
  planned verification ran after its last edit, whether each requested file exists and would be
  delivered, and where installs and writes went. These are facts, not judgments; self-generated
  evidence remains admissible.
- An agent that stops with open obligations is continued once with the list; it can still stop
  after that, and a genuine out-of-control blocker is a recorded, disclosed position instead of a
  silent stop.
- Exact command matching can report a planned verification as not observed when the agent ran a
  wrapped variant; the text says how to clear it. Coverage limits: runs the hooks did not observe
  (another host, a missed hook, observation off) are invisible; `PATH` resolution may differ from
  the shell's; `effective_user` describes the hook process, not the delivery environment.
- Cost: one compact status read per Stop of a mapped session, one `stat` plus one or two
  `git check-ignore` calls per requested file per check, and one pass over the accepted prefix
  per case build and per compact status read.
- Scope of the requested-output read: it runs in `check` only. Status candidate findings and the
  AI-powered review's matching of local findings use the case alone, so they never show an absent
  output; the check result, its recorded finding and the receipt do. Like the structural test-edit
  accounting it sits beside, the read is not part of the frozen case: a resumed check reuses its
  checkpointed findings but re-reads the workspace for the gap codes, so a file written in that
  window can make the two disagree until the next check.
- A requested file value with whitespace, a glob or brace pattern, `~`, `$` or a URL scheme is not
  read at all, so trailing prose never manufactures an absent output.
- `GAP_CLASSIFICATION_VERSION` stays `"2"`: codes were added, no existing assignment changed.

## Alternatives considered

- **A `blocked` result outcome or a new obligation status.** Rejected for this change: it needs new
  event schema versions across reducers, receipts and every surface, while the decision marker is
  already a reviewed pattern. Issue #913 slice C still owns obligation-level acknowledgement.
- **Gate in the service at Stop ingest.** Rejected: the Stop hook frequently exhausts its drain
  budget before its own envelope reaches the service, so a gate computed there would often miss.
- **Make planned-verification facts receipt-blocking findings.** Rejected: the exact-identity match
  can miss a reformatted run, so they are agent-actionable readiness codes, not findings.

## Amendment (2026-10-06): a recorded blocker is re-asked once and checked once

TB4 validation run tb4v1 found a loophole in decision 4. A deterministic agent on
pretrain-shard-corruption recorded `yoetz-blocker:dependency_unavailable` for "no original snapshot
found", although the task said the data was recoverable. Any well-formed line was honoured, the
obligation became the standing `obligation_blocked_outside_agent_control`, and the Stop gate went
quiet. The owner decided the following, with no prerequisite such as a prior failed attempt:

1. **Deterministic: re-ask once, then honour.** Status `closure_readiness` gains the optional
   `blocked_obligations` list (`obligation_id`, closed `blocker_kind`, `decision_event_id`; ids
   and the closed kind only, on the unreleased status-result 1.4.0). At a mapped Stop, the gate
   also fires when this list names an `(obligation, kind)` pair the session has not yet been asked
   about. This includes `ready_with_limitations`, where nothing else is left. The continuation
   names each obligation and the claimed kind and asks the agent to confirm each is outside its
   control (authority, consent, a credential, a dependency it cannot obtain). It says that missing
   or inconsistent data the task says is recoverable, a failing test, or an infeasible-looking
   result is not a blocker, and it tells the agent to continue the work otherwise. The gate item is
   `blocker_recheck`, and the extra diagnostic is `closure_gate_blocker_rechecked`
   (`closure_gate_memory_unwritten` when the memory below cannot be written). Nothing judges the
   claim here.
2. **"Re-confirmed" means the agent stopped again, with no new protocol field.** Once the gate
   that named a pair is delivered, the hook remembers `<obligation id>:<kind>` for that Yoetz
   session in a second owner-only file (`observation/closure-gate-blockers.json`, at most 64
   keys per session and 128 sessions). The pair is then honoured at every later Stop, whatever the
   frontier. A second Stop, or recording the same blocker again, is the re-confirmation. A
   different kind for the same obligation is a new claim and is re-asked once. A new session is
   asked again once. The re-check cannot loop: each pair is asked at most once per session, and
   the host loop guard, once-per-frontier memory, budget and read-failure rules of decision 5
   still apply first. If the memory write fails, the agent may be asked once more at a later Stop,
   which is bounded by the same guards.
3. **Semantic: the closing review verifies each blocker once.** A final-phase review case adds one
   question (`recorded_blockers`) that lists each blocker decision, its kind and its open
   obligations, using ids and closed tokens only. Blocker decisions lead the decision section, so
   the 16-item cap never drops them. Statement and rationale (agent text) reach the reviewer only
   through the decision excerpt, which privacy enforcement classifies and span-redacts like any
   other item. The reviewer instruction asks for one verification per blocker against the task
   statement and the work. If either contradicts the blocker, the reviewer raises one challenge
   that cites the decision or obligation. That challenge is an ordinary AI-powered finding, and the
   agent answers it with `respond`. A genuine blocker stays a disclosed limitation and is not
   challenged. The routine phase does not judge blockers.
4. **Fixes found on the way.** Readiness in which every open obligation is blocked
   (`obligations_open` in `blocking_conditions`, disclosed as
   `obligation_blocked_outside_agent_control` rather than listed as work) failed the status
   model's own validation, so status failed and the gate read nothing. The validator now admits
   exactly that shape. Work-integrity also turned standing task facts into
   `ledger_stale_or_incomplete` findings, which made a check whose only gap was a blocker fail
   internally (`invalid_ranked_findings`). Standing task facts are now disclosures only, as decision
   4 intended.

The receipt still discloses blocked obligations as standing limitations, and the reviewer's
verdict on a blocker appears as a normal finding.
