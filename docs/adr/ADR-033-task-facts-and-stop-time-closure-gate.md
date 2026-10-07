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
     draining, because a run the service has not ingested would read as never observed;
   - any read failure, or less than five seconds of the Stop budget left, lets the agent stop.

   Every outcome is a bounded hook diagnostic (`closure_gate_continued`,
   `closure_gate_blocker_rechecked`, `closure_gate_memory_unwritten` (amendment),
   `closure_gate_not_required`, `closure_gate_repeat_suppressed`, `closure_gate_loop_guard`,
   `closure_gate_budget_exhausted`, `closure_gate_unavailable`) visible in `yoetz observe status`.
6. **Per-host delivery.** Codex: `decision: block` with `reason` (its only model-visible Stop
   channel). Claude Code: `hookSpecificOutput.additionalContext` at Stop, the documented non-error
   feedback that continues the conversation under the same `stop_hook_active` guard. Cursor:
   `followup_message` at `stop`, used for the gate only (ordinary advice still never auto-submits).
   Each host's runbook records this decision.
7. **Runtime facts are closed tokens classified in the hook.** For a tool event the hook adds
   `install_target` (`yoetz_runtime`, `workspace_env`, `private_env`, `system`, `unresolved`),
   `write_scope` (`outside_workspace`) and `effective_user` (`root`, `non_root`) to the structural
   payload; the control-request 2.9.0 schema and the domain envelope admit exactly these values.
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

## Amendment (2026-10-07): the re-check reaches active Stops, repair-first text, one view (#984, #985)

TB4 run tb4n1 showed the gate was single-shot per Codex run: 35 of the 38 attempts that declared a
blocker did so after the first gate, and their next Stop arrived with `stop_hook_active` set, so
the hook recorded `closure_gate_loop_guard` without reading status and the re-check of decision 1
above never ran. Codex honours repeated Stop blocks within one turn (codex-rs `turn.rs` sets
`stop_hook_active` once per turn and keeps honouring blocks; its test
`stop_hook_can_block_multiple_times_in_same_turn` asserts it); the limit was Yoetz's own. The gate
also fired on receipt-blocking findings the agent could not clear because of Yoetz's own limits,
and its text offered the blocker as the exit. The owner decided:

1. **Active Stops re-ask new blockers, capped.** A Stop the host already continued this turn
   (`stop_hook_active` on Codex and Claude Code, Cursor `loop_count > 0`) still reads status when
   at least five seconds of the Stop budget remain. It continues the agent only for a
   `blocked_obligations` key `<obligation id>:<kind>` the session has not been asked about, never
   for the ordinary items. Hard caps: at most one re-check per Stop, and at most two gate
   continuations per host turn, counted in a third owner-only file
   (`observation/closure-gate-turns.json`, opaque session ids and a count, 128 sessions) and reset
   at every mapped Stop the host did not continue, whether or not the gate is evaluated there; an
   unreadable or corrupt counter counts as the cap. On an active Stop the memory is written before the
   text is emitted; if it cannot be written, or status fails, the agent stops (fail open). The new
   diagnostic `closure_gate_active_stop_rechecked` joins `closure_gate_continued` and
   `closure_gate_blocker_rechecked` when that happens; `closure_gate_loop_guard` is recorded only
   when an active Stop emitted nothing. A blocker row readiness reports as `confirmation:
   confirmed` (the agent re-published the same line in a later decision) is never re-asked, and
   the readiness token `obligation_blocker_unconfirmed` is a gate item like `obligations_open`.
   How to confirm a blocker (publish the same `yoetz-blocker` line again in a later decision) is
   told only after the challenge: in the re-check, or in a later gate whose blocker was already
   re-asked. The offer that introduces the blocker line never says it, so publishing the line
   twice up front cannot skip the challenge (the kernel rule that a repeat confirms only after
   the challenge is owned by the blockers change). The re-check tells the agent that a Yoetz
   limit is never a blocker: finish the obligation and disclose any limit in the final answer
   (`self_verified` is for findings only).
2. **Repair first; a Yoetz limit is never a blocker (#984).** For receipt-blocking findings the
   text says: repair what you can; for a finding you repaired that Yoetz still cannot prove (its
   resolution names a Yoetz limit such as redaction, observation loss or a review-packet limit),
   verify it yourself, record that evidence and respond `self_verified` with how you verified it
   and the evidence ids (ADR-034); respond `acknowledged_not_done` only if you truly cannot or will
   not do it. Every gate says a Yoetz limit is never a `yoetz-blocker`. The blocker sentence, with
   "Data the task says is recoverable is not such a blocker" and the confirmation step, is offered
   only when open obligations (or an unconfirmed blocker) remain, never for a findings-only gate.
   The text never exceeds every host's 2,000-character bound: whole optional sentences are
   dropped (the drain note first, then the long obligation sentence, then the verification hint)
   and the re-check sentence is always kept; it names at most three blocked obligations.
3. **The drain note only when it changed the decision.** `observation_pending` is now computed for
   this task's own hook rows after the Stop drain (#994, owned by the observation lead). The
   planned-verification items are used when it is false; the "(Observations were still draining
   ...)" note is added only when a planned-verification item was present and dropped.
4. **No ordinary advice on any Stop.** Codex renders Stop text as `decision: block`, and Claude
   Code's Stop `additionalContext` also continues the conversation, so ordinary advice at Stop
   spent the turn's continuation the gate needs (tb4n1 hof-topology). Ordinary advice now stays
   pending for the next `PostToolUse` or `SessionStart` on every host; Cursor never delivered it
   at `stop`. Standing advice (provider repair, e.g. `connect_provider`) therefore no longer
   reaches Codex or Claude Code at Stop. To keep its once-per-turn cadence, a Stop that finds it
   pending marks the session (owner-only `observation/stop-withheld-standing-advice.json`, opaque
   session commitments only), and the first later advice-eligible `PostToolUse` may carry it;
   the mark clears once it is delivered or nothing is pending. Otherwise it reaches them at
   `SessionStart`. Cursor is unchanged (`sessionStart` only).
5. **The gate and the CLI read the agent's route.** A route-less `status` (the Stop gate, the CLI,
   an export) read the policy route, so on a strict-route session it listed
   `semantic_review_not_requested` as work the agent's own MCP view never showed (37 of 37
   deterministic exports). The service now remembers, per session, the route that session's MCP
   bridge named on its last successful `status` or `check`, in an owner-only file in the service
   state directory (`session-routes.json`: `ses_` ids and the closed route only, at most 256
   sessions with least-recently-written eviction, atomic replace, symlinks never followed,
   loaded lazily), so it survives a service restart or upgrade. A later route-less `status` for
   the same session reads on that route. A failed call teaches nothing; when two bridges on
   different routes serve one session, the last successful call wins. A route-less `check` is
   unchanged. Before any bridge call for the session, a route-less read still uses the policy
   route. The applied route is visible on `status` `view: versions` (`route_profile` on each
   version slice); the compact view carries no route field, so it is not labelled there.

## Amendment (2026-10-07): a blocker is claimed until confirmed after the challenge (#985, #978, #986)

tb4n1 showed three more blocker defects. In the deterministic arm one blocker line on every open
obligation turned readiness `ready_with_limitations` with nothing left to do although the main
deliverable was undone (pretrain-shard-corruption, payments-pipeline-fix; both scored 0).
Thirty-one of 38 blocker attempts named only finished obligations to excuse findings Yoetz could
not clear; such a blocker changed nothing yet read as a claim. And the closing review accepted
every blocker it was shown, including one the task statement contradicted. The owner decisions for
C2 (challenge a blocker when it is published) and C4/C5 apply:

1. **Claimed, then confirmed.** The first accepted blocker decision for an `(obligation, kind)`
   only *claims* it. It stays agent work: readiness lists the agent-actionable Stop-gate token
   `obligation_blocker_unconfirmed` instead of `obligations_open`, and a claimed blocker
   suppresses no task fact or `requested_item_never_attempted`. It becomes the standing
   `obligation_blocked_outside_agent_control` only when the same `yoetz-blocker:<kind>` line for
   that obligation arrives in a later publish batch, which is necessarily after the publish-time
   challenge below (and, if the agent stopped, the Stop re-ask). A repeat in the same batch, two
   lines in one decision, or a dry run never confirms. A later decision of a different kind for
   the obligation starts a new claim of that kind (even over a confirmed one), and a superseded
   decision counts in neither role. The rule reads only recorded facts (ledger position and the
   record's operation id), so it is replay-stable and needs no migration. Two back-to-back
   publishes still confirm: the first result's `blocker_claimed` notice is the challenge, and no
   text the agent can read before claiming (finding repair text, guidance, skills, the gate's
   blocker offer) says how to confirm, so a reflexive double publish has nothing to follow. A
   rule requiring an intervening record of some other kind was rejected: "not the same agent
   burst" has no replay-stable definition, and any such record is cheap to manufacture.
   Status rows carry `confirmation` (`claimed|confirmed`) and `confirmation_event_id` (additive on
   the unreleased status-result 1.4.0). When every open obligation is confirmed blocked,
   `completion_plan_not_claimed` is disclosed as standing too (C9).
2. **Publish-time challenge and no-effect notice.** A `publish_work` result, dry runs included,
   carries `blocker_notices` with fixed text per `(obligation, kind)`: `blocker_claimed` (repair
   first; a Yoetz limit is never a blocker, respond `self_verified`; data the task says is
   recoverable is not a blocker; how to confirm), `blocker_confirmed`, or
   `blocker_without_effect` for a blocker naming no open obligation. The last is accepted (no
   protocol break) and changes no readiness, gap, finding or receipt section; it points to
   `self_verified`, or `acknowledged_not_done` as a last resort. Rejecting such a blocker at
   admission stays a later option.
3. **The closing review challenges what the task contradicts (#978).** The blocker question
   tells the reviewer to quote the blocked obligation's own description and evidence expectation
   from its privacy-gated packet item and requires a challenge when the statement says the
   outcome is achievable or the data recoverable, the obvious prerequisite was not attempted, the
   material contradicts the blocker, or it names a Yoetz or review limit. Being the task's main
   deliverable calls for close scrutiny, not an automatic challenge: a genuine credential or
   authority blocker on it may stand. The question itself carries ids and fixed text only, never the obligation text,
   because questions are not privacy-scanned. A golden question pins the tb4n1 pretrain case.
4. **Blocker texts agree (#984 F1).** The `requested_item_never_attempted` repair text, the MCP
   outcome hint, the approved-checks continuation, the guidance and the skills all say: repair
   first; for a Yoetz limit, verify yourself and respond `self_verified`; `acknowledged_not_done`
   is the last resort; `yoetz-blocker` only for an open obligation genuinely blocked outside your
   control. Only the `blocker_claimed` notice and the Stop re-check say how to confirm one.
5. **One clean-compatible gap list (#986 E2).** `kernel.deterministic_scope.CLEAN_COMPATIBLE_GAPS`
   (standing in `GAP_CLASSIFICATION` and tolerated by the deterministic local absence proof,
   excluding AI-review `semantic_*` and evidence-strength `evidence_*` codes, plus the existing
   advisory sets) bounds both the receipt conclusion and the scoped deterministic verdict, and a
   pack that is `skipped/not_applicable` on the whole case (coordination on a single-agent run)
   counts as complete; `scope_excluded` and `material_unavailable` do not. Host-observation gaps
   such as `host_outcome_unavailable` and `unpaired_event` therefore no longer bar
   `no_unresolved_deterministic_findings`, but only where they are guarded: a full check reads
   them as clean-compatible only when its command counters show no unknown or live failed outcome
   (`commands_complete`), the scoped verdict keeps its own counter checks, and the receipt treats
   `HOST_OBSERVATION_GUARDED_GAPS` as advisory only when the applicable check's own coverage
   carried them. Full-check completeness (`application.check.full_check_gaps_clean`) reads the
   same list. `semantic_review_not_requested` still bounds the
   receipt: a check records only `deterministic_mode` or `no_material_semantic_case` with it, never
   whether the serving route required AI-powered review (a strict route records
   `blocked_by_policy`/`route_semantic_ceiling` and its own gap instead), so the receipt cannot
   apply the route rule without reading live configuration, which would break replay.

## Amendment (2026-10-07): disclosures are not blockers; premise disputes are asked once (#995, #997, #984)

Owner-approved 2026-10-07 (issue #995; L5 request D7a under #984).

1. **Disclosure lines (#995).** tb4n1 agents declared blockers on finished work because a hidden
   verifier or a private trace was out of reach (ks-solver, lake-temp-glm, vpp-loss-divergence), or
   blocked repeatedly on a choice a best-effort assumption could make (cargo-flight-dispatch). A
   `decision_recorded` statement line `yoetz-assumption:<obligation id>` or
   `yoetz-verification-limit:<obligation id>` (exact line, well-formed id; the rationale carries
   the text) now records that instead (`task_facts.disclosure_declarations`). It never blocks,
   resolves, or changes an obligation's status; the earliest unsuperseded decision records each
   `(obligation, kind)`, a decision superseded through `supersedes_event_id` withdraws it (as for
   blockers), and an id naming no recorded obligation is a `missing_ref` like a blocker's
   `affected_obligation_ids`. Readiness lists the standing codes `assumption_disclosed` and
   `verification_limit_disclosed` (`GAP_CLASSIFICATION_VERSION` "4"); `receipt-document` 1.3.0
   carries `disclosed_assumptions` rows `{obligation_id, kind, decision_event_id}` (ids and the
   closed kind only) and the section "Assumptions and verification limits the agent disclosed";
   the conclusion is unchanged. The blocker offer, the re-check, the `blocker_claimed` publish
   notice, the requested-item repair text, the MCP rejected-outcome hint and the guidance say an
   inherent verification limit or a best-effort choice is not a blocker: finish and disclose it.
   The review packet's blocker section does not list disclosures yet.
2. **Obligation acknowledgement (#997).** The gate and repair texts name an obligation-level
   `acknowledged_not_done` (ADR-032 slice C amendment) as the honest last resort after repair.
3. **Premise disputes (D7a).** L5's opaque predicate `finding_todo.standing_premise_disputes`
   (imported behind a guard: a build without it reports nothing) names acknowledged-not-done
   findings whose challenge says the task itself requires the work. Readiness discloses the
   standing code `finding_premise_disputed`; `receipt-document` 1.3.0 lists
   `premise_disputed_finding_ids` (a subset of `acknowledged_not_done_finding_ids`) in the section
   "Not done although the review says the task requires it". On a Stop the host has not already
   continued, the gate asks once (closed item `premise_recheck`, remembered as
   `premise:<acknowledged count>` beside the blocker keys, so a new acknowledgement asks again);
   in a combined gate the sentence is dropped before the blocker re-check under the 2,000-character
   bound.
