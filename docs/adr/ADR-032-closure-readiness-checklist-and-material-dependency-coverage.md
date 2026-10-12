# ADR-032 — Closure readiness as a checklist, and material-dependency coverage

**Status:** Proposed for [issue #913](https://github.com/TheGaySupreme123/yoetz/issues/913). The
maintainer acknowledged the design-gated scope on 2026-09-30 and adopted option 2 of the issue (the
agent-actionable / standing / acknowledged split with `ready_with_limitations`). The scoped local
verdict in the amendment below is the narrow deterministic-only exception described by issue #971;
it does not change the receipt conclusion or suppress coverage. Decisions 1–5
are implemented. Decisions 6 and 7 are recorded here as the direction the issue recommends; the
single status coverage definition of decision 7 is implemented, and the rest of 6 and 7 is tracked
on the issue.
**Implemented by:** `src/yoetz/kernel/closure_readiness.py`, `src/yoetz/application/status.py`,
`src/yoetz/adapters/memory/ledger.py`, `src/yoetz/protocol/models.py`,
`src/yoetz/protocol/readiness_text.py`, `src/yoetz/mcp/summaries.py`, `src/yoetz/cli/render.py`,
`src/yoetz/tui/`, the status-result 1.4.0 schema, and the shipped guidance and skills.
**Relates to:** ADR-019 (declared completion scope), ADR-020 (typed evidence digest provenance),
ADR-027 (task lineage), ADR-030 (typed recovery directives), and issues #904, #905, #910, #911,
#912, #917, #971.

## Context

In all 58 Yoetz sessions of the DeepSWE v2 benchmark, `closure_readiness.blocking_conditions`
contained `coverage_gaps_declared`, and in 36 of them it was the only condition. The condition was
appended whenever the page carried any gap. Every Codex session carries standing gaps
(`host_outcome_unavailable`, `unpaired_event`), and a local-only check always adds
`semantic_review_not_requested`, so readiness could never say "you are done". Agents could not tell
work remaining from a limitation their host always has; they rechecked unchanged state, or stopped
without a checklist end state.

The verdict in that lane is honest and stays: a local-only check with gaps is
`insufficient_coverage`. What was missing is a stop signal that says the agent is finished and
names what the receipt will disclose.

## Decisions

1. **Readiness is a checklist.** Every `status` view carries, beside the unchanged
   `blocking_conditions`, a `state` and three groups:
   - `agent_actionable`: what the agent can still do — `obligations_open`, `findings_unanswered`,
     an unacknowledged `receipt_findings_unresolved`, `no_plan_published`,
     `no_obligations_declared`, `projection_stale`, `check_in_progress` (a check holds the session
     frontier; its result is still to come), `check_not_recorded` or `check_not_applicable` (the
     receipt's own applicability rule: run a check after the material change), and every gap code
     the table classifies as actionable;
   - `standing_limitations`: gap codes no available agent action removes under the current host,
     profile and privacy policy; they are disclosed on the receipt, never instructions;
   - `acknowledged_not_done`: obligations and findings the agent recorded as not done, with a
     reason (ids, bounded to 64, plus `acknowledged_not_done_count`).

   `state` is `action_required` while `agent_actionable` is non-empty, `ready_with_limitations`
   when it is empty and something is standing or acknowledged, `ready` when nothing remains at
   all, and `unknown` exactly when readiness itself is unknown (`readiness_unknown`).
   `blocking_conditions` keeps naming everything that bounds the conclusion, so
   `coverage_gaps_declared` remains, now as disclosure; nothing is filtered or suppressed.

2. **A closed, versioned classification table.** `yoetz.kernel.closure_readiness` assigns every gap
   code the product emits exactly once to `agent_actionable` or `standing_limitation`, and
   `gap_classification_version` (currently `"2"`) names the table that classified a response. The
   classification test: a code is standing when no agent action available under the current host,
   profile and privacy policy removes it; it is actionable when a documented agent action (publish,
   respond, revise a claim or plan, recheck after a material change, re-read status once the
   service catches up) removes it. Disclosure codes that describe the bounds of a review, a
   deliberate selection or a capture failure are standing. Of the 20 codes observed in the v2
   evidence only `completion_plan_not_claimed` is unconditionally actionable.

3. **Build-time completeness, runtime conservatism.** A conformance test enumerates every gap-code
   producer — `ObservationGapCode`, `CoordinationGapCode`, the `*_GAP` constants,
   `semantic_coverage_gap_code` outputs, the channel baselines, the lineage manifest template, and a
   syntax-tree scan of gap-sink literals across `src/yoetz` (deterministic-check, command-attempt,
   receipt, lineage, observation and import producers) — and fails when one emits an unclassified
   code or the table names a code nothing emits. Prefixed forms (`coverage:<code>`,
   `check_coverage:<code>`, `retained_finding_coverage:<code>`, `semantic_outcome:<code>`,
   `lineage:<code>:…`) classify by their base code. A code the running build does not know — for
   example one read from a ledger a newer build wrote — is reported as `unclassified_gap:<code>` in
   `agent_actionable`, so the conservative default is visible and never reads as done.

4. **One route-dependent code.** `semantic_review_not_requested` is standing on a route where
   AI-powered review is optional or disabled. It is actionable only when the effective verification
   policy requires AI-powered review, the serving route can dispatch it, and no check whose
   AI-powered review succeeded has been recorded without a later material change (remedy: run it).
   A strict MCP route never dispatches AI-powered review (ADR-018), so a status read served by it
   classifies the code as standing even under a `required` policy: the remedy is the owner's
   (serve the policy route), and asking the agent for an impossible check would recreate the
   unchanged-state recheck loop. Status callers without a route (CLI, terminal interface, closure
   preparation) check on the policy route and keep the policy-derived rule. The same session can
   therefore read `ready_with_limitations` to an agent on a strict MCP connection and
   `action_required` in the CLI or terminal interface. That is coherent, not a contradiction:
   readiness answers "what can *this* caller still do", and the CLI can run the required review on
   the policy route while the strict process cannot. The ledger, `known_gaps`, the verdict and the
   receipt are identical on both.

5. **Derived per request; no verdict changes.** Readiness is derived from the compact projection and
   the recorded prefix at the requested frontier on every read, never cached across frontiers and
   never recorded. A restart, a reattach or an upgrade over a ledger written by an older build
   recomputes it without migrating any event, and old receipts keep their recorded wording.
   Readiness facts that an adapter cannot derive make readiness `unknown`, never a stop state.
   `standing_limitations` promises disclosure on the receipt, so it holds only recorded gaps: a live
   lineage token from status's catalog comparison that no recorded evaluation carries yet stays
   agent-actionable, because a receipt folds recorded lineage only.
   Classification never removes a code from `known_gaps`, never changes a check verdict or receipt
   conclusion, and never strengthens coverage. The frozen directive for each state lives in
   `yoetz.protocol.readiness_text`; the `ready_with_limitations` sentence is the owner-approved
   "Nothing further to do. N standing limitation(s) and M acknowledged item(s) will be disclosed on
   the receipt. Request the receipt." MCP text, the CLI and the terminal interface render it from
   the state token and service counts, in ADR-030's directive style. No readiness state is rendered
   as verified: the terminal interface never uses its verified glyph for any of them.

6. **Acknowledged, not done (direction).** Findings use the `acknowledged_not_done` `respond`
   disposition defined by #905, with its required reason; readiness reads a finding's latest
   response disposition by value, so no second finding mechanism exists. Obligations get the
   explicit form owned by #913: an obligation-level disposition published through `publish_work`
   with the same name and a required short reason. An acknowledged obligation leaves
   `obligations_open` and joins `acknowledged_not_done`; it is terminal — a later completion is a
   new linked item, and the receipt shows both. One receipt section, "Acknowledged, not done",
   lists each item with its reason; it is never folded into a pass or counted as resolved.

7. **Material-dependency coverage (direction).** A *material dependency* of a conclusion is the
   closure of the effective completion claims' `supporting_refs`, the resolved obligations'
   `resolution_evidence_refs`, and the results and evidence those references name. Receipt and
   completion coverage fold `weakest()` over that closure rather than over every projection record.
   Service-verified capture (an `observation_captured` digest with `immutable_snapshot` strength and
   a `captured_object_id`) may raise `evidence_immutability` and `artifact_observation` for the
   evidence it backs, never caller-declared strength. `ledger_freshness` derives from real
   freshness facts (lag, staleness after a material change, redaction, unknown events), not from
   the presence of a gap, and every gap stays in `known_gaps`. Page-level and task-level coverage
   are either unified or named distinctly. *Implemented part:* status reports one definition —
every projection view's envelope `coverage` and `gaps` are the compact task coverage, so a results
or history view can no longer read `service_authenticated / current / 0 gaps` beside a partial
task. The closure fold, capture-raised strength and fact-derived freshness remain open on the
issue.

## Consequences

- An agent whose remaining conditions are all standing reads `ready_with_limitations`, requests the
  receipt and stops; the receipt still says `insufficient_coverage` and lists every gap.
- A new gap code cannot ship unclassified, and an unknown code keeps the task actionable rather than
  hiding behind a stop state.
- The unreleased status-result 1.4.0 schema is edited in place: the checklist fields are optional
  on the wire, so a result shaped by an earlier 0.3 build still validates, but when present they
  are complete, and this build emits them on every status success. Guidance, every host skill and
  the status tool description name the stop signal.
- A standing set differs per host; each host runbook records its own.

## Alternatives rejected

- **Suppress `coverage_gaps_declared` when every gap is structural.** It hides limitations instead
  of classifying them.
- **Tolerate structural gaps in the check verdict.** It would let `no_issue_detected` and
  `no_unresolved_deterministic_findings` describe work whose record was only consistent.
- **Guidance that tells agents to ignore `coverage_gaps_declared`.** The product must classify, not
  the prompt.
- **An open-ended heuristic.** A closed table can be reviewed per host and tested for completeness.

## Amendment — bounded deterministic-only scoped verdict (2026-10-04, #971)

The earlier option-3 rejection applies to treating standing coverage as permission to call the
whole task clean. Issue #971 adopts a narrower result for a check whose effective mode is
`deterministic_only` (including an omitted mode resolved by a disabled verification policy):
`no_issue_detected` may describe the deterministic rules within that check's recorded scope when
the frozen totals show no open or unreadable obligation, no unattempted requested item, no unknown
or relevant live observed failure, and no actionable finding, including one that the public finding
cap would suppress. The internal ranking state is `scoped_complete`; it does not add a wire verdict
token.

The allowlist is closed to `semantic_review_not_requested`, plan-drift advisory codes, and the
informational pre-existing-test-edit codes. Any other gap, an actionable finding, or a blocking
total keeps the ordinary `insufficient_coverage` or `action_required` result. Every gap remains in
the check coverage, status and receipt. The receipt therefore continues to say that AI-powered
review did not run and retains its coverage-bounded conclusion; a scoped local verdict never means
that the work is correct or that a provider reviewed it. Non-deterministic modes retain the prior
completeness rules.

## Amendment — completion needs an answerable signal (2026-10-05, TB4 pilot)

**Context.** In the Terminal-Bench 4 pilot (Yoetz `d925fe46`, Codex), an agent missed a stated
requirement, resolved three coarse self-written obligations with one shared bundle of its own
evidence, and reached a receipt. The one relevant signal, `instruction_requirement_unmapped`, fired
on all six Yoetz attempts but was a standing advisory, so nothing asked the agent to answer it. The
maintainer requested these changes on 2026-10-05 (design-gated: check outcomes and closure).

**Decisions.** Both rules are structural: they read recorded relations and closed host-derived
tokens, never the statement, plan, obligation or command prose.

1. *Unmapped task statement.* `instruction_requirement_unmapped` is reclassified from standing to
   `agent_actionable` (`plan_unrefined_before_first_edit` and
   `obligation_evidence_stale_after_scope_edit` stay standing; `PLAN_DRIFT_ADVISORY_GAPS` names
   them). Every whole-case check also raises a local `task_requirement_unmet` finding
   (research-evidence identity, fact `task_statement_unmapped`, missing fact
   `statement_sourced_obligation_absent`) whose single subject is the current statement event,
   while a task statement is recorded and the effective plan declares obligations of which none
   cites that event in `source_refs`. The finding text names the event id and the repair: publish
   statement-sourced obligations with `plan_revised`. No statement, an unreadable or absent plan,
   and an explicit empty-scope declaration keep their earlier behaviour. The gap no longer counts as
   advisory for check completeness, the scoped deterministic verdict, or the receipt conclusion.
2. *Uncorroborated completion.* The work-integrity rule `claim_without_admissible_evidence` gains
   a second trigger (facts `observed_verification_uncited` / `observed_verification_absent`): an
   effective completion claim whose support chain (`supporting_refs`, `limitation_refs`, and the
   resolution evidence of the obligations it names) cites no hook-observed verification result
   recorded after the latest hook-observed edit. A verification result is a service-stamped
   observed command result with a recorded outcome whose host runner class is not `exploration`
   or `vcs`; hook-captured evidence (native tool output) and evidence a verification result links
   count at their own frontier. The rule is silent when hooks observed neither an edit nor a verification run (captured
   evidence alone corroborates but never makes it apply), so a
   host without hooks keeps its coverage disclosure instead of an unanswerable finding. Repair:
   replace the claim citing the observed `res_` id from `status view=results`.
   *Amended by ADR-033 (tb4n1 E7, #987):* self-generated evidence stays admissible, so the
   agent's own admissible `command` result or `test_result`/`command_output` evidence published
   after the latest hook-observed edit also satisfies the rule; it fires only when every cited
   verification predates that edit or none is cited.
3. *Test-edit justification.* An edit to a pre-existing test file is also justified when an
   effective obligation citing the statement event lists the file as a `requested_items` entry with
   `item_kind` `file` (exact repository-relative path, `./` form, absolute path ending in the
   path, or its digest). The decision marker remains accepted.

**Consequences.** A check rerun with no new events returns these findings again; `respond` answers
but never resolves them, and the receipt keeps `unresolved_findings_remain` until a later check
proves them absent. The rules check presence of a link, not adequacy: one statement-sourced
obligation clears the first rule however coarse the plan, and any observed non-exploration run
after the last edit clears the second. They make an unmapped request or an uncorroborated claim
visible and answerable; they do not prove the work correct. Both fired on every deterministic
pilot attempt, including the two that passed the hidden tests, because no agent cited the
statement or an observed run; the guidance now asks for both from the start. A persisted check
replays through the text-contract digest.

**Versions (maintainer-approved 2026-10-05).** Check results produced under these rules carry new
identifiers: `research-evidence` and `work-integrity` move to `0.2.0` (`coordination` stays
`0.1.0`), and `gap_classification_version` moves to `"2"` (the reclassification in decision 1 and
the earlier standing classification of `compound_outcome_unavailable`). New checks run and select
only the current pack versions. Earlier identities stay readable: recorded checks and findings,
check results replayed from the ledger, and results an earlier 0.3 service shaped keep `0.1.0` or
`"1"`, and the active 0.3 contracts admit both. A pack's versions form one lineage, so the finding
issue key names the pack without its version and a later check at the same or a newer version can
resolve a finding recorded before the upgrade. `docs/INTERFACES.md` records the contract details.

## Amendment — an honest repair must clear (2026-10-05, pilot blockers)

**Context.** Two verifiers of the TB4 amendment (`94531351`) reproduced end to end that a correctly
repaired finding could stay unresolved forever, and that a completion claim could bypass the
statement rule. The maintainer's priority: an agent must never claim completion without an
answerable finding, and an honest agent doing the prescribed repair must be able to clear it. The
maintainer approved these changes for the pilot (design-gated: check outcomes and closure).

**Decisions.**

1. *Tolerance follows the finding's basis, not its kind.* `finding_resolution` used to refuse every
   test-edit accounting code for every `task_requirement_unmet` row. Now only the test-edit row
   (fact `preexisting_test_edit_unjustified`) is bounded by `preexisting_test_baseline_unknown`; it
   tolerates the informational counts once the unjustified code is gone. The statement-based rows
   and every AI-powered row tolerate the accounting set. Command-attempt gaps no longer block local
   rows whose rule never reads command attempts or command identity, a requested-item row whose
   obligations request no command, nor AI-powered rows whose subjects name no command material; `obligation_evidence_stale_after_scope_edit` no longer blocks
   an AI-powered row whose subjects name no stale obligation. An explicit empty-scope declaration
   (`completion_scope_declared_none`) no longer blocks any row, and an answered statement row
   also tolerates `completion_scope_undeclared`. Material that contradicts a repair
   still blocks: a later `instruction_requirement_unmapped` blocks the statement row, the
   unjustified-edit code blocks every row, and a returned issue is never resolved.
2. *A repeated statement is not an amendment.* An obligation maps the request when it cites any
   event that recorded the current statement content (`equivalent_event_ids`), and an event that
   repeats the current statement byte for byte (a re-attach, or a plan event restating it) leaves
   the earlier event current, so the finding subject and the review packet's source ref stay put.
   The repeat is still recorded as history. An amended statement must be mapped again.
3. *No completion on an undecomposed request.* Supersedes decision 1's empty-scope exception: with a
   statement recorded and a completion claim, no plan or an explicit empty scope raises the same
   `task_requirement_unmet` identity (fact `task_statement_scope_empty`). Its repair is
   statement-sourced obligations, or a `decision_recorded` whose statement holds the exact line
   `yoetz-no-material-work:<statement event>` with a rationale. That decision is a structural answer
   the next check reads; it is contradicted, and ignored, while any edit is recorded or while the
   check-time change capture shows any changed path. Hosts record shell writes (`sed -i`,
   redirections, scripts) as command actions, not edits, so the capture is the structural witness
   that no file changed; when no capture is available the decision is not honoured (fail closed).
   Uncommitted changes present before the task count as changed paths too. Mid-task checks before a
   completion claim, and tasks with no statement, are unchanged. The ledger-only
   `instruction_requirement_unmapped` drift advisory has no capture and keeps the edit-action rule.
4. *Repair text is the full working sequence.* The test-edit finding names the statement event and
   every step that makes the repair clear (new obligation with the test path, `plan_revised`, an
   edit action attempting the path with its result, a verification rerun after that edit action and
   resolution citing that fresh observed evidence, superseding claim).
5. *Emission matches resolution.* Both research-evidence `task_requirement_unmet` rules are raised
   only by a check whose research-evidence execution completed, the condition their resolution
   requires; a recorded statement is a research-evidence root, so the pack runs before any claim.
6. *Standing limits never become uncleared findings.* A hook records a keyed command commitment,
   never command text, so a requested command item is always `command_attempt_uncorroborated`; it
   stays in coverage and on the receipt but is no longer a `ledger_stale_or_incomplete` subject
   (the #912 principle). A path-metadata capture cannot read skip markers; that is now its own
   standing code `preexisting_test_skip_unknown` instead of an unknown baseline.
7. *Corroboration is verification-class.* Only a hook-observed non-`exploration`/`vcs` command
   result, or captured output such a result links, after the latest observed edit corroborates a
   completion claim. A run whose host stated no outcome (a long run that outlived its yield)
   corroborates that it ran but never triggers the rule.

**Consequences.** Every finding these rules raise has a documented repair that clears it on the
next check. The rules still check structural links, not adequacy. Pack identities stay
`research-evidence`/`work-integrity` `0.2.0` and `gap_classification_version` `"2"`: the 0.3 line
is untagged, and the new code `preexisting_test_skip_unknown` is classified standing in the same
table. A Codex unified-exec follow-up (`write_stdin`) is still materialized as `other`, so a long
run's final exit status reaches the ledger only through a session-stream outcome correction; the
outcome-less run still corroborates.
Since #1001 a call whose unknown hook result has such a correction counts once, with the corrected
outcome, in check totals and the deterministic scope, and its `host_outcome_unavailable` gap leaves
the frozen case; tb4n1 recorded every Codex shell call twice (one unknown, one known), which made
a clean deterministic verdict unreachable on Codex.

## Amendment — blockers outside the agent's control and task facts (2026-10-06, #977)

ADR-033 adds two readiness inputs without changing the table's existing assignments. Open
effective obligations that a recorded `decision_recorded` names with the exact statement line
`yoetz-blocker:<authority|consent|credential|dependency_unavailable>` read as the standing
`obligation_blocked_outside_agent_control` instead of `obligations_open`, but only when every open
obligation is so named; obligation-level acknowledgement as not done (decision 6) is still open.
The task-fact gap codes of ADR-033 are classified once each in `GAP_CLASSIFICATION`, and the
Stop hook continues an agent once per frontier while `agent_actionable` holds open obligations,
an unacknowledged receipt-blocking finding, or one of the repairable task facts.

## Amendment — slice C: obligation-level `acknowledged_not_done` (2026-10-07, #997, #913)

Owner-approved 2026-10-07 (issue #997). Decision 6's obligation form ships. tb4n1 showed why: an
agent that would not finish one obligation had no honest exit except a `yoetz-blocker`, so 31 of
38 blocker attempts named obligations.

1. **Wire.** `obligation_published` 1.0.0 is released and frozen. `obligation_published` 1.1.0 is
   an additive superset: the status enum is `open | resolved | acknowledged_not_done`
   (`ObligationStatus.ACKNOWLEDGED_NOT_DONE`) and `acknowledged_not_done_reason` (1..4096 UTF-8
   bytes, non-blank) is required exactly with that status and forbidden otherwise;
   `resolution_evidence_refs` stays `resolved`-only. A payload uses 1.1.0 if and only if it uses a
   1.1.0-only feature (this status, or the #1002 item kind and role on the same version), so an
   open or resolved obligation keeps its 1.0.0 bytes and old ledgers replay unchanged. The
   event-draft 1.2.0 and opaque-event 1.2.0 drafts gain the pair; the `publish_work` descriptor
   carries a template.
2. **Reducer.** Allowed transitions are open→resolved, open→acknowledged_not_done,
   acknowledged_not_done→open and acknowledged_not_done→resolved; the latest effective publication
   wins and the meaning fields must repeat. A resolved obligation is not acknowledged afterwards.
3. **Readiness.** An acknowledged obligation is not open (it leaves `obligations_open` and
   `open_obligation_count`) and not resolved. `acknowledged_not_done` lists it beside acknowledged
   findings, so a scope whose only remaining obligations are acknowledged reads
   `ready_with_limitations`. The `status view=obligations` row keeps the released
   `open|resolved` vocabulary and shows it as `open` (not resolved); readiness names the
   acknowledgement.
4. **Facts and findings.** No planned-verification or requested-output fact, and no
   `requested_item_never_attempted` finding, is reported for an acknowledged obligation; the
   acknowledgement discloses it instead. A completion claim over it is admitted.
5. **Receipt.** `receipt-document` 1.3.0 (unreleased, in place) carries
   `acknowledged_not_done_obligation_ids` (ids only; the reason stays on the obligation) with the
   section "Obligations acknowledged as not done", and the conclusion is at best
   `insufficient_coverage`, never clean (schema rule and domain check).
6. **Texts.** The gate, the requested-item repair text and the guidance name it as the honest last
   resort after repair, never a blocker.
7. **One listing under either counting regime.** Projections may count an acknowledged
   obligation among open obligations (`open_obligation_count`, the `obligations_open` blocking
   condition) or not. Readiness never treats it as open work: the derived open set excludes it,
   `obligations_open` is not agent-actionable when every open obligation is acknowledged (or
   confirmed blocked) and none is unreadable, and it appears once, under `acknowledged_not_done`.
   The Stop gate then names no number for open obligations. A resolved obligation stays final:
   a later acknowledgement or reopening is refused.
8. **Review follow-ups (2026-10-07).** An acknowledgement is challenged like a blocker: the Stop
   gate asks once per acknowledged obligation (closed item `acknowledgement_recheck`, keys
   `ack:<obligation id>` plus `ack-count:<n>` beyond the listed ids, in the blocker re-check
   memory and caps, also on an active Stop), and the closing review's blocker question lists
   acknowledged obligations for the reviewer to test against the task statement. The gate offers
   acknowledgement only inside a blocker re-check, as the last resort after repair. Status
   readiness carries `acknowledged_obligation_count` (untruncated; `open_obligation_count` never
   includes them), and the CLI, MCP summary, receipt outstanding-work section and check totals
   count an acknowledged obligation once, apart from open ones (check totals keep their closed
   keys: the remainder of `declared` is rendered as acknowledged). Publishing `open` or
   `resolved` on 1.1.0 is refused with a hint naming 1.0.0. Residual: `status view=obligations`
   shows an acknowledged obligation as `open` with no marker; L6 owns that view and adds the reason.

## Amendment (2026-10-08): the route is recorded on the check (#986, E2)

Owner decision (issue #986, L4 residual (b) / E2): **"Record route; don't block".** Each check
records whether its route required AI-powered review (`semantic_route_required`, optional on the
unreleased `check-recorded` and `check-result` 1.4.0, written only as `false`). When the route did
not require review, `semantic_review_not_requested` is a disclosure that no longer bounds the
receipt conclusion; when it did, or the check predates the field, it still bounds it. The
classification table and `GAP_CLASSIFICATION_VERSION` are unchanged: the code stays
`route_dependent`, standing on a non-requiring route and actionable only where the serving route
requires and can dispatch review. The scoped-local-verdict allowlist above is unchanged; the
receipt's tolerance of the code is decided from the applicable check's recorded route, never from
live configuration, so replay is stable. Details: ADR-033, amendment of 2026-10-08.

## Amendment (2026-10-08): a gap a later check cleared is history, not a limitation (#1017)

Owner decision (tb4n2 audit A-4): **keep cleared gaps in the receipt, but mark them historical.**
In tb4n2, receipts listed `planned_verification_not_observed` and `planned_verification_stale`
after the latest check had stopped carrying them: a still-current retained finding stamped by an
earlier check carried the code in its own coverage, and the #912 fold surfaced it as a
`retained_finding_coverage:<code>` gap that bounded the conclusion. The fold itself stays (the
document coverage still never drops a representable gap), but a receipt gap row now has a status.
A code is `historical` when it reached the receipt only through retained-finding coverage, an
earlier `check_recorded` carried it, and the latest tested check does not; the row records
`cleared_at_frontier`, the subject frontier of the first check after the last one that carried it.
Everything else stays `live`, including a code no recorded check ever carried. The derivation reads
only recorded checks, so replay is stable. A historical gap never lowers the conclusion, is never
listed as a current limitation or counted in the result's coverage, and is rendered in its own
"Cleared earlier (historical)" section; only the unreleased `receipt-document` 1.3.0 artifact writes
it, and earlier artifacts keep every gap live exactly as issued. A parent's lineage snapshot of a
child applies the same rule: a retained-only code the child's latest tested check cleared is left
out of the child's snapshot coverage, so a cleared child gap never bounds the parent as
`lineage_child_coverage_gap`. Classification and `GAP_CLASSIFICATION_VERSION` are unchanged. Field
names: `docs/INTERFACES.md`.

## Amendment (2026-10-11): readiness is built from the closure verdict (#1026, ADR-046)

tb4n3 showed the checklist agreeing with the receipt only by accident: sixteen of sixteen
successful runs read `ready_with_limitations` / "Nothing further to do" and then received a receipt
below clean. ADR-046 replaces the private per-site answers with one closure verdict, and the
checklist is now built from it.

1. **Classes, not flags.** `closure_readiness_facts` computes the closure of every current finding
   and every effective obligation once (`kernel/closure_class`). `receipt_findings_unresolved` is
   agent-actionable only for findings whose class is `agent_work`. An acknowledged requirement
   (`settled_unmet`) is final, so readiness stays `ready_with_limitations`, and it is still
   counted: `receipt_blocking_finding_count` is `to_do + unmet`, and the predicted receipt
   conclusion says what it does. A finding the agent rejected with a reason is `awaiting_ruling`:
   the new agent-actionable token `finding_rejection_awaiting_ruling` (a check is the next move; the
   reviewer rules), listed in `awaiting_ruling_findings` with the frontier of the rejection.
   A reviewer's limitation request is agent work (`acknowledge`) counted as "to disclose", never as
   receipt-blocking.
2. **The table is a view.** `GAP_CLASSIFICATION` (version `"7"`) is derived from
   `kernel/gap_effect.GAP_EFFECT_TABLE`, which also decides whether a gap bounds the receipt on each
   route. The three readiness-only finding tokens are rows of the same table. A condition that
   names findings the facts do not classify stays actionable.
3. **The receipt's own gaps.** Status unions the gaps the receipt would carry (judged with the
   applicable check's `GapContext`) into the declared gaps, so a limitation that first appears on
   the receipt is listed on status. The check-absence codes (`check_not_recorded`,
   `check_not_applicable`, `check_payload_unavailable`) keep their own handling.
4. **A prediction and counters beside the directive.** Status carries `predicted_receipt`,
   `finding_counts`, `obligation_counts`, `awaiting_ruling_findings` and `rechecks`. The
   owner-approved `ready_with_limitations` sentence is unchanged byte for byte; the predicted
   conclusion is a separate sentence appended after it, and the phrase "receipt-blocking" is no
   longer printed.
5. **One state for the acknowledged obligation.** The check's next step reads the obligation
   closures (decision 7 of the 2026-10-07 amendment, now the single rule): an acknowledged
   obligation is never open work, and a `yoetz-verification-limit` obligation is disclosed
   (`externally_evaluated`), not open.

## Amendment (2026-10-11): reviewer limitation requests and the language of settled items (#1026)

A reviewer's challenge whose requested next step is `state_unresolved_limitation` on a
requirement-shaped finding asks the agent to say plainly what cannot be verified. That is not work
that repair can clear, so it is not counted as receipt-blocking (owner decision Q4): it stays
`agent_work` with the single next action `acknowledge` until the agent answers it, and the answer
decides what it means (owner decision 2026-10-12, ADR-046 amendment): a reasoned `acknowledged`, or a
`yoetz-verification-limit:<obligation>` decision covering the obligation it concerns, settles it as
`limitation_disclosed` (the requirement may be met but cannot be verified here), and the receipt
then discloses it in "Verification limits" at `insufficient_coverage`; `acknowledged_not_done` says
the requirement is not met, so it is `limitation_acknowledged_not_done`, an unmet requirement at
`unresolved_findings_remain`. When it is the only agent work left the check's next step is
`disclose_limitations`. An `act` challenge never qualifies, and neither do the agent's own words.
Details: ADR-046 section 1.
