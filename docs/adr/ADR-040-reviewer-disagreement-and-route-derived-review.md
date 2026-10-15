# ADR-040: Binding rules for reviewer disagreement; review requirement derived from the route

- Status: accepted (2026-10-08)
- Issues: #1020 (tb4n2 R1), #1021 (tb4n2 R6), #1024 (tb4n3 RC-1), #1030 (tb4n3 RC-7), #1042, #1043,
  #1046 (tb4n4, amendment of 2026-10-12 below); tb4n5 follow-ups of #1042 and #1046 and the
  action/result pairing rule (amendment of 2026-10-13 below)
- Amends: ADR-034 (finding to-do states), ADR-033 amendment of 2026-10-08 (#986, "record route;
  don't block"), ADR-006 (reviewer instruction)
- Maintainer acknowledgement: the owner approved all tb4n2 core issues R1-R10, design changes
  included, on 2026-10-08 (maintainer TheGaySupreme123: "all r been agreed").
- Implemented by: `kernel/later_material.py`, `kernel/check_standing.py`, `kernel/reducers.py`
  (`invalidates_recorded_check`), `domain/finishup_tools.py` (tb4n3 RC-6, #1029),
  `application/check.py` (`_admit_prior_verdicts`, `_disputed_after_rebuttal`,
  `_record_restatement`, `_restated_finding`, `semantic_route_required`), `kernel/concern.py`,
  `kernel/limitation.py`, `application/review_concern.py` (tb4n3 RC-1 and RC-7, amendment below),
  `kernel/finding_resolution.py` (`apply_check_rulings`), `kernel/finding_todo.py`,
  `kernel/receipt_builder.py` (`_conclusion`), `domain/receipts.py`, `kernel/closure_readiness.py`,
  `adapters/providers/openai_responses.py`; guidance `workflow.md`, `coverage-and-receipts.md`
  and the Codex skill. tb4n4 amendment: `kernel/review_frame.py`, `application/check.py`
  (`validate_semantic_judgment(review_phase=...)`, `_review_deferred_before_first_edit`,
  `_review_skip_gaps`), `kernel/task_facts.py` (`material_edit_recorded`),
  `kernel/finding_resolution.py` (`_TASK_FACT_GAPS_TOLERATED_WHEN_FIXED`), `domain/findings.py`
  (`AGENT_CRITERION_UNMET`, `is_limitation_request`), `kernel/closure_class.py`,
  `kernel/gap_effect.py` and `kernel/closure_readiness.py` (`_closing_review_facts`). tb4n5
  amendment: `kernel/policies/work_integrity.py` (`_unresolved_action_findings`),
  `kernel/deterministic_checks.py` (`action_batches`), `kernel/finding_resolution.py`
  (`_action_result_link_proven`), `application/publish_work.py` (`_action_notices`),
  `protocol/models.py` (`PUBLISH_ACTION_NOTICE_TEXTS`), `mcp/summaries.py`,
  `kernel/review_frame.py` (`local_rule_owned`), `application/check.py`
  (`SEMANTIC_REJECTED_LOCAL_RULE_OWNED`, `_ruling_material`, `_DISAGREEING_RULINGS`),
  `kernel/review_round.py` (`unassessable_review_exhausted`), `application/respond.py`.

## Context

FinishUP exists to catch incomplete work. It is not a bug finder, and the worst outcome is FinishUP
steering the agent wrong. In the tb4n2 benchmark the AI-powered reviewer did exactly that:

- **formal-crypto (semantic arm, 2 of 2 runs).** The reviewer raised `task_requirement_unmet`
  ("short known samples cannot reconstruct longer targets") and asked for "the exact
  benchmark-generator specification", which the agent cannot obtain. The agent rejected it with a
  reasoned rebuttal. Three closing reviews repeated it with `still_present`, citing nothing newer
  than the rebuttal. The agent then emptied a working `solve.sage` that, in the deterministic arm,
  passed all 19 hidden tests.
- The same re-raise-after-rebuttal pattern appeared on payments, vpp and interleaved. On payments
  one concern minted four finding ids, because each re-published completion claim changed the
  finding's subject set.
- The reviewer raised `requested_item_never_attempted` during routine reviews before any work was
  claimed (4 of 14 attempts).
- No deterministic-arm receipt could read clean: an explicitly deterministic-only (strict MCP)
  route still recorded that review was required under the default `verification.semantic =
  required`, and answers recorded after the last check kept the receipt bounded.

The reviewer instruction already said "do not raise again a finding the main agent has answered
unless material newer than that response shows the problem remains", but nothing enforced it, and
nothing told the reviewer that the artifact it asks for must be obtainable.

## Decision

### 1. `disputed_after_rebuttal` (code rule, issue #1020)

A reviewer ruling that keeps an AI-powered finding open (`still_present`, `answered_not_fixed` or
`unassessable`) is recorded by FinishUP as the ruling `disputed_after_rebuttal` when all of these hold
(amended 2026-10-13, tb4n5: `unassessable`, and an unsupported `fixed` demoted to it, never are;
see the amendment of 2026-10-13 below):

- the finding was shown to the reviewer as a rulable prior finding;
- the agent's latest readable response is `rejected` with a non-blank reason;
- the ruling cites no recorded material (`evd_`, `res_`, `act_`, `evt_`) with a ledger sequence
  after that response. Citing an earlier finding, a re-published claim or a re-stated obligation
  (or the event that recorded either) is not material: the agent restating its position is not evidence that the problem remains.

The same rule applies to a challenge that restates the rejected finding (by `restates`, by the
matching restatement key, or by replying to it), using the challenge's cited refs. The reviewer
never sends this value; it is not in the provider judgment schema.

The ruling latches the new to-do state `disputed_after_rebuttal` (projection field
`disputed_after_rebuttal_by_check_event_id`). The state is final, like `rejection_accepted`:

- it is not agent work: `receipt_blocking_finding_count` and the Stop gate do not count it;
- it counts no review round, and `respond` refuses further answers (`finding_terminal`);
- it is never upgraded to `verified_resolved` by a later review that stops naming it;
- it is never clean: closure readiness lists the standing code `finding_disputed_after_rebuttal`
  (`GAP_CLASSIFICATION_VERSION` `"5"`), the receipt lists it in `disputed_after_rebuttal_finding_ids`
  with its own "Disputed after rebuttal" section, and the conclusion is at best
  `insufficient_coverage`;
- the next review packet carries it as a non-rulable `yoetz.settled-finding/1` row (with the
  agent's rebuttal), so a restatement of it folds onto it instead of minting a new id. A challenge
  that cites material recorded after the rebuttal is a new sighting and is minted, linked to it;
- redacting the latching check clears the latch, as for `rejection_accepted`.

A ruling citing material newer than the rebuttal keeps the reviewer's own ruling; the review stays
a dialogue whenever there is something new to discuss.

### 2. Obtainable remedies (reviewer instruction, issue #1020)

The reviewer may ask only for repairs or artifacts the agent can produce from the task statement,
the workspace and the tools shown in the packet. It must not demand a hidden grader, benchmark
generator, private specification or user answer; a concern only such an artifact would settle is a
`state_unresolved_limitation` of priority at most 2, and an earlier finding it concerns is ruled
`unassessable`. It must never recommend delivering less, emptying a file or withdrawing working
code. (tb4n3 amendment below: a working partial solution may be accepted; an empty-file or
withdrawal fallback is never approved when a tested deliverable existed.)

### 3. Findings are advisory (guidance and Codex skill, issue #1020)

Agent guidance states: findings are advisory; never empty, truncate or delete a working deliverable
because a finding is open; disagree through `respond` (`rejected` with a reason, or
`acknowledged_not_done`).

### 4. Restatements across claim churn (issue #1020)

`_restated_finding` keeps the exact subject-set match first. Failing that, it matches the same
finding kind over a normalized key (`concern_key`, tb4n3 amendment below): each claim maps to the claim currently
superseding it, and when both sides name obligations the key is the obligation set alone. A
re-published claim is not new material; every other subject ref (obligations included, as on the
exact path) must be no newer than the earlier finding, or than the agent's reasoned rejection when
the challenge cites nothing recorded after that rejection.

### 5. No AI-powered "never attempted" before any completion claim (issue #1020)

Until an effective completion claim is recorded, an AI-powered `requested_item_never_attempted`
challenge is dropped and counted (`semantic_challenges_rejected`, reason `routine_completeness`).
The deterministic requested-item facts are unaffected.

### 6. Review requirement derived from the route (issue #1021, owner decision)

`semantic_route_required` is true when the check asked for `semantic_required`. Otherwise an
explicitly deterministic-only route (the strict MCP route the owner registered, which can never
dispatch AI-powered review) did not require review, whatever the verification policy says. A strict
process serving a Codex host whose applied route record says `policy` (the registration drift of
issue #537) is stale rather than an owner choice, so there the policy still decides. The policy
route keeps the earlier rule. This supersedes the sentence in the ADR-033 amendment of 2026-10-08
that the route profile does not matter.

### 7. Responses after the last check are advisory (issue #1021)

When the only material recorded after the applicable check is the agent's answers to that check's
own findings (`CheckSuffixClass.RESPONSES_ONLY`), `check_current_as_of_earlier_frontier` is a
disclosure and does not bound the receipt conclusion. Finding states already reflect those
answers. Observations or other later material keep it bounding.

#### Amendment 2026-10-11 (issue #1029, tb4n3 RC-6): the suffix is classified, not counted

The rule above never matched a real run. The records that follow a deterministic arm's final
check are the `check` call's own hook observation and the host's stream bookkeeping (opaque
`event_msg`/`response_item`/`token_usage_record` rows, completion signals), not responses, so the
code bounded 17 of 17 tb4n3 final receipts and was the only bound in three D attempts. Conversely
an observed edit after the check produced the same standing code, so a post-check edit read like
a status poll.

`kernel/later_material.later_material_class` (re-exported by `kernel/reducers`) is now the one
predicate over a record accepted after a check, shared by the reducer, `kernel/check_standing`
(receipt context, receipt capacity, compact status coverage, closure readiness) and the receipt
builder. Classes:

| class | what it is | effect |
|---|---|---|
| `yoetz_own_call` | the observation of a call to one of FinishUP's own MCP tools, any host spelling (`mcp__finishup__x`, `mcp__plugin_finishup_finishup__x`, bare `x`, `finishup:x`, `plugin-finishup-finishup:x`, Cursor's generic `MCP:x` by the closed basenames) | ignored |
| `exploration` | an observed run of the hook's `exploration` runner class, a native read tool, a routine-read summary | ignored |
| `no_tool_activity` | host stream bookkeeping that names no tool call: `Opaque observation kind=<Codex wrapper kind>`, `Observed completion signal kind=...`; and a host poll tool that returns the output of work started earlier (Codex `wait`, a poll output that follows the last check in 18 of 27 tb4n2/tb4n3 semantic-arm attempts) | ignored |
| `non_counting_write` | an observed edit whose every path is scratch or FinishUP-owned (ADR-042) | ignored |
| `response` | a cooperative answer to a finding | advisory (above) |
| `edit_or_write` | an observed deliverable, workspace or outside-workspace edit | supersedes the check: `check_not_applicable`, freshness `stale_after_material_change`, closing review required again |
| `other` | anything FinishUP cannot prove harmless: an unclassified command or tool, an unpaired host result, a subagent, a lineage manifest | keeps the bounding disclosure |

A result is classified by the action it answers. A FinishUP receipt or export the agent saved is
exempt even when a declared output directory would otherwise make a lexical `yoetz_owned` write
count for verification staleness (ADR-042 decision 1): it is the output about the check, so no
check could cover it, and counting it would invalidate the check that produced it. The exemption
ends where a declared output is itself a packaged FinishUP tree (`.agents/...`): a write there may be
the deliverable and keeps counting.

Readiness keeps `check_current_as_of_earlier_frontier` a standing disclosure (the gap table and
`gap_classification_version` are unchanged), including while a counted observation bounds the
receipt. The tb4n2 B5 proposal to list it as agent work ("one more check removes it") was
examined and not adopted: every variant of it can regenerate after the check it asks for, and an
instruction an agent cannot complete is the worst outcome (steered wrong). Reproduced regenerators:
Cursor's structural `afterMCPExecution` result of every call (including each check's own) carries
no tool identity; an agent running the FinishUP CLI through its shell (`finishup check ...`) records a
named command after every check; a late-delivered observation lands after any check. The receipt
still discloses and bounds, and the limitations text names the first bounding record; wave 2's
`gap_effect` decides with the host facts. Content the host captured for a call (tool output, a
workspace diff) is evidence recorded under that call's action and takes the action's class; the
late output of an edit is `other` with rule `evidence_of_edit` (the edit is the superseding record).

Provenance (owner lineage rule): the receipt gap cites the superseding or first counted record
(`subject_refs`), and the limitations text names the record, its ledger sequence, the closed rule
(`observed_counting_edit`, `unclassified_observed_action`, ...), the check's subject frontier and
how many later records were classified harmless, by class. `closure_readiness.check_cause`
carries the same facts on status. The hook records the tool and whether a write left the
workspace, not the path, so the text says which record changed after which check, not which file.

Known host limits, recorded in each integration runbook: Cursor's structural `afterFileEdit`
profile and any unpaired or post-only result carry no tool identity (`other`, disclosed, never
superseding); Cursor `StrReplace`/`Delete` and any other tool the materializer records as an
`other` action are disclosed, not superseding; a late-delivered pre-check edit observation
supersedes the check (the safe side; ingestion order is not occurrence time).

## Consequences

- A repeated, unobtainable or unsupported demand can no longer keep a finding open or re-ask the
  agent; it stays visible as a disagreement and the receipt cannot read clean.
- A real problem the reviewer raises again with new material still reaches the agent.
- Risk: the normalized restatement key can fold two distinct concerns of the same kind on the same
  obligations. The earlier finding stays open (or final) and the restatement is disclosed through
  `semantic_restatements_suppressed`.
- Risk: a reviewer that is right but cites nothing new is recorded as a disagreement, not as open
  work. That is the owner's frame: findings are advisory, and the receipt still discloses it.

## Wire

All unreleased on 0.3, changed in place: `check-recorded` 1.3.0/1.4.0 (`prior_finding_verdict`
gains `disputed_after_rebuttal`), `check-result` 1.3.0/1.4.0 (`todo_state` value; optional count
`finding_checklist.counts.disputed_after_rebuttal`, present only when non-zero), `status-result`
1.4.0 (`todo_state` value; `gap_classification_version` `"5"`), `receipt-document` 1.3.0 (optional
`disputed_after_rebuttal_finding_ids`; a clean conclusion beside it is invalid).

## Amendment 2026-10-11 (issues #1024 and #1030, tb4n3 RC-1 and RC-7): limitation requests and one dialogue per concern

Owner decision RC-1 ("I thought we fixed that?!? why not fixed?") and the Q4 lifecycle. Nine of nine
tb4n3 `state_unresolved_limitation` findings ended `acknowledged_not_done` (ks, vpp, payments, lake,
cargo): the P0-3 prompt text reached every review, but the code minted the compliant answer as
priority-1 receipt-blocking work, so a compliant reviewer and a non-compliant one produced the same
outcome. RC-7: one concern became up to six ids, a rebuttal was erased by a later acknowledgement,
and `acknowledged_not_done` / `self_verified` were one-way doors.

### Limitation requests (RC-1)

`domain.findings.is_limitation_request` is the one predicate: a reviewer finding (origin
`semantic_model_derived`) whose recorded challenge asks `state_unresolved_limitation` and whose kind
is one of `task_requirement_unmet`, `completion_with_open_obligations`,
`requested_item_never_attempted`, `claim_without_admissible_evidence`,
`evidence_does_not_support_claim`. `finding_demands_work` is the kind trait minus that predicate.
The consumers that asked "is this finding agent work" read it: ranking (a limitation-only check
reads `insufficient_coverage`, never `action_required`), check totals, deterministic scope and
`finding_blocks_receipt`. The receipt's own "Verification limits" section and the closure-readiness
classes (`limitation_requested`, `limitation_disclosed`) are built on `limitation_standing` by the
tb4n3 RC-3 change (ADR-046), not here.

`kernel/limitation.limitation_standing` is the lifecycle, replay-derived:

- **limitation_requested** (to disclose): the request is recorded, never repair work, never
  receipt-blocking, never a Stop-gate token. Its only next action is one answer.
- **limitation_disclosed**: the agent says the requirement may be met but cannot be verified here,
  by a reasoned `respond` (`acknowledged`, or `self_verified`, which already requires a reason and
  the agent's evidence) or by a recorded `finishup-verification-limit:<obligation id>` decision on an
  obligation the finding concerns. Acknowledging a limitation request needs no recorded resolution
  attempt (this relaxes the #885 rule for that class only; repair demands keep it). It is settled and
  never clean: closure readiness and the receipt list it, and a re-raise of the same concern folds
  onto it. A `rejected` answer disputes the request instead; `reopened` takes an answer back.
- **limitation_acknowledged_not_done** (owner decision 2026-10-12, amendment below): the agent
  answered `acknowledged_not_done`, which says the requirement is NOT met. It is an unmet
  requirement like any other, not a verification limit.

Guards, each tested: **G1** a challenge asking the agent to `act` is never a limitation request, even
beside a `finishup-verification-limit` decision (the reviewer sees an obtainable path). **G2** nothing
reads the agent's own words, so an agent that answers an `act` finding "I could not find it" does not
turn it into a limitation (the pretrain-shard-corruption rescue, where the acknowledgement re-check
sent the agent back and it recovered the inputs, is kept). **G3** `declared_output_emptied` is
independent of the class: a disclosed limitation never clears the fact that a delivered file was
emptied. **G4** the class is never clean.

Reviewer instruction (same change): the final-phase question and the standing instruction say that a
requirement only a hidden evaluator or an unobtainable artifact can establish is a `not_assessable`
row once the packet shows the agent disclosed it (an obligation acknowledged as not done, a
`finishup-verification-limit` decision, or a limitation request it acknowledged); a requirement
quantified over unbounded inputs is judged on the tested part (`supported`) with the remainder stated
as a limitation, never `not_supported`; the acknowledged-obligation question keeps the genuine-blocker
carve-outs; and "a reasoned fallback ... may be approved" is replaced by: a working partial solution
may be accepted, an empty-file or withdrawal fallback is never approved when a tested deliverable
existed. The packet carries recorded limitation decisions and acknowledgement states beside the
obligations (`yoetz_already_disclosed`) and a disclosed limitation as a non-rulable
`yoetz.settled-finding/1` row marked `limitation_already_disclosed`. Agent guidance: never empty or
withdraw a working deliverable over a finding or an "empty file if unsolved" clause.

### One dialogue per concern (RC-7)

**Concern identity** (`kernel/concern.concern_key`): the obligations a finding concerns (named
directly, or reached through the claims it cites), the other non-event subject refs, with the event
that recorded an obligation dropped (an anchor, not a subject). `same_concern` is obligation overlap,
else ref containment; `equal_concern` is the same obligation set, else equal refs. Requirement kinds
(`task_requirement_unmet`, `completion_with_open_obligations`, `requested_item_never_attempted`) are
comparable with each other, and `evidence_does_not_support_claim` joins them only when both name an
`obl_` directly. A different kind is never folded into an open item: that hid a requirement demand
behind a bookkeeping finding.

**Fold rules** (`_restated_finding`, `_restates_target`, `_record_restatement`): an open, rulable
target folds a challenge of the same kind over `equal_concern` (a narrower or wider challenge is a
distinct issue whose discrepancy a ruling cannot carry, Greptile P1 on #943); a settled target
(`acknowledged_not_done`, `self_verified`, a disclosed limitation, `rejection_accepted`,
`disputed_after_rebuttal`) folds any overlap of a comparable kind, because the re-raise cannot change
what the agent settled. A settled item remembers what its re-raises cited (`absorbed_refs`, at most
32 typed non-work ids), so a later re-raise naming only what the first re-raise added still folds
(formal-crypto S). A reply to an answered open item with no standing rejection still mints a linked
finding. The review summary now lists unnamed folds as well as named ones.

**Standing position** (reducer fact `standing_position`, `kernel/finding_resolution`): the earliest
unretracted reasoned answer (`rejected`, `acknowledged` with a reason, `acknowledged_not_done`,
`self_verified`), with its ledger sequence; `reopened` retracts it. A later `acknowledged` no longer
erases an earlier `rejected` (12 of 16 tb4n3 rejections were overwritten before the next review: cargo
S). `last_ruling_frontier` is the sequence of the newest check that ruled on the finding.
`standing_answer_frontier` and `kernel.finding_todo.finding_standing` / `ruling_since` expose them.

**New material** (`application/review_concern.concern_material_after`): a ref counts only when it is
evidence, a result or an action recorded after the bound (the later of the standing position and the
last ruling); never a finding, claim or response/decision/check/plan event; an obligation counts only
if its `introduced_frontier` (a new reducer fact; republication only changes status) is after the
bound; evidence the agent itself cited in an answer never counts; when the concern names obligations
the ref must be linked to them (a result of an action listing one, evidence such a result or a claim
over them cites or an obligation lists as resolution evidence, an edit action, or an unlinked result
that did not succeed: a new failing run can show the problem remains, a new passing run cannot). Not
implemented: narrowing by cited file paths (evidence rows carry no path in the projection); the rule
above is the narrowest the recorded facts allow.

**Ruling admission** (`_admit_prior_verdicts`): `withdrawn` needs no citation and is admitted against
a rejection that stands; a `fixed` whose citations are trimmed but stay supported stays `fixed`; a
`still_present` or `answered_not_fixed` that loses a citation is `unassessable`; an unsupported
downgrade over a standing position that cites no concern material is recorded `disputed_after_rebuttal`;
a ruling on a resolved item or a disclosed limitation is set aside. (Amended 2026-10-13, tb4n5: only
an unsupported `still_present` or `answered_not_fixed` becomes the dispute; an unsupported `fixed`
or `withdrawn`, and an `unassessable`, stay `unassessable`. A `fixed` may cite the repair by the
event that recorded it.)

**Reverse edges** (ADR-034 amendment): `acknowledged_not_done` and `self_verified` are not one-way
doors; see there. The respond text for a refused answer names the state and the way out and no longer
says "answer it there" about an item `respond` refuses.

Wire (unreleased 0.3, changed in place): `response-recorded` 1.1.0, `respond-request` and
`respond-result` 1.1.0 gain the disposition `reopened` (reason required); `respond-result` 1.1.0 gains
optional `closure_after {todo_state, limitation?}` (the state the answer produced, simulated at its
own frontier); status finding items allow `resolved: true` on `acknowledged_not_done` and
`self_verified` (absence proven after the answer). `result_recorded` acceptance of a causal parent
without `action_id` is not implemented: the frozen event schema still requires `action_id`, so the
finding text for `action_without_result` names the `act_` id and the linking recipe, and the MCP
rejection of an unlinkable result says what links one (N3-5).

Risks: the normalized fold can still merge two distinct concerns of a comparable kind that overlap
on one obligation, but only into a settled item or the same open kind over an equal concern, and each
fold is disclosed through `semantic_restatements_suppressed` and the review summary. A concern
absorbed into a settled item stays absorbed (bounded at 32).

## Amendment 2026-10-12 (issue #1024, owner decision): the agent's answer decides what a limitation request means

Decision (maintainer TheGaySupreme123, 2026-10-12), replacing the Q4 reading of `acknowledged_not_done`
("any `respond` acknowledgement with a reason settles it as a disclosure"): a reviewer's
`state_unresolved_limitation` request is answered by the agent, and the agent's answer decides what it
means.

| Agent answer | Meaning | State and class | Receipt |
|---|---|---|---|
| none yet | to disclose | `limitation_requested`, `agent_work`, next action `acknowledge` | counted "to disclose", never repair work (unchanged) |
| `acknowledged` with a reason; a reasoned `self_verified`; a `finishup-verification-limit:<obligation>` decision | the requirement may be met but cannot be verified here | `limitation_disclosed`, `settled_disclosed` | at best `insufficient_coverage`, listed under "Verification limits" (as before) |
| `acknowledged_not_done` | the requirement is NOT met | `limitation_acknowledged_not_done`, `settled_unmet` | `unresolved_findings_remain`, listed with the requirements acknowledged as not done, never under "Verification limits" |

Why: the Q4 reading moved lake S (`fnd_8bdad2d0`, reward 0, accuracy really unmet) from
`unresolved_findings_remain` to `insufficient_coverage`. An agent that says "not done" has said the
requirement is unmet; the receipt must not turn that into a verification limit. The agent who finds
the requirement may be met after all takes the answer back with `reopened` and discloses.

Implementation: one place. `kernel/limitation.limitation_standing` reads the agent's answer first
(a third state `limitation_acknowledged_not_done`, `LimitationStanding.unmet`, basis
`respond_acknowledged_not_done`) and `disclosing_response` no longer counts `acknowledged_not_done`;
`kernel/closure_class` maps a limitation request in the `ACKNOWLEDGED_NOT_DONE` to-do state to the
basis `limitation_acknowledged_not_done` (`FINDING_BASES`: `settled_unmet`,
`unresolved_findings_remain`, next actions `reopen`, `repair`). Every consumer reads the class:
status, the check checklist and continuation, `closure_prepare`, the receipt document and its
renderings (the finding is in `acknowledged_not_done_finding_ids`, not `limitation_disclosed_finding_ids`),
the readiness `acknowledged_not_done` list, and the post-compaction recap. A recorded decision line
never turns an `acknowledged_not_done` answer into a disclosure (the answer is read first); the
decision line still marks the obligation `externally_evaluated`. The reviewer packet row of an
answered request carries `disposition: acknowledged_not_done` and no `limitation_already_disclosed`
mark. Guards G1-G4 are unchanged and still tested. Wire (unreleased, in place):
`closure_basis` gains `limitation_acknowledged_not_done` (status-result 1.4.0, check-result 1.4.0) and
`respond-result` 1.1.0 `closure_after.limitation` gains the same value.

Agent guidance (the four host skills, `workflow.md`, `request-templates.md`,
`coverage-and-receipts.md`, the finding explanation, the CLI continuation text and the `respond`
descriptor): "If the requirement may be met but cannot be verified here, respond `acknowledged` with
the reason; respond `acknowledged_not_done` only when you know it is not met."

## Amendment 2026-10-12 (issues #1042, #1043, #1046, tb4n4): the review judges incomplete work

The owner asked for #1038-#1052 to be fixed together on 2026-10-12 (maintainer TheGaySupreme123);
that request is the acknowledgement these design-gated changes need. tb4n4 measured the semantic
arm: of 79 reviewer findings 34% were correctness opinions outside the frame and only 35% were
in-frame incomplete-work catches; 19% were wrong (agents rejected 14 of 15 with evidence, so the
cost was time). 5 `action_without_result` and 4 premature "nothing implemented yet" findings were
about FinishUP's own process state although the instruction forbids it (section 5 dropped only "never
attempted"). On interleaved-vigenere S the reviewer turned failures of the agent's own oversized
stress runs (12 streams, seed lengths 9-32, beyond the sample family) into
`task_requirement_unmet`; the agent spent about forty minutes adding a language model that loaded
two undeclared data files, and the grader's copy printed nothing. 18 of 61 semantic-arm tasks
reviewed the plan before any work, and 39 `self_verified` answers in 24 tasks (plus 16
`resolution_attempt_required` rounds) followed a reviewer `fixed` ruling that environment facts
such as `verification_only_as_root` kept from closing its finding.

### 1. A routine review judges incomplete work; correctness concerns are advisory (#1042)

The reviewer instruction and the routine question say: during work in progress judge incomplete
work only (an obligation marked resolved or left unfinished, planned verification not run, a missing
or emptied output, a done or ran claim the packet does not show, an early stop); work not yet
started is not a defect; a correctness concern is returned as `code_defect`. The check enforces the
frame without extra packet bytes: `validate_semantic_judgment(..., review_phase="routine")` records a
`code_defect` challenge that would mint a new finding as an advisory note, appended to the fenced
`review_summary` under a fixed FinishUP header and counted in `advisory_notes` (the accounting is
returned = accepted + rejected + suppressed + advisory). A re-raise of a recorded finding still folds
onto it. No gap is added: the review saw everything and the note is kept whole. The final phase
(`final_review`, or any completion claim) is unchanged: correctness and completeness are findings
there. The phase comes from the review input manifest, else from `select_semantic_budget_profile`;
a caller that passes none keeps the earlier rules.

### 2. Process state is filtered and disclosed, never minted (#1042)

`kernel/review_frame.py` decides from the frozen projection and the challenge's resolved subjects,
never the reviewer's words; anything unreadable keeps the challenge.

- `finishup_process_state_only`: every subject is the hook observation of a call to one of FinishUP's own
  tools (or its result), or, for `action_without_result`, any hook-observed action (pairing a hook
  observation with its result is FinishUP's capture; the `check` call is always in flight). A
  description is trusted only on a service-stamped observation. Reason `yoetz_process_state`, every
  phase.
- Amended 2026-10-13 (tb4n5 follow-up): the local rule owns the action/result relation for every
  readable action or result, published or observed. `local_rule_owned` drops an
  `action_without_result` or `result_without_action` challenge that cites a readable action or
  result event and nothing unreadable, reason `local_rule_owned`, every phase; see the amendment of
  2026-10-13 below. The restriction to hook-observed subjects above stays only for
  `yoetz_process_state`.
- Section 5 now reads the phase the packet named: during a routine review an AI-powered
  `requested_item_never_attempted` is dropped (reason `routine_completeness`); the closing review
  keeps it even when the agent stops without a completion claim, which is exactly the early stop
  a closing review exists to catch.

"Nothing implemented yet" raised under `task_requirement_unmet` or
`completion_with_open_obligations` is not filtered: without the reviewer's words it cannot be told
from a real unmet requirement or an obligation left unfinished (in frame). Those raised before any
work go with the review before the first edit (section 4), and the routine instruction says work not
yet started is not a defect; whether that covers all four tb4n4 cases needs the exports.

Both reasons disclose the new standing code `semantic_process_state_filtered` (gap table G5d,
disclosed on both routes, tolerated by both absence proofs) instead of `semantic_challenges_rejected`,
which keeps bounding for every other dropped challenge: a challenge about FinishUP's state is not
material the check failed to carry. Item 3 of #1042 (wrong-finding and in-frame rates per run) is
the maintainer's harness measurement; the bounded `semantic_review_accounting` record now carries
`semantic_challenges_advisory`, `semantic_agent_criteria` and `semantic_rejected_yoetz_process_state`
beside the existing per-reason counts, so a run's findings can be attributed to the frame.

### 3. The agent's own probe is its own criterion (#1043)

New finding kind `agent_criterion_unmet` (priority 2, research-evidence pack): a failure only on
probes the agent itself authored beyond the task's stated scope. The owner's nuance holds: criteria
the agent declared are its commitments, so the finding is real; the defect was the label. The
reviewer is told to use it, never `task_requirement_unmet`, for such a failure.
`is_limitation_request` is true for this kind whatever next step the reviewer asked for (guard G1
applies to requirement kinds; narrowing one's own criterion is always honest), so the #1024
lifecycle applies: `limitation_requested` ("to disclose", never receipt-blocking work),
next actions `acknowledge` and `repair`; a reasoned `acknowledged` narrows it into
`limitation_disclosed` (receipt at best `insufficient_coverage`, listed under "Verification limits");
`acknowledged_not_done` is `limitation_acknowledged_not_done`; a later check that proves it absent
resolves it. The finding explanation says "Your own criterion ... fix it, or narrow the criterion".
Two parts of that lifecycle belong to the reviewer's request to state a hidden evaluator's limit and
never apply to the agent's own criterion (review of #1043). A `finishup-verification-limit` decision
neither discloses it nor marks its obligation `externally_evaluated` (`kernel.limitation`, G1): the
probe fails here, and only the agent's own answer to that finding narrows it, so an unrelated
decision line recorded for a hidden grader can no longer settle it unanswered. And the check never
continues with `disclose_limitations` ("no repair is needed") for it: an open one is work, so
`overall_next.action` and `finding_checklist.next` read `work_open_findings` (the checklist still
says `decide_at_budget` at the round budget), and the text says fix it, or narrow it with
`acknowledged` and a reason. The finding counters still count it under `to_disclose`; no token,
basis or wire shape changed.

Kernel routing (`agent_probe_only`), deterministic and conservative: a reviewer
`task_requirement_unmet` is recorded as `agent_criterion_unmet` only when (a) at least one effective
obligation that is neither acknowledged as not done nor confirmed blocked requests a command (the
task's own sample or verifier as the plan declares it); (b) the case carries none of
`planned_verification_failed|not_observed|stale|unobservable|outcome_unknown`, so every declared
verification ran after the last edit and passed; (c) the challenge cites at least one recorded run,
and every work subject it cites is a hook-observed command run (the action, its result, or output
evidence that result lists) matching none of those requested commands and not linked by the agent to
a requested command value (PL6-3, `task_facts.agent_linked_run_events`: the link the task facts
accept as that obligation's planned verification, `planned_verification_agent_linked`, so a linked
run is the declared verification, never a run beyond it; review of #1043 x #1049); obligations,
claims and the plan or statement events it also cites are the requirement being judged; (d) the
command-identity key is registered (hook rows store commands only as keyed commitments). An edit,
an agent-published action, a linked run, an unmatched or unreadable row, a frozen prefix the check
could not read (links unknown), or a missing key keeps `task_requirement_unmet`. The review
summary says, in fixed words and a count, that the challenge was recorded as the agent's own
criterion. Residual, disclosed here: hook rows carry neither command text nor paths (privacy), so the
predicate cannot tell a run of the agent's own stress script from a run of a task-supplied example
the agent did not declare as verification; such a failure is also routed. It stays a visible,
never-clean finding the agent must fix or narrow with a reason, and the receipt lists the narrowing.

Wire, all unreleased on 0.3 and changed in place: `finding_kind` gains `agent_criterion_unmet` on
`finding` 1.4.0, `finding_recorded` 1.4.0 (the only version that carries it), provider judgment
1.2.0, check-result 1.4.0 and status-result 1.4.0. A delegated child's finding keeps its kind
on the parent: the lineage child-finding row of `child-dependencies-recorded` 1.0.0 and
`receipt-document` 1.3.0 (both unreleased, widened in place) admits `agent_criterion_unmet`
(priority 2, actionable) and the two review kinds it had omitted, `code_defect` and
`task_requirement_unmet`. Before that, a child holding any of the three produced a manifest outside
its schema and a parent JSON receipt that failed validation (review of #1043).

### 4. No review before the first material edit (#1046)

A check runs the local checks only and records `not_requested`/`deferred_before_first_edit`
(check-result and check-recorded 1.5.0; 1.4.0 still replays `deterministic_mode`) with the
standing gap `semantic_review_deferred_before_first_edit` (G7, semantic-only for absence proofs; its
effect follows the route the check recorded, below) when all hold: the phase is routine; the mode,
the `policy` route and the configured reviewer would dispatch a review (`semantic_required`
included); the frozen prefix records no material edit (`material_edit_recorded`: a counting
observed edit or shell write under ADR-042/045, whether or not its result arrived, so a Codex shell
`apply_patch <<EOF` counts by the files its patch names, or an agent-published `edit` action); and
the check-time capture did not observe a workspace change. Nothing is composed or sent. The deferral
comes before the review's own admission, so a pre-work check asks for no repository grant,
disclosure decision or review input either, and a missing provider or a policy block
(`not_configured`, `blocked_by_policy`) is reported by the first check after the edit. A resumed
check keeps its decision: one already in `semantic_wait` keeps its review, and one resumed in
`ready_to_finalize` reads no fresh capture: if its operation owns a review job it reviewed and is
not deferred, otherwise the frozen prefix decides. The deferral never applies to the closing
review, and where the deferred check's route requires review readiness asks for that review
(below), so a task whose work is not an edit still reaches one there. The older stopped-round skip (`semantic_review_skipped_insufficient_packet`, ADR-006
tb4n1 D3, #983) is a separate rule this section does not change: it can still skip a closing review
that is not `semantic_required`.
The deferral is not a failed review: the verdict reads from the local checks, never
`incomplete_check`. Its effect follows the route the deferred check recorded, exactly like the
`semantic_review_not_requested` it rides with (ADR-046 rule G1): where the check recorded
`semantic_route_required: false` (a route that does not require review) both are disclosed, so the
check, status and receipt read as a `deterministic_only` check on that route would, and a deferral
FinishUP chose never reads worse than a local-only check the agent chose; where review is required
both bound (`insufficient_coverage`) until a review is current. The next check after the first
edit reviews as configured. Where the deferred check's route requires review, that review stays
owed: the deferred check counts as a use of AI-powered review for `closing_review_required` (it
stands in for the review the task owes, also when a `semantic_required` check runs under an
optional policy), and while the latest check so deferred, the actionable
`semantic_review_not_requested` no longer hides `closing_review_required`: a routine check would
only defer again, so the closing review (the Stop gate's review token) is the way to supply it.
Where the check recorded `semantic_route_required: false`, a deferral asks for nothing, exactly like
a `deterministic_only` check on that route: counting it as a use there would leave an optional
reviewer that cannot answer (a missing credential, a provider timeout: neither current nor
undeliverable) demanding the closing review at every Stop, and the check's own next step would
disagree with status. The CLI, MCP check text, status text, and the receipt limitations section say
"AI-powered review is on; it starts after your first edit." Older records that still carry
`deterministic_mode` beside the deferral gap render that same sentence.

### 5. A cited `fixed` ruling closes its finding despite environment facts (#1046)

`_TASK_FACT_GAPS_TOLERATED_WHEN_FIXED` (issue #1000: `write_outside_workspace`,
`obligation_blocked_outside_agent_control`) now holds every environment fact:
`verification_only_as_root`, `install_into_private_env`, `install_into_yoetz_runtime` and the
planned-verification observer heuristics (`agent_linked`, `matched_by_prefix`, `outcome_unknown`,
`unobservable`). Admission already requires a `fixed` ruling to cite evidence or a result recorded
after the finding (by its own id or, since the amendment of 2026-10-13, by the event that recorded
it). The facts stay on the receipt (gap table G4) and the resolved finding's
explanation names the ones its resolving check carried. Facts about the deliverable
(`requested_output_*`, `declared_output_*`, `deliverable_references_undeclared_file`), every
agent-actionable fact and a silent review keep blocking.

Gap table: two recorded codes added (215 recorded + 3 readiness-only rows); they ship under the
unreleased classification version `"8"`, with #1044's `G0c` row (ADR-046). Hosts: the change is in the shared check, kernel and provider
instruction, so Codex, Claude Code and Cursor behave the same; no host adapter changed. Acceptance
on the tb4n4 exports (replaying the 60 exports for the wrong-finding and in-frame rates) remains for
the maintainer.

## Amendment 2026-10-13 (tb4n5 follow-ups of #1042 and #1046): the findings lifecycle

Evidence: the tb4n5 rerun on 0.3 at 0291f441d (#1054), 18 attempts, read by two independent
reviews. Owner decisions of 2026-10-13: state the action/result pairing rule and return a
publish-time notice; a sibling action in the same publish batch does not trigger
`action_without_result`; a plain ledger link resolves it under capture gaps, disclosed on the
receipt; the local rule owns `action_without_result`/`result_without_action` and the AI duplicates
are dropped; `evt_` citations map to the result or evidence they recorded and an unsupported
`fixed` never becomes a dispute; an acknowledgement may still count as a rebuttal.

### 1. Every published action is paired with its result

tb4n5 raised `action_without_result` in 13 of 18 attempts (15 local findings), each on an action
the agent itself published, 8 edits, 4 research actions and 3 commands. None was a lost link: every
agent published the result after the finding asked for it. Agents conveyed outcomes through
evidence and decisions, which link nothing, and no guidance said up front that an
`action_recorded` needs a `result_recorded` naming its `act_` id.

- **Guidance.** `workflow.md` step 5 and the pre-flight, the operating card, `publication.md` and
  `request-templates.md` (a completed-action example publishing the result in the same batch) state
  the pairing rule: a result whose payload `action_id` is the action's id, any outcome, normally in
  the same batch; evidence, decisions and causal parents do not link an action.
- **Publish-time notice.** `publish_work` (and its dry run) returns `action_notices` naming each
  action the batch recorded that no result names yet, with one fixed text (`result_not_linked`).
  It admits as many rows as a batch admits drafts (100), so a full batch is never cut, records
  nothing and changes no finding. Golden vectors: fixture `CAN-018`
  (`scripts/generate_publish_action_notices_fixture.py`, checked by the resource ripple).
- **Same-batch siblings.** A sibling action of the same cooperative `publish_work` batch is never
  "subsequent unrelated work" (8 of 15 tb4n5 findings fired only on one, medical S L95). The frozen
  case carries the batches (`DeterministicCase.action_batches`, emitted only when present); the
  work-integrity pack stays `0.3.0`, unreleased and amended in place. A genuinely unaccounted action
  is still raised by unrelated work in a later batch, and only a result naming the action links it.
- **A ledger link resolves it under capture gaps.** A readable result naming the readable
  action at the tested frontier proves a deterministic `action_without_result` absent even under
  `truncated_payload` or `content_capture_unavailable` (tb4n5 react S stayed open under them after
  the agent linked the result and had to answer `self_verified`); the codes stay on the check and
  receipt. The owner's decision names capture gaps only, so `command_attempt_uncorroborated` and
  `command_attempt_mismatch` keep #682's obligation partition (INTERFACES, "Command-gap
  independence"): tb4n5 formal S, an unbound action under `command_attempt_mismatch`, still reads
  `command_relation_independence_unproven`; the owner may widen this later. Redacted or unavailable
  ledger rows, a later result and every ordinary qualification rule still block.

Hosts: the rule, notice and guidance are shared (check, kernel, publish and the MCP text channel),
so Codex, Claude Code and Cursor behave the same; the CLI returns the same JSON field. No host
adapter changed.

### 2. The local rule owns the action/result relation (#1042 follow-up)

In 3 of 9 S tasks the reviewer raised "action has no linked result" beside the local finding on the
same agent-published action: vigenere S cited the local subject plus an evidence event, live-db S
the identical subject, and medical S cited the sibling command while its text named the engine
edit. #1042's filter dropped such a challenge only when every subject was hook-observed, so all
three were minted; each local twin resolved after the agent linked the result, and each AI twin
latched `disputed_after_rebuttal` (never clean), and the agent's corrective `self_verified` was
refused with `finding_terminal`. The reviewer sees a bounded packet and cannot know that a result
outside it exists; the local rule reads the whole ledger and decides the relation exactly.

The label is never proof: a reviewer can file a false completion or an unrun verification under
`action_without_result`. `kernel.review_frame.local_rule_owned` is therefore true only when the
cited records show nothing but the pairing gap the local rule decides: an `action_without_result`
challenge whose every cited event recorded a readable action that no readable result names (at
least one), or a `result_without_action` challenge whose every cited event recorded a readable,
successful result whose action is absent (at least one); either may also cite events of readable
evidence that no claim and no result that did not succeed cites (the vigenere S shape). Every other
subject keeps the challenge as the reviewer gave it: an action that already has a result (the
concern is not the missing link), a claim or an obligation (a completion, requirement or
planned-verification concern), a result or evidence of a run that did not succeed (a failure
concern), a decision, or anything unreadable or unknown. A dropped challenge is counted under the
rejection reason `local_rule_owned` (`semantic_rejected_local_rule_owned` in the accounting record)
and disclosed through the existing standing code `semantic_process_state_filtered` (G5d: never
bounding, never vetoing an absence proof). Every other kind about the same action is reviewed as
before. This supersedes the "agent-published actions are kept" rule of section 2 above for these
two kinds only. Residual: a concern about an unpaired action that cites nothing else (for example
"the verification never ran" filed as `action_without_result` on the unpaired command) is dropped;
the local rule raises the missing result once later work exists, the publish notice names it at
once, and the planned-verification task facts still report an unobserved or outcome-unknown run.
The reviewer instruction is unchanged; the gloss of both kinds still describes them.

### 3. A cited repair resolves; only a held-open ruling is a dispute (#1046 follow-up)

tb4n5 S ended with 8 of 11 AI findings `disputed_after_rebuttal` and none `verified_resolved`.
kv-live-surgery S `fnd_c96c2b9f` is the concrete case: the agent published the repair result
(`res_fc7a82cf`, event `evt_3318a99d`), acknowledged the finding with a reason citing it, and the
next reviewer supported the repair citing `evt_3318a99d`; the row latched as a dispute, carried
`semantic_prior_verdicts_unsupported`, and its detail still said "repair it, then check" or
`self_verified`, both refused on a final item. The exports omit raw reviewer rulings, so the other
seven are not all proven agreed repairs; the admission hole and the terminal text are.

- `_ruling_supported("fixed")` resolves an `evt_` citation to the evidence or result that event
  recorded before the after-the-finding test. The packet offers both by event id; tb4n5 reviewers
  cited `res_` 0 times in 41 reviews. An event that recorded anything else never supports `fixed`.
- Ruling admission records `disputed_after_rebuttal` only for a `still_present` or
  `answered_not_fixed` ruling (supported or not) over a standing position with nothing newer. An
  unsupported `fixed` (the reviewer says the issue is gone), an unsupported `withdrawn`, and the
  reviewer's own `unassessable` (it could not judge) are recorded `unassessable`: an open round the
  next review can rule on, never a disagreement the agent can no longer answer. Section 1 and the
  RC-7 ruling-admission rule are amended accordingly.
- That open round has a hard bound (`kernel.review_round.unassessable_review_exhausted`, the
  insufficient-packet stop of tb4n1 D3 applied to one finding): after two completed reviews in a
  row ruled one AI-powered finding `unassessable` with no edit since the older of them, or four in
  a row whatever was edited, later checks skip the AI-powered review and record the existing
  standing code `semantic_review_skipped_insufficient_packet`, whose CLI, MCP and receipt text now
  say "could not assess the packet or a finding you answered". The finding is never resolved or
  turned into a dispute by this: it stays open, the receipt reads `unresolved_findings_remain` and
  discloses the skip, closure readiness demands no further review, and the gap is a FinishUP limit,
  so the agent may answer `self_verified` for a repair it verified itself. A recorded edit re-arms
  one more review until the cap of four. As for insufficient packets, a `semantic_required` check
  still runs the review the user or policy requires; the bound stops the reviews FinishUP would
  otherwise keep requesting. (The tb4n5 Codex check reproduced the unbounded form: budget 2,
  seven completed reviews, eight provider calls.)
- No-repeat protection is unchanged: an acknowledgement with a reason still counts as a rebuttal
  (owner, 2026-10-13); a held-open ruling or a restatement of the concern over it that cites
  nothing newer still latches the dispute; a restatement that contradicts a `fixed` ruling still
  does too.
- The resolution explanation of a `disputed_after_rebuttal` row no longer requires the latest
  answer to be `rejected`: an acknowledged item reads "Disputed after rebuttal ... takes no further
  response" instead of the unresolved repair instruction; its `next_actions` stay `none`.

### 4. A repeated answer on a resolved finding gets a precise hint

Four of the seven tb4n5 `finding_terminal` refusals were an `acknowledged` sent after a recheck had
already proved a local `action_without_result` absent. `respond` still records nothing and still
returns `finding_terminal` (no wire change), but the message for `verified_resolved` now says the
issue was proved absent, nothing is owed and not to retry, and the one for
`disputed_after_rebuttal` says what the state means.

Not changed here: #1043 (`agent_criterion_unmet` routing for agent-published probes) stays as
decided; the formal-crypto case is not shown to be beyond the task's scope.
