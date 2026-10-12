# ADR-040: Binding rules for reviewer disagreement; review requirement derived from the route

- Status: accepted (2026-10-08)
- Issues: #1020 (tb4n2 R1), #1021 (tb4n2 R6), #1024 (tb4n3 RC-1), #1030 (tb4n3 RC-7)
- Amends: ADR-034 (finding to-do states), ADR-033 amendment of 2026-10-08 (#986, "record route;
  don't block"), ADR-006 (reviewer instruction)
- Maintainer acknowledgement: the owner approved all tb4n2 core issues R1-R10, design changes
  included, on 2026-10-08 (maintainer TheGaySupreme123: "all r been agreed").
- Implemented by: `kernel/later_material.py`, `kernel/check_standing.py`, `kernel/reducers.py`
  (`invalidates_recorded_check`), `domain/yoetz_tools.py` (tb4n3 RC-6, #1029),
  `application/check.py` (`_admit_prior_verdicts`, `_disputed_after_rebuttal`,
  `_record_restatement`, `_restated_finding`, `semantic_route_required`), `kernel/concern.py`,
  `kernel/limitation.py`, `application/review_concern.py` (tb4n3 RC-1 and RC-7, amendment below),
  `kernel/finding_resolution.py` (`apply_check_rulings`), `kernel/finding_todo.py`,
  `kernel/receipt_builder.py` (`_conclusion`), `domain/receipts.py`, `kernel/closure_readiness.py`,
  `adapters/providers/openai_responses.py`; guidance `workflow.md`, `coverage-and-receipts.md`
  and the Codex skill.

## Context

Yoetz exists to catch incomplete work. It is not a bug finder, and the worst outcome is Yoetz
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
`unassessable`) is recorded by Yoetz as the ruling `disputed_after_rebuttal` when all of these hold:

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
| `yoetz_own_call` | the observation of a call to one of Yoetz's own MCP tools, any host spelling (`mcp__yoetz__x`, `mcp__plugin_yoetz_yoetz__x`, bare `x`, `yoetz:x`, `plugin-yoetz-yoetz:x`, Cursor's generic `MCP:x` by the closed basenames) | ignored |
| `exploration` | an observed run of the hook's `exploration` runner class, a native read tool, a routine-read summary | ignored |
| `no_tool_activity` | host stream bookkeeping that names no tool call: `Opaque observation kind=<Codex wrapper kind>`, `Observed completion signal kind=...`; and a host poll tool that returns the output of work started earlier (Codex `wait`, a poll output that follows the last check in 18 of 27 tb4n2/tb4n3 semantic-arm attempts) | ignored |
| `non_counting_write` | an observed edit whose every path is scratch or Yoetz-owned (ADR-042) | ignored |
| `response` | a cooperative answer to a finding | advisory (above) |
| `edit_or_write` | an observed deliverable, workspace or outside-workspace edit | supersedes the check: `check_not_applicable`, freshness `stale_after_material_change`, closing review required again |
| `other` | anything Yoetz cannot prove harmless: an unclassified command or tool, an unpaired host result, a subagent, a lineage manifest | keeps the bounding disclosure |

A result is classified by the action it answers. A Yoetz receipt or export the agent saved is
exempt even when a declared output directory would otherwise make a lexical `yoetz_owned` write
count for verification staleness (ADR-042 decision 1): it is the output about the check, so no
check could cover it, and counting it would invalidate the check that produced it. The exemption
ends where a declared output is itself a packaged Yoetz tree (`.agents/...`): a write there may be
the deliverable and keeps counting.

Readiness keeps `check_current_as_of_earlier_frontier` a standing disclosure (the gap table and
`gap_classification_version` are unchanged), including while a counted observation bounds the
receipt. The tb4n2 B5 proposal to list it as agent work ("one more check removes it") was
examined and not adopted: every variant of it can regenerate after the check it asks for, and an
instruction an agent cannot complete is the worst outcome (steered wrong). Reproduced regenerators:
Cursor's structural `afterMCPExecution` result of every call (including each check's own) carries
no tool identity; an agent running the Yoetz CLI through its shell (`yoetz check ...`) records a
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
  the agent's evidence) or by a recorded `yoetz-verification-limit:<obligation id>` decision on an
  obligation the finding concerns. Acknowledging a limitation request needs no recorded resolution
  attempt (this relaxes the #885 rule for that class only; repair demands keep it). It is settled and
  never clean: closure readiness and the receipt list it, and a re-raise of the same concern folds
  onto it. A `rejected` answer disputes the request instead; `reopened` takes an answer back.
- **limitation_acknowledged_not_done** (owner decision 2026-10-12, amendment below): the agent
  answered `acknowledged_not_done`, which says the requirement is NOT met. It is an unmet
  requirement like any other, not a verification limit.

Guards, each tested: **G1** a challenge asking the agent to `act` is never a limitation request, even
beside a `yoetz-verification-limit` decision (the reviewer sees an obtainable path). **G2** nothing
reads the agent's own words, so an agent that answers an `act` finding "I could not find it" does not
turn it into a limitation (the pretrain-shard-corruption rescue, where the acknowledgement re-check
sent the agent back and it recovered the inputs, is kept). **G3** `declared_output_emptied` is
independent of the class: a disclosed limitation never clears the fact that a delivered file was
emptied. **G4** the class is never clean.

Reviewer instruction (same change): the final-phase question and the standing instruction say that a
requirement only a hidden evaluator or an unobtainable artifact can establish is a `not_assessable`
row once the packet shows the agent disclosed it (an obligation acknowledged as not done, a
`yoetz-verification-limit` decision, or a limitation request it acknowledged); a requirement
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
a ruling on a resolved item or a disclosed limitation is set aside.

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
| `acknowledged` with a reason; a reasoned `self_verified`; a `yoetz-verification-limit:<obligation>` decision | the requirement may be met but cannot be verified here | `limitation_disclosed`, `settled_disclosed` | at best `insufficient_coverage`, listed under "Verification limits" (as before) |
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
