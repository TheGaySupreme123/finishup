# ADR-040: Binding rules for reviewer disagreement; review requirement derived from the route

- Status: accepted (2026-10-08)
- Issues: #1020 (tb4n2 R1), #1021 (tb4n2 R6), #1024 (tb4n3 RC-1), #1030 (tb4n3 RC-7), #1042, #1043,
  #1046 (tb4n4, amendment of 2026-10-12 below)
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
  and the Codex skill. tb4n4 amendment: `kernel/review_frame.py`, `application/check.py`
  (`validate_semantic_judgment(review_phase=...)`, `_review_deferred_before_first_edit`,
  `_review_skip_gaps`), `kernel/task_facts.py` (`material_edit_recorded`),
  `kernel/finding_resolution.py` (`_TASK_FACT_GAPS_TOLERATED_WHEN_FIXED`), `domain/findings.py`
  (`AGENT_CRITERION_UNMET`, `is_limitation_request`), `kernel/closure_class.py`,
  `kernel/gap_effect.py` and `kernel/closure_readiness.py` (`_closing_review_facts`).

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

## Amendment 2026-10-12 (issues #1042, #1043, #1046, tb4n4): the review judges incomplete work

The owner asked for #1038-#1052 to be fixed together on 2026-10-12 (maintainer TheGaySupreme123);
that request is the acknowledgement these design-gated changes need. tb4n4 measured the semantic
arm: of 79 reviewer findings 34% were correctness opinions outside the frame and only 35% were
in-frame incomplete-work catches; 19% were wrong (agents rejected 14 of 15 with evidence, so the
cost was time). 5 `action_without_result` and 4 premature "nothing implemented yet" findings were
about Yoetz's own process state although the instruction forbids it (section 5 dropped only "never
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
`review_summary` under a fixed Yoetz header and counted in `advisory_notes` (the accounting is
returned = accepted + rejected + suppressed + advisory). A re-raise of a recorded finding still folds
onto it. No gap is added: the review saw everything and the note is kept whole. The final phase
(`final_review`, or any completion claim) is unchanged: correctness and completeness are findings
there. The phase comes from the review input manifest, else from `select_semantic_budget_profile`;
a caller that passes none keeps the earlier rules.

### 2. Process state is filtered and disclosed, never minted (#1042)

`kernel/review_frame.py` decides from the frozen projection and the challenge's resolved subjects,
never the reviewer's words; anything unreadable keeps the challenge.

- `yoetz_process_state_only`: every subject is the hook observation of a call to one of Yoetz's own
  tools (or its result), or, for `action_without_result`, any hook-observed action (pairing a hook
  observation with its result is Yoetz's capture; the `check` call is always in flight). A
  description is trusted only on a service-stamped observation. Reason `yoetz_process_state`, every
  phase.
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
which keeps bounding for every other dropped challenge: a challenge about Yoetz's state is not
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
lifecycle applies unchanged: `limitation_requested` ("to disclose", never receipt-blocking work),
next actions `acknowledge` and `repair`; a reasoned `acknowledged` narrows it into
`limitation_disclosed` (receipt at best `insufficient_coverage`, listed under "Verification limits");
`acknowledged_not_done` is `limitation_acknowledged_not_done`; a later check that proves it absent
resolves it. The finding explanation says "Your own criterion ... fix it, or narrow the criterion".

Kernel routing (`agent_probe_only`), deterministic and conservative: a reviewer
`task_requirement_unmet` is recorded as `agent_criterion_unmet` only when (a) at least one effective
obligation that is neither acknowledged as not done nor confirmed blocked requests a command (the
task's own sample or verifier as the plan declares it); (b) the case carries none of
`planned_verification_failed|not_observed|stale|unobservable|outcome_unknown`, so every declared
verification ran after the last edit and passed; (c) the challenge cites at least one recorded run,
and every work subject it cites is a hook-observed command run (the action, its result, or output
evidence that result lists) matching none of those requested commands; obligations, claims and the
plan or statement events it also cites are the requirement being judged; (d) the command-identity
key is registered (hook rows store commands only as keyed commitments). An edit, an agent-published
action, an unmatched or unreadable row, or a missing key keeps `task_requirement_unmet`. The review
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

A check runs the local checks only and records `not_requested`/`deterministic_mode` with the new
standing gap `semantic_review_deferred_before_first_edit` (G7, semantic-only for absence proofs; its
effect follows the route the check recorded, below) when all hold: the phase is routine; the mode,
the `policy` route and the configured reviewer would dispatch a review (`semantic_required`
included); the frozen prefix records no material edit (`material_edit_recorded`: a counting
observed edit or shell write under ADR-042/045, or an agent-published `edit` action); and the
check-time capture did not observe a workspace change. Nothing is composed or sent. The deferral
comes before the review's own admission, so a pre-work check asks for no repository grant,
disclosure decision or review input either, and a missing provider or a policy block
(`not_configured`, `blocked_by_policy`) is reported by the first check after the edit. A resumed
check already in `semantic_wait` keeps its decision; the deferral never applies to the closing
review, and readiness asks for that review (below), so a task whose work is not an edit still
reaches one. The older stopped-round skip (`semantic_review_skipped_insufficient_packet`, ADR-006
tb4n1 D3, #983) is a separate rule this section does not change: it can still skip a closing review
that is not `semantic_required`.
The deferral is not a failed review: the verdict reads from the local checks, never
`incomplete_check`. Its effect follows the route the deferred check recorded, exactly like the
`semantic_review_not_requested` it rides with (ADR-046 rule G1): where the check recorded
`semantic_route_required: false` (a route that does not require review) both are disclosed, so the
check, status and receipt read as a `deterministic_only` check on that route would, and a deferral
Yoetz chose never reads worse than a local-only check the agent chose; where review is required
both bound (`insufficient_coverage`) until a review is current. The review stays owed: the next
check after the first edit reviews as configured, and closure readiness asks for the closing review
after a deferral on every route. A deferred check counts as a use of AI-powered review for
`closing_review_required` (it stands in for the review the task would have run), and while the
latest check deferred, the actionable `semantic_review_not_requested` on a required route no longer
hides `closing_review_required`: a routine check would only defer again, so the closing review
(the Stop gate's review token) is the way to supply it. The CLI, the MCP check lead and the
receipt's limitations sentence say "AI-powered review deferred".

### 5. A cited `fixed` ruling closes its finding despite environment facts (#1046)

`_TASK_FACT_GAPS_TOLERATED_WHEN_FIXED` (issue #1000: `write_outside_workspace`,
`obligation_blocked_outside_agent_control`) now holds every environment fact:
`verification_only_as_root`, `install_into_private_env`, `install_into_yoetz_runtime` and the
planned-verification observer heuristics (`agent_linked`, `matched_by_prefix`, `outcome_unknown`,
`unobservable`). Admission already requires a `fixed` ruling to cite evidence or a result recorded
after the finding. The facts stay on the receipt (gap table G4) and the resolved finding's
explanation names the ones its resolving check carried. Facts about the deliverable
(`requested_output_*`, `declared_output_*`, `deliverable_references_undeclared_file`), every
agent-actionable fact and a silent review keep blocking.

Gap table: two recorded codes added (215 recorded + 3 readiness-only rows); they ship under the
unreleased classification version `"8"`, with #1044's `G0c` row (ADR-046). Hosts: the change is in the shared check, kernel and provider
instruction, so Codex, Claude Code and Cursor behave the same; no host adapter changed. Acceptance
on the tb4n4 exports (replaying the 60 exports for the wrong-finding and in-frame rates) remains for
the maintainer.
