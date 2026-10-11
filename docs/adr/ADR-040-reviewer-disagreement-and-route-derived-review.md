# ADR-040: Binding rules for reviewer disagreement; review requirement derived from the route

- Status: accepted (2026-10-08)
- Issues: #1020 (tb4n2 R1), #1021 (tb4n2 R6)
- Amends: ADR-034 (finding to-do states), ADR-033 amendment of 2026-10-08 (#986, "record route;
  don't block"), ADR-006 (reviewer instruction)
- Maintainer acknowledgement: the owner approved all tb4n2 core issues R1-R10, design changes
  included, on 2026-10-08 (maintainer TheGaySupreme123: "all r been agreed").
- Implemented by: `kernel/later_material.py`, `kernel/check_standing.py`, `kernel/reducers.py`
  (`invalidates_recorded_check`), `domain/yoetz_tools.py` (tb4n3 RC-6, #1029),
  `application/check.py` (`_admit_prior_verdicts`, `_disputed_after_rebuttal`,
  `_record_restatement`, `_restated_finding`, `_concern_key`, `semantic_route_required`),
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
code, and it may approve a reasoned, disclosed fallback.

### 3. Findings are advisory (guidance and Codex skill, issue #1020)

Agent guidance states: findings are advisory; never empty, truncate or delete a working deliverable
because a finding is open; disagree through `respond` (`rejected` with a reason, or
`acknowledged_not_done`).

### 4. Restatements across claim churn (issue #1020)

`_restated_finding` keeps the exact subject-set match first. Failing that, it matches the same
finding kind over a normalized key (`_concern_key`): each claim maps to the claim currently
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
| `no_tool_activity` | host stream bookkeeping that names no tool call: `Opaque observation kind=<Codex wrapper kind>`, `Observed completion signal kind=...`; and a host poll tool that returns the output of work started earlier (Codex `wait`, the trailing call of 9 of 14 tb4n2 semantic-arm suffixes) | ignored |
| `non_counting_write` | an observed edit whose every path is scratch or Yoetz-owned (ADR-042) | ignored |
| `response` | a cooperative answer to a finding | advisory (above) |
| `edit_or_write` | an observed deliverable, workspace or outside-workspace edit | supersedes the check: `check_not_applicable`, freshness `stale_after_material_change`, closing review required again |
| `other` | anything Yoetz cannot prove harmless: an unclassified command or tool, an unpaired host result, a subagent, a lineage manifest | keeps the bounding disclosure |

A result is classified by the action it answers. A Yoetz receipt or export the agent saved is
exempt even when a declared output directory would otherwise make a lexical `yoetz_owned` write
count for verification staleness (ADR-042 decision 1): it is the output about the check, so no
check could cover it, and counting it would invalidate the check that produced it.

When the suffix still bounds (`other` records), readiness lists
`check_current_as_of_earlier_frontier` as agent-actionable, because one more check removes it,
instead of "nothing further to do" beside a receipt it will bound. It stays a standing disclosure
when only responses followed. The gap table and its version are unchanged: the move is made by
the `earlier_frontier_bounds` readiness fact, like `check_not_applicable`.

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
