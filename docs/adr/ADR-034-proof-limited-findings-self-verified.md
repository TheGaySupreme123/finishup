# ADR-034 — Proof-limited findings: the `self_verified` respond disposition

**Status:** Accepted for [issue #984](https://github.com/TheGaySupreme123/yoetz/issues/984). The
owner chose this design on 2026-10-07 while reviewing TB4 run tb4n1: "I prefer this even if yoetz
can't find, let the agent respond and populate it." This counts as the maintainer
acknowledgement for this design-gated protocol change. It grants no runtime, credential,
disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/kernel/self_verification.py`, `src/yoetz/kernel/finding_resolution.py`
(`finding_resolution_attempt`, `UNRESOLVED_FINDING_NEXT_STEPS`, `finding_is_resolved`),
`src/yoetz/kernel/finding_todo.py`, `src/yoetz/kernel/closure_readiness.py`
(`finding_self_verified`), `src/yoetz/application/respond.py`, `src/yoetz/domain/findings.py`,
`src/yoetz/domain/events.py`, `src/yoetz/domain/receipts.py`, `src/yoetz/kernel/receipt_builder.py`,
`src/yoetz/protocol/models.py`, `src/yoetz/cli/render.py`, `src/yoetz/mcp/descriptors.py`,
`src/yoetz/mcp/summaries.py`, `scripts/generate_schemas.py`, and
`fixtures/canonical/review-dialogue-1.3.0.case.json`.
**Relates to:** ADR-032 (closure readiness), ADR-033 (Stop-time closure gate and blockers), and
issue #905 (`acknowledged_not_done` and terminal to-do states).

## Context

A finding is resolved only when a later qualifying check proves it absent
(`kernel/finding_resolution.py`). Yoetz's own limits can keep that proof out of reach for good:

- capture and observation loss (`command_attempt_uncorroborated`, `content_redacted`,
  `observation_input_loss`);
- review-packet limits (`semantic_packet_insufficient`, `semantic_reference_scope_reduced`, clipped
  diffs, content types the reviewer cannot see).

In tb4n1, readiness kept `receipt_findings_unresolved` agent-actionable in every case. The
Stop-time gate (ADR-033) then gave the agent two exits: repair, or stop for a `yoetz-blocker`. The
agent could not repair a Yoetz limit, so it filed a blocker on finished work:

- 38 attempts declared a blocker, and every one of them had been gated first.
- 27 to 30 attempts blamed Yoetz for work they had already finished.
- Those blockers claimed "authority", "consent" or "dependency unavailable".
- The time spent after the work was done was a median of 4.8 minutes in D and 10.4 in S, against
  0.4 minutes in V.
- 38 receipts read `unresolved_findings_remain`, and none read clean.

`acknowledged_not_done` (#905) means "I will not do it". That is the wrong statement for work that
is finished.

## Decision

`respond` gains a terminal disposition, `self_verified`. The agent states three things:

- it repaired the finding;
- Yoetz cannot prove the repair because of a Yoetz limit;
- it verified the repair itself.

**Required fields.**

- `reason` (non-blank, at most 4096 bytes): how the agent verified the repair.
- `evidence_refs`: 1 to 64 ids of evidence or results recorded in this task.
- No waiver fields.

Any recorded `evd_`/`res_` id is accepted, whatever its evidence version, strength or content
availability. That includes a `digest_only` artifact row, the shape an image or binary
deliverable gets. Only the field rules are schema-enforced. Admission refuses with a typed
`INVALID_REQUEST` reason:

- `response_fields_invalid`: the reason is blank or there is no evidence;
- `finding_terminal`: the item is already final;
- `finding_not_rechecked`: no later check has tested the finding;
- `finding_not_proof_limited`: Yoetz still sees the issue, or names work the agent can do.

**Wire.** These versions change in place; all are unreleased on 0.3:

- respond-request/result 1.1.0;
- `response_recorded` 1.1.0, the event version shared with `acknowledged_not_done`;
- status-request 1.2.0 and status-result 1.4.0 (finding filter, row `todo_state`, readiness
  `gap_classification_version` "3");
- check-result 1.3.0 and 1.4.0 (`finding_checklist.counts.self_verified`);
- receipt-document 1.3.0 (`self_verified_finding_ids`, plus a rule that forbids
  `no_unresolved_deterministic_findings` beside it);
- closure-prepare-request 1.0.0.

**Effect.**

- **To-do state.** The terminal state is `self_verified`. `finding_is_resolved` never reports such
  a finding as resolved, even after a later absence proof. This is the same invariant
  `acknowledged_not_done` has: the item stays the agent's own verification and never becomes a
  Yoetz-proven row afterwards.
- **Agent work.** It is not agent work. `finding_blocks_receipt` is false for it, so it leaves
  `receipt_blocking_finding_count` and `receipt_findings_unresolved`. The Stop gate does not fire
  on it.
- **Readiness.** Readiness discloses the standing code `finding_self_verified`, which is new in
  gap classification version 3.
- **Receipt.** The receipt lists the ids in their own section, "Self-verified by the agent; Yoetz
  could not prove the repair", in JSON, markdown and text. Its conclusion is at best
  `insufficient_coverage`. This is a separate early-return in `receipt_builder._conclusion`.
- **Review.** The item is not reviewed again. A reviewer restatement folds onto it, as it does
  for `acknowledged_not_done`.

### Eligibility

The rule lives in `kernel/self_verification.py`: `self_verification_refusal(state, finding_id,
records) -> str | None`, `finding_proof_limited(...)`, and the pure
`reasons_proof_limited(reasons, origin)`. It reads only recorded checks, never response prose. It
does not change any proof rule.

1. Take the newest later check that could resolve the finding (`_could_resolve`), or else the newest
   later check (`finding_resolution_attempt`, the same choice the explanation makes). If there is
   none, or that check tested a frontier before the finding, refuse with `finding_not_rechecked`.
2. Compute that check's resolution reasons. The finding is **not proof-limited** when any of these
   holds:
   - the reasons are empty;
   - they name agent work: `finding_not_in_checked_frontier`, `matching_policy_not_completed`,
     `subject_outside_checked_scope`, `no_material_change_since_finding`, `findings_suppressed`
     (the check's ranking cap withheld findings, so whether the issue fired again is unknown), or
     an unreadable check or unreadable returned findings;
   - `semantic_review_not_completed`, unless that check's review could not complete for a durable
     reason (not requested, not configured, blocked by policy or forbidden data, classification
     uncertain, human denied, approval expired); a timeout, rate limit or unavailable transport is
     transient, so the agent runs `check` again;
   - they include a `coverage:<code>` that `GAP_CLASSIFICATION` does not class as standing
     (agent-actionable, route-dependent or unknown);
   - for a deterministic finding, `issue_returned_again`;
   - for an AI-powered finding, `issue_returned_again`, `reviewer_verdict_still_present` or
     `reviewer_verdict_answered_not_fixed`, unless the same check also carries a *packet* limit:
     `semantic_packet_insufficient`, `reviewer_assessment_incomplete`,
     `finding_material_outside_reduced_review_scope`, or a packet-side `coverage:` code (reduced
     reference scope, reduced refs, item or capacity limits, withheld or redacted review content,
     unselected, redacted or truncated content, a truncated or redacted check-time change). An
     unrelated capture or observation loss, or unproven freshness, never overrides a reviewer that
     saw the repair and still sees the issue.
3. `respond` also requires at least one cited evidence or result id recorded after the finding:
   evidence from before the repair cannot show that the repair was verified.
4. Every other reason is a Yoetz limit, so the finding is eligible. Because a standing code counts
   as a limit, a new gap code becomes self-verifiable as soon as `closure_readiness` classifies it
   standing.

### Texts

Every text that tells the agent what to do with an unresolved finding uses the same order:

1. Repair it, then check.
2. If you repaired it and Yoetz cannot prove it, verify it yourself, record that evidence, and
   respond `self_verified`.
3. Respond `acknowledged_not_done` only if you truly will not or cannot do it.

These texts are the finding explanation suffix (`UNRESOLVED_FINDING_NEXT_STEPS`), the CLI
budget hint and the `respond` descriptor. The shared sentence is
`domain.findings.SELF_VERIFIED_GUIDANCE`, and it says that a Yoetz limit is never a
`yoetz-blocker`.

## Consequences

- **Gate and blockers.** A repaired finding blocked by a Yoetz limit no longer keeps readiness
  `action_required`. The gate stops pushing agents toward false blockers.
- **Receipts.** A receipt never reads clean on the agent's word alone. It discloses each
  self-verified id and stays at best `insufficient_coverage`.
- **Older artifacts.** A receipt artifact older than 1.3.0 has no terminal sections. There a
  self-verified item still counts as unresolved, as `rejection_accepted` does.
- **Lineage (owner decision, 2026-10-07: "carry it as self-verified").** A child task's
  self-verified finding rolls up to the parent as "self-verified by the child agent; Yoetz could
  not prove it". The frozen `child-dependencies-recorded` row keeps `actionable` and `resolved`
  honest (actionable by kind, never resolved) and adds `self_verified: true`, emitted only when
  true so every other manifest keeps its bytes. The parent evaluator keeps such a row out of its
  actionable set, so the parent never reads `unresolved_findings_remain` for work it cannot do,
  and names the same standing code `finding_self_verified` on an accepted child, which keeps the
  parent from reading clean: the parent receipt is at best `insufficient_coverage`. The
  receipt-document `1.3.0` child row carries `self_verified` and markdown/text render it, so the
  parent and child receipts agree. A pending or rejected child stays an annotation. The #905
  states `rejection_accepted` and `acknowledged_not_done` still read as actionable and
  unresolved in the snapshot.
- **Agent misuse.** An agent can still call a repair verified when it is not. The answer is
  attributable, carries the agent's own evidence ids, and is listed by id. The eligibility rule
  limits it to cases where Yoetz's newest check no longer positively sees the issue.

## Reverse path

A `self_verified` item is final:

- `respond` refuses anything further with `finding_terminal`;
- a replay of the same request (same `request_id`) returns the recorded answer; any other answer on the item is refused with `finding_terminal` and records nothing;
- a later positive sighting is never folded onto the terminal row: a local rule that fires again is allocated a new finding id (`prior_finding_ids` skips `self_verified` rows), and a reviewer restatement of the issue is minted as a new open finding instead of being suppressed.

The disposition never closes another finding and never removes a coverage gap. If the agent
wrongly self-verifies, the receipt still shows the item, its reason and its evidence, and a
reviewer or human reads them there.

## Amendment 1 (issue #996): `duplicate_of` links a re-raised finding to an earlier one

**Status:** Accepted. Owner decision on 2026-10-07 while reviewing tb4n1: "P4-2 (duplicate_of):
APPROVED. Build it after L5's D5 automatic `restates` linking so it covers what that misses." This
counts as the maintainer acknowledgement for this design-gated protocol change on the unreleased
`respond-request`/`respond-result` `1.1.0`, `response_recorded` `1.1.0`, `status-request` `1.2.0`,
`status-result` `1.4.0` and `receipt-document` `1.3.0` wires.

**Context.** In tb4n1 a reviewer concern raised again was minted as a new finding, so agents
answered the same issue repeatedly (music-harmony semantic: 34 publishes and 50 status calls after
the gate). D5 links a re-raise automatically when the reviewer cites the earlier open finding
(`restates`). It misses re-raises minted anyway: prior findings over the packet limit,
deterministic duplicates, and restatements of a terminal item.

**Decision.**

- `respond` gains the disposition `duplicate_of` with a required `duplicate_of_finding_id`.
  `reason` and `evidence_refs` are optional; waiver fields are refused. It is not terminal.
- Admission accepts only a genuine restatement. It refuses, with typed reason codes, a target
  that is the same finding (`duplicate_target_same_finding`), unknown or unreadable
  (`duplicate_target_unknown`), recorded after this finding (`duplicate_target_not_earlier`), of a
  different origin or kind (`duplicate_target_different_issue`: a different kind is a different
  issue), or itself linked as a duplicate (`duplicate_target_is_duplicate`; Yoetz refuses rather
  than re-pointing, and the refusal names the finding to link to). A finding other findings
  already link to cannot become a duplicate itself (`duplicate_has_duplicates`), so no chain forms
  through a later link. A finding whose link a check broke cannot be re-linked
  (`duplicate_link_broken`).
- A link holds while both findings are readable, the target is earlier with the same origin and
  kind, and no remaining readable check broke it (`kernel/projections.duplicate_link_holds`).
  While it holds the duplicate inherits only the earlier finding's never-clean final answers,
  `self_verified` and `acknowledged_not_done`. It never inherits `verified_resolved` or
  `rejection_accepted`: otherwise the duplicate stays `open` but answered, and only its own
  qualifying check resolves it. Readiness counts an open (or inherited) pair once, naming the
  earlier finding (`finding_todo.duplicate_counting_id`); an open duplicate of a resolved,
  rejection-accepted or non-actionable earlier finding is counted on its own.
- A linked duplicate stays in the next review's prior findings even when it inherited a final
  state, with `duplicate_of_ref`, and rulings on it are admitted, so a reviewer can rule
  `still_present` and break a wrong link.
- The link breaks while any later readable check returned the duplicate again, returned a local
  finding with its issue key (the rule fired again), or carried a `still_present` or
  `answered_not_fixed` ruling on it. An AI-powered issue key alone is too coarse to break a link.
  The projection records every such check (`duplicate_link_broken_by_check_event_ids`, emitted
  only when non-empty); redacting one removes only its id, exactly as a full replay over the
  remaining readable checks would. A broken link, or an earlier finding that became unreadable,
  leaves the duplicate needing its own answer.
- Status findings rows carry `duplicate_of_finding_id` exactly while the link holds. Receipts on
  the 1.3.0 artifact list `duplicate_finding_links` by ids in a "Linked duplicates" section.
- Lineage (issue #996, B2): a child's frozen finding rows read `resolved` from the same to-do
  predicate as the child's receipt, and a pair counted once by the child's readiness is one row,
  so a self-verified pair rolls up to the parent once.

**Honesty.** Linking never resolves a finding and never makes a receipt clean: a duplicate reads
resolved only when its own qualifying check proved it absent. An open duplicate keeps
`unresolved_findings_remain`; an inherited `acknowledged_not_done` keeps it blocking; an inherited
`self_verified` keeps the conclusion at best `insufficient_coverage`.

**Reverse path.** The link is not final. The agent can answer the duplicate with another
disposition at any time while it is not in an inherited final state; a later check or a review
breaks the link; redacting every breaking check restores it.

**Status of self-verified children (S2).** Status readiness lists the standing code
`finding_self_verified` when an accepted child holds self-verified findings, and the status lineage
row carries `self_verified_finding_count`, so status agrees with the parent receipt's
`insufficient_coverage` (ADR-027).

## Amendment (2026-10-08, issue #1020): `disputed_after_rebuttal`

[ADR-040](ADR-040-reviewer-disagreement-and-route-derived-review.md) adds a sixth to-do state,
`disputed_after_rebuttal`: the reviewer kept an AI-powered finding open after the agent's reasoned
`rejected` answer and cited nothing recorded after it. Yoetz records it, not the agent. Like
`self_verified` it is final, not agent work and never clean (readiness standing code
`finding_disputed_after_rebuttal`; receipt `disputed_after_rebuttal_finding_ids`); like
`rejection_accepted` it is latched by a check and cleared when that check is redacted.
