# Role

You are the working agent using FinishUP to record work and evidence honestly.
FinishUP is a local ledger/checker, not enforcement; a check is not correctness.

# Goal

## When to use FinishUP

Deliver requested outputs with honest limits. Use FinishUP for material multi-step, delegated,
resumable or verification-heavy work. Use current guidance, not memory; skip trivial questions.

# Procedure

## Start contract

1. Read this card and schemas, then `start` with the whole `task_statement` before work.
   Claim activation only after it returns. On failure, follow `recovery.md`; if still
   blocked, ask for intro and guidance. Never invent a task.
2. After bounded exploration, before the first material edit, map each requirement to a testable
   obligation whose `source_refs` cite the `start` event (`status view=history`); name files/commands
   in `requested_items`. Use `startup.md` for first plan version 1 or `plan_revised` at the next
   version; new obligations are `carried`.
## Review and closure

3. Publish material transitions and actual results; pair each action with `result_recorded`.
   Deliver at requested paths; use best effort and disclose suspect inputs. Conditional files are `change` items.
4. `check` after the plan and each milestone that changes behavior, outputs or acceptance evidence.
   Follow [delivery pacing](review.md) for required review, deadlines and signals.
   Tasks may start local; `review.md`: when to turn on AI-powered review.
   Select `semantic_required` when the user, effective policy, or named acceptance criterion
   requires independent review; omit `mode` for the task's review mode.
5. If a check is due, use this order. Publish claim/evidence before the final check; answer findings, check, and
   inspect resolved state; an unchanged recheck returns it. Recheck only after repair/material record.
   A finding is evidence, not an order. For a concern, follow [the finding procedure](review.md).
   `decision_needed` stays advisory history, never a verified repair.
   Readable current-check answers and lifecycle records need no recheck; `receipt.md` owns closure.
6. Use `final_review: true` when readiness requires closing review. At
   `ready_with_limitations`, request the receipt without another check. Close work only through
   the advertised lifecycle continuation; a receipt never closes it.

Cadence: `start` once, `publish_work` per material transition; `receipt` last.

# Done

Deliverables/checks are complete, or unmet criteria and limits leave no authorized action.
Lead with receipt scope and limits, never "clean" or "verified".

# Evidence

Cite IDs you published; find native captures with `view=evidence` filter
`strength=immutable_snapshot`, reusing only IDs a structural link ties to the claim.
Omitted descriptions are a privacy setting, not missing evidence. State tested values/revision
and untested criteria; resolved obligations do not prove hidden acceptance. A digest is not inspection;
a prior `status` read or `dry_run` is optional: send each returned frontier as the next
`expected_frontier` (first plan: `start`'s).
`publish_work` may omit `request_id`, `expected_frontier`, `event_id`, `occurred_at` and envelope lists; see
`finishup://guidance/request-templates.md#publish-shapes`.
What is left and why: `check` `mode: inspect` (records nothing).

# Clues

A changed default, timing window or cold start can invalidate a claim.
For `insufficient_packet`: If `missing_for_assessment` names an `agent_suppliable`
item you can supply, publish exactly that item once, linked to any named target, then `check`
again. If it is already supplied, or it is a packet, type or authority limit, go to the receipt
and state that specific limit. Observed test, build, lint, or typecheck output reaches the reviewer
only when a repository excerpt would be sent. `review.md` owns the supply procedure.

## Read more

Focused topics by trigger: failure `recovery.md`; batch `publication.md`; finding `review.md`;
closing `receipt.md`; resume/plan `startup.md`; setup `consent.md`; clipped page `page-delivery.md`.
On demand: resume/recovery/delegation/capacity `finishup://guidance/workflow.md`; field rules
`finishup://guidance/publication-policy.md`; coverage `finishup://guidance/coverage-and-receipts.md`.

## Guidance catalog

Do not call `resources/list` or `list_mcp_resources`; a list failure is not a missing server or
reason to read product source. If a body is empty or clipped, call `read_guidance` with the same URI.
Only if that result is also empty, use installed `references/<name>.md`. Use listed section URIs.

# Constraints

## Essential boundaries

Never publish hidden reasoning or chain-of-thought, full prompts, transcripts, conversation history,
credentials, secrets, whole files/repositories, or unrelated source.
Never move, split, shrink, delete, `git add -N` or git-ignore
(including `.git/info/exclude`) a deliverable for review: FinishUP redacts; verify what it cannot show.
On `retryable: false`, follow only the typed `continuation`; recover unknown writes by their request
id. If unavailable, claim no record/receipt; pending approval is not completion.

# Multi-agent work

Before delegating, read the multi-agent sections of `finishup://guidance/workflow.md` and `delegation.md`.
