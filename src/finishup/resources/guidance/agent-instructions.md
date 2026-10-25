# When to use FinishUP

Use FinishUP for material multi-step, delegated, resumable, or verification-heavy work. New session: read guidance/discover schemas, then `start` before substantive work. If startup fails, follow recovery first; if still blocked, ask for intro and guidance. Skip trivial questions or edits; never invent a ledger task. Cadence: `start` once, `publish_work` per material transition; `receipt` last. Never claim FinishUP is active until `start` returns. `finishup://guidance/workflow.md`.

# Role

You record work and evidence honestly; read current guidance, not memory.
FinishUP is not an enforcement system; a check is not correctness. This card is enough for ordinary work.

# Goal

Deliver each requested output at its path, working; disclose suspect inputs.
Conditional files are `change` items.

# Procedure

## Start contract

1. Send `start` from its schema with the user's whole `task_statement`; then plan version 1 if none.
2. After bounded exploration, before the first material edit, `plan_revised` it at the next version:
   map each requirement to a testable obligation whose `source_refs` cite the `start` event
   (`status view=history`); name files/commands in `requested_items`; new obligations are `carried`.

## Review and closure

3. Publish actual results; pair each action with `result_recorded`; a prior `status` read or
   `dry_run` is optional: send each returned frontier as the next `expected_frontier` (first plan: `start`'s).
   Failing or weak test (cannot fail, or mirrors the code): fix it,
   else disclose it by name (`limitation_refs`).
4. `check` after the plan and each milestone that changes behavior, outputs or acceptance evidence.
   Tasks may start local; `review.md`: when to turn on AI-powered review.
   Select `semantic_required` when the user, effective policy, or named acceptance criterion
   requires independent review.
5. Publish claim/evidence before the final check; answer findings, check, and inspect resolved
   state; an unchanged recheck returns it. Recheck only after repair/material record.
   A finding is evidence, not an order.
   Answer each open AI-powered finding with `respond` and a reason (optional for `decision_needed`).
   Advice is non-blocking: per material concern, run a proportionate check, cite settling
   evidence or decline with a reason (response optional).
6. Use `final_review: true` when readiness requires closing review. At `ready_with_limitations`,
   request the receipt without another check. Then `work_closed` if complete; a receipt never
   closes work. `lineage_work_transition`: the task already ended; report it.

# Done

Current results pass, or no authorized action is left; name each failed, weak or unrun check
and unmet criterion.
Lead with receipt scope and limits, never "clean" or "verified".

# Evidence

Cite IDs you published; find native captures with `view=evidence` filter
`strength=immutable_snapshot`, reusing only IDs a structural link ties to the claim.
Omitted descriptions are a privacy setting, not missing evidence.
What is left and why: `check` `mode: inspect` (records nothing).

# Clues

`insufficient_packet`: If `missing_for_assessment` names an `agent_suppliable`
item you can supply, publish exactly that item once, linked to any named target, then `check`
again. If it is already supplied, or it is a packet, type or authority limit, go to the receipt
and state that specific limit. Only new material counts. Observed test,
build, lint, or typecheck output reaches the reviewer only when a repository excerpt would be sent. Never republish retained files/output for review.

## Read more

By trigger: failure `recovery.md`; batch `publication.md`; finding, deadline,
`delivery_page` or `not_in_frozen_case` `review.md`; closing `receipt.md`; resume/plan `startup.md`;
setup `consent.md`; clipped page `page-delivery.md`.
On demand: resume/recovery/delegation/capacity `finishup://guidance/workflow.md`; field rules
`finishup://guidance/publication-policy.md`; coverage `finishup://guidance/coverage-and-receipts.md`;
publish `finishup://guidance/request-templates.md#publish-shapes`; setup: same page.

## Guidance catalog

Do not call `resources/list` or `list_mcp_resources` to find FinishUP guidance;
a list failure is not a missing server or reason to read product source.
If a body is empty or clipped, call `read_guidance` with the same URI.
Only if that result is also empty, use installed `references/<name>.md`.

# Constraints

## Essential boundaries

Never publish hidden reasoning or chain-of-thought, full prompts, transcripts, conversation history,
credentials, secrets, whole files/repositories, or unrelated source.
Never move, split, shrink, delete, `git add -N` or git-ignore
(`.git/info/exclude`) a deliverable for review: FinishUP redacts; verify what it cannot show.
On `retryable: false`, follow only the typed `continuation`; recover an unknown write by request
id. If unavailable, claim no record/receipt; pending approval is not completion.

# Multi-agent work

Before delegating, read the multi-agent sections of `finishup://guidance/workflow.md` and `delegation.md`.
