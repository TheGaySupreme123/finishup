# When to use FinishUP

Use FinishUP for material multi-step, delegated, resumable, or verification-heavy work. New session: read guidance/discover schemas, then `start` before substantive work. If startup fails, follow recovery first; if still blocked, ask for intro and guidance. Skip trivial questions or edits; never invent a ledger task. Cadence: `start` once, `publish_work` per material transition; `receipt` last. Never claim FinishUP is active until `start` returns. `finishup://guidance/workflow.md`.

Read current guidance, not memory. FinishUP is not an enforcement system; a check is not correctness. This card is enough for ordinary work.

# Task first

Deliver each requested output at its path, best-effort and disclosed if an input looks off; conditional files are `change` items, not placeholders.

# Guidance catalog

Do not call `resources/list` or `list_mcp_resources` to find FinishUP guidance; a list failure is not a missing server or reason to read product source. If a body is empty or clipped, call `read_guidance` with the same URI. Only if that result is also empty, use installed `references/<name>.md` or the topic's parent index.

Focused topics by trigger: failed write `recovery.md`; batch `publication.md`; finding `review.md`; closing `receipt.md`; resume `startup.md`; delegate `delegation.md`; setup `consent.md`; clipped page `page-delivery.md`. A long page lists its `#anchor` sections on page 0; read one listed section, not the page.

# Start contract

Author `start` from its schema: a fresh `req_` UUIDv4, the user's whole `task_statement`, a held `session_id` or `workspace_ref` + `external_ref`.

`start` records intent; after bounded exploration, before the first material edit, publish one `plan_revised` refinement mapping every instruction requirement to a testable obligation whose `source_refs` cite the `start` event (`status view=history`) and whose `requested_items` name the files/commands.

# Essential boundaries

Never publish hidden reasoning or chain-of-thought, full prompts, transcripts, conversation history, credentials, secrets, whole files/repositories, or broad unrelated source. Never move, split, shrink, delete, `git add -N` or git-ignore (incl. `.git/info/exclude`) a deliverable for review: FinishUP redacts, and you verify what it cannot show. On `retryable: false`, follow only the typed `continuation`; retry an unknown write by its request id. If FinishUP is unavailable, say no record or receipt exists.

# Review and closure

Tasks may start local; `review.md`: when to turn on AI-powered review. Select `semantic_required` when the user, effective policy, or named acceptance criterion requires independent review; `semantic_if_configured` only if optional; `deterministic_only` only for local or no-egress work.

Writes return frontier, ids, errors; a prior `status` read or `dry_run` is optional: send each returned frontier as the next `expected_frontier` (first plan: `start`'s). `publish_work` may omit `request_id`, `expected_frontier`, `event_id`, `occurred_at` (no `date`), envelope lists. Give each action a `result_recorded` naming its `act_` id. Cite IDs you published; find native captures with `view=evidence` filter `strength=immutable_snapshot`, reusing only IDs a structural link ties to the claim. Omitted descriptions are a privacy setting, not missing evidence. What is left and why: `check` `mode: inspect` (records nothing).

`check` after the plan and each milestone; cite observed runs (`status view=results`). Publish claim/evidence before the final check; answer findings, check, and inspect resolved state. On a finding, change the work or record what it names; an unchanged recheck returns it. Recheck only after repair/material record. After `insufficient_packet`: If `missing_for_assessment` names an `agent_suppliable` item you can supply, publish exactly that item once, linked to any named target, then `check` again. If it is already supplied, or it is a packet, type or authority limit, go to the receipt and state that specific limit. Only new material counts; tie it to any named target. The reviewer reads up to three permitted files or records itself, so never republish a retained file or recorded output only to show it; the review summary says what it still needs. Verification follow-ups include observed test, build, lint, or typecheck output only when a repository excerpt would be sent.

Lead final prose with the receipt's scope and limits; never headline "no findings", "clean", or "verified".

# Review dialogue

Before the receipt, run the closing `check` with `final_review: true`. Answer each open AI-powered finding with `respond` and a reason; `review.md` maps each case.

# Multi-agent work

Before delegating, read the multi-agent sections of `finishup://guidance/workflow.md` and `delegation.md`.

# Read more

This card is `finishup://guidance/agent-instructions.md`; on demand only: resume/recovery/delegation/capacity `finishup://guidance/workflow.md`; event shapes, corrections `finishup://guidance/publication-policy.md`; check/receipt `finishup://guidance/coverage-and-receipts.md`; publish `finishup://guidance/request-templates.md#publish-shapes`; setup: same page.
