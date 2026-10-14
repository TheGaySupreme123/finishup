# When to use FinishUP

Use FinishUP for material multi-step, delegated, resumable, or verification-heavy work. New session: read guidance/discover schemas, then `start` before substantive work. If startup fails, follow recovery first; if still blocked, ask for intro and guidance. Skip trivial questions or edits; never invent a ledger task. Cadence: `start` once, `publish_work` per material transition; `receipt` last. Never claim FinishUP is active until `start` returns. `finishup://guidance/workflow.md`.

Read current guidance, not memory. FinishUP is not an enforcement system; a check is not correctness. This card is enough for ordinary work.

# Task first

Deliver each requested output at its path, best-effort and disclosed if an input looks inconsistent; conditional files are `change` items, not placeholders.

# Guidance catalog

Do not call `resources/list` or `list_mcp_resources` to find FinishUP guidance; a list failure is not a missing server or reason to read product source. If a body is empty or clipped, call `read_guidance` with the same URI. Only if that result is also empty, use installed `references/<name>.md` or the topic's parent index.

Focused topics by trigger: failed write `recovery.md`; batch `publication.md`; finding `review.md`; closing `receipt.md`; resume `startup.md`; delegate `delegation.md`; setup `consent.md`; clipped page `page-delivery.md`. A long page lists its `#anchor` sections on page 0; read one section, not the page, and use only listed anchors.

# Start contract

Author `start` from its schema: a fresh `req_` UUIDv4, the user's whole `task_statement`, a held `session_id` or `workspace_ref` + `external_ref`.

`start` records intent; after bounded exploration, before the first material edit, publish one `plan_revised` refinement mapping every instruction requirement to a testable obligation whose `source_refs` cite the `start` event (`status view=history`) and whose `requested_items` name the files/commands.

# Essential boundaries

Never publish hidden reasoning or chain-of-thought, full prompts, transcripts, conversation history, credentials, secrets, whole files/repositories, or broad unrelated source. Never move, split, shrink, delete, `git add -N` or git-ignore (incl. `.git/info/exclude`) a deliverable for review: FinishUP redacts, and you verify what it cannot show. On `retryable: false`, follow only the typed `continuation`; keep an unknown write's request id. If FinishUP is unavailable, say no record or receipt exists.

# Review and closure

Select `semantic_required` when the user, effective policy, or named acceptance criterion requires independent review; `semantic_if_configured` only if optional; `deterministic_only` only for local or no-egress work.

Writes return frontier, ids, errors; a prior `status` read or `dry_run` is optional: send each returned frontier as the next `expected_frontier` (first plan: `start`'s). Give each action a `result_recorded` naming its `act_` id. Cite IDs you published; find native captures with `view=evidence` filter `strength=immutable_snapshot`, reusing only IDs a structural link ties to the claim. Omitted descriptions are a privacy setting, not missing evidence. What is left and why: `check` `mode: inspect` (records nothing).

`check` after the plan and each milestone; cite observed runs (`status view=results`). Publish claim/evidence before the final check; answer findings, check, and inspect resolved state. On a finding, change the work or record what it names; an unchanged recheck returns it. Recheck only after repair/material record. After `insufficient_packet`, go to the receipt; never use `deterministic_only` merely to shorten closure.

Final prose and receipts lead with scope: evidence/checks covered, what was not verified, frontier, review status/reason, coverage limits; then actionable-unresolved, unanswered, and resolved-history counts. Never headline "no findings", "zero findings", "clean", or "verified". Keep the final answer no stronger than the receipt's weakest coverage.

# Review dialogue

Before the receipt, run the closing `check` with `final_review: true`. Answer each open AI-powered finding with `respond` and a reason; `review.md` maps each case.

# Multi-agent work

Before delegating, read the multi-agent sections of `finishup://guidance/workflow.md` and `delegation.md`; a helper without a selector does no FinishUP work.

# Read more

This card is `finishup://guidance/agent-instructions.md`; on demand only: resume/recovery/delegation/capacity `finishup://guidance/workflow.md`; event shapes, corrections `finishup://guidance/publication-policy.md`; check/receipt `finishup://guidance/coverage-and-receipts.md`; request bodies, setup: one section of `finishup://guidance/request-templates.md`.
