# When to use Yoetz

Use Yoetz for material multi-step, delegated, resumable, or verification-heavy work. New session: read guidance/discover schemas, then `start` before substantive work. If startup fails, follow recovery first; if still blocked, ask for intro and guidance. Skip trivial questions or edits; never invent a ledger task. Cadence: `start` once, `publish_work` per material transition; `receipt` last. Never claim Yoetz is active until `start` returns. `yoetz://guidance/workflow.md`.

This small core is required before `start`. Read current guidance, never memory. Schemas are wire authority. Yoetz is a local ledger/checker. Yoetz is not an enforcement system; a check is not correctness.

# Task first

Deliver every requested output at its path, even if an input looks inconsistent: write a best-effort artifact and disclose the assumption.

# Guidance catalog


Do not call `resources/list` or `list_mcp_resources` to find Yoetz guidance. The five index URIs are the complete legacy catalog; a list failure is not a missing server or reason to read product source. If a body is empty or clipped, call `read_guidance` with the same URI; verify `structuredContent.text`, byte counts, offsets, revision, and final digest. `page_size` is 4 through 16,384 UTF-8 bytes; default 4,096. Only if that result is also empty, use installed `references/<name>.md` or the focused topic's parent index.

Focused topics: `startup.md`, `recovery.md`, `publication.md`, `review.md`, `receipt.md`, `delegation.md`, `consent.md`, `page-delivery.md`. Heading topics such as `yoetz://guidance/workflow.md#start-and-resume` are a closed catalog: use only anchors guidance names verbatim; an unknown anchor's rejection lists the valid ones.

# Start contract

Discover the `start` schema, use a fresh `req_` UUIDv4, and provide `mode`, `task_title`, `task_statement`, `requested_view`, `actor`, `client`, plus a held `session_id` or `workspace_ref` + `external_ref`. A child needs a selector.

`start` records intent; after bounded exploration and before the first material edit, publish one `plan_revised` refinement mapping every instruction requirement to a testable obligation whose `source_refs` cite the `start` event (`status view=history`) and whose `requested_items` name requested files/commands.

# Essential boundaries

Never publish hidden reasoning or chain-of-thought, full prompts, transcripts, conversation history, credentials, secrets, whole files/repositories, or broad unrelated source. Never hide, delete, or git-ignore a deliverable (incl. `.git/info/exclude`) to keep secrets from review; Yoetz redacts and discloses. Never reshape your deliverable for the reviewer: never split, move, shrink, stash, delete, `git add` (incl. `-N`) or git-ignore deliverables or workspace files to fit the review packet; content the packet cannot show is a Yoetz limit, so verify it yourself and disclose it. Recover via schemas/guidance, never SQLite or source. On `retryable: false`, follow only the typed `continuation`; keep an unknown write's request id. If Yoetz is unavailable, say no record or receipt exists.

# Review and closure

Select `semantic_required` when the user, effective policy, or named acceptance criterion requires independent review; `semantic_if_configured` only if optional; `deterministic_only` only for local or no-egress work. Read review/coverage before `check`.

Before material evidence or a completion claim, read `status`; cite IDs you published. Find native captures with `view=evidence` filter `strength=immutable_snapshot`, reusing only IDs a structural link ties to the claim. Omitted descriptions are a privacy setting, not missing evidence. `check` after the plan and each milestone; cite observed runs (`status view=results`) as support. Publish claim/evidence before the final check; answer findings, check, and inspect resolved state. On a finding, change the work or record what it names; an unchanged recheck returns it. Recheck only after repair/material record. After `insufficient_packet`, go to the receipt; never use `deterministic_only` merely to shorten closure.

Final prose and receipts are scope-first: lead with evidence/checks covered, what was not verified, frontier, review status/reason, and coverage limits; then give actionable-unresolved, unanswered, and resolved-history counts. Never headline “no findings”, “zero findings”, “clean”, or “verified”. Keep the final answer no stronger than the receipt's weakest coverage.

# Review dialogue

Before the receipt run the closing review: `check` with `final_review: true`. Answer every AI-powered finding with `respond` and a reason (`acknowledged` requires one); for `requested_next_step: answer_question`, answer in the reason.

# Multi-agent work

Before delegating, read the multi-agent sections of `yoetz://guidance/workflow.md` and `delegation.md`; a helper without a selector does no Yoetz work.

# Read more

Triggers: startup `yoetz://guidance/agent-instructions.md`; resume/recovery/delegation/capacity `yoetz://guidance/workflow.md`; publication `yoetz://guidance/publication-policy.md`; check/receipt `yoetz://guidance/coverage-and-receipts.md`; schema/setup/consent/import `yoetz://guidance/request-templates.md`. Read with `read_guidance`.
