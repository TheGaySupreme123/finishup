# ADR-047 — The inspection check, and an operating card instead of a startup reading list

**Status:** Accepted for [issue #1048](https://github.com/TheGaySupreme123/yoetz/issues/1048)
(tb4n4 D: Yoetz-only steps took a median 11.5 minutes per attempt, 38% of the arm's time: status
4.6 minutes over 780 calls, publish 4.1 minutes over 651 calls of which 291 were dry runs, and
guidance 2.8 minutes over 728 calls at a median of 82 KB per attempt; separately, payments D
measured latency with a harness that bypassed the supervisor the service is deployed under and
Yoetz did not notice). Design gate: protocol. Maintainer acknowledgement: the owner's 2026-10-12
request to fix #1038-#1052 in one change, and the maintainer's idea on the issue (2026-10-12) to
let the agent ask Yoetz to look deeper at its own records as a type of the existing `check`
rather than a new tool. It adds one value to the unreleased `check-request` 1.1.0 `mode` enum and
one result branch to the unreleased `check-result` 1.4.0, both in place; it changes no released
wire shape. It grants no runtime, credential, disclosure, egress or destructive-action authority.
**Implemented by:** `src/yoetz/application/check_inspection.py`,
`src/yoetz/application/check.py` (`execute_check` routes `mode: inspect` there),
`src/yoetz/application/status.py` (`current_closure_readiness`),
`src/yoetz/application/service.py`, `src/yoetz/service/daemon.py` (read-only classification, never
detached), `src/yoetz/protocol/recovery.py` (`READ_ONLY_CHECK_MODES`, `timeout_operation_kind`),
`src/yoetz/mcp/server.py` and `src/yoetz/cli/bootstrap.py` (a timed-out inspection is a read; the
bridge's `status` deadline), `src/yoetz/protocol/models.py` (`CheckInspectionModel`, the request
refusal, the leaf rules), `src/yoetz/protocol/inspection_text.py`, `src/yoetz/cli/render.py`,
`src/yoetz/mcp/summaries.py`, `src/yoetz/mcp/descriptors.py`, `scripts/generate_schemas.py`,
`scripts/generate_check_inspection_fixture.py`,
`guidance/agent-instructions.md` (the operating card), `guidance/publication-policy.md`,
`guidance/request-templates.md`, `guidance/workflow.md`, `guidance/receipt.md`, the four host
skills under `skills/`.
**Relates to:** ADR-029 (observation wait, `await_observations`), ADR-032 (closure readiness),
ADR-035 (declared delivered set), ADR-042 (write classification), ADR-045 (path and command
matching), ADR-046 (one closure verdict).

## Context

Two habits cost most of an agent's Yoetz time without making the record better:

1. **A status read and a dry run before every material publish.** `publication-policy.md`
   prescribed "read `status view=obligations` ... then `dry_run: true` ... then publish with the
   same `request_id`". A write is already all or nothing: it appends nothing when any draft is
   rejected and names what stopped it, not every error (for drafts, the first rejected draft and
   its field, so another bad draft surfaces only on the next attempt; a dry run stops at the same
   place), and an accepted write returns the new frontier and the accepted ids, so the ritual
   doubled the calls and added a status read per write. When the agent did need the picture, it
   took several status views (compact, obligations, results, findings) to assemble it.
2. **Five startup documents.** The initialize text and the host skills told the agent to read
   `publication-policy.md` before `publish_work` and `coverage-and-receipts.md` before `check`,
   with `workflow.md` and `request-templates.md` beside them: about 275 KB, read in pieces at a
   median of 82 KB per attempt.

And one gap: nothing compared where verification evidence came from with what the task declared
it must cover, so evidence from a harness that bypassed the declared deployment read like any
other resolution evidence.

## Decision

### 1. `check` with `mode: inspect`

`inspect` is a value of the existing `check` `mode`, not a new tool or operation. It is a read,
routed exactly like `status` (payload read; no write capability, no frozen case, no event, no
operation record, no finding, no reviewer, no egress). The daemon, the MCP bridge and the CLI
classify it read-only by one set of modes (`READ_ONLY_CHECK_MODES`), so a failure, a timeout
included, is a retryable read failure answered by a fresh request (continuation
`read_timeout_new_identity`, no `replay_request_id`), and the daemon never runs it detached. The
bridge gives it the `status` call deadline (30 seconds by default), not the 300 seconds kept for a
check that may run an AI-powered review: an inspection waiting on a running review's dispatch gate
then gets a typed read timeout inside the common 60-second host tool limit.
**It is not recorded.** `status` reads are not recorded either; an inspection changes nothing that
closure, a receipt or a later check reads, so an event would only add a record the next
inspection must classify as Yoetz's own activity.

The request model refuses `final_review`, `max_findings`, `policy_packs` and `scope` beside
`inspect`, each at its own field (`extra_forbidden`): an inspection mints nothing, and accepting
those options silently would let an agent believe a review or a scoped check ran. The rule is not
a schema conditional because a root `if`/`then` lowers the whole advertised check input to
`unknown` on the observed hosts (the check input's presentation budget admits no conditional).
`await_observations` is accepted and reported as on any check. `expected_frontier` is not
compared; `subject_frontier` names what was read.

The answer is its own branch of `check-result` 1.4.0, `state: inspected`, with no verdict,
findings, coverage vector, versions or `result_frontier`, so it cannot be mistaken for a check
result. Every leaf is structural (ids, closed tokens, counts, requested-item indexes, keyed
command commitments); no command text, path or prose leaves the service. Three sections:

- **`remaining`**: what is left to close and why. Readiness, the predicted receipt conclusion and
  the `agent_actionable` / `standing_limitations` split come from the one function status uses
  (ADR-046), so the two cannot disagree; the split is the answer to "the agent's gaps versus
  Yoetz's own" (standing limitations are the bounds of observation, capture, review and route).
  Every unresolved obligation and finding follows with its class and basis. An agent-work
  obligation names what it lacks and whose move it is: requested items with no attempt (by
  index), no resolution evidence, an asserted command whose linked observed run differs, an
  unconfirmed blocker (the agent's), or an asserted command run no hook observation is linked to
  (`command_run_not_observed`, Yoetz's: whether it ran is outside what Yoetz recorded).
- **`observed_since_check`**: every hook-observed action after the last recorded check, classed by
  the one `later_material` predicate, with tool, write class, outcome, exit status and keyed
  command commitment. Yoetz's own calls and host bookkeeping are not listed (they never change the
  work). Observed edits carry a write class, never a path, because the hooks record none.
- **`evidence_alignment`**: for each obligation citing resolution evidence, the declared items
  (requested commands, and files or directories not marked `input`) beside, per cited result or
  evidence item, the action it came from (hook-observed, agent-asserted or untraceable), that
  action's keyed command commitment and outcome, and which declared items it names through a
  recorded link: the action's `attempted_items` (ADR-045 path matching) or, for a requested
  command, the observed run's keyed identity under the shared planned-command matcher.
  `evidence_off_declared_items` flags evidence that traces to an action naming no declared item
  (the payments case: a latency harness that never ran the requested supervisor command nor named
  its configuration). **Coverage bound:** Yoetz records no command text, working directory,
  environment or service configuration, so this compares only those recorded links; a test run is
  not linked to a file it exercised unless the action that ran it names the file. It is
  deterministic and conservative: no link is ever inferred from text or timing. A revised plan can
  carry more obligations than the 64-row list, so flagged rows are listed first and the section
  counts every row (`obligation_count`) and every flag (`off_declared_count`) before the bound: a
  dropped row is counted and never hides a flag.

The CLI (`yoetz check` with the JSON request) and the MCP `check` text channel print the same
lines from the structural branch. The terminal interface does not offer `inspect`: it already
renders the task's status, and the inspection exists to save an agent's calls.

### 2. No mandatory status read or dry run before a write

Guidance says a status read and a dry run before a publish are optional: use a dry run when unsure
a batch will be accepted (a claim correction, a plan revision, a large batch), and `check` with
`mode: inspect` when the agent needs the picture. Before resolving an obligation the agent still
accounts for every requested item without an attempt; the inspection names them by index.

### 3. The operating card

`agent-instructions.md`, already the one mandatory pre-start read, becomes the operating card:
it says it is enough for ordinary work, carries the write and inspection rules above, and points
to `workflow.md`, `publication-policy.md`, `coverage-and-receipts.md` and `request-templates.md` as
references read on demand (when a result, error or continuation names one, or when unsure). The
initialize texts and the four host skills stop telling the agent to read the publication policy
before `publish_work` and the coverage page before `check`. The full pages stay available,
unchanged in location and catalog. The card plus the host skill plus the initialize block stays
within the existing 8 KiB mandatory-surface budget for every host (the card alone is under 5 KB).

## Alternatives rejected

- **A new tool or operation.** Six operations are the contract (ADR-002); the maintainer asked for
  a type of `check`.
- **A policy pack value.** Packs are versioned rule sets whose findings are recorded; an
  inspection mints and records nothing.
- **Reusing the check success branch.** It requires a verdict, findings, a coverage vector and
  policy executions; filling them for a read would manufacture a completion-grade shape.
- **Recording the inspection.** Nothing downstream reads it, and every later read would have to
  classify it as Yoetz's own activity.
- **Reading service configuration or the working directory to answer item 3.** Yoetz records
  neither, and reading them would widen what the service touches; the recorded-link comparison is
  the honest bound.

## Consequences

- An agent can replace a series of status reads with one call (a `check` call, which its host
  approves as it approves any `check`), and publishes without a preview unless it is unsure. A
  lost inspection answer is answered by asking again.
- The startup surface no longer sends agents to about 275 KB of procedure pages.
- Evidence that never touched what the obligation declared is visible before the receipt.
- `command_run_not_observed` and `evidence_off_declared_items` are advisory facts on a read; they
  change no closure class, gap, finding or receipt.

## Host and platform decisions

The same on Codex, Claude Code and Cursor on every supported platform: `mode: inspect` is a value of
the existing MCP `check` tool and of the CLI request, needs no host hook, and its text channel is
host-independent (Cursor's exact-JSON text copy carries the same body).

Host approval is per tool, not per mode. The `check` descriptor is the same for every mode
(`readOnlyHint: false`; `openWorldHint: true` on the policy route), so each host gates an
inspection exactly as it gates any `check`: Codex asks for approval (or its guardian decides, or
approval policy `never` refuses) on the policy route unless the project admits `check`; Claude
Code follows the `check` allow or ask rule, or its permission mode without admission; Cursor's
Auto-review admits it through the `check` allowlist entry or classifies it like any
non-allowlisted call. An inspection needs no Yoetz disclosure decision, and a held one leaves
nothing pending in Yoetz, so guidance tells the agent to read `status` instead rather than wait as
for a held review. Where `check` cannot be admitted (on Codex, a policy route without a grant that
permits external review) an inspection costs an approval that the `status` reads it replaces do
not; a read-only advertisement would need a separate tool, which this ADR rejects, so the gap is
recorded in the host runbooks with issue #1048 as its owner. Claude Code's `PermissionDenied`
advisory skips a denied inspection as it does a `deterministic_only` check (no AI-powered review
notice, no retry offer).

## Verification

`tests/integration/application/test_check_inspection.py` drives the real application facade and
the daemon's privacy projection over the payments shape (evidence from a harness that bypassed the
declared supervisor command and configuration, an unattempted obligation, observed actions after
the check) and the aligned case; it asserts the ledger head does not move, every leaf classifies
structural, and the CLI and MCP texts agree; a keyed observed run of the requested supervisor
command is named and the bypassing harness run is flagged.
`tests/unit/mcp/test_recovery_directive_delivery.py` holds the bridge's and the CLI's read
classification of a failed inspection and its `status` deadline beside an unchanged minting check.
Golden vectors CAN-017
(`fixtures/canonical/check-inspection-1.4.0.case.json`) freeze the request rule and the branch.
`tests/conformance/surfaces/test_operating_card.py`
measures the card and holds the guidance changes. The real-data replay of the tb4n4 exports
remains for the maintainer.

## Amendment (2026-10-13, tb4n5, issues #1048 and #1049): where the next frontier comes from

tb4n5 kept the requirement and half of decision 2. Dry runs fell from 123 to 10, but status reads
before a write doubled (75 to 139 adjacent writes): 85 of 87 state-sensitive publishes read status
first only to copy its head as `expected_frontier`, and six first-plan batches sent
`expected_frontier: null` and were refused `expected_frontier_required`. The card called a status
read optional while three surfaces still named status as the frontier source: the publication
policy ("Read it from `status`"), the field description every write tool advertises ("returned by
status") and the `expected_frontier_required` message and its continuation ("Call status to read
the current frontier").

- **The requirement stays.** `expected_frontier` remains ADR-022's optimistic-concurrency guard; a
  server-side default would authorize a transition against unseen cooperative state.
- **The held frontier is the source.** Every write already returns one, and an observation-only
  suffix since is tolerated (ADR-022). The first plan sends the `frontier` `start` returned (its
  `next_request_template` already carries it); every later write sends the `result_frontier` of
  the last accepted `publish_work`, `check` or `respond`. A status read is for a caller holding no
  frontier, or after a genuine `frontier_changed` conflict. The publication policy, the
  `publication.md` topic, the request templates (the first-plan template and the replacement
  rules), `workflow.md`, the card and the advertised field description say so; the `start` and
  accepted `publish_work` text summaries say which write sends the returned frontier next.
- **A missing frontier has its own continuation.** `expected_frontier_required` now maps to
  `frontier_held_required` (ADR-030 registry): send the held frontier and retry under the same
  `request_id`. `frontier_changed` keeps `frontier_refresh_required`, which reads `status`.
- **Inspection is named where the work is listed.** A status text at `action_required` ends with
  the optional "What is left and why, in one read: check with mode inspect (records nothing)." and
  the card's inspection sentence leads with the question it answers. Status stays the read for
  exact ids and meaning fields; nothing forces the inspection.
- **#1049 follow-ups in the same text surfaces.** The card asks for answers to each open AI-powered
  finding (a `verified_resolved` or final finding, `next_actions: none`, takes no response), as do
  the `respond` description, `workflow.md` and the respond template, which now also cites the
  post-finding `evd_`/`res_` an acknowledgement needs. `request-templates.md#publish-work` and
  `#ordinary-publication` are explicit aliases of `#publication-templates`, and both documents
  alias `#plan-and-obligations`. The request-templates resource description counts the eighteen
  families `publish_work` admits (nine ordinary, seven lifecycle, two coordination) instead of
  "nine ordinary publication families"; the policy's sixteen are the core families and it says
  so. A digest subject refused by its `evidence_kind` branch is hinted with that branch's subset
  (INTERFACES, MCP error hints).

The card stays inside the 8 KiB mandatory budget: the Codex surface sat 9 bytes under it, so the
additions replaced the inspection sentence's list of what it returns (the `check` description
keeps it); the optional `read_guidance` `page_size` reminder did not fit and stays in the
`read_guidance` description.

Verification: `tests/conformance/surfaces/test_frontier_source_consistency.py` scans the shipped
guidance, skills, usage docs, every advertised tool and schema description and the missing-frontier
error, directive and nudge for status-as-frontier-source wording and checks the stated rule;
`tests/integration/application/test_held_frontier_sequence.py` drives start, hook observations,
the first plan with the start frontier and a later write with the returned one, with no status
read, and keeps a cooperative write in between a conflict; `tests/unit/mcp/test_summaries_text_fallback.py`
holds the start, publish and status texts; `tests/unit/mcp/test_guidance_family_inventory.py`,
`tests/unit/mcp/test_tb4n4_call_traps.py` and `tests/unit/mcp/test_tb4n5_digest_subject_hint.py`
hold the counts, aliases and subject hint (the five recorded tb4n5 subject shapes).
