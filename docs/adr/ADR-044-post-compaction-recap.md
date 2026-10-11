# ADR-044 — A bounded, sourced recap of Yoetz state when a host resumes after compaction

**Status:** Accepted for [issue #1027](https://github.com/TheGaySupreme123/yoetz/issues/1027)
(tb4n3 N3-7 / RC-4). Maintainer acknowledgement (TheGaySupreme123, 2026-10-11, owner decision 2 for
the tb4n3 remediation): "on the post-compaction session start, inject a bounded receipt-style recap
of Yoetz state so the agent resumes with what Yoetz knows." The one wire change is an optional
field on the compact status item of the unreleased status-result 1.4.0. This ADR grants no
runtime, credential, disclosure or destructive-action authority, adds no service operation and no
MCP tool.
**Implemented by:** `src/yoetz/domain/compaction_recap.py` (the pure composer),
`src/yoetz/domain/bounded_text.py` (`compose_parts`, `list_variants`),
`src/yoetz/cli/compaction_recap.py` (status result to facts, pending-row count),
`src/yoetz/cli/hooks.py` (`_read_status(recap=...)`, `_read_recap_facts`, `_with_compaction_recap`),
`src/yoetz/cli/observe_hooks.py` (`_session_start_attach`, `_compaction_recap_text`,
`_session_start_source`), `src/yoetz/cli/hook_io.py` (`limit`), `src/yoetz/protocol/models.py`
(`StatusLatestCheckModel`), `src/yoetz/adapters/memory/ledger.py` (`_latest_check`),
`schemas/operations/status-result-1.4.0.schema.json`.
**Relates to:** ADR-010 decision 8 (a trigger hook earns no coverage), ADR-022 decision 15 (the
compaction fold this lane repaired), ADR-032 (closure readiness), ADR-033 (task facts, the Stop
gate), ADR-009 (the `agent_context` disclosure ceiling).

## Context

Codex compacted 8 of 27 tb4n3 attempts, and compaction keeps recurring in the longest, hardest
runs. After a compaction the agent resumes from a summary of its own work. Yoetz's only response
was one cue, "for compaction in an already-started host session, use your held current ids for
status" (`cli/hooks.py::_active_context`). The ids come back; the state does not. An agent that
lost its context did not know which obligations were open, which findings awaited an answer, what
the last check concluded, which outputs it had declared, or what Yoetz thought it should do next,
until it spent calls rediscovering them.

The owner's original idea for the compaction hook was exactly this: "to have a receipt for the work
till then, to help the compaction go better." The same tb4n3 round showed the other half of the
problem: every post-compaction command outcome was lost from the ledger (ADR-022 decision 15,
amendment for #1027), so a recap built over that ledger would have been wrong. That is fixed in
the same change.

## Decisions

1. **The recap is a read of `status`, not a new operation.** A host's post-compaction start already
   reads the mapped session's compact `status`; the recap states what that one result (and, when
   time allows, one `obligations` view) carried. It is a trigger-hook output in ADR-010's sense:
   it observes nothing, records nothing, earns no coverage, claims nothing, and discloses only
   what `status` would already have returned under the `agent_context` ceiling. A description,
   summary or path that `status` withheld stays withheld in the recap ("text withheld by the
   disclosure policy"). It is not evidence; `status` is the live read.

2. **What it states, and from where.** Every line ends with `[source ...]` naming the status view
   and the frontier it was read at, the recorded check event, the hook mapping, or the local
   outbox:

   | Line | Content | Source |
   |---|---|---|
   | `ids` | task, session and writer ids | hook mapping |
   | `frontier` | head sequence and a digest prefix | status compact head frontier |
   | `plan` | plan event id, declared / open / acknowledged-not-done counts, task text when disclosed | status compact |
   | `readiness` | `closure_readiness.state`, the `agent_actionable` tokens, blocked-obligation count | status compact closure_readiness |
   | `open obligations` | up to 10 ids with a quoted excerpt of the description, the rest counted | status compact |
   | `findings awaiting your response` | up to 10 ids with priority, kind and a quoted excerpt, total and receipt-blocking counts, marked reviewer text and advisory | status compact |
   | `last check` | verdict, the frontier it examined, the check event id; or "none recorded" (readiness reports `check_not_recorded`); or "not reported by this status" | status compact `latest_check` |
   | `declared deliverables` | requested `file` / `directory` items with role `output` of obligations in the current plan (`in_current_plan`), each with its obligation and that obligation's status, quoted on one line; up to three obligations pages are read, and a line says when pages remain unread; "unavailable" if the read did not answer or the view could not place obligations in the plan | status obligations, at that read's own frontier |
   | `next` | one plain-words sentence for `closure_readiness.state` | status compact closure_readiness |
   | note | the number of this session's undelivered local rows that would add ledger work, when any | local outbox |

   The next action is a rendering of the readiness `state` and `agent_actionable` that `status` and
   the Stop gate already use. The recap adds no classifier.

3. **Bounded and honest under pressure.** The recap is at most 2,400 characters and the whole
   compaction-start context at most 4,000 (`RECAP_LIMIT`, `RECAP_CONTEXT_LIMIT`; every other hook
   context keeps its 2,000-character bound), ASCII only, composed by `compose_parts`. The
   identity, frontier, next-action and closing lines are required. Findings and open obligations are
   required in their shortest form (a count that points at `status`) and are upgraded first; plan,
   readiness, last check and deliverables yield in that order. A section the budget cannot hold is
   named in one line ("Omitted for space, ask status: ..."); nothing is dropped silently, and text
   taken from the task or a reviewer is flattened to one quoted 80-character excerpt that cannot
   close its own quotes.

4. **Where it is emitted.** Only on a host's post-compaction start (`SessionStart`, `source:
   compact`), never on `startup`, `resume`, `clear` or any other event, and after the held-ids cue
   and the admission notice so those keep their own bounds.

   - Codex: two `SessionStart` hooks run concurrently on a compact start, the `hooks
     session-start` re-ground hook (registered for `resume|compact`) and the shared `hooks observe
     SessionStart` hook. Whichever holds the session lifecycle lock reads status and carries the
     active context; the other cannot read status and emits at most the admission notice (the
     tb4n3 sglang S rollout shows exactly that pair of developer messages). So both can carry the
     recap, and only a hook that reads status composes it: when the two overlap, the lock holder
     does and there is one recap, never none. The lock is released before the pass emits its
     output, so two hooks that run back to back (not overlapping) can each read status and each
     carry the recap, exactly as each already repeats the held-ids cue; that costs a repeated block,
     never a missing one. The re-ground hook's discarded delegation to the observe pass asks for
     no recap.
   - Claude Code and Cursor: the shared observe pass. Their wrappers encode the lifecycle source in
     the structural action (`claude_session_compact`, `cursor_session_compact`), which
     `_session_start_source` now resolves.

5. **Currency, and why `PreCompact` does not drain.** The recap is read after the compaction, from
   the ledger. The Codex re-ground hook counts the undelivered local rows before it reads status
   (the delegated observe pass drains them afterwards). The ordinary observe pass already reconciles the Codex session stream and drains the
   outbox on `PreCompact` and `PostCompact`, and a compaction itself runs for minutes with no tool
   call (about four minutes in the tb4n3 sglang S rollout), so every pre-compaction row has been offered
   to the ledger before the recap reads it. A second drain in `PreCompact` would add a synchronous
   cost to a hook Codex registers asynchronously and would not make the answer more current. If
   rows are nevertheless still undelivered, the recap says how many; it never claims freshness it
   did not read.

6. **It never blocks and never invents.** Any failure to read, compose or render leaves the
   existing held-ids context exactly as before. A missing field reads "not reported", never a
   default. The obligations reads are up to three pages of at most 1.5 s each, started only within the
   first four seconds of the hook (so they add nothing to the worst case that already exists when
   the compact read itself is slow, in which case the recap is skipped); if they fail or run out
   of time the recap says deliverables are unavailable or that pages remain unread. A positive
   count whose rows the status did not preview (withheld ones) is still stated as a count.

7. **Two additive wire fields.** The compact status item gains `latest_check`
   `{check_event_id, checked_frontier, verdict}`, read off the recorded `check_recorded` event the
   projection's latest tested state points at, absent when no check exists. Each obligations-view
   item gains `in_current_plan`, true exactly for the obligations of the current plan's effective
   scope (`task_facts.effective_obligations`: not waived, not superseded), absent when the scope
   cannot be read. Both are status-result 1.4.0, unreleased, `optional_non_null`. The first is the
   only way the recap, or an agent, can name the last check without opening it; the second is how
   a reader tells declared deliverables from the historical ones the view also lists, with the same
   definition the readiness facts use. An older service omits both, and the recap then says "not
   reported" or "unavailable" rather than claim a deliverable.

8. **Provenance is per read, and text is quoted.** The deliverables line names the obligations
   read's own head frontier, not the compact read's. Every value interpolated outside a quoted
   excerpt is reduced to a safe token (no whitespace, quote or control character), and every
   piece of task, reviewer or path text is flattened to a quoted single-line excerpt, so a field
   cannot start a line of its own or forge a `[source ...]` label.

## Per-host decisions

| Host | Decision | Why | Follow-up |
|---|---|---|---|
| Codex | **Supported.** `SessionStart` source `compact` through the re-ground hook; the SessionStart `additionalContext` reaches the model as a `hooks.additional_context` developer message (confirmed in the tb4n3 sglang S rollout, which shows the admission notice and the held-ids cue arriving at the compaction start). | The plugin registers `resume\|compact` re-ground and `PreCompact`/`PostCompact` observation hooks. | Whether `PreCompact` accepts model-visible context (which would put the receipt into the summarization itself, the owner's original idea) is not documented in any certified Codex profile; verify before claiming it. |
| Claude Code | **Supported.** `SessionStart` source `compact` through the shared pass; `hookSpecificOutput.additionalContext`. | Claude Code reports `source: compact` on the post-compaction start and Yoetz already maps it to `claude_session_compact`. No `PreCompact` hook is registered. | Claude's own `additionalContext` size handling is not asserted here; the 4,000-character bound is Yoetz's, and the recap stays under it. |
| Cursor | **Not supported here; the shared path is source-driven.** | Cursor's certified profile (cursor-ide-3.17.8) registers `sessionStart` once per conversation and documents no post-compaction event or context channel; `sessionStart` is fire-and-forget, so even a start that fired would not be guaranteed to land before the agent's next action. If Cursor reports `source: compact` the same code serves it (tested), but no live evidence exists. | Re-read Cursor's hooks reference for a post-compaction event with an injection channel; if one exists add it to `CURSOR_ORDINARY_HOOK_EVENTS` and certify it. |

## Consequences

- The agent resumes with the receipt-style facts Yoetz recorded, each with its provenance, in one
  bounded block instead of several rediscovery calls.
- The post-compaction ledger is now trustworthy enough to recap: command outcomes are no longer
  lost (ADR-022 amendment, #1027).
- A bounded character allowance larger than the default exists for exactly one caller.
- No guidance text changes: the held-ids cue and the workflow's status step are unchanged, and the
  recap is a convenience, not a replacement for `status`.

## Not decided here

- Replaying a committed hook operation (same reconstructable role set) never compares the copy's
  outcome with the committed one: operation digests do not cover payloads (ADR-022). A second hook
  `PostToolUse` for a finished call is paired as unpaired evidence by the hook layer, so a real
  host does not produce one; the event-id duplicate path added with this ADR does compare (it
  refuses a differing explicit outcome for a non-stream copy).

- Injecting the recap into the compaction summarization itself (needs a host `PreCompact` context
  channel; see the Codex follow-up).
- A recap for `resume`: a resumed session replays its own transcript, so the compaction problem
  does not arise; the plain re-ground is unchanged.
- Any MCP tool, CLI command or TUI surface that prints the recap on demand. `status` is that read.
