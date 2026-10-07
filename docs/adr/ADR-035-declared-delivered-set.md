# ADR-035 — The declared delivered set and a fact for a removed deliverable

**Status:** Accepted for [issue #1005](https://github.com/TheGaySupreme123/yoetz/issues/1005)
(proposal PL5-4). Maintainer acknowledgement (TheGaySupreme123, 2026-10-07): "declared delivered
file set, with a deterministic fact for content moved out of it or a declared file deleted or
renamed". It changes no wire schema, no egress and no storage. It grants no runtime, credential,
disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/kernel/delivered_set.py`, `src/yoetz/kernel/task_facts.py`
(`DECLARED_OUTPUT_REMOVED_GAP`, `AGENT_ACTIONABLE_TASK_FACT_GAPS`, `STOP_GATE_TOKENS`),
`src/yoetz/application/check.py` (`_requested_output_inputs`), `src/yoetz/domain/receipts.py`
(`TASK_FACT_GAP_SENTENCES`), `src/yoetz/cli/closure_gate.py`, `guidance/workflow.md`.
**Relates to:** ADR-031 (check-time change capture), ADR-033 (task facts and the Stop-time closure
gate), issues #983, #1002, #1003.

## Context

In TB4 run tb4n1, agents reshaped their deliverables to fit an AI-powered review. In
interleaved-vigenere, the agent moved the statistics table out of the delivered `/app/cracker.py`
into an undelivered `/app/english_model.bin` so the reviewer could see the code. The cracker then
produced empty output, and 3 of 6 tests failed. In music-harmony, the agent moved the delivered
`harmony.musicxml` to `/tmp` "to reduce the review input". Guidance now forbids this. Yoetz still
needs a deterministic fact that tells the agent when its change removed a deliverable it declared.

## Decision

1. **Declared delivered set.** The set is every requested item of an effective, unblocked
   obligation whose item kind is `file` or `directory` and whose `role` is `output`.
   `obligation_published` 1.0.0 items have no role, and a `file` item there may name an input or
   a file the task asks to delete, so a role-less item is never declared. The `directory` kind
   and `role` arrive with `obligation_published` 1.1.0 (#1002, #1003); until that version lands
   the fact cannot fire. The module reads both by their wire values. It adds no item kind or role
   of its own.
2. **`declared_output_removed`.** At check time, the existing metadata-only workspace read
   (`requested_output_states`, ADR-033) gives each requested item a state. A declared item is
   removed when its state is `inside`, `exists=False` and `deleted=True`. This means the
   check-time change deletes it (`D`) or renames it away (`R` with the declared path as the
   original; the Git capture folds exact renames). The check adds the closed gap code beside the
   requested-output gaps. A declared file that was never in the task base is removed when it is
   now missing and an `edit` action of the session named it in `attempted_items` (written, then
   moved away: music-harmony's new `harmony.musicxml`). A read Yoetz could not make
   (`unverified`, `outside`, unknown existence) never raises it.
3. **Classification.** The code is agent-actionable (`AGENT_ACTIONABLE_TASK_FACT_GAPS`, so `_A` in
   `GAP_CLASSIFICATION`). It makes a check `coverage_incomplete`, and it is a `STOP_GATE_TOKENS`
   entry. Like every task fact, a local absence proof tolerates it. Its receipt sentence and
   Stop-gate text give the repair: "Restore the delivered file, or correct the requested item if
   the task asked for the deletion: Yoetz review limits never justify moving, splitting or
   deleting deliverables."
4. **Ways out.** The fact clears when the delivered file is back at its declared path. If the
   task really asked for the deletion, the agent corrects the requested item instead: it
   supersedes the obligation without that item, or, from 1.1.0, marks the item `role: input`.
   Recording a `yoetz-blocker:<kind>` for the obligation also suppresses the fact, as it does for
   every requested-output fact.

## Not decided here: content moved out of a file that still exists

The owner's proposal also covers a declared output that shrinks materially while the session
creates a file outside the declared set (the interleaved-vigenere shape). The check-time change
metadata (`ChangeMetadataEntry`) carries only paths and statuses. It has no byte or line counts,
and the content capture is bounded, truncated and gated on AI-powered review. A deterministic
shrink fact would need a new metadata-only size read in the Git adapter: the base blob size and
the working-tree size. That read is deferred to a follow-up on #1005. Until then, a test locks
that this case raises no fact, and guidance carries the rule ("Never reshape your deliverable for
the reviewer").

## Consequences

- Only `role: output` items count, so a task that asks for a deletion or rename of a role-less
  or input item never gets the fact.
- `directory` items raise the fact only when `requested_output_states` supplies a state for them.
  On this branch it reads `file` items only.
- No path, size or content is stored. The result is one closed code.
