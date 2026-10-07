# ADR-035 — The declared delivered set and a fact for a removed deliverable

**Status:** Accepted for [issue #1005](https://github.com/TheGaySupreme123/yoetz/issues/1005)
(proposal PL5-4). Maintainer acknowledgement (TheGaySupreme123, 2026-10-07): "declared delivered
file set, with a deterministic fact for content moved out of it or a declared file deleted or
renamed". It changes no wire schema, no egress and no storage. It grants no runtime, credential,
disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/kernel/delivered_set.py`, `src/yoetz/kernel/task_facts.py`
(`DECLARED_OUTPUT_REMOVED_GAP`, `DECLARED_OUTPUT_CONTENT_MOVED_GAP`,
`AGENT_ACTIONABLE_TASK_FACT_GAPS`, `STANDING_TASK_FACT_GAPS`, `STOP_GATE_TOKENS`),
`src/yoetz/application/check.py` (`_requested_output_inputs`),
`src/yoetz/application/check_change.py` (`requested_output_states`),
`src/yoetz/adapters/git_change_capture.py` (`count_change_lines`), `src/yoetz/domain/receipts.py`
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

5. **`declared_output_content_moved` (owner decision, 2026-10-07).** Content moved out of a
   declared output that still exists (the interleaved-vigenere shape) is a **non-blocking
   disclosure**. When a declared `file` item exists, is inside the checked repository and the
   check-time change modifies it (`M`), the check makes one bounded, metadata-only line-count
   read through the Git adapter (`count_change_lines`): Git's `--numstat` from the task base for
   tracked changes, the newline count of each untracked file Git does not ignore (no link
   followed, at most 8 MiB per file and 64 MiB per call, never a credential-named or binary file),
   and the declared file's line count in the base blob. Only numbers leave the adapter; no path,
   size or content is stored. The rule, in integer arithmetic: the declared file lost
   `L = removed - added` lines with `L >= 20` and `2 * L >= base lines`, and the same change added
   `G` net lines (`added - removed`, at least 0, per file) to files outside the declared delivered
   set (not a declared `file`, not beneath a declared `directory`) with `2 * G >= L`. Lines moved
   into another declared output, a shrink with no matching growth elsewhere, a binary or
   unreadable file, and a read that fails never raise it; a truncated read only lowers `G`. The
   code is a standing disclosure (`STANDING_TASK_FACT_GAPS`, `_S`), never a `STOP_GATE_TOKENS`
   entry, never a finding and never receipt-blocking. Its receipt sentence says content may have
   moved out of a delivered file into an undelivered one and asks the agent to check the
   deliverable still works where the task delivers it; the Stop-gate text carries the same note
   only when the gate already fires for another reason. The same role rule applies: role-less
   items never count. The counts are a point-in-time read without the capture's stability
   re-check, which is acceptable only because the result never blocks.

## Consequences

- Only `role: output` items count, so a task that asks for a deletion or rename of a role-less
  or input item never gets the fact.
- `directory` items raise the fact only when `requested_output_states` supplies a state for them.
  On this branch it reads `file` items only.
- No path, size or content is stored. The result is closed codes only.
- `declared_output_content_moved` is a heuristic. A legitimate split into an undeclared helper
  module raises it (the agent can declare the helper as an output); a table moved into a binary
  file, or growth spread beyond the read's bounds, does not.
- Untracked files are counted whether or not they predate the task (no base untracked set is
  recorded), so a large pre-existing untracked file can supply `G` for a declared file that only
  shrank. The receipt sentence says so ("untracked files may predate the task"); the fact stays a
  disclosure for that reason. The declared set used to exclude growth is built from the first 64
  probed `file` items (the requested-output probe bound); growth into a declared output beyond
  that bound counts as undeclared. A path containing CR or LF is skipped by the line-count read.
