# ADR-035 — The declared delivered set and a fact for a removed deliverable

**Status:** Accepted for [issue #1005](https://github.com/TheGaySupreme123/finishup/issues/1005)
(proposal PL5-4). Maintainer acknowledgement (TheGaySupreme123, 2026-10-07): "declared delivered
file set, with a deterministic fact for content moved out of it or a declared file deleted or
renamed". It changes no wire schema, no egress and no storage. It grants no runtime, credential,
disclosure or destructive-action authority.
**Implemented by:** `src/finishup/kernel/delivered_set.py`, `src/finishup/kernel/task_facts.py`
(`DECLARED_OUTPUT_REMOVED_GAP`, `DECLARED_OUTPUT_CONTENT_MOVED_GAP`,
`AGENT_ACTIONABLE_TASK_FACT_GAPS`, `STANDING_TASK_FACT_GAPS`, `STOP_GATE_TOKENS`),
`src/finishup/application/check.py` (`_requested_output_inputs`),
`src/finishup/application/check_change.py` (`requested_output_states`),
`src/finishup/adapters/git_change_capture.py` (`count_change_lines`), `src/finishup/domain/receipts.py`
(`TASK_FACT_GAP_SENTENCES`), `src/finishup/cli/closure_gate.py`, `guidance/workflow.md`.
**Relates to:** ADR-031 (check-time change capture), ADR-033 (task facts and the Stop-time closure
gate), issues #983, #1002, #1003.

## Context

In TB4 run tb4n1, agents reshaped their deliverables to fit an AI-powered review. In
interleaved-vigenere, the agent moved the statistics table out of the delivered `/app/cracker.py`
into an undelivered `/app/english_model.bin` so the reviewer could see the code. The cracker then
produced empty output, and 3 of 6 tests failed. In music-harmony, the agent moved the delivered
`harmony.musicxml` to `/tmp` "to reduce the review input". Guidance now forbids this. FinishUP still
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
   moved away: music-harmony's new `harmony.musicxml`). A read FinishUP could not make
   (`unverified`, `outside`, unknown existence) never raises it.
3. **Classification.** The code is agent-actionable (`AGENT_ACTIONABLE_TASK_FACT_GAPS`, so `_A` in
   `GAP_CLASSIFICATION`). It makes a check `coverage_incomplete`, and it is a `STOP_GATE_TOKENS`
   entry. Like every task fact, a local absence proof tolerates it. Its receipt sentence and
   Stop-gate text give the repair: "Restore the delivered file, or correct the requested item if
   the task asked for the deletion: FinishUP review limits never justify moving, splitting or
   deleting deliverables."
4. **Ways out.** The fact clears when the delivered file is back at its declared path. If the
   task really asked for the deletion, the agent corrects the requested item instead: it
   supersedes the obligation without that item, or, from 1.1.0, marks the item `role: input`.
   Recording a `finishup-blocker:<kind>` for the obligation also suppresses the fact, as it does for
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
- The line-count read counts untracked files whether or not they predate the task, so a large
  pre-existing untracked file can supply `G` for a declared file that only shrank. The receipt
  sentence says so ("untracked files may predate the task"); the fact stays a disclosure for that
  reason. (Since issue #1045 a task-start base records which untracked files predate the task, and
  the change listing, so the created-file candidates of `deliverable_references_undeclared_file`,
  leaves out the unchanged ones and lists a changed one as a modification; the line-count read does
  not use that snapshot.) The declared set used to exclude growth is built from the first 64
  probed `file` items (the requested-output probe bound); growth into a declared output beyond
  that bound counts as undeclared. A path containing CR or LF is skipped by the line-count read.

## Amendment (tb4n2 R2, issue #1022): deliverable_references_undeclared_file

tb4n2 interleaved-vigenere: the declared deliverable `cracker.py` loaded `english_model.npz` and
`english_words.json.gz`, files the agent created in the workspace and never declared. The grader
received only the declared files, so the deliverable failed. FinishUP now discloses that shape.

- **Deliverables read.** Every effective obligation's requested item with role `output` and kind
  `file` whose check-time state is `inside` and existing (not deleted), skipping blocked and
  `acknowledged_not_done` obligations, whose name has a source-code suffix (`.py .sh .bash .js
  .mjs .cjs .ts .rb .pl .r .R .jl .lua .php`) or no suffix and a `#!` first line.
- **Candidates.** Files the check-time change created (untracked, or status `A`) minus every
  declared `file` or `directory` value of any role, compared root-relative; a declared directory
  covers the files beneath it. Pre-existing tracked repository files are never candidates.
- **Rule.** The fact fires when a deliverable contains a one-line quoted string literal (single,
  double or backtick quotes) equal to a candidate's root-relative path, ending with `/` plus that
  path (which covers its absolute path under the root), or equal to the candidate's basename when
  that basename is at least 5 bytes long.
- **Bounded local content read.** The adapter method `count_undeclared_references` reads at most
  256 KiB from the start of at most 16 deliverables per check, one component at a time from the
  validated root descriptor without following a link, never a credential-named or multiply linked
  file, and skips binary content (a NUL byte in the prefix). Only a count leaves the adapter; no
  path or content is returned, logged or stored. Any failure means the fact is not raised.
- **Standing and non-blocking.** `deliverable_references_undeclared_file` is a
  `STANDING_TASK_FACT_GAPS` disclosure: never a finding, never a `STOP_GATE_TOKENS` entry, never
  receipt-blocking. Declaring the referenced file as an output or input clears it. It is a
  heuristic: a reference built at run time from pieces, or beyond the read bound, is not seen, and
  a matching literal that is not actually loaded still raises it.

## Amendment (tb4n2 R2, issue #1022): declared_output_emptied

tb4n2 formal-crypto S emptied its delivered `/app/solve.sage` (0 bytes) after an open finding,
while six obligations stayed recorded `resolved`; FinishUP showed only the standing
`obligation_evidence_stale_after_scope_edit`, so the Stop gate said nothing. A recorded status is
now re-derived from the current deliverable (ADR-041):

- **Rule.** `emptied_declared_items` names a declared `file` of an obligation that is `resolved`,
  or that an effective completion claim names (never `acknowledged_not_done`), whose check-time
  state is `inside`, existing and not deleted, and which is a regular file of 0 bytes
  (`size_bytes` from the same link-free metadata probe; no content read) whose name is not
  conventionally empty (`__init__.py`, `py.typed`, `.gitkeep`, `.keep`, `.nojekyll`), or a
  tracked file of at least `CONTENT_MOVED_MIN_LINES` task-base lines that kept fewer than a tenth
  of them, is not the content-moved shape (that stays the standing disclosure above), and no
  other declared delivered item changed in the same change (a split into another declared
  output is a refactor).
- **Agent work.** `declared_output_emptied` is in `AGENT_ACTIONABLE_TASK_FACT_GAPS` and
  `STOP_GATE_TOKENS`. While it stands the obligation's `resolved` no longer counts as delivered;
  the ledger is not rewritten. It clears at the next check once the file is restored or the
  obligation is republished `open` or `acknowledged_not_done` (the reducer admits both from
  `resolved`, ADR-041). A disclosure line does not clear it: an unrelated assumption must never
  hide an emptied deliverable.
- **Limits.** An untracked file truncated to a non-zero size is not seen (no earlier size is
  stored); an unread size or line count never raises the fact.

## Amendment (tb4n3 RC-5, issue #1028, ADR-045): emptied is a history fact keyed on the path

The rule above was a state test ("0 bytes") used for a change fact ("emptied"), and it was keyed on
the obligation. ADR-045 replaces it: each check records the size and line count of every declared
output file, including untracked ones (`DeliverableState`, `check_recorded` 1.4.0
`deliverable_states`), and `deliverable_state_change` answers `emptied`, `truncated`, `removed`,
`unchanged` or `None` only with **proof of earlier content** (task-base lines, or an earlier check
that read it with content). A file created empty never fires; a new file cut to a stub does; a
truncated capture is unknown, not changed. The fact is keyed on the path: it fires while an
obligation declaring the path is delivered, or the path was recorded with content while delivered
or verified, whatever the obligation's status is now, so an `acknowledged_not_done` republish or a
new "empty fallback" obligation cannot clear it. The single exit is a `finishup-assumption` decision of
an obligation declaring the path that names the path. The lines "clears ... once the obligation is
republished open or acknowledged_not_done" and "An untracked file truncated ... is not seen" above
no longer hold. The content-moved disclosure is unchanged and now also covers untracked
deliverables.

## Amendment (tb4n4, issue #1044): an undeclared dependency blocks closure and is named

tb4n4 interleaved-vigenere S: the delivered `artifacts/cracker.py` loaded `english_ngrams.npz` and
`english_words.npz` from beside itself, and only the cracker and its `requirements.txt` were
declared. The R2 disclosure above fired correctly, but its text ended "Embed it, rebuild it at
runtime, or disclose the dependency." The agent disclosed it and verified the cracker itself; the
grader received only the two declared files, the program printed nothing, and the attempt scored 0.
The deterministic arm passed with a self-contained file. Disclosing a file the grader never
receives is not a delivery. Recorded from the maintainer's request of 2026-10-12 (fix #1044 in the
tb4n4 remediation PR), which is the acknowledgement for the storage change below.

- **Agent work, on every surface.** `deliverable_references_undeclared_file` leaves
  `STANDING_TASK_FACT_GAPS` for `AGENT_ACTIONABLE_TASK_FACT_GAPS` and is a `STOP_GATE_TOKENS` entry.
  In the one gap table (ADR-046) it is rule `G0c`: readiness `A`, actionable on both routes, so the
  check is not clean, status reads `action_required` and lists it in `agent_actionable`, the
  predicted receipt and the receipt read `insufficient_coverage` (`live_gap_bounds`), and the Stop
  gate continues the agent. Gap classification version `"8"`. It is still never a finding.
- **The ways out are repairs.** Embed the file's content in the deliverable, rebuild it at run time,
  or declare the file as a requested item (a delivered output; a file the task itself provides is a
  `role: input` item). The read is unchanged on this point: every declared `file` or `directory` of
  any role excludes a candidate, and a deliverable that no longer names the file does not raise it.
  A `finishup-assumption` or `finishup-verification-limit` decision, a final-answer disclosure or a
  self-verification never clears it; the receipt sentence, the Stop-gate item and the guidance no
  longer offer "disclose the dependency". As before, a confirmed blocker or an
  `acknowledged_not_done` obligation is not read (it is already below clean).
- **Named, once, where the agent and the reader look.** The adapter method is now
  `find_undeclared_references(workspace, deliverables, candidates)`: it returns `(deliverable
  index, candidate index)` pairs into the caller's own tuples (at most 64), so no path leaves it
  that the caller did not hand it. The check records, on the referencing deliverable's
  `DeliverableState` (`check_recorded` 1.4.0, unreleased, changed in place), the optional
  `undeclared_references`: at most eight sorted root-relative paths of 1-256 characters (valid
  UTF-8, no control character, no leading `/`, no empty, `.` or `..` segment), with
  `undeclared_reference_count` when more were found than are named. This is the one path text a
  check records, and a deliberate exception to "a keyed commitment, never text": a commitment cannot
  tell the agent which file to declare. It lives in the encrypted event payload, never in a
  structural table, log or error. Status `closure_readiness.undeclared_references` (status-result
  1.4.0, unreleased, optional) carries the rows of the applicable check; each path is a
  `repository_excerpt` content leaf of the privacy projection, so a policy can withhold it. The
  receipt (its gap detail and its limitations sentence, in JSON, markdown and text) and the
  Stop-gate text print one sentence, `task_fact_tokens.undeclared_reference_variants`: "Undeclared
  files: <obligation> item <n> names "<path>" and "<path>"." Each path goes through
  `bounded_text.quoted_path` (ASCII, one line, no double quote, at most 120 characters), the
  rendering the post-compaction recap already used. Only the `full_local` receipt names a path: the
  `default_local_export` and `redacted_share` profiles clear the gap detail, like every gap detail,
  and their limitations sentence counts the files instead ("<obligation> item <n> names 2
  file(s)"). The MCP text summary, the hook diagnostics and the gate memory never carry a path.
- **Residuals.** The read is still a literal-matching heuristic over a bounded prefix (a path built
  from pieces at run time is not seen). An untracked file the task started with is not a candidate
  when the base is a task-start base carrying the #1045 snapshot: unchanged since, it is not part
  of the change, and changed since, it is listed as a modification, not as created. Without that
  snapshot (a `first_check` base or a base recorded before #1045), or past the snapshot's bound,
  it is still a candidate, so a task-provided untracked data file a deliverable loads stops the agent
  until it is declared `role: input`: one publish, chosen over letting a disclosure stand in for a
  missing delivery. A path that cannot be named is counted, not shown.

The R2 amendment's "Standing and non-blocking", "Only a count leaves the adapter" and "no path ...
is returned, logged or stored" no longer hold; the rest of it does.
