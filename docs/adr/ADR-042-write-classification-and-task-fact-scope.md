# ADR-042 — Which edits make verification stale, and which task facts bear on a finding

**Status:** Accepted for [issue #1018](https://github.com/TheGaySupreme123/yoetz/issues/1018)
(tb4n2 core issue R4: ACTIONS P1-2, P1-3, P1-4b, P1-7 E4 parts, P1-16). Maintainer
acknowledgement (TheGaySupreme123, 2026-10-08): "all r been agreed", approving R1-R10 including
their design changes; the Stop-gate token set and the classification rule are the design-gated
parts. It edits the unreleased control-request 2.9.0 structural payload in place (one enum). It
grants no runtime, credential, disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/domain/write_scope.py`, `src/yoetz/cli/runtime_facts.py`,
`src/yoetz/adapters/integrations/codex_session_stream.py` (`_file_change_write_scope`),
`src/yoetz/application/observation_materialize.py` (`_runtime_description_facts`,
`_action_kind`), `src/yoetz/kernel/observed_failures.py` (`observed_edit_counts`,
`NON_COUNTING_WRITE_TOKENS`), `src/yoetz/kernel/task_facts.py` (`_observed_state`,
`STOP_GATE_TOKENS`), `src/yoetz/kernel/policies/work_integrity.py`,
`src/yoetz/domain/observation_selection.py` (`_runner_class_for_argv`),
`src/yoetz/kernel/task_fact_scope.py`, `src/yoetz/kernel/self_verification.py`,
`src/yoetz/cli/closure_gate.py`, `guidance/receipt.md`, `skills/codex/yoetz/SKILL.md`.
**Relates to:** ADR-022 (observation authorship), ADR-033 (task facts and the Stop-time closure
gate), ADR-034 (`respond self_verified`), ADR-035 (declared delivered set).

## Context

Yoetz's job is to catch incomplete work, and one of its clearest signals is "the work changed after
the last verification run". In TB4 run tb4n2 that signal was mostly noise, and where it mattered it
did not stop the agent:

- every observed edit moved the "latest edit" mark, so scratch files under `/tmp` (pretrain D/S:
  `/tmp/solve_remap.py` and three more), log files, and a receipt the agent saved into the workspace
  after the receipt (cad S `/app/yoetz_receipt.md`, lake D `/app/output/yoetz_receipt.json`) made
  `planned_verification_stale` and `edited_after_last_verification` fire and reopened closure;
- the interleaved S `edited_after_last_verification` fact was false. A ledger reconstruction from the
  export (the last `apply_patch` at ingestion 833; `python -m pytest` passing at 875 and again after
  the context compaction at 1039/1041) showed the cause was not late ingestion:
  `python -m pytest` was classified runner `other`, never verification, while an early
  `python /app/dev/build_model.py` was classified `build` because its file name contains "build". The
  only "verification" run of the task predated every edit;
- task facts are task-wide in a check's coverage, so `coverage:edited_after_last_verification` sat
  in the resolution reasons of every AI-powered finding and disqualified unrelated review findings
  from `respond self_verified` (interleaved S `fnd_6fa89200`, `fnd_d4acc8c3`);
- an obligation item with `role: input` was reported "never attempted" (formal S `/root/data`,
  interleaved D sample inputs), and one published research action counted as acting on every
  obligation (lake S);
- `edited_after_last_verification` was not a Stop-gate token, so cad S and interleaved S stopped
  with it in `agent_actionable` and the gate said `closure_gate_not_required`.

## Decisions

1. **Four write classes.** An observed edit's paths are `deliverable` (a declared `role: output`
   file, ADR-035), `workspace` (any other workspace path, and a real write outside the workspace such
   as an installed package the task told the agent to patch), `scratch` (a path outside the workspace
   under a fixed temporary root: `/tmp`, `/var/tmp`, `/dev/shm`, their `/private` aliases, the macOS
   per-user and WSL Windows temp directories; the process's own `TMPDIR` claims no outside write, as
   ADR-033 decision 7 says, but is not named scratch, so replay never depends on it) or `yoetz_owned` (a
   receipt or export file named `yoetz[-_.]receipt*.{md,markdown,json,txt,text}` /
   `yoetz[-_.]export*.…`, Yoetz's state directory or isolation root, `.agents/plugins/yoetz`,
   `.agents/skills/yoetz`). The rule is lexical and never resolves a path through the filesystem.
   Every path inside the workspace counts, a log file included (a log may be a deliverable; shell
   redirects into logs are commands, never edits, and a log under a temporary root is scratch), and
   a path whose workspace relation is unknown counts (a temporary directory may be the workspace).
   Only `deliverable` and `workspace` (and real outside) writes make an earlier verification stale.
   Deliverables take precedence, per class (`task_facts.non_counting_edits_exempt`): no scratch
   edit is exempt when a requested non-input file or directory lies under or contains a fixed
   temporary root (a deliverable under `/tmp`), and no Yoetz-owned edit is exempt when a requested
   non-input file has a receipt or export name or any requested non-input directory exists (a
   receipt saved into a declared output directory changes that delivery).
2. **The hook names the class, the kernel reads a closed token.** The control-request 2.9.0
   structural fact `write_scope` (unreleased; edited in place) admits `outside_workspace`, `scratch`
   and `yoetz_owned`. An edit tool reports `scratch` or `yoetz_owned` only when every path it names is
   in that class (Yoetz-owned wins over scratch); any workspace path makes it an ordinary edit;
   `outside_workspace` wins over everything. A Codex session-stream `FileChange` item is classified
   from its own change paths; the stream knows no workspace root, so it names only `yoetz_owned`
   (never `scratch` or `outside_workspace`). A patch's `Delete File` paths are classified too, so a
   patch that deletes a workspace file is a workspace edit. The observed action description carries `(write scratch)` or
   `(write yoetz_owned)` beside the existing `(write outside_workspace)`; no path crosses.
3. **Non-counting edits.** `kernel.task_facts._observed_state` and the work-integrity "completion
   claim must cite a verification after the latest observed edit" rule skip an edit carrying a
   non-counting token: it never advances the latest edit and is not acting. Edits recorded before
   the token existed count as before. Shell redirects stay commands, not edits.
4. **Yoetz's own MCP tools are never edits or commands.** A server-qualified Yoetz MCP tool
   (`mcp__yoetz__*`, `mcp__plugin_yoetz_*__*`) materializes as `other` whatever its name contains.
   Another server's tool keeps the name rules (`mcp__fs__edit_file` may really edit a file).
5. **Python module runs are classified by module.** `python[3[.x]] [-X opt] -m <module>` is `test`
   for pytest, unittest, nose2, tox, nox and doctest; `typecheck` for mypy and pyright; `lint` for
   ruff, flake8, pylint, pyflakes and pycodestyle; `build` for build and compileall; `other`
   otherwise. A pytest run that only reports on itself or collects (`--version`, `-h`, `--help`,
   `--collect-only`, `--collectonly`, `--co`, `--fixtures`, `--funcargs`, `--fixtures-per-test`,
   `--markers`, `--setup-only`, `--setup-plan`) is `other`. A project runner's `run` (`uv run`,
   `poetry run`, `pipenv run`, `pdm run`, `hatch run`, `rye run`) is classified by the command it
   runs (options and their operands skipped); `uv run --script` runs the agent's script (`other`). A script an interpreter runs is never a `build` because its file name contains
   "build"; only an explicit `build` argument (`python setup.py build`) is.
6. **Task facts are scoped per finding for self-verification.** `kernel.task_fact_scope` decides
   whether a task fact bears on one finding: an obligation-scoped fact only when the finding is
   about that obligation (an obligation subject ref, a claim subject ref naming it — a completion
   claim naming none covers every effective obligation — or an action-event subject ref naming it);
   the requested- and declared-output facts (read at check time, so their scope is not replayable)
   always; the task-wide `edited_after_last_verification` only for a finding about verification or evidence
   (`claim_without_admissible_evidence`, `evidence_does_not_support_claim`,
   `stale_evidence_for_changed_state`, `failed_work_omitted`, `weak_or_stale_response`,
   `ledger_stale_or_incomplete`). `self_verification_refusal` drops the `coverage:` reasons of
   facts that do not bear on the finding before applying ADR-034's rule; when an unrelated fact is
   the only reason left, it is kept (the agent clears it by doing that work). The refusal-reason
   payload (tb4n2 R5, closure lane) reads the same scoped list. Closure readiness, the Stop gate
   and finding resolution keep every task fact task-wide: they are work the agent owes whatever
   finding is open.
7. **"Never attempted" waits for work on that obligation.** A requested item with `role: input` is
   never reported unattempted. Otherwise an item is reported only once a completion claim names the
   obligation (or claims the whole task), or the agent published a producing action (edit, command,
   other) naming the obligation or naming none — the same rule ADR-033 applies to an absent requested
   output. A published research or review action is not acting.
8. **`edited_after_last_verification` is a Stop-gate token.** It joins `STOP_GATE_TOKENS` after the
   planned-verification tokens and the gate's observation-dependent set (never used while this
   task's hook observations are still draining). Gate text: "you edited the work after your last
   verification run: re-run the verification you planned (or the tests you last ran) on the final
   state", followed by the existing "Run each planned verification after your last edit" repair.
   The once-per-frontier and active-Stop rules of ADR-033 are unchanged: an active Stop still never
   continues the agent for ordinary items.
9. **The receipt is not a workspace file.** Guidance (`receipt.md`) and the Codex skill tell the
   agent never to save the receipt into the workspace or an output directory; decision 1 makes a
   saved receipt a non-counting write even when an agent does.

## Consequences

- Scratch work outside the workspace and a saved receipt no longer reopen closure or keep a stale fact alive; real
  edits to the work, including docs inside the workspace and writes outside it, still do. A file
  misclassified as scratch would hide a real edit from the stale rule only; the closure checklist,
  requested-output facts and the review still see the workspace change.
- A `python -m pytest` run after the last edit now clears `edited_after_last_verification` and
  `planned_verification_stale`; a script whose name contains "build" no longer counts as one.
- An agent that edits after its last verification run and stops is continued once to re-run it.
- Unrelated task facts no longer refuse `self_verified`; a verification finding is still refused
  while the work changed after the last run.
- Earlier ledgers replay unchanged except where a description already carries a new token (none
  can) and the E4/acting rules, which are derived at check time and not stored.

## Alternatives considered

- **Content sniffing for receipt files.** Rejected: the receipt has no fixed header, and a name rule
  plus guidance covers every observed case.
- **Treating every MCP tool as non-editing.** Rejected: a third-party file-system MCP server really
  edits files.
- **Scoping task facts inside finding resolution.** Deferred: it changes which recorded findings
  resolve on replay; the self-verification scope fixes the observed failure without that.
- **Re-asking new observation tokens on an active Stop (tb4n2 N-C5).** Not taken here; the gate's
  active-Stop rule stays as ADR-033 decided.
