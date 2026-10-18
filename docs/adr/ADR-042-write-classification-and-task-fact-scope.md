# ADR-042 — Which edits make verification stale, and which task facts bear on a finding

**Status:** Accepted for [issue #1018](https://github.com/TheGaySupreme123/finishup/issues/1018)
(tb4n2 core issue R4: ACTIONS P1-2, P1-3, P1-4b, P1-7 E4 parts, P1-16). Maintainer
acknowledgement (TheGaySupreme123, 2026-10-08): "all r been agreed", approving R1-R10 including
their design changes; the Stop-gate token set and the classification rule are the design-gated
parts. It edits the unreleased control-request 2.9.0 structural payload in place (one enum). It
grants no runtime, credential, disclosure or destructive-action authority.
**Implemented by:** `src/finishup/domain/write_scope.py`, `src/finishup/cli/runtime_facts.py`,
`src/finishup/adapters/integrations/codex_session_stream.py` (`_file_change_write_scope`),
`src/finishup/application/observation_materialize.py` (`_runtime_description_facts`,
`_action_kind`), `src/finishup/kernel/observed_failures.py` (`observed_edit_counts`,
`NON_COUNTING_WRITE_TOKENS`), `src/finishup/kernel/task_facts.py` (`_observed_state`,
`STOP_GATE_TOKENS`), `src/finishup/kernel/policies/work_integrity.py`,
`src/finishup/domain/observation_selection.py` (`_runner_class_for_argv`),
`src/finishup/kernel/task_fact_scope.py`, `src/finishup/kernel/self_verification.py`,
`src/finishup/cli/closure_gate.py`, `guidance/receipt.md`.
**Relates to:** ADR-022 (observation authorship), ADR-033 (task facts and the Stop-time closure
gate), ADR-034 (`respond self_verified`), ADR-035 (declared delivered set).

## Context

FinishUP's job is to catch incomplete work, and one of its clearest signals is "the work changed after
the last verification run". In TB4 run tb4n2 that signal was mostly noise, and where it mattered it
did not stop the agent:

- every observed edit moved the "latest edit" mark, so scratch files under `/tmp` (pretrain D/S:
  `/tmp/solve_remap.py` and three more), log files, and a receipt the agent saved into the workspace
  after the receipt (cad S `/app/finishup_receipt.md`, lake D `/app/output/finishup_receipt.json`) made
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
   receipt or export file named `finishup[-_.]receipt*.{md,markdown,json,txt,text}` /
   `finishup[-_.]export*.…`, FinishUP's state directory or isolation root, `.agents/plugins/finishup`,
   `.agents/skills/finishup`). The rule is lexical and never resolves a path through the filesystem.
   Every path inside the workspace counts, a log file included (a log may be a deliverable; shell
   redirects into logs are commands, never edits, and a log under a temporary root is scratch), and
   a path whose workspace relation is unknown counts (a temporary directory may be the workspace).
   Only `deliverable` and `workspace` (and real outside) writes make an earlier verification stale.
   Deliverables take precedence, per class (`task_facts.non_counting_edits_exempt`): no scratch
   edit is exempt when a requested non-input file or directory lies under or contains a fixed
   temporary root (a deliverable under `/tmp`), and no FinishUP-owned edit is exempt when a requested
   non-input file has a receipt or export name or lies in a packaged FinishUP tree, or any requested
   non-input directory exists (a
   receipt saved into a declared output directory changes that delivery).
2. **The hook names the class, the kernel reads a closed token.** The control-request 2.9.0
   structural fact `write_scope` (unreleased; edited in place) admits `outside_workspace`, `scratch`
   and `yoetz_owned`, and since ADR-045 `notes` and `workspace` (a shell command that writes the
   workspace). The wire enum is generated from the hook's own closed set (`WRITE_SCOPES`), so the
   wire admits every value the hook emits (#1039: it had refused `notes` and `workspace` at the
   client, and those observations never reached the ledger). An edit tool reports `scratch` or
   `yoetz_owned` only when every path it names is in that class; any workspace path, or a mix of
   scratch and FinishUP-owned paths, makes it an ordinary edit; `outside_workspace` wins over
   everything. A Codex session-stream `FileChange` item is classified
   from its own change paths; the stream knows no workspace root, so it names only `yoetz_owned`
   (never `scratch` or `outside_workspace`). A patch's `Delete File` paths are classified too, so a
   patch that deletes a workspace file is a workspace edit. The observed action description carries `(write scratch)` or
   `(write yoetz_owned)` beside the existing `(write outside_workspace)`; no path crosses.
3. **Non-counting edits.** `kernel.task_facts._observed_state` and the work-integrity "completion
   claim must cite a verification after the latest observed edit" rule skip an edit carrying a
   non-counting token: it never advances the latest edit and is not acting. Edits recorded before
   the token existed count as before. Shell redirects stay commands, not edits.
4. **FinishUP's own MCP tools are never edits or commands.** A server-qualified FinishUP MCP tool
   (`mcp__finishup__*`, `mcp__plugin_finishup_*__*`) materializes as `other` whatever its name contains.
   Another server's tool keeps the name rules (`mcp__fs__edit_file` may really edit a file).
5. **Python module runs are classified by module.** `python[3[.x]] [-X opt] -m <module>` is `test`
   for pytest, unittest, nose2, tox, nox and doctest; `typecheck` for mypy and pyright; `lint` for
   ruff, flake8, pylint, pyflakes and pycodestyle; `build` for build and compileall; `other`
   otherwise. A pytest run that only reports on itself or collects (`--version`, `-h`, `--help`,
   `--collect-only`, `--collectonly`, `--co`, `--fixtures`, `--funcargs`, `--fixtures-per-test`,
   `--markers`, `--setup-only`, `--setup-plan`) is `other`. A project runner's `run` (`uv run`,
   `poetry run`, `pipenv run`, `pdm run`, `hatch run`, `rye run`) is classified by the command it
   runs (global and run options and their operands skipped); `uv run --script` runs the agent's
   script (`other`). Any verifier invoked only with `--help`, `-h`, `--version` or `-V` is `other`. A script an interpreter runs is never a `build` because its file name contains
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
9. **The receipt is not a workspace file.** Guidance (`receipt.md`) tells the agent never to save
   the receipt into the workspace or an output directory (the Codex skill has no room under its
   8 KiB mandatory budget, so it relies on that page); decision 1 makes a
   saved receipt a non-counting write even when an agent does.

10. **An observed edit after a check supersedes it (tb4n3 RC-6, issue #1029).** The classification
    above also decides whether a later write changes what a recorded check covered:
    `kernel/later_material.later_material_class` reads the same closed `write ...` tokens and the
    same declared-output precedence (`task_facts.non_counting_edits_exempt`). A deliverable,
    workspace or real outside-workspace edit after the check makes it `check_not_applicable`
    (ADR-040 section 7); scratch and FinishUP-owned writes do not. One difference: a FinishUP receipt or
    export name stays non-counting even when a declared output directory makes it count for
    verification staleness, because a receipt cannot be covered by the check it reports on.

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

## Amendment (tb4n3 RC-5, issue #1028, ADR-045): notes and shell writes

Two write classes are added. `notes` is the agent's own working notes inside the workspace
(`NOTES.md`, `todo.txt`; a narrow name list, never `.log`, never README or report names): it is
non-counting like `scratch` and `yoetz_owned`, and a declared output (or any declared directory)
with such a name overrides the class. `workspace` is carried by a shell command whose attributable
writes (redirect targets, `tee`, `sed -i`, the destination of `cp`/`mv`/`install`/`rsync`, `touch`,
`truncate`, `dd of=`) include a path in the workspace; the kernel counts a command carrying
`workspace` or `outside_workspace` as an edit, so `cat > solve.py <<EOF` after the last test makes
the verification stale. A write the hook cannot attribute (`$VAR`, `~`, a script that opens files
itself) is not counted.

## Amendment (2026-10-13, tb4n5, issue #1049): a command mismatch is scoped like a task fact

`command_attempt_mismatch` is agent-actionable and keyed per obligation and requested command item
(`kernel.command_attempts`), but it is not a task fact, so decision 6 never scoped it: in tb4n5
react-lead-form S a mismatch on a command obligation (one observed `npm run submit` run cited for
its `npm test` and `npm run build` items) refused `self_verified` on an `action_without_result`
finding about an edit action that named no obligation and asserted no command item. Formal-crypto
S's refusal was about the mismatched obligation itself and stands (its agent cleared it with the
PL6-3 link).

`scoped_resolution_reasons` now drops `coverage:command_attempt_mismatch` when no mismatched item
(`task_fact_scope.command_mismatches`, the effective obligations' `asserted_observed_mismatch`
rows) is about the finding: the finding is about the mismatched obligation
(`finding_obligation_scope`), or a subject is an action that asserted the item, a linked observed
run event, or a result or evidence the obligation cites for its resolution (or that result's
action). A subject this projection cannot place, or a mismatch the current prefix no longer shows,
keeps it (fail closed), and an unrelated mismatch that is the only reason left still refuses (the
agent clears it by repairing the link, and the next check can then resolve the finding). Finding
resolution, closure readiness and the Stop gate are unchanged. A refusal on the mismatch now names
the mismatched obligation, the requested item index, the asserting action and the linked observed
run event, and the three ingredients of the PL6-3 link (`action_kind` command, `attempted_items`
holding the exact value, `causal_parents` naming the run), or citing the result of an observed run
of exactly that command; never the command text. Verification:
`tests/unit/kernel/test_tb4n5_command_mismatch_scope.py` replays the react S shape.

Check follow-up (2026-10-13, Codex check D1/D2): the scope fails closed on every unreadable link.
A claim or obligation subject that is missing or redacted, the action an event subject records
when that action is unreadable, or an event the projection cannot place keeps the mismatch;
only a subject whose every link was read and found unrelated drops it. The same unreadable-subject
rule now also keeps an obligation-scoped task fact (decision 6), which previously treated a
redacted claim as naming nothing; an event subject no projection row records counts as unreadable
there too (round 2, check D6). A finding on the linked observed run's result event (not only
its action event) bears on the mismatch: a result subject resolves through its recorded action.
`command_mismatches` is memoized for the last (projection, prefix, command-identity key
generation), so a key change in the process recomputes it.

## Amendment (2026-10-18, n7 RC2, issue #1106): project documentation never makes verification stale

In n7, a README or changelog edit after the last test raised `edited_after_last_verification`
(and its Stop prompt), although such an edit usually changes nothing the test, build or check
exercised. Folding documentation into `notes` would have made it non-counting (not acting, not
material for a later review), which conflates the agent's scratch notes with project work and
contradicts the README exclusion above. A sixth class is added instead.

- **`docs`** is a write whose every path is project documentation inside the workspace
  (`domain.write_scope.classify_write_path`, lexical like every class):
  - a conventional documentation name in any directory: `README`, `CHANGELOG`, `CHANGES`,
    `HISTORY`, `NEWS`, `AUTHORS`, `CONTRIBUTORS`, `CONTRIBUTING`, `LICENSE`/`LICENCE`, `COPYING`,
    `NOTICE`, `CODE_OF_CONDUCT` or `SECURITY` with a `.md`/`.markdown`/`.rst`/`.txt`/`.adoc`
    extension (optionally after a `-`/`_` suffix and a language tag: `CHANGES-1.x.rst`,
    `README.ja.md`). Without an extension only names no script plausibly has qualify: a bare
    `README`, `CHANGELOG`, `AUTHORS` or `CONTRIBUTORS`, and `LICENSE`/`LICENCE`/`COPYING`/`NOTICE`
    with an optional suffix (`LICENSE-MIT`). `bin/security-scan`, `scripts/history` or `news` may
    be a program a test runs, so they stay ordinary edits;
  - a `.md`/`.markdown`/`.rst`/`.adoc`/`.asciidoc` file outside a directory whose files a test or
    program reads as data (`test`, `tests`, `testing`, `spec`, `specs`, `__tests__`, `fixtures`,
    `testdata`, `test_data`, `data`, `prompts`, `templates`, `snapshots`, `__snapshots__`, and the
    agent hosts' `.agents`, `.claude`, `.codex`, `.cursor` and `skills` trees). Those directories
    are read on the path *inside* the workspace: a relative path as it is, an absolute one less the
    workspace root, so a workspace that itself sits in a host-managed worktree
    (`<repo>/.claude/worktrees/<name>`, `~/.cursor/worktrees/…`, `~/.codex/worktrees/…`) or under
    `/srv/data` is not data. An absolute path with no root to strip (the Codex session stream knows
    none) or a relative path that climbs out (`../`) cannot be placed, so only a conventional name
    makes it `docs`.

  `.txt` is never documentation by its extension (`requirements.txt` is read by the build).
  `notes` wins over `docs`; outside the workspace nothing changes. An edit tool names `docs` only
  when every path is documentation; a shell command only when documentation is the one class it
  writes; a Codex `FileChange` is named from its own paths. Any mix is an ordinary edit.
- **Semantics.** A `docs` write counts as acting, as a material edit (`material_edit_recorded`),
  as later material after a check (closing-review currency, `kernel.later_material`) and for
  concern-fold materiality. It never advances the latest edit for `edited_after_last_verification`,
  `planned_verification_stale` or work-integrity's "a completion claim must cite a verification
  after the latest observed edit" (`observed_failures.observed_write_stales_verification`,
  `STALE_EXEMPT_WRITE_TOKENS`). `work-integrity/0.3.0` is unreleased, so this rule changes within
  that policy generation without a version bump.
- **Deliverables win**, by the same precedence rule as `notes`: a declared non-input file with a
  documentation name or extension (in any directory: the declared-path test is deliberately wider
  than the class), or any declared non-input directory, turns the exemption off
  (`task_facts.stale_exempt_write_tokens`, `write_scope.docs_artifact_name`). Removing the
  declaration turns it back on.
- **Wire.** The unreleased control-request 2.9.0 `write_scope` enum is edited in place (decision
  2; maintainer request on #1106) and stays generated from `WRITE_SCOPES`. Version skew cannot
  reach the ledger: the schema manifest pins the 2.9.0 bytes, and both sides of the control
  handshake compare the whole manifest digest before any request frame, so a new hook never sends
  `docs` to an older service. It is refused as `manifest_mismatch`; the hook keeps its rows, and
  the MCP bridge's start, or `finishup service restart`, supersedes the stale holder through its
  lock stamp, after which the rows drain. The check-result 1.5.0 inspection row keeps its own scope
  list: a `docs` row shows no `write_scope`, still class `edit_or_write`. Naming `docs` there is a
  separate protocol change, left to a follow-up the #1106 owner opens.
- **Risks accepted.** The exemption is lexical, so it is bounded to what a path can show:
  - a verification that reads the documentation itself (doctests over a README or `.rst` file:
    `pytest --doctest-glob`, `python -m doctest`, a Rust doc test that includes `README.md`; a
    docs build such as `sphinx-build -W` or `mkdocs build --strict`; a Markdown lint) is not made
    stale by a later edit of that file. Declaring the file, or its directory, as an output turns
    the exemption back on;
  - a Markdown file a program reads at run time outside those directories (a prompt kept at the
    repository root) no longer makes verification stale unless it is declared.

  Rows recorded before the class existed keep counting as before (an edit-tool row with no scope, a
  shell row with `write workspace`). An older reader does not parse `(write docs)`; downgrade over
  0.3 ledgers is already unsupported.

Verification: `tests/unit/domain/test_write_scope.py`, `tests/unit/domain/test_shell_writes.py`,
`tests/unit/kernel/test_tb4n3_facts.py` (`c2i`-`c2k`, through each host's real hook chain),
`tests/unit/kernel/test_requirement_coverage_findings.py`,
`tests/unit/kernel/test_shell_write_supersedes.py`,
`tests/unit/protocol/test_structural_fact_wire_parity.py` and
`tests/unit/protocol/test_service_control_schemas.py` (the 2.9.0 enum pin); the handshake refusal
is pinned by the `manifest_mismatch` cases in `tests/unit/service/test_control_protocol.py` and
`tests/unit/service/test_client.py`.
