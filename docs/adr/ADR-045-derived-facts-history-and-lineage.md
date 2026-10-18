# ADR-045 — Derived facts carry history and lineage

**Status:** Accepted for [issue #1028](https://github.com/TheGaySupreme123/finishup/issues/1028)
(tb4n3 core issue RC-5, lane LF: `declared_output_emptied` on files created empty, the
formal-crypto S emptied solver, exact-string command identity, the dormant
`edited_after_last_verification`, exact-value attempt matching and binary-by-suffix). Maintainer
acknowledgement (TheGaySupreme123, 2026-10-11 owner decisions 7, 9 and 10): planned-command
matching normalizes wrappers and may match by prefix, a prefix-only match counts but is disclosed,
a `finishup-assumption` naming the path clears an emptied deliverable, and "if we add facts or info it
has lineage and where from". It adds one optional field to the unreleased `check_recorded` 1.4.0 and
two optional fields to the unreleased `status-result` / `check-result` 1.4.0, and edits the
hook-observation structural payload in place (one enum value, one raised bound). It grants no
runtime, credential, disclosure or destructive-action authority.
**Implemented by:** `src/finishup/kernel/delivered_set.py`, `src/finishup/kernel/fact_lineage.py`,
`src/finishup/kernel/task_facts.py`, `src/finishup/kernel/closure_readiness.py`
(`current_fact_lineage`), `src/finishup/kernel/command_attempts.py`,
`src/finishup/kernel/policies/work_integrity.py`, `src/finishup/kernel/receipt_builder.py`,
`src/finishup/domain/command_segments.py`, `src/finishup/domain/observation_selection.py`,
`src/finishup/domain/shell_writes.py`, `src/finishup/domain/write_scope.py`,
`src/finishup/domain/events.py` (`DeliverableState`), `src/finishup/application/check.py`,
`src/finishup/application/check_change.py`, `src/finishup/application/missing_for_assessment.py`,
`src/finishup/application/status.py`, `src/finishup/cli/closure_gate.py`, `src/finishup/cli/render.py`,
`src/finishup/cli/runtime_facts.py`, `src/finishup/mcp/summaries.py`, `src/finishup/protocol/models.py`
(`FactLineageModel`), `scripts/generate_schemas.py`.
**Relates to:** ADR-033 (task facts and the Stop-time gate), ADR-035 (declared delivered set),
ADR-041 (obligation status re-derived), ADR-042 (write classification and task-fact scope).

## Context

Deterministic "incomplete work" facts were computed from a point-in-time snapshot and an exact
string. tb4n3 (28 real Codex runs) showed what that costs:

- `declared_output_emptied` fired on `size_bytes == 0` with no "was ever non-empty" history. It was
  false on a file created empty (cargo D: its only gate token; cargo S: the agent added `python3`
  to a correct `apt-packages.txt` to clear it, which is steering the work wrong), missed a new file
  cut to a stub, and was disabled by a truncated capture. It was also keyed on the obligation. In
  formal-crypto S the agent republished the solver obligation `acknowledged_not_done` between two
  checks, which cleared the fact by design, then declared a new "deliver an empty `solve.sage`"
  obligation whose resolved status made the fact self-contradictory; the working solver stayed
  emptied (reward 0).
- Command identity was an exact string. A task-quoted flag set (`g++ -O3 -std=c++17 ... -I/app`)
  never matched the real compile, `timeout 3000 python3 x.py` never matched `python x.py`, and the
  runner classifier called every composed (`;`, `&`, `|`, `>`, `<`) command `compound` and every
  env-prefixed, absolute-path, `make synth` or `g++` command `other`. Neither counts as a
  verification run, so `edited_after_last_verification` was dormant in about 70% of runs and false
  in others (sglang D re-verified for seven minutes). Retro S re-ran `make test` as separate pure
  commands to satisfy the matcher.
- `requested_item_never_attempted` compared the agent's `attempted_items` byte for byte and let one
  untargeted action mark every obligation "acted on" (retro S, lake S).
- A binary deliverable was decided by suffix before any content sniff, and ISO 10303-21 `.step` /
  `.stp` (ASCII) were on the list.
- No derived fact said where it came from. The agent read a bare code.

## Decision

### 1. Deliverable history, recorded per check, keyed on the path

Each check records one `DeliverableState` per declared output `file` it read, in the optional
`check_recorded` 1.4.0 field `deliverable_states` (absent when the check read none, so those checks
keep their bytes): the obligation id and item index, a keyed commitment to the root-relative path
(`path_key`, the installation key that commits commands, its own domain; absent without the key),
`size_bytes`, `lines`, `base_lines`, a `basis`, and the check's conclusion (`change`, `proof`,
`prior_*`, `accepted_by`). Sizes and line counts are read for new (untracked) files as well as
tracked ones: `application/check_change._with_declared_line_counts` extends the bounded line-count
read to every existing declared file. Nothing but counts, closed tokens, ids and a keyed commitment
is stored.

`kernel/delivered_set.deliverable_state_change(state, history, ...)` answers `emptied`, `truncated`,
`removed`, `unchanged` or `None` (unknown) for one declared file:

- `emptied` and `truncated` need **proof of earlier content**: the tracked file has lines at the
  task base, or an earlier check recorded the path with content. A file only ever seen empty, an
  unread size, a path outside the repository and a truncated capture prove nothing: they are
  unknown, not changed. A conventionally empty name (`__init__.py`, `.gitkeep`, ...) is never
  emptied.
- `truncated` needs at least 20 earlier lines and fewer than a tenth of them left (or, when no line
  count could be read, a tenth of the bytes of a file of at least 2,048), and is not raised for the
  content-moved shape (ADR-035: the standing disclosure) or when the other declared outputs gained
  about as many lines (a split is a refactor).
- `removed` is the existing deleted-or-renamed rule plus a file an earlier check recorded with
  content that is now gone.

`assess_deliverables` decides per **path**: the rows that declare the same file share one history,
one verdict and one exit. The fact `declared_output_emptied` (one code for emptied and truncated;
the lineage says which; `declared_output_removed` keeps its code) fires when the change is emptied
or truncated **and** the file counts as a delivery: an obligation declaring the path is resolved or
claimed complete now, or an earlier check recorded the path with content while it was delivered
(`basis delivered`) or while a passing verification run was observed (`basis verified`). The
obligation's current status does not matter beyond that, so republishing the obligation
`acknowledged_not_done` or declaring a new "empty fallback" obligation on the same path cannot clear
it. This is the formal-crypto S fix. The "withdrawn after passing verification" case the issue
proposed as a second code is this same code with `basis verified`/`delivered`; one code keeps the
gate token, readiness classification and receipt aligned (`GAP_CLASSIFICATION_VERSION` 7).

**The one exit** is a `finishup-assumption:<obligation id>` decision of an obligation that declares
the path, whose statement or rationale names that exact path (the declared value or the
root-relative path, as a whole token): the task asked for this file to be empty. The check records
the state with `accepted_by` and does not raise the fact; the receipt already discloses the
assumption. A disclosure line that names no path never hides it. It clears at the next check, like
every other check-time fact; between checks the last check's answer stands (a limit the check-time
design already had, and the reason `edited_after_last_verification` also watches edits).

### 2. Lineage on every derived fact

`kernel/fact_lineage.FactLineage` is the small typed record: the fact code, a closed `rule`, a
closed `state`, the obligation id and item index, the observing check (event id and subject
frontier), the prior state (`prior_size_bytes`, `prior_lines`, `prior_frontier`, `prior_event_id`:
"15975 bytes at frontier 312"), the `proof` and `basis`, the observed run or edit events it rests
on, and the accepting decision. Closed tokens, counts and ids only; no path or command text.
`lineage_text` is the one renderer, so every surface prints the same `Why:` sentence.

Lineage is derived from the same records on every surface, never stored separately:
`closure_readiness.current_fact_lineage` (the applicable check's `deliverable_states` plus
`task_fact_signals(...).lineage`). It is carried as the optional `fact_lineage` list on status
`closure_readiness` and the check result (`FactLineageModel`), rendered in the CLI, the MCP text
summary (an optional part of the bounded composer: after the closure state, the stop instruction,
the agent-actionable items and the `check_cause` lineage, ahead of every boilerplate sentence, so a
tight bound drops it before anything required), the Stop-gate text (beside the tokens it explains,
the last optional ladder sentence dropped under the host bound, and the first optional part of the
composed fallback to go) and the receipt (the gap detail, so json, markdown and text agree). Covered
facts: `declared_output_emptied`, `declared_output_removed`, `declared_output_not_reviewable`,
`planned_verification_not_observed`, `planned_verification_failed`, `planned_verification_stale`,
`planned_verification_matched_by_prefix` and `edited_after_last_verification`.

### 3. Canonical command commitments

`domain/command_segments.canonical_words` reduces one simple command to its canonical argv: leading
`VAR=value` assignments and the wrappers `timeout`, `nice`, `ionice`, `nohup`, `stdbuf`, `env`,
`setsid`, `time`, `command`, `exec` and `uv`/`poetry`/`pipenv`/`pdm`/`hatch`/`rye run` dropped,
argv[0] reduced to its basename, `python3` and `pythonX.Y` to `python` (dropping only `-u`, `-B`
and `-q`; `-O`, `-W`, `-X`, `-E`, `-I`, `-s` and `-S` can change what a verifier does and stay),
`python -m pytest` and `py.test` to `pytest`. Arguments are never reordered or rewritten: two commands that run different
things never share a form. The hook commits, beside the whole-command and segment commitments, three
domain-separated kinds per simple command (`canonical_command_commitments`): `full` (the whole
canonical argv), `prefix` (each leading run of two or more arguments) and `flag` (one per argument
after argv[0]). They travel in the same `command_segment_commitments` list, whose bound rises from 32
to 80 (32 segments, 48 canonical; full forms first, so a bound only costs the looser matches).

The planned side computes the same kinds from its own text (`planned_segments`) and
`task_facts.planned_match` returns how a run matched: `exact`, `normalized` (same command up to
wrappers, aliases, absolute paths), `prefix` (the run began with the planned arguments and went on)
or `flags` (the planned program and all its flags are present, in any order). A single-token planned
command only ever matches whole. A planned `cd`/`export` segment may be absent from the run, which
makes the match a prefix one. `exact` and `normalized` are clean. A `prefix` or `flags` match
**counts as run** (the planned verification is not reported unobserved, and the run's outcome and
staleness apply as for any matched run) but raises the standing disclosure
`planned_verification_matched_by_prefix` with lineage naming the observed run: FinishUP cannot tell
whether the run is what the plan meant. Like `planned_verification_agent_linked` it is disclosed and
does not bound the conclusion. An older hook sends no canonical commitments and matches exactly, as
before.

The runner class now classifies a composition by its strongest verifying segment
(`cd /app && pytest -q | tail`: `test`), wrappers are stripped first, a program run from a `bin/`
directory is that tool, a compiler or hardware-toolchain run is `build`, `vvp` is `test`, a script
whose own name says it runs tests is `test`, and bare `make` is `build`. `compound_outcome_unavailable`
is raised by its own masking test, unchanged. A segment that redirects into a file is not
exploration. A run that matches a command the task asked for (any match kind) is also a
verification run for `edited_after_last_verification`, whatever its class: `sage solve.sage ... &&
cmp ...` is composed and classes `compound`, yet it is the check the task named.

**Shell writes count as edits.** `domain/shell_writes` names the paths a command visibly writes
(redirect targets, `tee`, `sed -i`, the destination of `cp`/`mv`/`install`/`rsync`, `touch`,
`truncate`, `dd of=`) and classifies them like an edit tool's paths. A command whose attributable
writes include a workspace path carries `write_scope: workspace` (a real outside-workspace write
carries `outside_workspace`); the kernel counts both as edits. The agent's own working notes
(`NOTES.md`, `todo.txt`; `.log` is never named by extension) are the new non-counting `notes` scope,
overridden by a declared output of that name. A command that writes only one non-counting class
(notes, or FinishUP material) carries that same scope, so the declared-output override applies to a
shell write as to an edit tool; a command that writes two non-counting classes
(`: > NOTES.md; : > finishup_receipt.md`) counts as an edit, as a mixed edit-tool call does, because
one token cannot carry both classes' overrides. A shell command that wrote counts as an edit
whatever its exit status (`: > f; false` emptied `f`). The rule is one predicate,
`kernel/observed_failures.observed_shell_write_counts`: a COMMAND whose runtime tokens carry
`write workspace` or `write outside_workspace` is an edit, and one that carries only a non-counting
class is an edit only where a declared output overrides that class. Every consumer of "the agent
changed files after X" shares it: the latest-edit fact (`task_facts`), later-material
classification (a shell write after a check is `edit_or_write`, so it supersedes the check and
re-arms the closing review exactly like an edit tool, ADR-046), the claim-verification
latest-edit rule (`work_integrity`) and the concern-fold materiality test (`review_concern`). A
failed or outcomeless shell write supersedes as a failed edit does, and the latest-edit fact counts
a shell write whose result never arrived as it counts an edit tool call still pending (#1046
review). A Codex shell `apply_patch <<EOF` is always one: Codex applies the patch itself and fires
only the pre-event (#1041), so the hook names the files its patch headers name
(`*** Update File: ...`), classified as the native `apply_patch` tool's paths are; the heredoc body
is otherwise data. A command with no write token
(unknown scope, or `none`) and FinishUP's own exploration runs stay as before. One classifier decides every path, in the
hook as in the Codex stream: the hook has no separate outside-workspace precheck, so
`cp source.json /opt/finishup_receipt.json` is `yoetz_owned` (FinishUP's own material), not
`outside_workspace`.

**The parser prefers a missed write to a guessed one.** A false write tells the agent its
verification is stale (steering, burned time); a missed write hides an edit made after it. Both
matter and a false write is worse, so `domain/shell_writes` names no write when it cannot be sure:

- *Text is not syntax.* The lexer is the module's own, not `shlex`. A quoted or escaped operator
  or keyword (`'!' touch f` runs a command named `!`), a comment, the word `tee` as an argument, a
  here-string, a heredoc body, and the inside of `[[ ... ]]` and `(( ... ))` (where `>` and `<`
  compare) write nothing. `$(...)`, `${...}`, `$[...]`, `$'...'` and backticks are opaque, with
  their own quote and nesting state (`echo "$(echo "x > f")"` writes nothing); inside `$(...)` a
  comment's parenthesis and a heredoc body (the `git commit -m "$(cat <<'EOF' ... EOF)"` idiom)
  close nothing, while a `case` there (its patterns end in an unmatched `)`) makes the command
  unlexable. A heredoc starts only at an unquoted `<<`/`<<-`; its delimiter is the word with
  quotes removed (`'END-DATA'`, `$'EOF'`; an escape inside `$'...'` is not decoded, so the command
  is unlexable); `<<-` strips leading tabs, and only tabs, when matching the closing line; in an
  unquoted heredoc a body line ending in a backslash continues on the next, and the joined line is
  what is compared; an unterminated body runs to the end, as in bash. The body of an unquoted heredoc is data here even
  though bash expands `$(...)` in it: a write hidden in one is a missed write, accepted. A write
  inside `bash -lc '...'` is attributed (the wrapper's command text is parsed in turn, to a bounded
  depth); a wrapper argument the outer shell expands (`bash -c "... '$OUT'"`) is unknown and names
  nothing.
- *A path is attributable only if it is literal.* Each word records whether an unquoted `$`,
  backtick, glob character, brace or leading `~` could change it. Quoting or an escape makes those
  characters literal, so `'/opt/$report.txt'` and `/opt/file\*.py` are real (outside-workspace)
  targets, while `"$OUT"`, `~/f`, `*.py` and `{a,b}` name no path.
- *Unlexable is silent.* Unbalanced quotes, an unterminated expansion or a trailing backslash make
  the whole command name no write. The existing disclosure is unchanged: an unattributed write
  only means the kernel does not count that command as an edit.
- *Redirections.* `>& file` and `1>& file` write a file; a descriptor target (`>&2`, `>&-`)
  duplicates or closes, and `2>& file` is an ambiguous redirect in bash: the redirections before it
  were opened, the ones after it and the command are not. `<>` opens read-write and creates an
  absent file, so it counts. A redirection with no target is a syntax error: that command and
  everything after it is not run. A file named `-` is a file (`touch -` is stdout).
- *Options.* `sed` reads `-e`/`-f` attached or separate, `-i[SUFFIX]` (GNU: the suffix swallows the
  rest of the word, so `-i.bak1` and `-ie`), `--in-place[=SUFFIX]` and `--`. After a bare `-i`,
  macOS takes the next word as the suffix (`-i ''`, `-i .bak`) where GNU takes it as the script or
  a file; for `sed` only the files both readings agree on are writes (`sed -i '' 's/a/b/' f` is `f`,
  `sed -i '' f` is none), and `gsed` is GNU. `cp`/`mv`/`install` read `-t DIR`, `-tDIR`,
  `--target-directory[=]DIR` and every operand of `install -d`; `touch -r REF` and
  `truncate -r REF` read their reference (`truncate` needs `-s` or `-r`); the last `dd of=` wins;
  operands after `--` are operands even if they begin with `-`; an rsync `host:path` or
  `rsync://` destination is remote, `-n`/`--dry-run`/`--list-only` transfer nothing, and its
  option values (`--exclude PATTERN`) are no paths. An invocation that exits before writing names
  nothing: `--help`/`--version` (also of a wrapper such as `timeout`), `bash -n`, `-t DIR` with no
  source, with `-T`, or given twice. The bodies of compound statements (`then`, `do`, `{ ... }`,
  function definitions) are not read: whether they run is control flow, and a `[[ ... ]]` test's
  `||`, `&&` and parentheses are test syntax. An expansion is assumed to yield a word.
- *A directory destination is classified by where it is.* `cp -t DIR`, `install -d DIR` and
  `dest/` write files named after something else, so a notes or receipt *file name* never exempts
  the directory (`cp -t NOTES.md src.py` is a workspace write); a FinishUP tree or state directory
  still does.
- *Bounded.* The parser is linear: no pattern backtracks, no region is rescanned and
  `strip_wrappers` is handed a constant-size head of each command. The hook's other `shlex` pass
  (install-target detection) reads the same bounded head (`bound_command`). Text longer than 16,384
  characters (the hook's command-normalization limit, `MAX_SHELL_WRITE_CHARS`) is analysed only up
  to its last newline inside that limit, so a long `cat > f <<'EOF'` body still names `f` (8 of the
  9 over-limit commands in the recorded n2 and n3 runs are exactly that) and so does the same
  command inside the `/bin/bash -lc '...'` argv the rollout records (the wrapper's cut script is
  analysed in turn). A write after the limit is not seen. The command a cut interrupts (an open
  quote, an expansion, a continued line) is dropped whole, never completed by a guess, and a text
  with no newline inside the limit names nothing. This never raises and never blocks the hook; it
  is a coverage limit of the same kind as an unattributable path, not an error.

### 4. What counts as an attempt

`requested_item_never_attempted` counts a requested command as attempted when a hook-observed run
matches it by `planned_match` (any outcome), and a file or directory when the agent named the same
path in another spelling (`value_in_attempted`: normalized, relative tail). A global action (no
`obligation_refs`) works on the obligations whose items its `attempted_items` name, not on every
obligation. Status `command_attempts` compares a keyed observed action with the planned command by
the same matcher.

### 5. Binary

Git's NUL sniff of the check-time change decides first: a changed file it listed as binary is
unsupported, one it listed with line counts (text) is not, whatever its suffix; the suffix list
decides only for a file the change did not list. `.step` and `.stp` leave the list. When a review
ran and a declared deliverable is a type the packet never carries, the check raises the standing
disclosure `declared_output_not_reviewable` (recorded per item as `unreviewable`) on status and the
receipt, so a present-but-not-reviewed deliverable is named.

## Consequences

- A created-empty deliverable is no longer a false gate; a stub cut of a new file is caught; an
  emptied working solver stays reported through an acknowledgement or an "empty fallback"
  obligation. The gate text says so and names the one exit.
- Looser command matching can read as "run" a command that did less than the plan. That is why a
  prefix or flags match is disclosed with the observed run's id, never clean.
- A check now reads the session's records to find its history (it already did for review rounds)
  and runs the line-count read whenever a declared file exists.
- **Known coupling (wave 2).** The A-12 acceptance re-read rides on other Stop-gate tokens. Removing
  the false `declared_output_emptied` and flag-prefix tokens means it is delivered less often until
  it becomes its own once-per-frontier readiness item (owner decision 6, wave 2).
- Shell-write attribution trades recall for honesty. Writes the parser does not read (`perl -pi`,
  `awk -i inplace`, `ln`, `curl -o`, a script that opens files itself, an expansion-built path, a
  write after the 16,384-character bound, a heredoc body that runs `$(...)`, a `then`/`do` body, a
  command whose group holds a `case`) are missed writes: the command is not counted as an edit and
  nothing says so. Known false-write direction, not seen in the 2,343 recorded commands: a relative
  path written after a `cd` out of the workspace (`cd /tmp && echo x > f`) is read against the
  workspace, as before; and a redirection whose target is an expansion that fails is assumed to
  succeed. The tests lock the false-write direction harder (every false write found by review is a
  vector).
- Not done here, owned elsewhere: the Stop gate's active-Stop suppression of ordinary tokens and the
  premise text (RC-8, wave 2), the hook-observed-edit check invalidation (`c4`, lane LO), and a real
  reducer reopen of a resolved obligation.

## Amendment (tb4n4, issue #1049): an agent link is never a command mismatch

Section 4 had status `command_attempts` compare every linked observed run with the planned command
by `planned_match`. That included the PL6-3 agent link (ADR-033: a cooperative `command` action
naming the exact requested value in `attempted_items` with the observed run in `causal_parents`),
which the planned-verification fact reads as run and discloses as `planned_verification_agent_linked`
and which the `planned_verification_not_observed` sentence tells the agent to publish. The same link
then read `asserted_observed_mismatch`, so completion carried the agent-actionable
`command_attempt_mismatch`, every `self_verified` answer was refused on it, and no publication
cleared it (tb4n4 kv: the protocol command `VERSION` declared as a requested `command` item, linked
to the client run that sent it, looped). A linked run that does not match is now `unknown` when any
linked run is such an agent link, so the link yields the standing `command_attempt_uncorroborated`
beside the `planned_verification_agent_linked` disclosure: the observed outcome still decides, the
equivalence stays disclosed and the receipt is never clean on it. An assertion that is not a
`command` action (an `edit` copying the value) or a resolution result alone still reads a mismatch.
`kernel.command_attempts` is the one rule; status, closure preparation, check gaps and the receipt
read it unchanged.

## Amendment (2026-10-18, n7 RC2, issue #1106): heredoc bodies never decide a command's class

`domain.observation_selection.command_runner_class` split the whole command text with `shlex`
before segmenting it, so one odd quote inside a heredoc body (a patch line `+x = 2  # don't`, a
docstring, prose) made the text unsplittable and classed a patch-then-test command `compound`.
`compound` is no verification run, so the test never cleared `edited_after_last_verification`.
When the whole-text split fails, the quote-aware segmenter (`command_segments.command_structure`,
which treats a non-shell heredoc body as data) now decides, as it already did for every balanced
compound. An unterminated quote, substitution or heredoc still classes `compound`, and a heredoc
command is never `exploration`. Segment matching and the planned side are unchanged.

A heredoc-fed patch is a write (`domain.shell_writes.heredoc_patch_paths`): `apply_patch`/
`applypatch` by its `*** Add|Update|Delete File:`/`*** Move to:` headers (as since #1046), and `git
apply` and `patch` by each unified-diff file header (`---` directly followed by `+++`; a deletion
names its old path) less the leading components their `-p` strip removes (`git apply` strips one; a
bare `patch` drops one leading `a/`/`b/`). An invocation that writes nothing (`git apply
--check|--stat|--numstat|--summary|--cached`, `patch --dry-run|-C|--check`) names nothing. One that
applies a patch the reader cannot place is still a write, an unplaced one that counts as an ordinary
`workspace` edit (#1106 r3, `shell_writes.heredoc_patch_writes`): it reads its patch from a file (an
operand, `-i`), moves what it writes (`-d`, `-o`, `--directory`), uses an option the reader does not
know, or names a header it cannot read (a quoted path, a strip deeper than the path, or no
`---`/`+++` pair at all, as a pure rename has). Codex intercepts a shell `apply_patch` only as the
whole script (`apply_patch <<EOF`, or `cd <dir> && apply_patch <<EOF`; Codex 0.159
`apply-patch/src/invocation.rs`), so only that form is a pre-only attempt
(`shell_writes.codex_intercepts_shell_apply_patch`); a patch followed by a test runs in the shell
and its post pairs as usual.

Kept limits, documented rather than fixed:

- One command that writes and verifies is one run at one ledger position, so its verification
  covers its own writes. `pytest -q && sed -i …` (verify, then write) is not reported; fixing it
  needs per-segment write order, and a lexical writer rule would demote `pytest | tee /tmp/log`.
  The segmenter fallback above does not widen this limit: when the whole-text split fails and a
  simple command after the last verifying one writes (a redirect, a `sed -i`/`cp`/`tee` target, or
  a `apply_patch`/`patch`/`git apply` invocation: `pytest -q && git apply <<'EOF' …it's… EOF`),
  the run stays `compound`, as that shape always was. Commands are compared in first-seen order,
  so a repeated test after the write (`pytest; git apply <<EOF …; pytest`) also stays `compound`:
  a missed verification, never a hidden edit.
- A job started in the background (`&`, `nohup`) and polled from a later tool call is recorded
  when it starts, with a masked composition; its completion is visible only in its log, which
  FinishUP never reads (output text is never an outcome). A `wait` in a later call is another
  shell. Recognizing it honestly is not possible, so guidance asks for each verification in the
  foreground, in one tool call. A Codex unified-exec run that yields and is polled to exit is
  recognized through its `item_completed` `CommandExecution` row (ADR-022, #910).

Verification: `tests/unit/domain/test_observation_selection.py`,
`tests/unit/domain/test_shell_writes.py`, `tests/unit/cli/test_runtime_facts.py`,
`tests/unit/kernel/test_tb4n3_facts.py::test_c2h_patch_then_test_with_an_apostrophe_clears_edited_after`
(and `::test_c2h_a_patch_after_the_test_in_one_odd_quote_command_still_stales`),
`tests/unit/cli/test_n7_shell_call_identity.py` (a rollout `CommandExecution` argv names its
heredoc patch through its one host-shell layer) and
`tests/integration/observation/test_codex_pre_only_apply_patch.py`. The heredoc readers are linear
in the text (`test_heredoc_patch_readers_are_linear`); unlike the token parsers they are not cut at
`MAX_SHELL_WRITE_CHARS`, since a patch past that bound is still a write.
