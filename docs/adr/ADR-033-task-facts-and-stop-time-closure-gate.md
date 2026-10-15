# ADR-033 — Deterministic task facts, explicit blockers, and the Stop-time closure gate

**Status:** Accepted for [issue #977](https://github.com/TheGaySupreme123/finishup/issues/977). The
owner requested this design-gated work explicitly in the 2026-10-06 session that reviewed TB4 run
tb4f1; the issue records that acknowledgement. It covers host hook behaviour, the control-request
structural fields, the work-integrity policy-pack version, and the change to "FinishUP is not an
enforcement system". It grants no runtime, credential, disclosure or destructive-action authority.
**Implemented by:** `src/finishup/kernel/task_facts.py`, `src/finishup/kernel/closure_readiness.py`,
`src/finishup/kernel/policies/work_integrity.py`, `src/finishup/kernel/deterministic_checks.py`,
`src/finishup/kernel/observed_failures.py`, `src/finishup/application/check.py`,
`src/finishup/application/check_change.py`, `src/finishup/adapters/git_change_capture.py`,
`src/finishup/adapters/memory/ledger.py`, `src/finishup/application/observation_materialize.py`,
`src/finishup/cli/runtime_facts.py`, `src/finishup/cli/closure_gate.py`, `src/finishup/cli/observe_hooks.py`,
`src/finishup/kernel/policies/observation_advice.py`, `src/finishup/service/ready_composition.py`,
`src/finishup/domain/observation.py`, `src/finishup/domain/receipts.py` (`TASK_FACT_GAP_SENTENCES`),
`src/finishup/cli/hook_diagnostics.py`, `src/finishup/mcp/summaries.py` (rejected-outcome hint),
`src/finishup/protocol/policy_packs.py`, `src/finishup/kernel/finding_resolution.py`, the control-request
2.9.0 structural payload, and the work-integrity 0.3.0 pack identity.
**Relates to:** ADR-019 (completion scope), ADR-022 (observation authorship), ADR-031 (check-time
change capture), ADR-032 (closure readiness), and issues #909, #910, #913.

## Context

In TB4 run tb4f1 the deterministic arm received no task information. Of 160 unique deterministic
findings, none concerned the task: 137 were `requested_item_never_attempted` raised against a
fresh plan before any work, and that finding meant only "no published action names this item", so
atrx-vep-crispr cleared it by publishing an attempt and never wrote its report. Nothing stopped
an agent with work left: pretrain-shard-corruption stopped with three open obligations and
`closure_readiness.state = action_required`, while guidance let it "record the blocker" and the
result enum had no `blocked` outcome to record. Meanwhile the hooks already saw facts that matter
for delivery: packages installed into FinishUP's own interpreter, files written outside the
workspace, verification run only as root.

The owner's direction: deterministic FinishUP makes few judgments but must calculate and surface facts
the agent can act on; self-generated evidence stays admissible (that is a deliberate difference
from AI-powered review); blockers are acceptable only when outside the agent's control; and the
agent must not be able to stop silently with known work left.

## Decisions

1. **Task facts are closed gap codes derived from hook observations and the ledger.**
   `kernel.task_facts.task_fact_signals(projection, records)` reads only service-stamped hook
   observations (ADR-022) and the effective plan, and returns closed codes, each classified exactly
   once in `GAP_CLASSIFICATION`:
   - `planned_verification_not_observed`, `planned_verification_failed`,
     `planned_verification_stale` (agent-actionable): an effective obligation's requested item of
     kind `command` was not matched to an observed run, failed on its latest matched run, or last
     ran before the latest observed edit. The match uses the installation-keyed command commitment
     the hook already computes (#909): the requested value gets the same light normalization and
     keyed HMAC, so no command text is compared, stored or shown. Segment matching (tb4n1, owner
     decision "segment match of compound commands, reject placeholders"): the hook also commits,
     in-process, to each simple command of a composed run (`domain.command_segments`: top-level
     unquoted `&&`, `||`, `;`, `|`, `&`, parentheses and line breaks; leading `VAR=value`, `time`,
     `env`, `nohup`, `exec` and introducing shell keywords and every redirection dropped; the body
     of a here-document fed to a shell; the argument of a `bash -lc`/`sh -c` wrapper), at most 32
     sorted commitments plus a closed composition token (`single`, `and_chain`, `masked`) on the
     control-request 2.9.0 structural fields `command_segment_commitments` and
     `command_composition`. Materialization appends them to the observed action's `command` field
     as `omitted:<identity> <composition> <segment>...`; a simple command keeps the historical
     `omitted:<identity>` bytes, and failure supersession still reads only the leading identity.
     Mixed versions: the two structural fields change the control-request 2.9.0 bytes and so the
     schema-manifest digest the handshake pins, so a newer hook or CLI never sends them to an
     older running service; it supersedes that service on first connect
     (`tests/subprocess/test_installed_upgrade_supersedes_stale_service.py`) and no row is lost
     to a schema refusal. A newer service reads older rows unchanged: they carry no suffix, so
     only the whole-command identity matches, exactly as before. An older service reading a newer
     ledger (a downgrade, which no supported path performs; 0.2.x never opens a 0.3 ledger without
     the backup-first migration) sees no identity on composed rows only: it matches nothing on
     them and cannot supersede a composed failure by a later rerun, so it errs toward "not
     observed" and a still-live failure, never toward a false match.
     A planned command matches a run that is it, that is its only simple command, or that
     contains it (or all of its simple commands) as segments. A segment match takes the run's
     outcome for `single`, a success for a successful `and_chain`, and is otherwise
     `planned_verification_outcome_unknown`: a pipe, `;`, `||` or script outcome names no part.
     An unsplittable command (unterminated quote, substitution or here-document) has only its
     whole identity. Agent link (PL6-3, #1003; owner: "disclose it as an agent-asserted
     equivalence; the observed outcome still decides"): a cooperative `action_recorded` of kind
     `command` whose `attempted_items` holds the exact requested value and whose `causal_parents`
     names a hook-observed command action links that observed run to the item, attributed per
     obligation as `attempted_items_for_obligation` does. Only an observed command action parent
     counts (never a cooperative action or result); the linked run's observed outcome and position
     decide not_observed, failed, stale and outcome_unknown exactly like a direct match, and a
     placeholder or prose item stays unobservable. When an item matches only through such a link
     the standing code `planned_verification_agent_linked` discloses it. No wire change. The service registers the key at composition; a process without it computes
     no planned fact rather than claiming a command never ran.
   - `planned_verification_outcome_unknown` and `planned_verification_unobservable` (standing): a
     matching run stated no outcome; or no keyed observed command exists to match against, or the
     requested value names no observable command: a `<placeholder>` token (admitted before
     publication refused it) or plain prose of three or more alphabetic words led by a
     title-case word of two or more letters (`Broad GSEA CLI`; `R CMD check pkg` is a command).
     A single token (`legacy-score`) is always a command. A placeholder is a `<name>` not glued
     to a preceding word or digit, whose further words start with a letter, closed by `>` at the
     end, before whitespace or a quote; redirections (`sort <in.txt>out.txt`, `cmd <dump.sql
     2>&1`) are commands. Publication refuses a new `command` item with an unquoted placeholder as
     `EVENT_INVALID` `requested_command_placeholder`, located at
     `/event_drafts/N/payload/requested_items/K/value`, before append.
   - `edited_after_last_verification` (agent-actionable): an observed edit after the latest
     observed run the hook classified as `test`, `lint`, `typecheck` or `build`.
   - `install_into_yoetz_runtime`, `install_into_private_env`, `write_outside_workspace`,
     `verification_only_as_root` (standing): recorded history classified at the host boundary.
   - `obligation_blocked_outside_agent_control` (standing): decision 4.

   Ledger-only codes enter the frozen deterministic case (with the obligation as subject) and the
   compact status gaps, exactly like plan-drift signals, so status, check, closure preparation,
   receipts and the TUI share one answer. Standing task facts are advisory for the check verdict,
   the receipt conclusion and the scoped local verdict; no task fact vetoes a local absence proof.
2. **Requested outputs are read at check time.** For every effective obligation's requested item of
   kind `file`, the check (every mode) asks the change-capture adapter for a metadata-only probe
   through the ADR-011/031 hardened Git runner, after the structural change capture already passed
   the repository fence: the path is located under the validated root lexically, reached without
   following a link and only `stat`-ed, and `git check-ignore -q` answers whether Git would add
   it (honouring `.gitignore`, `.git/info/exclude`, a repository excludes file and the owner's
   global ignore file); for an ignored path a second `git check-ignore -v` names the rule's source.
   A requested directory is changed when the change touches any path beneath it (the capture
   lists files, never directories), and the repository root itself is inside and changed by any
   change (tb4n1: `/app/src` with four new files was reported unchanged and `/app` outside; #987).
   A file that does not exist, and is not a tracked file the change deletes, raises
   `requested_item_never_attempted` with the fact `requested_output_absent`, whatever was
   published: naming a file in `attempted_items` does not create it (a file the request asks for
   only under a condition is runtime behavior, corrected in the plan, not the deliverable: see the
   tb4n5 amendment on conditional outputs). It is raised only once a
   completion claim covers that obligation (it names it, or names no obligation), or acting has
   started and one of the agent's own `edit`, `command` or `other` actions is attributed to it
   (an action with no `obligation_refs` is global; hook-observed actions name no obligation and
   never count); before then it is
   the plan, and the guided pre-work check found every output absent (tb4n1: 48 of 68 first
   findings; #989). The review packet's `requested_output_absent` task fact follows the same
   rule (`reportable_absent_outputs`). An output excluded by
   `.git/info/exclude` (a local exclude) or by a `.gitignore` the task's own change created is
   `requested_output_git_ignored` (agent-actionable: diff-based delivery omits it; in shadow-relay
   the agent added the exclude); one ignored by a pre-existing `.gitignore`, even one the task
   edited, or by a global excludes file is the
   standing `requested_output_ignored_by_repository`; an unread one is the standing
   `requested_output_unverified`. A `file` item names any file the request names, read-only
   inputs included, and an existing file the change leaves untouched or a path outside the
   repository is exactly what an input looks like. So `requested_output_unchanged` and
   `requested_output_outside_workspace` are standing disclosures only for an item the record
   asserts was written: an `edit` action whose `attempted_items` names that exact value (attributed
   to obligations as `attempted_items_for_obligation` does). Validation run tb4v1 reported both
   for task inputs (`/app/data` files tracked and unchanged; `/app/packet` inputs outside a
   `/workspace` repository); requested items carry no input/output role, and the record's edit
   assertion is the narrowest existing signal. The cost is accepted: an output written only by a
   `command` action (a script writing a report) is not checked for these two codes, because a
   command that reads an input looks the same; the value match is exact, as for
   `requested_item_never_attempted`, so a differently spelled path marks nothing. Both failures
   are silence on a standing disclosure, never a false fact; an absent output is still found. No path is stored, returned
   or sent. The same check's AI-powered review packet (including the closing review, ADR-006)
   carries these requested-output codes, and `requested_output_absent` when a requested file is
   missing, in its coverage `known_gaps`, so the reviewer judges the work beside them.

   **Declared roles and directories (issue #1002).** `obligation_published` 1.1.0 lets the record
   say what each requested item is; 1.0.0 is released and stays admitted and byte-identical. A
   `file` or `directory` item may carry `role: "input" | "output"` (absent keeps the 1.0.0 reading
   above; any other kind refuses a role), and `item_kind` gains `directory`. The same version adds
   the status `acknowledged_not_done` with a required non-blank `acknowledged_not_done_reason`
   (#996; readiness and receipt meaning are owned there). The version is a pure function of the
   payload: 1.1.0 iff it carries a role, a `directory` item or `acknowledged_not_done`, so every
   other obligation keeps its 1.0.0 bytes; each version refuses the other's payloads. The rules:
   - **`role: input`** is the task's data. It is not probed, and none of the requested-output codes
     (`absent`, `unchanged`, `git_ignored`, `ignored_by_repository`, `outside_workspace`,
     `unverified`) is ever reported for it (tb4n1 layout-config: the read-only
     `/app/layout_spec.json` was reported unchanged). It never justifies editing a pre-existing
     test file (`test_edit_visibility`): an input is read, not asked to change.
   - **`role: output`** is a declared delivery. It counts as written for
     `requested_output_unchanged` and `requested_output_outside_workspace` without an exact `edit`
     match, which closes the accepted gap above for outputs a command writes.
     `kernel.task_facts.declared_output_items` returns every effective obligation's `file` or
     `directory` item with `role: output` (blocked obligations included) — the declared delivered
     set ADR-035 reads.
   - **`directory`** is probed like a `file` (changed when any path beneath it changed; ignore and
     location as above). An existing directory that holds no file — empty, or only empty
     directories — is absent: the adapter lists it from the root descriptor, opening each
     directory `O_NOFOLLOW`, never following a link, never opening a file, and bounded (4,096
     entries, 64 pending directories); any non-directory entry counts as content, and an exceeded
     bound or a refused open is unknown, which never reports absence. A `file` item naming a
     directory keeps its 1.0.0 reading (existence only). `requested_output_absent` still waits for
     work on its obligation (`reportable_absent_outputs`, unchanged). A directory whose files the
     change deleted is `deleted`, not absent, exactly like a deleted file. A `directory` item is never a
     planned verification command, a URL, or a test-edit justification.
   - **`acknowledged_not_done` is not resolved.** The reducer keeps the last effective status among
     `open`, `acknowledged_not_done` and `resolved` (meaning fields must repeat; `resolved` stays
     terminal). Every other consumer treats it like `open`: open-obligation lists and counts
     (`open_effective_obligations`, compact status, check totals, receipts, the startup gate),
     `completion_with_open_obligations`, research-evidence support, live-failure obligation refs,
     coordination ownership and overlap input, and closure preparation, which may still resolve
     it. Status `view=obligations` (status-result 1.4.0) shows the status (the `open` filter
     matches it) and `acknowledged_not_done_reason`, the agent's own text, under the same
     `obligation_text` category and omission as the obligation's description.
   - **Unchanged by role or `directory`:** `requested_item_never_attempted` for an unattempted item
     still compares exact values against `attempted_items`, whatever the role (an input is cited by
     a `research` action); check totals count requested items the same way; project coordination
     still declares only `file` and `source` items as overlap resources (a directory is not an
     exact resource identity, and a read of the same file can still be a relevant overlap); the
     AI-powered review packet carries the obligation record verbatim, so role and kind reach the
     reviewer in its text. Status `view=obligations` (status-result 1.4.0, unreleased, edited in
     place) shows `directory` items and the optional `role`; earlier status-result versions are
     frozen and do not describe them.
3. **The plan is not an omission.** `requested_item_never_attempted` for an unattempted item waits
   until the agent has started acting: an observed edit, an observed run the hook classified as
   `test`, `lint`, `typecheck` or `build`, or any published action. Investigation commands
   (exploration, version control, and the unclassified `other`/`compound` shells) are not acting. Its repair text no longer
   offers "or revise its obligation" as the default exit; an absent output's text asks for a
   best-effort artifact and names the blocker form, and (tb4n5 amendment) names the one plan
   correction for a conditional output. These rule changes move the work-integrity pack
   to `0.3.0`; earlier versions stay decodable and form one lineage.
4. **Blockers are explicit and closed.** A readable, unsuperseded `decision_recorded` whose
   statement holds the exact line `finishup-blocker:<kind>`, for a kind in `authority`, `consent`,
   `credential`, `dependency_unavailable`, records that the obligations in its
   `affected_obligation_ids` are blocked by something outside the agent's control. No event schema
   changes (the same marker pattern as `finishup-no-material-work`). FinishUP cannot verify the claim:
   it honours it and discloses it. Readiness reports open obligations that are all so named as the
   standing `obligation_blocked_outside_agent_control` instead of `obligations_open`; their
   requested items raise no never-attempted or absent-output finding; the Stop gate does not list
   them as work, but re-asks each recorded blocker once (see the 2026-10-06 amendment).
   A blocker never waives the closing review (ADR-006, #976): the receipt is the final
   step after a final review, recording the blocker is itself a material change, and running
   `check` with `final_review: true` stays within the agent's control, so
   `closing_review_required` stays agent-actionable and keeps the gate armed until that review
   is current. Missing data the task says is recoverable, an inconsistent input, or a failing test
   are not blocker kinds. The result `outcome` enum stays `success|failure|partial|unknown`.
5. **The Stop-time closure gate continues the agent once per ledger frontier.** At a mapped
   session's Stop hook, the hook reads the service's compact `status` and continues the agent when
   `closure_readiness.state` is `action_required` and `agent_actionable` holds any of
   `obligations_open`, `receipt_findings_unresolved`, `closing_review_required` (the closing
   AI-powered review the checklist requires after the last material change; its repair is
   `check` with `final_review: true`), `planned_verification_failed`,
   `planned_verification_not_observed`, `planned_verification_stale` or
   `requested_output_git_ignored`. The message names what remains with counts and closed tokens
   only, and how to record a genuine blocker. Loop safety:
   - the host loop guard is honoured first (`stop_hook_active` on Codex and Claude Code; Cursor's
     `loop_count > 0`), so an agent is continued at most once per host turn;
   - an owner-only memory (`observation/closure-gate.json`, opaque session and frontier ids)
     suppresses a second gate at the same session and frontier;
   - planned-verification items are ignored while the session's observation outbox is still
     draining, because a run the service has not ingested would read as never observed. Since
     #994 the Stop pass first drains the task's rows toward the current frontier (ADR-022
     amendment of 2026-10-07), so this applies only to rows that remain after that bounded
     drain, and only to rows that can change this task's facts;
   - any read failure, or less than five seconds of the Stop budget left, lets the agent stop.

   Every outcome is a bounded hook diagnostic (`closure_gate_continued`,
   `closure_gate_blocker_rechecked`, `closure_gate_memory_unwritten` (amendment),
   `closure_gate_not_required`, `closure_gate_repeat_suppressed`,
   `closure_gate_turn_end_after_continue` (first recorded as `closure_gate_loop_guard`, renamed by
   the 2026-10-11 amendment), `closure_gate_budget_exhausted`, `closure_gate_unavailable`) visible in `finishup observe status`,
   beside the Stop drain's own `stop_drain_complete` / `stop_drain_incomplete` (#994).
6. **Per-host delivery.** Codex: `decision: block` with `reason` (its only model-visible Stop
   channel). Claude Code: `hookSpecificOutput.additionalContext` at Stop, the documented non-error
   feedback that continues the conversation under the same `stop_hook_active` guard. Cursor:
   `followup_message` at `stop`, used for the gate only (ordinary advice still never auto-submits).
   Each host's runbook records this decision.
7. **Runtime facts are closed tokens classified in the hook.** For a tool event the hook adds
   `install_target` (`yoetz_runtime`, `workspace_env`, `private_env`, `system`, `unresolved`),
   `write_scope` (`outside_workspace`) and `effective_user` (`root`, `non_root`) to the structural
   payload; the control-request 2.9.0 schema and the domain envelope admit exactly these values.
   Interpreter resolution uses the hook process's `PATH` (the agent's); an interpreter under the
   hook's own `sys.prefix` is FinishUP's runtime. Every other install is judged against the *task
   interpreter*: FinishUP records none, so the hook resolves the first `python3` and `python` on that
   `PATH` outside its own runtime. Environments compare by root (the executable's directory's
   parent, following directory links but never the executable's own link). The task's own
   environment is `system` (no fact); another virtual environment, or any interpreter outside a
   virtual environment when the task's is one, is `private_env`; against a non-venv task
   interpreter another non-venv `pip` stays `system`, because its interpreter is unknowable
   without reading it. `pip`/`python -m pip`/`uv pip` `--target`, `-t`, `--prefix` or `--root`
   to an absolute directory is `workspace_env` inside the workspace (vendoring) and `private_env`
   outside it; a relative or variable directory is `unresolved`. `--user` classifies as the
   interpreter running pip (its user site is imported by that interpreter; pip refuses it in a
   virtual environment). A conda environment (`conda-meta/`) counts as an environment of its own
   like a venv, and a prefix command's own options (`sudo -H -u builder`) and pip's attached
   `-t/dir` are read. `uv pip install` without `--python` stays `unresolved`. `write_scope`
   ignores writes into temporary scratch space (tb4n1 E6, #1000: 28 of 33 firings were `/tmp`
   logs, none a misplaced deliverable): `/tmp`, `/private/tmp`, `/var/tmp`, `/private/var/tmp`,
   `/dev/shm`, anything under `/dev/`, the macOS per-user `/var/folders/*/*/T`, and the
   WSL 2 Windows temporary directories (`/mnt/<drive>/Users/*/AppData/Local/Temp`,
   `/mnt/<drive>/Windows/Temp`), and the `TMPDIR`/`TEMP`/`TMP` values whose last component names
   temporary space (`tmp`, `temp`, `scratch`; a `TMPDIR=/results` hides nothing), read from the
   environment and never probed (no
   `tempfile.gettempdir`, which touches the filesystem, may fall back to the working directory
   and raises). An environment root that is `/`, contains the home directory, or is or contains
   the workspace is never trusted. The rule is lexical (`..` is normalized first, links are not
   followed), so a symlink under a temporary root that points elsewhere stays exempt; that is
   accepted. Materialization appends them to the
   observed action description in a fixed closed suffix order, which is how the ledger carries
   them. Observation advice delivers `install_into_yoetz_runtime`, `install_into_private_env` and
   `write_outside_workspace` once each at the next advice-bearing event (advice only, never a
   ledger finding); observation-advice moves to `0.1.8`.
8. **"Not an enforcement system" is narrowed, not reversed.** FinishUP still blocks no tool call and
   gates no receipt; a check is still not correctness. The one active behaviour is the Stop
   continuation above, bounded to once per frontier and per host turn, honouring declared
   blockers, and never claiming work is incorrect.

9. **Self-generated verification counts after the last edit (tb4n1 E7, #987).** The ADR-032 uncorroborated-completion rule
   asked for a hook-observed run even when the claim cited the agent's own command result
   published after the last edit (2 D / 6 S tb4n1 attempts), contradicting the self-generated
   evidence decision above. The agent's own admissible `command` result or
   `test_result`/`command_output` evidence published after the latest hook-observed edit now
   satisfies it; the rule reports only a claim whose every cited verification predates that edit.
   A self-published command counts only outside the `exploration` and `vcs` runner classes, as for
   observed runs (`git status` or `ls` verifies nothing). Ordering uses ledger position, so an
   observed edit still draining when the check runs is not yet "the latest edit": the check can
   admit a claim that a later-drained edit makes stale. The Stop-time drain narrows that window,
   and the next check after the edit lands reports it; the rule never claims more than the
   recorded order.

## Consequences

- The deterministic arm now tells the agent, at check time, at status and at Stop, whether its own
  planned verification ran after its last edit, whether each requested file exists and would be
  delivered, and where installs and writes went. These are facts, not judgments; self-generated
  evidence remains admissible.
- An agent that stops with open obligations is continued once with the list; it can still stop
  after that, and a genuine out-of-control blocker is a recorded, disclosed position instead of a
  silent stop.
- Exact command matching can report a planned verification as not observed when the agent ran a
  wrapped variant; the text says how to clear it. Coverage limits: runs the hooks did not observe
  (another host, a missed hook, observation off) are invisible; `PATH` resolution may differ from
  the shell's; `effective_user` describes the hook process, not the delivery environment.
- Cost: one compact status read per Stop of a mapped session, one `stat` plus one or two
  `git check-ignore` calls per requested file per check, and one pass over the accepted prefix
  per case build and per compact status read.
- Scope of the requested-output read: it runs in `check` only. Status candidate findings and the
  AI-powered review's matching of local findings use the case alone, so they never show an absent
  output; the check result, its recorded finding and the receipt do. Like the structural test-edit
  accounting it sits beside, the read is not part of the frozen case: a resumed check reuses its
  checkpointed findings but re-reads the workspace for the gap codes, so a file written in that
  window can make the two disagree until the next check.
- A requested file value with whitespace, a glob or brace pattern, `~`, `$` or a URL scheme is not
  read at all, so trailing prose never manufactures an absent output.
- `GAP_CLASSIFICATION_VERSION` stays `"2"`: codes were added, no existing assignment changed.

## Alternatives considered

- **A `blocked` result outcome or a new obligation status.** Rejected for this change: it needs new
  event schema versions across reducers, receipts and every surface, while the decision marker is
  already a reviewed pattern. Issue #913 slice C still owns obligation-level acknowledgement.
- **Gate in the service at Stop ingest.** Rejected: the Stop hook frequently exhausts its drain
  budget before its own envelope reaches the service, so a gate computed there would often miss.
- **Make planned-verification facts receipt-blocking findings.** Rejected: the exact-identity match
  can miss a reformatted run, so they are agent-actionable readiness codes, not findings.

## Amendment (2026-10-06): a recorded blocker is re-asked once and checked once

TB4 validation run tb4v1 found a loophole in decision 4. A deterministic agent on
pretrain-shard-corruption recorded `yoetz-blocker:dependency_unavailable` for "no original snapshot
found", although the task said the data was recoverable. Any well-formed line was honoured, the
obligation became the standing `obligation_blocked_outside_agent_control`, and the Stop gate went
quiet. The owner decided the following, with no prerequisite such as a prior failed attempt:

1. **Deterministic: re-ask once, then honour.** Status `closure_readiness` gains the optional
   `blocked_obligations` list (`obligation_id`, closed `blocker_kind`, `decision_event_id`; ids
   and the closed kind only, on the unreleased status-result 1.4.0). At a mapped Stop, the gate
   also fires when this list names an `(obligation, kind)` pair the session has not yet been asked
   about. This includes `ready_with_limitations`, where nothing else is left. The continuation
   names each obligation and the claimed kind and asks the agent to confirm each is outside its
   control (authority, consent, a credential, a dependency it cannot obtain). It says that missing
   or inconsistent data the task says is recoverable, a failing test, or an infeasible-looking
   result is not a blocker, and it tells the agent to continue the work otherwise. The gate item is
   `blocker_recheck`, and the extra diagnostic is `closure_gate_blocker_rechecked`
   (`closure_gate_memory_unwritten` when the memory below cannot be written). Nothing judges the
   claim here.
2. **"Re-confirmed" means the agent stopped again, with no new protocol field.** Once the gate
   that named a pair is delivered, the hook remembers `<obligation id>:<kind>` for that FinishUP
   session in a second owner-only file (`observation/closure-gate-blockers.json`, at most 64
   keys per session and 128 sessions). The pair is then honoured at every later Stop, whatever the
   frontier. A second Stop, or recording the same blocker again, is the re-confirmation. A
   different kind for the same obligation is a new claim and is re-asked once. A new session is
   asked again once. The re-check cannot loop: each pair is asked at most once per session, and
   the host loop guard, once-per-frontier memory, budget and read-failure rules of decision 5
   still apply first. If the memory write fails, the agent may be asked once more at a later Stop,
   which is bounded by the same guards.
3. **Semantic: the closing review verifies each blocker once.** A final-phase review case adds one
   question (`recorded_blockers`) that lists each blocker decision, its kind and its open
   obligations, using ids and closed tokens only. Blocker decisions lead the decision section, so
   the 16-item cap never drops them. Statement and rationale (agent text) reach the reviewer only
   through the decision excerpt, which privacy enforcement classifies and span-redacts like any
   other item. The reviewer instruction asks for one verification per blocker against the task
   statement and the work. If either contradicts the blocker, the reviewer raises one challenge
   that cites the decision or obligation. That challenge is an ordinary AI-powered finding, and the
   agent answers it with `respond`. A genuine blocker stays a disclosed limitation and is not
   challenged. The routine phase does not judge blockers.
4. **Fixes found on the way.** Readiness in which every open obligation is blocked
   (`obligations_open` in `blocking_conditions`, disclosed as
   `obligation_blocked_outside_agent_control` rather than listed as work) failed the status
   model's own validation, so status failed and the gate read nothing. The validator now admits
   exactly that shape. Work-integrity also turned standing task facts into
   `ledger_stale_or_incomplete` findings, which made a check whose only gap was a blocker fail
   internally (`invalid_ranked_findings`). Standing task facts are now disclosures only, as decision
   4 intended.

The receipt still discloses blocked obligations as standing limitations, and the reviewer's
verdict on a blocker appears as a normal finding.

## Amendment (2026-10-07): the re-check reaches active Stops, repair-first text, one view (#984, #985)

TB4 run tb4n1 showed the gate was single-shot per Codex run: 35 of the 38 attempts that declared a
blocker did so after the first gate, and their next Stop arrived with `stop_hook_active` set, so
the hook recorded the loop guard (`closure_gate_loop_guard`, now
`closure_gate_turn_end_after_continue`) without reading status and the re-check of decision 1
above never ran. Codex honours repeated Stop blocks within one turn (codex-rs `turn.rs` sets
`stop_hook_active` once per turn and keeps honouring blocks; its test
`stop_hook_can_block_multiple_times_in_same_turn` asserts it); the limit was FinishUP's own. The gate
also fired on receipt-blocking findings the agent could not clear because of FinishUP's own limits,
and its text offered the blocker as the exit. The owner decided:

1. **Active Stops re-ask new blockers, capped.** A Stop the host already continued this turn
   (`stop_hook_active` on Codex and Claude Code, Cursor `loop_count > 0`) still reads status when
   at least five seconds of the Stop budget remain. It continues the agent only for a
   `blocked_obligations` key `<obligation id>:<kind>` the session has not been asked about, never
   for the ordinary items. Hard caps: at most one re-check per Stop, and at most two gate
   continuations per host turn, counted in a third owner-only file
   (`observation/closure-gate-turns.json`, opaque session ids and a count, 128 sessions) and reset
   at every mapped Stop the host did not continue, whether or not the gate is evaluated there; an
   unreadable or corrupt counter counts as the cap. On an active Stop the memory is written before the
   text is emitted; if it cannot be written, or status fails, the agent stops (fail open). The new
   diagnostic `closure_gate_active_stop_rechecked` joins `closure_gate_continued` and
   `closure_gate_blocker_rechecked` when that happens; `closure_gate_turn_end_after_continue` is recorded only
   when an active Stop emitted nothing. A blocker row readiness reports as `confirmation:
   confirmed` (the agent re-published the same line in a later decision) is never re-asked, and
   the readiness token `obligation_blocker_unconfirmed` is a gate item like `obligations_open`.
   How to confirm a blocker (publish the same `finishup-blocker` line again in a later decision) is
   told only after the challenge: in the re-check, or in a later gate whose blocker was already
   re-asked. The offer that introduces the blocker line never says it, so publishing the line
   twice up front cannot skip the challenge (the kernel rule that a repeat confirms only after
   the challenge is owned by the blockers change). The re-check tells the agent that a FinishUP
   limit is never a blocker: finish the obligation and disclose any limit in the final answer
   (`self_verified` is for findings only).
2. **Repair first; a FinishUP limit is never a blocker (#984).** For receipt-blocking findings the
   text says: repair what you can; for a finding you repaired that FinishUP still cannot prove (its
   resolution names a FinishUP limit such as redaction, observation loss or a review-packet limit),
   verify it yourself, record that evidence and respond `self_verified` with how you verified it
   and the evidence ids (ADR-034); respond `acknowledged_not_done` only if you truly cannot or will
   not do it. Every gate says a FinishUP limit is never a `finishup-blocker`. The blocker sentence, with
   "Data the task says is recoverable is not such a blocker" and the confirmation step, is offered
   only when open obligations (or an unconfirmed blocker) remain, never for a findings-only gate.
   The text never exceeds FinishUP's 2,000-character bound (its own cap, not a documented host
   limit): whole optional sentences are dropped (the drain note first, then the long obligation
   sentence, then the required limitation ids, then the premise ask) and the re-check sentence is
   always kept; it names at most three blocked obligations. A planned-verification hint is a
   family instruction and is not shed for the limitation ids. When the ladder still cannot fit,
   the gate is composed (ADR-043) rather than clipped: the head, one instruction per present item
   family (obligations, planned verification, receipt-blocking findings, each with a short form)
   and the `check`/receipt close instruction are required, and the re-checks, blocker offer,
   limitation ids, premise ask and notes follow by priority with short forms.
3. **The drain note only when it changed the decision.** `observation_pending` is now computed for
   this task's own hook rows after the Stop drain (#994, owned by the observation lead). The
   planned-verification items are used when it is false; the "(Observations were still draining
   ...)" note is added only when a planned-verification item was present and dropped.
4. **No ordinary advice on any Stop.** Codex renders Stop text as `decision: block`, and Claude
   Code's Stop `additionalContext` also continues the conversation, so ordinary advice at Stop
   spent the turn's continuation the gate needs (tb4n1 hof-topology). Ordinary advice now stays
   pending for the next `PostToolUse` or `SessionStart` on every host; Cursor never delivered it
   at `stop`. Standing advice (provider repair, e.g. `connect_provider`) therefore no longer
   reaches Codex or Claude Code at Stop. To keep its once-per-turn cadence, a Stop that finds it
   pending marks the session (owner-only `observation/stop-withheld-standing-advice.json`, opaque
   session commitments only), and the first later advice-eligible `PostToolUse` may carry it;
   the mark clears once it is delivered or nothing is pending. Otherwise it reaches them at
   `SessionStart`. Cursor is unchanged (`sessionStart` only).
5. **The gate and the CLI read the agent's route.** A route-less `status` (the Stop gate, the CLI,
   an export) read the policy route, so on a strict-route session it listed
   `semantic_review_not_requested` as work the agent's own MCP view never showed (37 of 37
   deterministic exports). The service now remembers, per session, the route that session's MCP
   bridge named on its last successful `status` or `check`, in an owner-only file in the service
   state directory (`session-routes.json`: `ses_` ids and the closed route only, at most 256
   sessions with least-recently-written eviction, atomic replace, symlinks never followed,
   loaded lazily), so it survives a service restart or upgrade. A later route-less `status` for
   the same session reads on that route. A failed call teaches nothing; when two bridges on
   different routes serve one session, the last successful call wins. A route-less `check` is
   unchanged. Before any bridge call for the session, a route-less read still uses the policy
   route. The applied route is visible on `status` `view: versions` (`route_profile` on each
   version slice); the compact view carries no route field, so it is not labelled there.

## Amendment (2026-10-07): a blocker is claimed until confirmed after the challenge (#985, #978, #986)

tb4n1 showed three more blocker defects. In the deterministic arm one blocker line on every open
obligation turned readiness `ready_with_limitations` with nothing left to do although the main
deliverable was undone (pretrain-shard-corruption, payments-pipeline-fix; both scored 0).
Thirty-one of 38 blocker attempts named only finished obligations to excuse findings FinishUP could
not clear; such a blocker changed nothing yet read as a claim. And the closing review accepted
every blocker it was shown, including one the task statement contradicted. The owner decisions for
C2 (challenge a blocker when it is published) and C4/C5 apply:

1. **Claimed, then confirmed.** The first accepted blocker decision for an `(obligation, kind)`
   only *claims* it. It stays agent work: readiness lists the agent-actionable Stop-gate token
   `obligation_blocker_unconfirmed` instead of `obligations_open`, and a claimed blocker
   suppresses no task fact or `requested_item_never_attempted`. It becomes the standing
   `obligation_blocked_outside_agent_control` only when the same `finishup-blocker:<kind>` line for
   that obligation arrives in a later publish batch, which is necessarily after the publish-time
   challenge below (and, if the agent stopped, the Stop re-ask). A repeat in the same batch, two
   lines in one decision, or a dry run never confirms. A later decision of a different kind for
   the obligation starts a new claim of that kind (even over a confirmed one), and a superseded
   decision counts in neither role. The rule reads only recorded facts (ledger position and the
   record's operation id), so it is replay-stable and needs no migration. Two back-to-back
   publishes still confirm: the first result's `blocker_claimed` notice is the challenge, and no
   text the agent can read before claiming (finding repair text, guidance, skills, the gate's
   blocker offer) says how to confirm, so a reflexive double publish has nothing to follow. A
   rule requiring an intervening record of some other kind was rejected: "not the same agent
   burst" has no replay-stable definition, and any such record is cheap to manufacture.
   Status rows carry `confirmation` (`claimed|confirmed`) and `confirmation_event_id` (additive on
   the unreleased status-result 1.4.0). When every open obligation is confirmed blocked,
   `completion_plan_not_claimed` is disclosed as standing too (C9).
2. **Publish-time challenge and no-effect notice.** A `publish_work` result, dry runs included,
   carries `blocker_notices` with fixed text per `(obligation, kind)`: `blocker_claimed` (repair
   first; a FinishUP limit is never a blocker, respond `self_verified`; data the task says is
   recoverable is not a blocker; how to confirm), `blocker_confirmed`, or
   `blocker_without_effect` for a blocker naming no open obligation. The last is accepted (no
   protocol break) and changes no readiness, gap, finding or receipt section; it points to
   `self_verified`, or `acknowledged_not_done` as a last resort. Rejecting such a blocker at
   admission stays a later option.
3. **The closing review challenges what the task contradicts (#978).** The blocker question
   tells the reviewer to quote the blocked obligation's own description and evidence expectation
   from its privacy-gated packet item and requires a challenge when the statement says the
   outcome is achievable or the data recoverable, the obvious prerequisite was not attempted, the
   material contradicts the blocker, or it names a FinishUP or review limit. Being the task's main
   deliverable calls for close scrutiny, not an automatic challenge: a genuine credential or
   authority blocker on it may stand. The question itself carries ids and fixed text only, never the obligation text,
   because questions are not privacy-scanned. A golden question pins the tb4n1 pretrain case.
4. **Blocker texts agree (#984 F1).** The `requested_item_never_attempted` repair text, the MCP
   outcome hint, the approved-checks continuation, the guidance and the skills all say: repair
   first; for a FinishUP limit, verify yourself and respond `self_verified`; `acknowledged_not_done`
   is the last resort; `finishup-blocker` only for an open obligation genuinely blocked outside your
   control. Only the `blocker_claimed` notice and the Stop re-check say how to confirm one.
5. **One clean-compatible gap list (#986 E2).** `kernel.deterministic_scope.CLEAN_COMPATIBLE_GAPS`
   (standing in `GAP_CLASSIFICATION` and tolerated by the deterministic local absence proof,
   excluding AI-review `semantic_*` and evidence-strength `evidence_*` codes, plus the existing
   advisory sets) bounds both the receipt conclusion and the scoped deterministic verdict, and a
   pack that is `skipped/not_applicable` on the whole case (coordination on a single-agent run)
   counts as complete; `scope_excluded` and `material_unavailable` do not. Host-observation gaps
   such as `host_outcome_unavailable` and `unpaired_event` therefore no longer bar
   `no_unresolved_deterministic_findings`, but only where they are guarded: a full check reads
   them as clean-compatible only when its command counters show no unknown or live failed outcome
   (`commands_complete`), the scoped verdict keeps its own counter checks, and the receipt treats
   `HOST_OBSERVATION_GUARDED_GAPS` as advisory only when the applicable check's own coverage
   carried them. Full-check completeness (`application.check.full_check_gaps_clean`) reads the
   same list. `semantic_review_not_requested` still bounds the
   receipt: a check records only `deterministic_mode` or `no_material_semantic_case` with it, never
   whether the serving route required AI-powered review (a strict route records
   `blocked_by_policy`/`route_semantic_ceiling` and its own gap instead), so the receipt cannot
   apply the route rule without reading live configuration, which would break replay.

## Amendment (2026-10-07): disclosures are not blockers; premise disputes are asked once (#995, #997, #984)

Owner-approved 2026-10-07 (issue #995; L5 request D7a under #984).

1. **Disclosure lines (#995).** tb4n1 agents declared blockers on finished work because a hidden
   verifier or a private trace was out of reach (ks-solver, lake-temp-glm, vpp-loss-divergence), or
   blocked repeatedly on a choice a best-effort assumption could make (cargo-flight-dispatch). A
   `decision_recorded` statement line `finishup-assumption:<obligation id>` or
   `finishup-verification-limit:<obligation id>` (exact line, well-formed id; the rationale carries
   the text) now records that instead (`task_facts.disclosure_declarations`). It never blocks,
   resolves, or changes an obligation's status; the earliest unsuperseded decision records each
   `(obligation, kind)`, a decision superseded through `supersedes_event_id` withdraws it (as for
   blockers), and an id naming no recorded obligation is a `missing_ref` like a blocker's
   `affected_obligation_ids`. Readiness lists the standing codes `assumption_disclosed` and
   `verification_limit_disclosed` (`GAP_CLASSIFICATION_VERSION` "4"); `receipt-document` 1.3.0
   carries `disclosed_assumptions` rows `{obligation_id, kind, decision_event_id}` (ids and the
   closed kind only) and the section "Assumptions and verification limits the agent disclosed";
   the conclusion is unchanged. The blocker offer, the re-check, the `blocker_claimed` publish
   notice, the requested-item repair text, the MCP rejected-outcome hint and the guidance say an
   inherent verification limit or a best-effort choice is not a blocker: finish and disclose it.
   The review packet's blocker section does not list disclosures yet.
2. **Obligation acknowledgement (#997).** The gate and repair texts name an obligation-level
   `acknowledged_not_done` (ADR-032 slice C amendment) as the honest last resort after repair.
3. **Premise disputes (D7a).** L5's opaque predicate `finding_todo.standing_premise_disputes`
   (imported behind a guard: a build without it reports nothing) names acknowledged-not-done
   findings whose challenge says the task itself requires the work. Readiness discloses the
   standing code `finding_premise_disputed`; `receipt-document` 1.3.0 lists
   `premise_disputed_finding_ids` (a subset of `acknowledged_not_done_finding_ids`) in the section
   "Not done although the review says the task requires it". On a Stop the host has not already
   continued, the gate asks once (closed item `premise_recheck`, remembered as
   `premise:<acknowledged count>` beside the blocker keys, so a new acknowledgement asks again);
   in a combined gate the sentence is dropped before the blocker re-check under the 2,000-character
   bound. If even the shortest composition exceeds the bound (also in a gate that carries only
   re-checks), a blocker, acknowledgement or premise re-check whose whole sentence no longer fits
   is left out and its keys are not remembered as asked, so the next Stop asks it again (tb4n2
   integration).

## Amendment (2026-10-08): record the route; a local-only check on a non-requiring route does not block (#986, E2)

Owner decision (issue #986, L4 residual (b) / E2): **"Record route; don't block".** Each check
records whether its route required AI-powered review. When the route did not require review, the
gap `semantic_review_not_requested` is a disclosure and does not block a clean receipt or verdict.
When the route did require review, it still blocks exactly as before. Old checks without the field
keep the blocking behaviour, the safe default.

This replaces the earlier statement in this ADR that the receipt cannot apply the route rule.

1. **Record.** `check-recorded` 1.4.0 and `check-result` 1.4.0 (both unreleased, additive in
   place) gain the optional boolean `semantic_route_required`. A check's route required review
   when the check asked for it (`mode: semantic_required`) or the effective verification policy is
   `semantic: required`, whatever mode the caller chose. *Amended 2026-10-08 (issue #1021,
   [ADR-040](ADR-040-reviewer-disagreement-and-route-derived-review.md)):* an explicitly
   deterministic-only route (the strict MCP route the owner registered) did not require review
   unless the check asked for `semantic_required`; a strict process with Codex registration drift
   (#537) still follows the policy. The writer emits the field only as `false`, on a route that did not require review; a
   requiring route omits it. Checks on a requiring route and every check an older build wrote
   therefore keep their exact bytes, and replay reads them as before.
2. **Receipt.** The receipt conclusion treats `semantic_review_not_requested` as clean-compatible
   only when the applicable check recorded `semantic_route_required: false`, its AI-powered review
   status is `not_requested`, and its own coverage carries the gap. The code stays in coverage,
   the gap rows and the limitations section, which adds one fixed sentence saying the route did
   not require review. Absent or `true` keeps `insufficient_coverage`. Carried attempt gaps
   (`semantic_relevance_review_not_run`, `optional_semantic_review_blocked_by_policy`, …) and
   `semantic_review_skipped_insufficient_packet` keep bounding the conclusion.
3. **Verdict and readiness.** The check verdict rules are unchanged: a clean `deterministic_only`
   check already reached its scoped `no_issue_detected` verdict. Closure readiness keeps the
   ADR-032 route rule, so the code is standing on a non-requiring route and actionable only where
   the serving route requires and can dispatch review.
4. **Surfaces.** The CLI check rendering and the MCP check summary add a short clause when the
   field is `false`; guidance states that a local-only check blocks only where review is required.

## Amendment (2026-10-08): finer stale rule and a gate token for edits after verification (#1018)

ADR-042 refines decisions here without replacing them. An observed edit whose every path is scratch
(a temporary root outside the workspace) or FinishUP's own material (a saved receipt or export, FinishUP state,
the packaged FinishUP trees) carries `write_scope` `scratch` or `yoetz_owned` and never advances the
latest edit, so it never makes `planned_verification_stale` or `edited_after_last_verification`
fire and is not acting. `python -m pytest` and the other verification modules are verification
runs; an interpreter-run script is never a build by its file name. `edited_after_last_verification`
joins `STOP_GATE_TOKENS` and the observation-dependent set. `requested_item_never_attempted` never
names a `role: input` item and waits for a completion claim or published work on that obligation;
a research action is not acting. Task facts that do not bear on a finding no longer refuse
`respond self_verified` (ADR-034); readiness and the gate stay task-wide.

## Amendment (2026-10-11): the gate asks the re-checks readiness announces (tb4n3 RC-8, #1031)

tb4n3 (28 real Codex runs) showed the gate as a token-triggered rider composer. The four re-checks
(the acceptance re-read, the acknowledgement re-check, the blocker re-check and the premise ask) rode
on other tokens, so (a) the A-12 acceptance sentence was never asked in about 70% of the attempts,
because a gate only fired when another token was present, (b) the status directive said "Nothing
further to do" and a gate then challenged an acknowledgement the gate's own acceptance sentence had
invited in the same turn (ks S, cargo D), (c) a rejected finding awaiting the reviewer's ruling was
answered with a push to acknowledge it (ks S), and (d) in formal-crypto S every Stop after the first
was an already-continued Stop, whose items were never computed, so "never withdraw a working
deliverable" was never shown to the agent that emptied its solver, while the premise and
acknowledgement texts ("do that work unless it is genuinely impossible") sent it into 35 minutes of
impossibility research. The owner decided:

1. **One list of re-checks.** `closure_readiness.rechecks` (ADR-032 amendment, one closure verdict,
   ADR-046) lists stateless candidates `{kind, key, subjects, rule, since_frontier}` for the four
   kinds. Status, `closure_prepare`, the CLI, the TUI and the gate read that one list, and the status
   directive names the items ("At Stop you will be asked once to re-read: ..."). The gate asks
   exactly the announced re-checks and never one status did not announce: "Nothing further to do" is
   not followed by an unannounced gate. Delivery memory stays client-side (decision 3 of the
   original ADR): each key is asked once per session in `observation/closure-gate-blockers.json`
   (a blocker as `<obligation id>:<kind>`, as before). A readiness without the list, from a service
   older than the gate, announces none, so the gate asks none.
2. **The A-12 acceptance re-read is its own item** (owner decision 6). Key `accept:<h8 of the sorted
   resolved obligation ids>`, remembered as `accept:<h8>@<invite frontier>`. It is asked on a first
   Stop and on an already-continued Stop (within the per-turn cap), once per resolved set; the extra
   Stop turn it costs on a run that resolves obligations is accepted. It is not composed beside open
   obligations (acknowledgement stays the challenged last resort, #997), beside a rejected finding
   awaiting a ruling, or beside a withdrawn deliverable, whether or not that Stop names the item (an
   already-continued Stop does not): it then stays unasked and is asked at a later Stop. Its sentence gains the verification-limit branch: when the criteria can only be
   checked outside this environment (a hidden verifier, a withheld artifact) and the agent did the
   work, keep the obligation resolved and record `finishup-verification-limit:<obligation id>`; "I
   could not find it" never qualifies, so the pretrain S rescue is unchanged.
3. **No invite-then-challenge.** An `acknowledgement` re-check whose `since_frontier` (the frontier
   of the agent's current acknowledgement) is later than the earliest acceptance invite this session
   received answers that invite and is not asked. An acknowledgement published before any invite is
   challenged once, as before.
4. **`finding_rejection_awaiting_ruling` is a gate token** (ADR-040 amendment: a finding the agent
   rejected with a reason and no reviewer has ruled on). The text sends the agent to `check` with
   `final_review: true`, names the findings and the frontier of the rejection, and never offers
   acknowledgement; the acceptance invitation never appears beside it. `receipt_findings_unresolved`
   counts agent-work findings only (`finding_counts.to_do - awaiting_ruling`), and `self_verified` is
   offered only while `finding_counts.self_verify_eligible` is positive; otherwise the text names that
   it is not accepted and points at `status view=findings`. A service that sends no counts keeps the
   earlier wording.
5. **A withdrawn deliverable is voiced on an active Stop** once per key. `declared_output_emptied`
   and `declared_output_removed` bypass the active-Stop suppression, within `MAX_GATE_BLOCKS_PER_TURN`,
   keyed `emptied:<h8 of the declaring obligation items>` (a path is never put in the key or the text;
   an obligation item is one path), and recorded when a first-Stop gate voices them too. The text:
   "You withdrew a deliverable that passed your verification run; an empty file scores as no
   solution; restore it and disclose its limits." with the rule and obligation ids from
   `fact_lineage` (ADR-045). The owner's draft said "passed your tests"; a lineage basis `verified`
   means a test, lint, typecheck or build run passed while the file had content, so the sentence
   says "verification run" (Codex review round 1). It is said only when the basis is `verified`;
   otherwise the deliverable "held content".
6. **The premise and acknowledgement texts keep the working deliverable.** Both gain "If you cannot
   finish it, keep the working deliverable; acknowledgement never requires withdrawing or emptying
   it." after the unchanged push to work, so the ack re-check still sends an agent that gave up back
   to work (pretrain S) without teaching the formal-crypto S fallback.
7. **The predicted receipt conclusion** (ADR-046, owner decision Q1) is appended to the gate text as
   its lowest-priority sentence, from `closure_readiness.predicted_receipt` through the shared
   `predicted_receipt_variants`; it is the first sentence dropped under the bound and never makes a
   gate fire. The acceptance invite memory is protected from eviction: when the 64-key memory is
   trimmed the earliest invite (its frontier decides which acknowledgement answered it) and the
   newest seven are kept, so a long run cannot turn an answered acknowledgement back into a
   challenge.
8. **Composition** stays on the bounded composer (ADR-043): every new sentence is a part with a
   priority, the withdrawn-deliverable instruction is a required family instruction, the acceptance
   sentence is the first optional sentence dropped, and a re-check whose whole sentence did not fit
   is not recorded as asked. The fact-lineage sentence (ADR-045, where a fact came from) is the
   lowest-priority optional part and is trimmed right after the predicted conclusion; every token
   still says why it fired without it (its item clause, the awaiting-ruling `Why:` and the
   withdrawn-deliverable sentence with its rule and obligation).
9. **Diagnostics.** `closure_gate_loop_guard` is renamed `closure_gate_turn_end_after_continue`: it is
   the normal end of a continued turn, not a defect and not a loop guard. `closure_gate_acceptance_rechecked`
   counts the extra Stop turns the acceptance re-read costs.
10. **Hosts.** Codex, Claude Code and Cursor share the gate, its re-check list, texts and memory
   (`handle_observe`, `handle_claude_observe`, `handle_cursor_observe`); the only difference is how
   an already-continued Stop is detected (`stop_hook_active`; Cursor `loop_count > 0`), already
   normalised to `active_stop`. Each runbook records "supported, same code path". No OS-specific path
   is added; the memory files use POSIX `fcntl`, which WSL 2 provides.

Cost and risk: one extra gate turn on a run that resolves obligations (owner decision 6); the
per-turn cap of two still holds, so in a single-turn run whose first two Stops were spent on other
gates the acceptance re-read is not asked (it has no reserved third continuation; raising the cap
is an owner decision, not made here); a gate that reads a service older than itself asks no
re-check until the service restarts onto the new build; an acknowledgement published after any
acceptance invite counts as its answer even many Stops later (the invite's frontier is the only
memory), which is the owner's rule and is bounded by the one-per-key asking.

## Amendment (tb4n3 RC-5, issue #1028, ADR-045): command identity and lineage

A planned verification matches an observed run by more than its exact text. The hook commits three
domain-separated canonical kinds beside the whole-command and segment commitments (`full`:
wrappers `timeout`/`nice`/`env`/`nohup`/`stdbuf` and `VAR=` dropped, argv[0] by basename,
`python3` to `python`, `python -m pytest` to `pytest`; `prefix`: each leading run of two or more
arguments; `flag`: each argument after argv[0]); `task_facts.planned_match` reports `exact`,
`normalized`, `prefix` or `flags`. The first two are clean. A prefix or flags match counts as run
and raises the standing disclosure `planned_verification_matched_by_prefix` (lineage names the
observed run); like `planned_verification_agent_linked` it does not bound the conclusion. The
runner class of a composed command is its strongest verifying segment, and a run that matches a
planned command is a verification run whatever its class, so
`edited_after_last_verification` is no longer dormant behind `compound`/`other`, and a shell
command that visibly writes into the workspace is an edit (`write_scope: workspace`). Every
derived task fact carries a `FactLineage` (rule, subject, observing check and frontier, prior state,
supporting events) shown on status, the check result, the Stop-gate text and the receipt.

## Amendment (2026-10-12): the owner keeps the Stop-gate defaults (record only, #1031)

The cloud review of the tb4n3 gate work (issue #1031, ADR-033 amendment of 2026-10-11) left three
behaviors for the owner. The maintainer (TheGaySupreme123) decided on 2026-10-12 to keep all three as
they are. No code, text or wire changed; this section only records the decisions so they are not
re-opened as defects.

1. **The per-turn cap of two continuations stays** (`MAX_GATE_BLOCKS_PER_TURN`). In a single-turn run
   whose first two Stops were spent on other gates, the acceptance re-read is not asked: it has no
   reserved third continuation. Raising the cap or reserving a slot is not part of this decision; the
   extra turn the re-read costs on a run that resolves obligations was already accepted (decision 2
   above).
2. **An acknowledgement after an acceptance invite counts as answered, even several Stops later.** The
   invite's frontier is the only memory (decision 3 above): an `acknowledgement` re-check whose
   `since_frontier` is later than the earliest invite this session received is not asked. The rule is
   bounded by the one-per-key asking.
3. **A child's limitation keeps lineage rollups strict.** A child's findings reach the parent through
   the frozen `ChildFindingSnapshot`, which carries no closure class, so a parent cannot tell a child's
   unmet requirement from a child's disclosed limitation and keeps the strict reading (the child's
   `acknowledged_not_done` and `rejection_accepted` rows stay actionable and unresolved in the rollup).
   Rationale and the wire consequence are recorded in ADR-046 ("Not switched: lineage rollups stay
   strict" and its amendment of 2026-10-12).

Hosts: the gate is one code path for Codex, Claude Code and Cursor (decision 10 above); nothing here is
host- or OS-specific.

## Amendment (tb4n4, issues #1044 and #1050): an undeclared dependency is a gate item; the acceptance re-read asks only what the final message left out

Recorded from the maintainer's request of 2026-10-12 to fix #1044 and #1050 in the tb4n4
remediation PR.

1. **`deliverable_references_undeclared_file` is a `STOP_GATE_TOKENS` entry (#1044).** A delivered
   source file that loads a file the agent created and no requested item declares continues the
   agent on a Stop the host has not already continued. The item says a grader may receive only the
   declared files and gives the three repairs (embed the content, rebuild it at run time, declare it
   as a delivered output); disclosing the dependency does not clear it (ADR-035 amendment). The gate
   names the files from `closure_readiness.undeclared_references`, each through
   `bounded_text.quoted_path`: the one exception to "closed tokens, counts and service-minted ids" in
   the gate text, because the agent must act on exactly that file. No path is put in a key, a
   diagnostic or the gate memory. The acceptance invitation is not composed beside the token (an
   acknowledgement is not its exit), like a withdrawn deliverable.
2. **The acceptance re-read asks only what the final message did not address (#1050).** tb4n4: the
   re-read fired in 60 of 60 deterministic attempts (61 of 65 continuations); 41 attempts then did
   only FinishUP bookkeeping and none edited a deliverable (median cost 1.3 minutes, worst 12.9). Its
   one real value was five honest downgrades of overstated claims. The re-read stays, keyed and
   remembered as in the 2026-10-11 amendment, but where the host's Stop payload carries the agent's
   final message it is asked only for the resolved obligations that message does not address, and
   it names them.
   - **The rule (deterministic, `closure_gate.uncovered_acceptance`).** For each resolved obligation
     the acceptance text is its `acceptance_criteria`, or its description when it has none, or
     nothing when a privacy policy withheld it. The obligation is covered when the first 65,536
     characters of the final message contain its id, or when at least two thirds of the acceptance
     text's terms occur among the message's tokens. A token is a lowercase ASCII run of letters and
     digits (a decimal point between digits kept; anything else separates); a term is a token of at
     least three characters, or two with a digit, that is not one of 79 closed English function
     words; at most the first 64 distinct terms count. A text with no term, and a withheld text, is
     covered only by its id. Conservative by design: a bare "Done." or "all tests pass" covers
     nothing, and only a message that cites the obligation or restates most of its criterion does.
   - **The read.** When the gate would ask the re-read and a final message is present, it reads one
     `status view=obligations` page (filter `status: resolved`, limit 100, 750 ms) for the resolved
     obligations' texts and trusts it only when the rows with closure basis `resolved` hash to
     exactly the announced `accept:<h8>` key; a failed or slow read, a second page or a different set
     keeps today's re-read. The message is read in the hook process only: never sent to the service,
     stored, logged or put in a diagnostic.
   - **Outcomes.** Some obligations uncovered: the re-read names them (at most three, then a count)
     and is remembered as before. All covered: the re-read is not asked at this Stop, nothing is
     remembered (a later Stop whose message drops them is asked), and the hook records
     `closure_gate_acceptance_covered`. No final message (Cursor, an oversized Codex body, an older
     Claude Code): today's re-read for every resolved obligation.
   - **A confirmation is the end of it.** Where the re-read rides alone (no item in the same text asks
     for a check), it ends with "If every criterion is met, say so in your final answer and stop:
     that confirmation alone needs no new record, check or receipt." Nothing in the gate, readiness or
     the receipt asks for another round after a pure confirmation (the same frontier is suppressed, and
     an already-continued Stop asks only unasked keys); only a republish or a decision line is
     material and makes the next Stop's items apply.
   - **Unchanged.** The downgrade path: an unmet criterion is republished `acknowledged_not_done` and
     left out of the claim, an acknowledgement published after the invite answers it and is not
     challenged, and the verification-limit branch is the same sentence.
3. **Hosts.** The gate is still one code path. Codex passes `last_assistant_message` in its Stop
   body, read only when the body is within the trusted size; Claude Code's adapter passes its Stop
   payload's `last_assistant_message` beside the structural envelope (never inside it); Cursor's
   `stop` payload carries no final message (status and `loop_count` only), so Cursor keeps the
   re-read for every resolved set. Registering Cursor's `afterAgentResponse` to obtain the text is a
   host-integration change left to a follow-up, tracked on issue #1050. Each runbook records its
   decision.

Cost and risk: one extra bounded status read at a Stop that would ask the re-read with a message
present. The five tb4n4 downgrades came after the re-read; a final message that already restated
the overstated criterion would now skip it, which is the trade the issue accepted. The 60-export
replay that would measure it is the maintainer's (the exports are not in the repository).

## Amendment (2026-10-12): a local-only check by request discloses no missing review (#1041)

Owner decision (issue #1041, the N3-2 residual): after the 2026-10-08 amendment,
`semantic_review_not_requested` no longer bounded a deterministic-route receipt but was still listed
on every one of them (tb4n4's deterministic arm: every receipt). A check that asked for
`deterministic_only` on a route that did not require AI-powered review ran exactly what was
requested, so the code is no longer recorded for it at all:

1. **Check.** Such a check (it records `semantic_route_required: false`; its status stays
   `not_requested`, reason `deterministic_mode`) adds no `semantic_review_not_requested` to its
   coverage. A route that required review, a review the round stopped
   (`semantic_review_skipped_insufficient_packet`) and every other non-succeeding outcome keep
   their code exactly as before.
2. **Readers.** The receipt context and receipt-capacity admission no longer re-derive the code
   from the `not_requested` status of a check that recorded `semantic_route_required: false`; that
   check's own `known_gaps` are what it disclosed. Decision 2 of the 2026-10-08 amendment now
   tests the recorded route and status only. Checks an older build wrote keep the code they
   recorded, so their receipts are unchanged.
3. **Surfaces.** The receipt (JSON, markdown, text), status coverage and closure readiness all read
   the recorded coverage, so none lists the code for such a check. The check's own result still
   states `semantic_status: not_requested` and the receipt conclusion names deterministic coverage
   only (`no_unresolved_deterministic_findings`). Same on every host.

## Amendment (2026-10-13, tb4n5, issue #1050): the acceptance re-read asks only what the ledger flags

Owner decision of 2026-10-13 (recorded in the tb4n5 follow-ups): re-read only the resolved
obligations the ledger flags as risky, and delete the word-coverage check. It supersedes item 2's
rule of the tb4n4 amendment above; the downgrade, verification-limit and once-only confirmation
paths are kept.

tb4n5 measured the tb4n4 rule: the re-read fired in 18 of 18 attempts and
`closure_gate_acceptance_covered` was never recorded. Replaying `uncovered_acceptance` on the real
pre-gate final messages covered 1 of 110 resolved obligations: real final messages (345-742
characters) summarize results in other words and never cite an obligation id, and real criteria
are long (a median of 14 terms), so a message reached 0-45% of a criterion's terms against the 2/3
threshold. No lexical threshold works: at one third of the terms no attempt is fully covered. The
rule's fixtures were short criteria and near-verbatim restatements.

1. **The service flags; the gate names.** `kernel.acceptance_risk` derives, per request from the
   projection and its record prefix, which resolved obligations (closure basis `resolved`) the
   ledger flags, with three closed reasons: `requested_item_never_attempted` (a non-input requested
   item with no attempt in any spelling and, for a command, no matching hook-observed run: the
   work-integrity attempt test), `evidence_not_linked_to_declared_items` (it declares deliverables
   or commands and no cited resolution evidence traces through a recorded link to an action naming
   one: the inspection's `evidence_off_declared_items` or `evidence_unattributed`, now computed by
   the shared `kernel.evidence_alignment`), and `evidence_self_asserted_only` (no cited reference
   is a hook-observed run or its result, observation-captured evidence, an approved check or an
   import report, and no requested command item has a matching observed attempt).
   `ClosureReadinessFacts.acceptance_risk_obligation_ids` carries the set; the `acceptance` recheck
   names only it (rule `resolved_obligations_acceptance_risk`, key `accept:<h8>` over that set, so
   a changed flagged set asks again) and is absent when nothing is flagged. An unreadable resolved
   obligation is flagged with every reason (fail closed). A fact set without the list (hand-built,
   older) keeps every resolved obligation under the old rule token.
2. **The word-coverage check is deleted.** `uncovered_acceptance`, its token and stopword rules and
   the bounded `status view=obligations` read at Stop are removed: the gate reads compact status
   once.
3. **An explicit per-obligation attestation answers it.** A final message line
   `finishup-acceptance:<obligation id>:met` (also inline or in a bullet; `:not_met` or any other
   outcome is not one) for an announced obligation answers the re-read for it. The attestation is
   bound to the set this Stop's status read announces: an id outside it is ignored, and it counts
   only when the announced subjects hash to the announced key (at most eight; a longer or older
   list is asked in full). The gate names only the unattested obligations; a message attesting all
   of them is not asked and records `closure_gate_acceptance_covered`. The re-read text, and the
   status directive's re-check note, name the line. An attestation is the agent's statement: it
   records nothing, never changes a closure class, a finding, a receipt conclusion or coverage, and
   never suppresses an independent finding or another gate item; a not-met outcome is answered by
   the downgrade path (republish `acknowledged_not_done`) or the verification-limit decision,
   unchanged.
4. **Unchanged.** Keys, memory and once-per-session asking; the exclusions (never beside open
   obligations, a rejected finding awaiting a ruling, a withdrawn deliverable or an undeclared
   dependency); the once-only confirmation sentence where the re-read rides alone; the
   acknowledgement-after-invite rule. Hosts: the service side is host-independent; Codex and Claude
   Code pass the final message (attestations read), Cursor's `stop` carries none (every announced
   obligation asked; issue #1050 owns the `afterAgentResponse` follow-up). Each runbook records it.

Measured on tb4n5 (an approximate replay of the agent-published records before each first gate,
with observed results and observation-captured evidence from the exports; the kernel's keyed
command matcher was approximated by the exported command-attempt relation): 12 of 18 attempts and
40 of 111 resolved obligations would still be asked (21 flagged `evidence_self_asserted_only`, 21
`evidence_not_linked_to_declared_items`), against 18 of 18 and 110 of 110. Live-database S (every
resolution self-asserted) is still asked. **Known gap:** formal-crypto S's honest downgrade
followed a re-read of an obligation whose resolution cited an observed run of the requested
command with the requested output attempted; the ledger flags nothing there (the shortfall was in
the output, not in the record), so under this rule that downgrade relies on the closing review and
the agent's own final answer, not on the gate.

Verification: `tests/unit/kernel/test_tb4n5_acceptance_risk.py` (a clean resolution and one per
flag in one ledger: the clean one no longer triggers, each flagged one does, the key names exactly
the flagged set, a clean-only ledger announces none); `tests/unit/cli/test_closure_gate.py`
(realistic tb4n5 summaries, attestation parsing, partial and stale attestations, a `:not_met`
answer, the tb4n2 false-completion message, an incomplete list, an older service, absent host
message per host, no second status read).

Check follow-up (2026-10-13, Codex check D3): `acceptance_risk` runs on every status read, inside
the Stop gate's 4,000 ms status deadline. The first version resolved every cited evidence id
against the whole result inventory per obligation (200 resolved obligations, eight evidence refs
each, 20,003 results: about 4.5 s, 9.1 s on a loaded host). The inventories are now indexed once
per read (`evidence_alignment.results_by_evidence`, one pass over actions for attempted items, the
command-attempt fallback only for an obligation that requests a command), and an identical call
(same projection, prefix, resolved set and command-identity key generation) is answered from a
one-entry memo; the same shape now takes about 0.02 s. No risk decision changed. Round 2 (check
D3-R2): each cited reference's source actions are resolved once per read and deduplicated by
action identity, so 200 obligations sharing eight items, one of them behind 1,000 linked actions
(21,003 results), take about 0.07 s instead of about 9.3 s.
`tests/unit/kernel/test_tb4n5_acceptance_risk_cost.py` holds it under one second and counts one
index build per read.

## Amendment (tb4n5, react-lead-form): a conditional output is corrected in the plan, never by a placeholder

tb4n5/tb4n4 react-lead-form, 5 of 5 FinishUP attempts: the task asked for `incomplete_leads.json`
only when a contactable lead is incomplete and for `rejected_ledgers.json` only when an existing
ledger is malformed. Each agent declared both as unconditional `file` outputs; the final input was a
complete, accepted lead, so neither existed and `requested_output_absent` (decision 2) blocked the
receipt. The finding offered only "write each requested file", a reasoned `rejected` never rules on
a deterministic finding, and `self_verified` was refused, so each agent invented an exit: a false
`acknowledged_not_done` for work it had done (n4 D), an undocumented plan reclassification (n4 S
twice, n5 S), or deliverable code that wrote empty ledgers on every accepted submit and tests
rewritten from "absent" to "empty" (n5 D). Owner decision (2026-10-13): document the honest exit; no
new protocol role.

1. **What distinguishes them.** A `file` item with `role: output` is a promise to deliver that file
   now. A file the request asks for only under a runtime condition is behavior of the deliverable,
   not a delivered file: it is modelled as a `change` item whose value names the condition and the
   path, beside `file` items (`role: output`) for the source files that implement it. The check
   probes only `file` and `directory` items, so a `change` item is never reported absent.
2. **The documented correction.** When a conditional output was declared as a `file` and the final
   state does not meet the condition, the agent publishes a new obligation with the same acceptance
   criteria modelled as in 1, supersedes the old one with `plan_revised` (`change: superseded`, a
   reason, `replacement_obligation_ids`), records the work with each new item value in
   `attempted_items`, resolves the new obligation with its evidence and replaces the completion
   claim with one naming it. The old obligation leaves the effective plan, so the next qualifying
   check does not return the issue and resolves the historical finding; nothing waives it
   and no response resolves it. The `requested_output_absent` detail
   (`render_deterministic_finding_text`), `workflow.md`, `publication-policy.md`,
   `request-templates.md` and the operating card name this route, and every one forbids writing an
   empty or placeholder file, or changing when the deliverable writes the file, to satisfy the
   declaration. The decision-3 sentence "its repair is the deliverable itself, never a revised
   obligation" keeps holding for every other absent output.
3. **The claim follows the plan.** The claim-revision invariant `scope_overlap_required` now counts
   the replacements a `plan_revised` supersession recorded (the replay-derived
   `superseded_by_obligation_ids`, transitively) as overlap with the superseded claim's scope, so a
   claim that named only the corrected obligations can be replaced by one naming only their
   replacements. A replacement the plan never recorded is still refused. The same ancestry carries
   failure disclosure (checker review): the claim scope plus every obligation a supersession
   replaced by one in it, transitively (`claim_limitations.scope_with_supersession_ancestry`), is
   the scope for admissible `limitation_refs` (always: a relaxation), for
   `limitation_refs_complete` on a replacement whose overlap with a target exists only through a
   supersession (the case this change newly admits, so no recorded ledger holds one), and for the
   work-integrity failed-work relevance read at check time. A failure recorded on the superseded
   obligation must therefore still be disclosed by the replacement claim, and naming it there is
   admissible; a fresh claim over the replacement that omits it still replays as before and is
   reported by the check. Recorded ledgers replay unchanged.
4. **What does not change, and what a correction cannot drop.** A file the request asks for
   unconditionally stays required: the replacement obligation that still declares it (or any other
   obligation that does) raises the same `requested_output_absent`. A requested `file` or
   `directory` item (role `output` or none) of an obligation a `plan_revised` superseded with
   replacements stays requested on the superseded obligation
   (`task_facts.superseded_unnamed_outputs`) unless a replacement, transitively, re-declares it as
   a `file`/`directory` item that is not `role: input`, or releases it in the documented
   correction form: a `change` item that spells its declared path (the same path, a longer
   absolute spelling, or for an absolute declaration its tail with a directory; a bare file name
   in another directory does not count), names none of the superseded obligation's other requested
   outputs, states a condition (`when`, `if`, `unless`) and never calls it unconditional. Anything
   else is ambiguous and keeps it required (checker R2: a basename mentioned in incidental prose,
   or an output re-declared as an input, released a missing unconditional file). The check probes
   a kept output and reports it absent exactly as before, so dropping a missing deliverable from
   the correction does not launder it. A
   supersession without replacements, and a waiver, are explicit plan decisions outside this rule.
   `declared_output_removed`, `declared_output_emptied` and the closure gate are unchanged; the gate
   still says "Do not reshape your work for FinishUP". No event schema, wire field or pack version
   changes.

Tests: `tests/integration/closure/test_conditional_output_shape.py` (the react shape: two
conditional ledgers absent on an accepted lead resolve after the correction with no file written;
an unconditional missing output still blocks; with a real repository, the production workspace
probe and the real final receipt, the honest correction closes and a correction that drops an
unconditional missing output reads `unresolved_findings_remain`, as does one whose change item
mentions it in incidental prose or that re-declares it as an input) and
`tests/unit/kernel/test_claim_correction_replay.py` (the supersession carries claim scope only to
recorded replacements, and a failure or partial result on a superseded obligation, one or two
supersessions back, must still be disclosed and may be).

## Amendment (2026-10-14, issue #1050 follow-up): Cursor is never told to use the acceptance line

The 2026-10-13 amendment left Cursor asking every flagged set, but its text still told the agent
to end the final answer with `finishup-acceptance:<obligation id>:met`, a line Cursor's `stop`
payload (status and `loop_count` only) can never carry to the gate.

1. **`afterAgentResponse` is not registered.** Cursor's hook documentation gives it the response
   text, but Cursor acknowledges that its CLI and Cloud Agents do not dispatch it, and it
   documents no order between it and `stop`. Registering it would make the line work only on some
   Cursor surfaces, and would change the advertised Cursor event set (ADR-010) and add a
   cross-process memory of the attested ids. Revisit when Cursor dispatches it everywhere with a
   documented order before `stop`.
2. **Host-aware text, no new record.** The acceptance re-read sentence and the re-check note take
   the host. On `cursor` they say that Cursor passes FinishUP no final answer, that a met criterion
   stays resolved and is confirmed in the final answer, and that the re-read is not asked again for
   the set; that is the existing per-session, per-key memory, so the continued Stop passes and a
   later Stop with the same flagged set is not asked. The MCP bridge passes its host profile to
   `closure_prepare` and to the status and `closure_prepare` summary text (so Cursor's summary
   fallback and a generic bridge follow it too); the CLI and TUI, which do not know the agent's host, name Codex and Claude
   Code as the hosts that read the line. Codex and Claude Code text is unchanged. No protocol,
   schema or ledger record changes: a ledger-recorded acceptance answer would need a new event or
   disposition and is not part of this amendment.

Locked by `tests/unit/cli/test_closure_gate.py` (the Cursor Stop flow and the host-aware text),
`tests/unit/kernel/test_tb4n5_acceptance_risk.py` (the note per host),
`tests/integration/application/test_closure_composer.py` (the `closure_prepare` host) and
`tests/unit/mcp/test_tb4n3_closure_verdict_text.py` (the MCP summaries per host).

## Amendment (2026-10-15, issue #1079 item 3): a new closing review needs a material delta

tb4n5 asked for a closing review 5 times across trials where the only later records were
bookkeeping or dispositions. `closing_review_required` now goes stale only after a material task
or verification change (`kernel/closing_review_delta`): an observed edit or shell write, an
unclassified observed command or its result, or a cooperative edit or command. Claims, decisions,
plans, responses, coordination, assignments, findings, and evidence publication do not. An
unchanged newest check that failed with reason `coordinator_failure` does not ask for the same
`final_review` again; readiness adds the standing code `semantic_coordinator_failure` and the
status, closure-prepare, and receipt text name that FinishUP limit. A material change after the
failure asks again and clears the code. `invalidates_recorded_check` is unchanged, so a real edit
still makes the check inapplicable and still re-arms the closing review. The code is a readiness
token, not a coverage gap and not a new wire field.

## Amendment (2026-10-15, issue #1079 item 3): the check-cell pragma follows the capability

The Stop gate used to repeat `// @exec: {"yield_time_ms": 300000}` whenever the host was Codex.
Plain Codex exec and the benchmark host expose direct MCP calls plus `exec_command` and
`write_stdin`, which are not code-mode cells, and FinishUP's MCP server records no `clientInfo`
that says the client uses cells. The close instruction is now the neutral sentence unless code
mode was positively observed: a recorded `exec` cell for this session
(`LocalObservationStore.session_observed_code_mode`), or `check_cause.tool == "exec"`. Claude Code
and Cursor do not record those cells, so they keep the neutral sentence. `guidance/startup.md`
says the pragma and `yield_time_ms` apply only to a JavaScript `exec` cell.

## Amendment (2026-10-15, issue #1079 item 7): a risky completion claim names its verification

In 6 of 28 smoke trials the agent resolved a criterion or said every criterion was met when the
external verifier showed that was false. `acceptance_risk` still checks attempt and evidence
lineage, not whether the claim is true. This step does not reject a claim at publish time and
does not grade the sentence.

For rule `resolved_obligations_acceptance_risk`, the Stop re-read is answered only by
`finishup-acceptance:<obligation id>:met:<evd_ or res_ id>` or
`finishup-verification-limit:<obligation id>` (the `yoetz-` spellings too). A bare `:met` and a
generic all-met claim do not answer it. The legacy rule `resolved_obligations_acceptance_reread`
still accepts a bare `:met`, and still ends an alone re-read with the confirmation sentence.
Codex and Claude Code read those lines in the final message. Cursor's `stop` carries no final
message, so its text never contains `finishup-acceptance`: the agent publishes the
verification-limit decision or links the observed id in a record. The re-read is still asked once
per flagged set. An obligation that already has a `verification_limit` disclosure leaves the
recheck; the receipt still lists it.

`kernel.claim_verification.claim_verification_lines` appends that pairing to the receipt evidence
section in JSON, markdown and text: a header that a generic all-met claim does not stand in, then
one line per flagged obligation with its reason tokens and `verification_limit` or
`no_verification_limit`. A final-message line does not create the ledger link the receipt
reports. Compact receipt wording is unchanged. A projection hole does not fail the receipt: the
pairing for that obligation is omitted and the limitations section says the pairing could not
be read, naming only the obligation id when the scope can still be read.

## Amendment (2026-10-15, issue #1079 item 7): the cited id must be a recorded link

`finishup-acceptance:<obligation id>:met:<evd_ or res_ id>` does not pass because the id is
well-formed. Status carries `closure_readiness.admissible_verification` for a flagged
obligation when `kernel.verification_link` finds a readable `evd_` or `res_` row at or before
the closing frontier that the obligation cites, that `source_actions` ties to the obligation or
to one of its requested items, or that an effective claim's `supporting_refs` names for that
obligation or for the whole task. The gate accepts the line only when the cited id is in that
list. A missing id, or one linked only to another obligation, is unattested, and the re-read
says `` `<id>` is not linked to obligation `<obligation id>`. `` The
`finishup-verification-limit:<obligation id>` line remains the honest alternative and does not
need a row. There is still no truth grade and no publish-time rejection. Cursor still has no
final message: a published verification-limit decision leaves the recheck, and a nonempty
admissible list for an obligation is the record link that answers it. An absent list does not.
