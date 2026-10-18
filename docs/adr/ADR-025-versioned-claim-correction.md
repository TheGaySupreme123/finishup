# ADR-025 — Versioned append-only claim correction

**Status:** Accepted (2026-08-29), acknowledged in
[issue #432](https://github.com/TheGaySupreme123/finishup/issues/432).
**Implemented by:** `src/finishup/domain/events.py`, `src/finishup/kernel/claims.py`,
`src/finishup/kernel/observed_failures.py`, `src/finishup/kernel/reducers.py`, the local policy packs,
AI-powered review case and receipt builders, and the public claim schema, guidance, descriptors,
and conformance suites.
**Relates to:** ADR-002 (canonical protocol), ADR-019 (declared completion scope), and ADR-020
(typed evidence digest provenance).

## Context

`claim_recorded/1.0.0` uses one `supporting_refs` list for both evidence that supports a conclusion
and a partial or failed result that limits it. A later claim can dispute the earlier claim, but
`disputes_refs` deliberately records an unresolved contradiction; it is not supersession. A
decision can supersede another decision event, but not a claim. Trial-and-error correction
therefore appends more contradictions without providing a typed current replacement.

The failure is amplified by task-global limitation scans: a result recorded after a claim, or for
a disjoint obligation, can make that historical claim and unrelated later claims look incomplete.
Append-only history must remain intact, so mutation or erasure is not an acceptable repair.

## Decisions

1. **Claim correction is a new event-schema version.** `claim_recorded/1.1.0` requires
   sorted-unique `supersedes_claim_refs` containing claim ids and `limitation_refs` containing
   result ids; a producer sends an empty array when a field does not apply.
   `supporting_refs` retains its v1 meaning. Frozen `claim_recorded/1.0.0` bytes and decode behavior
   remain unchanged.

   The authoring path is additive too: `event-draft/1.1.0` adds the exact new pair,
   `opaque-unknown-event-draft/1.1.0` excludes it from opaque admission, and
   `publish-work-request/1.1.0` selects that union. Their 1.0 predecessors remain byte-identical.
   The frozen v1.0 union still admits the future pair as opaque; local control 2.4.0 embeds the
   exact-known request, while the manifest-bound handshake prevents a stale service from receiving
   it as an ordinary publication.

   Carrying that union costs host context, so two reviewed byte ceilings in
   `src/finishup/mcp/descriptors.py` move with it: the `publish-work-request` presentation budget from
   32,000 to 34,000 encoded bytes, and `ADVERTISED_SURFACE_BUDGET.max_encoded_bytes` from 200,000
   to 205,000. Both are deliberate one-time raises for the additive draft branches, not headroom
   for prose; the 20,000-byte instructions bound is unchanged, so guidance still pays for new text
   by compressing existing text.

2. **Replacement is explicit and whole-claim.** A replacement uses a fresh claim id, names one or
   more prior effective claims of the same kind, and declares obligation scope overlapping every
   target. The replacement becomes the effective current claim; the targets remain immutable in
   projection history. Narrowing a claim may deliberately leave former scope without a current
   completion claim; no scope is silently transferred.

   **Empty-scope repair (#859, 2026-09-26).** An already accepted target with empty
   `obligation_refs` has no declared scope to overlap. Explicitly naming it in
   `supersedes_claim_refs` permits either populated or empty replacement scope. Every populated
   target still requires overlap, including when mixed with empty targets. The same fresh-id,
   effective-target, same-kind, non-dispute, changed-meaning and limitation rules apply. The
   existing task/session/writer routing fences remain authoritative; another task's claim is not
   a target in this ledger. No scope is inferred from support, prose, or another claim.

   **Plan-recorded replacement (tb4n5, ADR-033 amendment).** A target obligation that a
   `plan_revised` supersession replaced (the replay-derived `superseded_by_obligation_ids`,
   followed transitively) carries its scope to those replacements: a replacement claim naming one
   of them overlaps the target. This is how a conditional output declared as a `file` is corrected
   without a placeholder. Only a recorded plan relation counts, never a claim's own word. The
   same ancestry keeps failure disclosure: a partial or failed result on a superseded obligation
   stays relevant to a claim over its replacement, both as required in `limitation_refs` and as
   admissible there.

   New ordinary v1.1 completion publications must explicitly include `obligation_refs`. An
   intentional `[]` remains valid and coverage-incomplete; it cannot coexist with obligation IDs
   in `supporting_refs`. Such IDs must be consciously declared as scope or removed from support.
   Dry-run and append reject these authoring errors before staging objects, with the structural
   invariants `completion_scope_must_be_explicit` and
   `empty_scope_must_not_support_obligations`. These are admission guards, not historical replay
   rules: legacy events and exact retries of already accepted operations remain readable and
   recoverable. Frozen v1.0 admission is unchanged. No new wire field or schema version is needed;
   this repairs the existing v1.1 correction operation and leaves all frozen schema bytes intact.

3. **Limitations are separate from support.** A v1.1 completion claim puts every relevant partial
   or failed result in `limitation_refs`; such a result is rejected from `supporting_refs`.
   A relevant result existed no later than the claim and either has unscoped action provenance or
   overlaps the claim's declared obligations. Unscoped claims/actions remain conservatively
   task-wide. `unknown` is not silently upgraded into either support or a typed partial/failure.

   Disclosure is not that upgrade. `claim_discloses_result` reads only `limitation_refs` for a v1.1
   claim, and the local limitation policy treats a relevant `unknown` result as limiting,
   so `limitation_refs` also *accepts* a relevant `unknown` result: it is the only field a v1.1
   claim has to disclose one, and without it `material_limitation_omitted` would be permanently
   unresolvable for exactly the claims this ADR introduces. Naming such a result states that it is
   limiting, not that it is a partial or a failure, so completeness never *requires* an `unknown`;
   only relevant typed partial and failed results must be present.

   Relevance and authorability are the same predicate. A result whose action record is missing or
   tombstoned is relevant task-wide, so it must be disclosed and must therefore also be linkable;
   additionally requiring a readable action to author the link would make relevance demand a
   reference the same replay rejects, leaving no recordable completion claim at all.

   **Observed-failure supersession (#909, 2026-09-30).** Relevance above is necessary but no longer
   sufficient for a *hook-observed* failed or partial result. One shared kernel predicate
   (`kernel/observed_failures.py`) retires such a result from the required set when, before the
   claim, a later hook-observed run of the same command identity succeeded, or ran again with a
   limiting failure or partial outcome. An unknown outcome does not certify repair, and a later
   edit never retires the failed verification. The command identity is the installation-keyed
   `hmac-sha256:` commitment the hook computes and materialization stores as
   `omitted:<commitment>`; rows without one (`omitted:structural`, every pre-#909 ledger) remain
   live until a completion claim names them in `limitation_refs`. Only service-stamped
   observations take part on either
   side: a cooperative failure keeps the exact duty above, and a cooperative success or edit
   never retires an observed failure. A retired result
   stays authorable in `limitation_refs`, and the receipt counts it once as history.
   `limitation_refs_complete`, `failed_work_omitted`, research-evidence limitations, and observation
   advice all read this one predicate, so admission and the packs cannot disagree. Loosening the
   required set cannot reject any history that the stricter rule accepted.

   **Segment certification and retire-on-pass (#1104, owner decision D2, 2026-10-18).** A later
   *success* also certifies an exact segment commitment (ADR-045) when its composition is
   `single` or `and_chain` and that segment ran exactly as listed: every simple command of a
   passing `cd /app && pytest -q > log 2>&1` exited zero, so it supersedes a failed `pytest -q`.
   The rule makes a segment worth exactly what the same simple command run as its own call is
   worth, and no more. A segment listed only after dropping a leading assignment, `env`, `time`,
   `nohup`, `exec`, a shell keyword or an input redirection (`< f`, `<<EOF`, `<<< s`, `<> f`)
   ran a different command, which can drop the very condition that failed
   (`PYTEST_ADDOPTS=--collect-only pytest -q` runs no test), so it certifies nothing. An output
   redirection does not change what the program runs and keeps the segment certifiable. A `cd`
   (or any other) segment before it counts like a separate earlier call: command identity has
   never included the working directory or the effects of earlier calls, so a passing
   `cd /elsewhere && pytest -q` supersedes a failed `pytest -q` exactly as `cd /elsewhere`
   followed by a separate `pytest -q` always has. The hook records which segments ran as listed
   by committing a marker beside each (`domain/command_segments.segment_certification_commitment`,
   SHA-256 over a domain and the segment's keyed commitment), inside the existing
   `command_segment_commitments` list; a list without markers (every ledger written before this
   amendment) certifies nothing. A `masked` composition (`;`, `||`, `|`, `&`, a shell
   here-document) certifies no segment, and a failed chain is superseded only by its own whole
   identity. Canonical, prefix, flag and marker commitments are domain-separated and never equal
   a command identity. A
   failure never uses its segments. Edits still never retire anything (#909). For this shared
   supersession rule (the claim-revision invariant, the packs, the receipt's observed-failure
   history sentence, "1 was later passed by the same command", and the advice rule) a passing run of a different command, including the planned verification
   after an edit, supersedes nothing: it proves the planned check passes, not that the command
   that failed now works. The observed failed-command *finding* below is the one exception the
   owner decided (2026-10-18).

   The observation coordinator materializes the advice copy of a live failure as a
   `finding_recorded` (rule `failed_command_unresolved`, kind `failed_work_omitted`). An
   **observed failed-command finding** is an observation-authored, deterministic, work-integrity
   `failed_work_omitted` finding that names no claim (`clm_`) in `subject_refs` (the pack's own
   finding always names its claim, so the two never mix). Its **failed run** is the one
   service-stamped hook-observed failed or partial result the finding names, directly or through
   the call it names (its action event or any of its result events: on Codex that is the hook's
   `unknown` result, and the failure is the session stream's outcome correction for the same
   action). No unique failed run means no rerun can retire it. The replay fold
   (`kernel/finding_retirement.py`, called by the reducer in ledger order) records on the
   finding record the earliest later hook-observed **success of another call** whose command
   identity is the failed run's or certifies it as a segment (`retired_by_event_id`,
   `retired_frontier`). "Later" is judged by the passing *call*, not only by where its outcome
   lands: its action must be recorded after the failed call's first hook-observed result (when
   FinishUP first knew that call had finished), as well as its passing result after the failed
   result. A call that began before the failure was known (a parallel call, a Claude Code
   `PreToolUse` recorded before the other call's failure, a Codex hook recorded before the
   failed call's) is no repair of it, however late its own exit (a lagging stream correction)
   arrives; on Codex the failed call's hook result is that first point, so both exits may lag. It reads the outcome the ledger finally records for each call: a
   hook-stated exit, a Codex stream correction joined to the call, or a stream-first copy that
   committed with its own outcome. **An `unknown` outcome never retires anything**: a Codex call
   whose exit never reached FinishUP stays open. `finding_is_resolved` reads the fact, so status,
   check, receipts, the Stop gate and lineage show `verified_resolved` with closure basis
   `retired_by_passing_run` naming the passing result's event. Ledgers written by older builds
   are retired at replay from facts they already hold; rows without a command identity never
   are. Redacting the passing run, the failed run, its action or the finding drops the fact
   (unreadable proof is no proof); nothing is deleted.

   **A passing planned verification also retires it (owner decisions 2026-10-18, recorded on #1104,
   the second in comment 6252094173; final).** "A later pass" has the broad reading: every open
   observed failed-command finding whose failed run precedes, in ledger order, a hook-observed
   success of another call that passed a **planned verification** is retired too, whatever command
   failed. Two conditions bound it. First, **the passing run is a verifier**: the runner class
   FinishUP's existing classification derived for it at the host boundary
   (`observation_selection.command_runner_class`, recorded in the observed action's description and
   read by `observed_failures.observed_action_is_verifier`) is `test`, `build`, `lint` or
   `typecheck`. A planned `true`, `ls`, `echo ok` or `git status` (`exploration` or `vcs`) passing
   retires nothing, so a plan cannot name a no-op and clear failures by running it. Second, **the
   obligation was effective when the run passed**, in ledger order. The pass point is the passing
   call's first hook-observed result (as above, when FinishUP first knew the call had finished: its
   `PostToolUse` on Claude Code and Cursor, the outcome-less hook result on Codex, whose exit lands
   later as a stream correction), and the plan is the one effective just before it
   (`task_facts.planned_verification_commands(..., effective_at=pass point)`): the plan scope is
   read from the plan events recorded before that point, and the obligation must have been first
   published (`introduced_frontier`) before it. An obligation published, or introduced by a plan
   version or revision, after the pass does not count, including one published between a Codex
   call's hook result and its joined exit; a plan published while the call ran and before it
   finished does. A later plan version or revision that supersedes the obligation or no longer names
   it does not undo a retirement that was valid when made. The obligation's status and waiver are
   read as the ledger records them now, the existing replay behavior kept consistently: a later
   `acknowledged_not_done` republication or a waiver is the agent's own statement that this
   obligation is not being done, so it un-retires what only that match retired (a reverse state the
   reducer re-derives after every plan, obligation or unreadable plan event), and a republication
   that reopens it retires again; an unreadable plan event makes the scope unreadable, so its passes
   retire nothing. A planned verification is thus a requested item of kind `command` (ADR-033) of an
   obligation effective at the pass that the agent has not acknowledged as not done (an obligation
   with a recorded blocker still counts, since a blocker decision is not a plan event and its
   command passing is still the planned verification passing), matched by the recorded rule only
   (`task_facts.planned_verification_passed` over `planned_match` kind `exact`): the
   installation-keyed whole-command commitment, or the planned command as a segment of the run, with
   the outcome that rule establishes for the planned command, which is a success only for a passing
   `single` run or `&&` chain. For retirement the segment must be one the success certifies, under
   the same bare-segment rule as above: a passing `PYTEST_ADDOPTS=--collect-only pytest -q`, `FOO=1
   pytest -q`, `exec pytest -q` or `pytest -q < answers.txt` ran a different command and passes no
   planned `pytest -q` (the ADR-033 task facts keep their looser reading). A canonical, prefix or
   flag match, an agent link and a masked composition (`;`, `|`, `||`, `&`) never count. A planned
   command whose own composition is masked (`pytest -q | tail -5`, `! pytest -q`, `pytest -q ||
   true`, `pytest -q &`, `pytest -q; true`) never counts either, even run exactly as planned: its
   recorded exit is not the planned work's, so its success is not a known one. Neither does an
   `unknown` outcome: on Codex 0.159, whose `PostToolUse` states no exit, only the session stream's
   correction joined by call id (or a stream-first copy with its own outcome) makes the planned run
   a known success. The owner accepted the trade-off that a passing planned verification also clears
   an unrelated earlier failure (a failed install that was never rerun), bounded by the two
   conditions above. The match needs the installation key the service registers (ADR-033); a process
   without it treats no run as a planned verification, which only ever retires less. This makes the
   projection fold, and so the stored projection snapshot and `projection_digest`, depend on the key
   as well as on the ledger: the service registers it before its startup bundle upgrade can replay
   or rebuild any task projection, and every process that stores or compares a task projection (only
   the service writes task ledgers) must hold it; a replay without the key derives fewer
   retirements, never more. The fact is `retired_by_planned_verification` beside
   `retired_by_event_id`, and every surface names the kind: closure basis
   `retired_by_planned_verification` (status, check, lineage), the receipt's history sentence
   ("retired by a later passing run of a planned verification, not of the command that failed") and
   its per-finding resolution line. When one run is both the same command and a planned verification
   it is recorded as the same command; the earliest qualifying run decides. The claim-level duty is
   unchanged: a completion claim must still name a failure in `limitation_refs` unless the same
   command passed later (the shared rule above). A failure retired only by a planned verification
   therefore still has to be named there, and the agent-facing text says so (the finding's
   resolution explanation, the shipped guidance and the product docs), so a retired finding never
   reads as a failure the claim may leave out.

   The advice snapshot's `failed_command_unresolved` item follows the shared rule, so after a
   retirement by a planned verification its rule still sees no pass of the failed command. The
   status advice view drops an item whose finding the ledger already retired
   (`finding_resolution.retired_failed_command_finding_ids`), so the advice and findings views
   agree, and the item's detail says only that the command has no later pass of itself. Known
   gap, follow-up owned by #1104: the hook-side advice (the top item a hook prints, read from the
   stored snapshot without the ledger) can still list that item until the observation evidence
   changes; the Stop gate, status, check and the receipt read the ledger and do not block on it.

   No check resolves such a finding: no local rule re-reads the advice condition, so a check's
   silence proves nothing, and `resolution_blockers` names `observed_failure_not_rerun` for it
   (a FinishUP limit, so `self_verified` remains open to an agent that verified the repair
   another way). `acknowledged` on it records that the failure is expected or stays: basis
   `failed_run_disclosed`, settled and disclosed, never clean (conclusion at best
   `insufficient_coverage`), no reason required by `respond` (the guidance asks for one).
   `acknowledged_not_done` settles it as bookkeeping (`acknowledged_not_done_bookkeeping`). A
   later pass still retires it after either answer. The requirement-level duty stays with the
   work-integrity pack: a completion claim must still name a live observed failure in
   `limitation_refs`, or the pack raises its own claim-level `failed_work_omitted`.

   Two failures carry no failed-work duty, read by one predicate
   (`observed_failures.observed_failure_exempt`) in every failure-accounting reader and by the
   advice rule: a proven read or exploration (`runner_class == "exploration"`, widened by #1104 to
   chains of reads, banners and `cd`, and to FinishUP's own read verbs and proven launcher), and a
   command that stopped the background job it launched itself (a closed shape derived from the
   command text, `domain/process_control.py`, never for a verifier) whose recorded exit is exactly
   `128 + signal`. The exit is read from the result being judged, so a Codex stream correction
   decides it like a hook-stated exit; an unknown exit never exempts; Claude Code's
   `PostToolUseFailure` states no exit, so the stop exemption never applies there. The shape is
   not a structural key: the local observation store and outbox are shared on disk by every build
   running during an upgrade, and an older reader refuses a workspace document holding an envelope
   key it does not know. It travels as a marker inside the existing `command_segment_commitments`
   list (`process_control_commitment`, SHA-256 over a domain, the token and the whole-command
   keyed commitment), which older builds accept as an inert commitment, and the ledger readers
   recover it from the action's `command` field. Every producer of command commitments adds it,
   the Codex session stream included, so a stream-first call is judged like a hook-first one.
   Known limit: the exit alone cannot tell the command's own `kill` from a host that terminates
   the whole command with the same signal (a timeout that sends `SIGTERM` to a hung probe). No
   host in scope states a timeout or interrupt flag for a shell call today; when one does, a set
   flag must refuse the exemption.

4. **Replay owns the revision invariants.** Missing, unreadable, already-superseded, wrong-kind, or
   disjoint targets; irrelevant or success limitations; non-success support; and incomplete
   limitation sets are rejected by the same pure replay path used by dry-run, memory append, and
   SQLite append. Dry-run therefore proves that the proposed append is structurally effective
   without writing it.

5. **Current evaluation is shared.** Local policies, AI-powered review claim selection, and receipt
   current-claim selection consume one replay-derived effective-claim set. Superseded claims stay
   available to history and historical finding projection. A qualifying recheck can mark findings
   against superseded claims resolved; it does not delete them.

   The edge that set produces is durable, not payload-derived. Applying a replacement writes
   `superseded_by_claim_id` onto each target's `ClaimProjectionRecord`, and every later rewrite of
   that row — an unreadable payload, a redaction tombstone, a re-published v1.0 claim id — carries
   it forward. Reading the edge from the replacement's live `supersedes_claim_refs` instead would
   let a `redaction_recorded` against the correcting event resurrect its target as a second current
   claim and free it for another correction. The snapshot key is emitted only when set, so
   snapshots of tasks without a correction stay byte-identical.

6. **Existing neighboring fields do not change meaning.** `disputes_refs` continues to record an
   explicit unresolved contradiction. `decision_recorded.supersedes_event_id` continues to
   supersede decision history only. Neither is inferred as claim replacement.

7. **Authoring uses existing status contracts.** Candidate finding detail names the accepted v1.1
   field and bounded claim/result ids. `status(history)` supplies event identity and schema version;
   `status(results)` resolves each result id to source event, payload availability, outcome, action,
   and evidence ids. A new status wire version is unnecessary.

8. **The required limitation ids are shown before the claim (amendment, F3; owner-approved).**
   In tb4n1, 34 of 35 `claim_revision_mismatch` rejections were `limitation_refs_complete`: the
   first completion claim missed a live failed or partial result, and only the retry, built from
   the rejection's ids, succeeded. The required-set rule is now one pure kernel helper
   (`kernel/claim_limitations.py`) that the replay reducer enforces unchanged. Status
   `closure_readiness` on the unreleased status-result 1.4.0 carries the optional pair
   `limitation_refs_required` (sorted result ids, at most 64) and `limitation_refs_required_count`.
   This is the set a whole-task completion claim recorded now must name. A scoped claim needs
   only those whose action names a claimed obligation, or names none. The MCP status summary,
   the CLI/terminal status and the Stop gate name these ids (ids only, bounded). The gate drops
   its sentence before the blocker re-check to stay within 2,000 characters.

## Consequences

A clean prior claim can be replaced after scope grows and produces an honest partial result. The
new completion claim retains that result as a limitation without treating it as support, while an
unrelated obligation's later completion claim does not inherit the limitation. Existing v1 claims
remain readable and keep their historical disclosure behavior.

The stricter v1.1 preflight can reject a proposed correction that an older v1 append would have
accepted and later challenged. This is intentional: the rejection occurs before irreversible
append and gives the author an exact field/invariant plus status views needed to repair it.

Narrowing has a further consequence worth stating outright: a correction that drops obligations
from `obligation_refs` also sheds the claim-scoped local findings that only the wider scope
produced — `completion_with_open_obligations` and `failed_work_omitted` for the dropped span stop
being raised against the effective claim, because no current completion claim covers that span any
more. That is the narrowing decision doing its job, not an erasure: the superseded claim and its
historical findings remain in projection history, and the receipt still lists every dropped
obligation as OPEN through `plan_scope.effective_obligation_refs`, so a reader sees uncovered scope
rather than silence. Read a scope-narrowing correction as a request to account for the dropped span
somewhere else, never as evidence that it was completed.

## Alternatives considered

**Mutate or delete the old claim.** Rejected because ledger history and receipt provenance are
append-only.

**Reinterpret `disputes_refs` as supersession.** Rejected because it would silently change frozen
v1 semantics and erase the distinction between contradiction and correction.

**Make every failure task-global forever.** Rejected because future and disjoint work cannot have
been disclosed by an earlier claim, and the resulting permanent finding growth is not actionable.

**Add a second status results surface.** Rejected because the existing bounded `results` and
`history` views already expose the structural facts needed to author a correction.
