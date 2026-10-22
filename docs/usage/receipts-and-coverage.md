# Receipts and coverage

A receipt says what was checked and how well. It is deliberately narrow, and reading it correctly
matters more than any other single thing in FinishUP.

The agent-facing rules are [`guidance/coverage-and-receipts.md`](../../guidance/coverage-and-receipts.md),
which ships with the product. This page is the human's version.

## Coverage is a vector, not a score

Six independent dimensions. Strength in one never compensates for weakness in another, and they
never collapse into a number:

| Dimension | Asks |
|---|---|
| participation | How did the work reach the ledger? (`cooperative_mcp`, `local_cli`, `codex_jsonl_import`, …) |
| authorship | How well is the author established? (`self_asserted`, `harness_observed`, …) |
| artifact observation | Did anything observe the artifacts, or only the published claims? (`published_only`, `hook_observed`, …) |
| content visibility | How much content was actually looked at? (`none`, `digest_only`, `targeted_excerpt`, …) |
| provenance | Local check, AI-powered review provider, imported, or participant-asserted? |
| freshness | Is the evidence bound to the current state? (current, stale, unknown, redacted) |

**The weakest material dependency bounds the conclusion.** Use the exact enum values the protocol
returns.

## Getting one

```text
finishup receipt --request '{"request_id":"req_...","format":"markdown", ...}' --json
```

Formats are `json`, `markdown`, and `text`. All three project under the default agent-context
policy. `json` carries the structured receipt in `document` with `human_text` null. `markdown`
and `text` keep `document` null by format and project the canonical sections (summary, findings,
limitations, versions, section items, and coverage notes) in `human_text`. If that projection
exceeds the wire bound, the longest sections are shortened, every section keeps its heading, and
`human_text` ends with a marker that names the shortened sections; the `json` format holds every
section in full. A receipt for a task with more than 100 findings, obligations or references (or
more than 64 gaps) lists the rows that matter most, unresolved findings first, and its summary
says how many of each were left out. Under a deliberately
stricter owner policy, digest-bound
`json` can fail closed with `PRIVACY_AUTHORITY_REQUIRED` (`receipt_json_projection_blocked`) —
re-request `markdown` or `text`, or widen agent-context policy from a local terminal. If a
human format cannot project those sections, the result names the omission; it does not return
an accepted receipt with an empty body and no pointer.

**The durable receipt is recorded even when projection is blocked.** A projection failure is a
disclosure decision, not a lost receipt.

## Reading one

Read these together, never in isolation: the frontier, the verdict, the coverage vector, the finding
disposition, evidence provenance, freshness, suppressed counts, and limitations. Derived Markdown is
a human view of the same structured record.

A limitation an earlier check reported and a later check no longer reports stays on the receipt as
history: it appears under "Cleared earlier (historical)" with the frontier at which a check first
stopped reporting it. A historical limitation is not a current limitation: it is not counted among
the receipt's limitations and does not weaken the conclusion. In the JSON receipt its gap row
carries `"status": "historical"` and `cleared_at_frontier`; a gap row without a status is current.

Honest:

> FinishUP found no local-check issue in the cooperatively published record at the stated frontier;
> artifact observation remained published-only.

Not honest:

> FinishUP proved the implementation is complete and correct.

## The trap: a clean local-only check

A clean `deterministic_only` check is **not** an implementation review. A clean result means “no
issue detected within local coverage”, and a clean receipt says the same:
`no_unresolved_deterministic_findings`. Where AI-powered review is required, a `deterministic_only`
check records `semantic_review_not_requested` and that limitation keeps the receipt at
`insufficient_coverage`. Where it is not required (it is optional or off, or the owner connected
this host for local checks only), the check records `semantic_route_required: false` and no
review gap: it ran the local checks it was asked for, so the receipt lists no missing review. If the only things recorded after your last check are your answers to
that check's findings, the receipt notes that the check is current as of an earlier point but that
note alone does not keep it from a clean conclusion. The receipt leads with its scope,
review status and material limitations, followed by the finding count and frozen check totals.

**A task in local mode.** Where your setting starts tasks local (the recommended setup answer),
a task that has not turned on AI-powered review checks with local checks only on a route that did
not require review, so its receipt reaches a clean local conclusion and says that AI-powered review
was not requested. The check, `status` and the receipt say which mode the task was in: whenever
the applicable check recorded its mode, the receipt's limitations section ends with a sentence on
how that check ran (for a local task, "ran local checks only (FinishUP); AI-powered review was not
requested for this task"). When the task turned AI-powered review on or off, a sentence before it
names each switch: its ledger sequence, its event id, the identity the ledger recorded for it (with
how that identity was established) and the authority it declared. A check that recorded no mode
(an installation that has not chosen a setting, in a task that never switched) adds nothing.
Under "every task" an agent's switch to local is listed but changes nothing, and a task that used
AI-powered review still gets its closing review before the receipt, even after going back to local
checks.

Omit `mode` to run in the task's review mode (the configured default where the task's mode was not
recorded). Use `semantic_if_configured` only when
review is known to be optional. If the user, policy, or acceptance requires AI-powered review,
select `semantic_required` for the final check and subsequent final rechecks. Reserve
`deterministic_only` for explicitly local or structural checks, or a user-authorized deliberate
no-egress choice; disclose the limitation and keep any required review unmet.

When you fall back to `deterministic_only` because an AI-powered review attempt was blocked or
unavailable, that earlier gap is carried forward to the local-only check, so the receipt records
that the environment refused rather than that the review was never asked for.

A check you run before your first edit (nothing changed yet, and not the closing review) never
calls the reviewer, whatever its mode: it runs the local plan checks, sends nothing, and records
`semantic_review_deferred_before_first_edit`. The check says: AI-powered review is on; it starts
after your first edit. Where AI-powered review is optional for the check,
that is a disclosure and does not lower the receipt's conclusion, just as a local-only check would
not; where review is required, the receipt stays at `insufficient_coverage` until a review runs.
The next check after you start changing the work reviews as configured, and the closing review is
never deferred. Where review is required, the closure checklist lists `closing_review_required`
after a deferred check until you run `check` with `final_review: true`, so work that never needs an
edit is still reviewed before it closes; where review is optional, a deferred check asks for
nothing more than a local-only check would.

## Prose the reviewer will not see whole

Publish accepts up to 8192 bytes of prose per field. One AI-powered review case item carries at most
4096 bytes. Text between those bounds records cleanly and then reaches the reviewer shortened — or,
for a whole event payload, replaced by a marker carrying only its digest. Coverage names this with
`semantic_case_content_over_item_limit`. Keep prose you expect a reviewer to read under 4096 bytes.

A local finding can name up to 64 subjects, but one review case item links at most 16. A wider
finding — typically `ledger_stale_or_incomplete` after many unresolved coverage gaps — stays in your
check result and receipt in full. The reviewer receives the other findings; this one is listed as
omitted rather than trimmed, and coverage names it with `semantic_case_finding_refs_over_limit`.
Resolving the underlying gaps narrows the finding and lets the next review carry it.

## When the reviewer needs more

A review that could not assess the work says what it needs instead of guessing. The check result
leads with `agent_next`: the one next step, and for each item the reviewer asked for, which record
it means and exactly how to supply it. It comes first in the result so that an agent whose host
shows only the start of a long result still reads it; `status view=operation` for the same request
id repeats it if the result was lost.

Supply each item once, then check again. What counts is new material tied to the named record: a
result of the same run or of the same exact command, evidence that names the record or its file
path, a correction of a named claim, or a response when the named record is a finding. Re-running
the same command counts for its output when FinishUP observed the run and captured the output, but
only once the reviewer is sent that output; your privacy setting may never send it. So publish the
run's result with its output as the summary even after a re-run, as `agent_next` says. A re-run
never supplies the exact command text: publish the action with that text. A response to anything
other than a finding, or a description of the output, does not count. If an item is a FinishUP
limit rather than missing work, verify it yourself and state the limit in the receipt.

## Completion scope is declared, not inferred

FinishUP reads completion scope only from the effective plan chain. It never invents obligations from
the prompt, source tree, workspace, or completion prose.

When a completion claim exists and the effective plan has zero declared obligations, the check is
coverage-incomplete in both cases:

- no typed reason: `completion_scope_undeclared` — the receipt says scope was never declared;
- a typed reason: `completion_scope_declared_none` — the receipt says the plan declared none and
  names only the closed reason value.

The typed declaration clears the status readiness blocker; it does not buy a clean verdict. A
positive declared count whose obligations are all resolved is the distinct resolved-scope state.
Redacted or unreadable scope remains unknown and never becomes zero.

When a plan changes after an effective completion claim, the claim and the current plan are still
compared independently:

- `completion_claim_outside_plan` means the claim names an obligation the current plan no longer
  declares;
- `completion_plan_not_claimed` means the current plan declares an obligation the claim omits.

An explicit waiver removes an obligation from the current plan; it does not supersede or rewrite a
historical completion claim. The relation remains a coverage limitation until the claim is replaced
or the plan is deliberately restated to match the intended scope.

Two findings stop a completion from reading clean until the agent answers them:

- `task_requirement_unmet` — a task statement is recorded and the plan declares obligations, but
  none of them cites the statement, or the agent claims completion with no plan or an explicitly
  empty one. The agent decomposes your request into obligations that cite it, or, when your request
  needs no material work and nothing was edited, records that decision with a reason. FinishUP checks
  only that link, not that every requirement was captured. Repeating your unchanged request when a
  session resumes does not count as a new request.
- `claim_without_admissible_evidence` (observed-verification form) — the hooks saw the agent edit
  or run checks, but the completion claim cites no observed verification run, or cites one whose
  recorded input changed after it ran. A change FinishUP cannot relate to the run's inputs asks a
  non-blocking rerun question instead, and so does a known input change under AI-powered review.
  The agent reruns its verification and cites that observed run.

Running the check again without changing the record returns the same finding. Neither finding
means the work is wrong, and clearing them does not prove it right.

## Candidate findings are not a check

`status` with `view=candidate_findings` is an advisory read. No verdict, no IDs, no receipt, and the
read records nothing. An empty list means no rule fired at that frontier — it is not
`no_issue_detected`.

Permitted after a candidate read: "I saw an unresolved attempt and went back to it."
Forbidden after a candidate read: "I checked and found nothing."

## Things that do not strengthen coverage

- Installing a harness integration.
- Firing a trigger-only hook. A proven trigger may prompt a bounded `status` re-grounding; it
  observes nothing and changes no coverage.
- Storing imported evidence. Imported evidence never gains cooperative authorship because FinishUP
  stored it.
- A digest. It records identity, not content inspection. A digest your agent publishes stays
  caller-asserted: it raises no finding, and the receipt's limitations say once, with a count,
  how many cited evidence items carry caller-asserted digests FinishUP did not verify, keeping
  digest-only items (the bytes were not retained) apart from withheld items (your agent recorded
  the bytes as withheld). No response, recheck, or further publication changes that.
- Constructing TOML, a path, or metadata. That is not proof of wire dispatch or AI-powered review.

Only a capability-proven, consented observation arm with real observation evidence earns
`hook_observed`. Absent, empty, paused, or degraded observation status does not.

## Findings and responses

Choose one recorded response per finding: accept and act, provide additional evidence, revise the
claim, dispute with evidence, or state an unresolved limitation. Then recheck after material change.

A response never deletes the original challenge. That is the point — the record keeps the
disagreement visible.

No disposition resolves a finding. Agents can record `acknowledged`, `acknowledged_not_done`,
`self_verified`, `provenance_disputed`, or `rejected`; `waived` is reserved for an authorized local-CLI human. Each records what was decided
and what evidence was attached; none clears the finding for receipt purposes. A readable response
does clear the status surface's `unanswered_finding_count`, while the actionable finding remains in
`receipt_blocking_finding_count` (except `self_verified`, below, and `acknowledged` on a command
FinishUP saw fail, which is disclosed instead).

Observation-authored, non-actionable findings (such as "Observation coverage is incomplete or
stale") are disclosed coverage limitations: they never count in `unanswered_finding_count` and need
no response, and they stay listed in status and on the receipt. Acknowledging one is optional, and
it never resolves the finding.

What does resolve a finding is proof: a later check that tested the repaired record and found the
same issue absent. That check must cover the finding — the whole case, or a scope that names the
finding's subject — with the owning policy pack run to completion, nothing suppressed, and its
proof inputs readable. Case-wide host-observation limitations (`captured_object_unavailable`,
`content_unselected`, `host_outcome_unavailable`, and `unpaired_event`) do not veto a local
finding's otherwise clean structured-ledger proof; they remain receipt coverage limitations. This
exception requires the finding's own recorded coverage to have been readable; host-observation
gaps on a hook-derived finding remain tolerated, and the exception never applies to an AI-powered
finding. Redacted or unavailable event payloads, redacted objects, missing references,
unknown events, weak original finding coverage, suppression, stale state, scoped-away work, or a
failed pack still change nothing, and a check that reports the same issue again keeps it current.

For an AI-powered finding, the recheck's reviewer also rules on each earlier finding it was shown.
A `fixed` ruling resolves that finding on that check even when the review could not assess the rest
of the case, but only if it cites evidence or a result recorded after the finding and every other
rule above still holds. A `fixed` that cites nothing newer counts only as unassessable, any other
ruling except `withdrawn`, which leaves the ordinary rules, keeps the finding current and names
why, and a ruling is never inferred from silence. An earlier finding the review was not shown (the
section was full or trimmed), or whose ruling was dropped as malformed, stays current on that check.

In a long session the AI-powered review sees a bounded part of the record, and coverage says so
with `semantic_reference_scope_reduced`. That limitation stays on every check, status view, and
receipt. It does not stop a repaired local finding from resolving, because the local check still
reads the whole record. An AI-powered finding raised under the same bounded review can resolve
once you repair it and a later AI-powered review completes without returning it. That review
must have actually sent the reviewer the finding itself (what was found, what it named and your
answer), the repair evidence your response cites, and the change you made. Each item the finding
named must also be accounted for: shown again, replaced by a corrected claim the review was shown,
or an early record that long work pushed out of the review's recent-history window. Correcting the
claim a reviewer criticised therefore does not keep the finding open. A mention, a link, or a note
that the item was left out or withheld does not count; a record shown through the event that
recorded it, or any part of a multi-part captured excerpt, does. Captured tool output counts only
when its own excerpt was shown. Cite your repair's evidence rather than only a result:
a result without evidence stays in a bounded review only while it is recent, while cited evidence
is selected first. If it did not send them, the finding stays current and names
`finding_material_outside_reduced_review_scope`. If the check also shows
`semantic_included_refs_not_recorded`, FinishUP could not record what that review sent. Make sure the
repair evidence is recorded and cited in your response, then run one new check. If it shows the
same code again, stop rechecking, keep the finding open and disclose it. While a finding stays
open, its explanation names the latest check that could have resolved it; a later check scoped to
other work, or one without a completed AI-powered review, cannot. A review whose scope became
bounded only after the finding was raised, or a clipped payload (`truncated_payload`), still leaves
the finding current.

A resolved finding is not erased. Status still lists it (`resolved: true`, shown when
`include_resolved` is requested), the receipt still carries it as history, and the receipt wording
says how many earlier findings were resolved by a later qualifying check, apart from any findings
that are still current and from any coverage limitations. Its own recorded coverage no longer lowers
the receipt's coverage; current findings, the current record, and the applicable check still do. One
exception is fixed by the released status wire: a finding whose latest response is
`provenance_disputed` stays current even after such a check.

Findings are a to-do list that ends. Each one is `open` or in a final state: `verified_resolved`
(proved absent as above), `acknowledged_not_done` (the agent said, with a required reason, that it
will not do it; it stays reopenable, and a later check that tests the work and finds the issue absent
resolves it), or `rejection_accepted` (the agent rejected an AI-powered finding with a reason and
a later review withdrew it; a withdrawal wins over the same review not raising it again, so such an
item never reads as proved absent). A final item never changes again and is not reviewed again; a
later `respond` to it records nothing and answers `finding_terminal`. New evidence about the same
problem comes back as a new finding. `acknowledged_not_done` is an honest "not done": it keeps the
receipt from reading clean and appears in its own "Acknowledged, not done" section. A reviewer's
request that you state a limit you cannot remove (a hidden evaluator, a withheld reference) is not
"not done" work: once you disclose it with one reasoned answer it is a settled limitation, and a
repeat of the same concern is recorded on it rather than raised again.

`self_verified` is the final state for a finding you repaired that FinishUP cannot prove repaired
because of its own limits (a *FinishUP limit*: content it could not capture or had to redact, lost
observations, a review packet that could not show the repair). You verify the repair yourself,
record that evidence, and respond `self_verified` with how you verified it and the evidence ids.
FinishUP accepts it only after a later check of the finding and only when that check no longer sees
the issue itself (`finding_not_rechecked` and `finding_not_proof_limited` otherwise; the
`finding_not_proof_limited` refusal lists the recorded reasons that disqualified it in
`blocking_reasons` and says what to do next). The item stops
being your work and never counts as receipt-blocking, but it is never resolved: closure readiness
lists `finding_self_verified` as a standing limitation, the receipt names it in its own
"Self-verified by the agent; FinishUP could not prove the repair" section, and the receipt's
conclusion is at best `insufficient_coverage`. A FinishUP limit is never a `finishup-blocker`.

Findings are advisory. When you disagree, respond `rejected` with your reasoning. If the review
then repeats the finding without citing anything recorded after your answer, FinishUP records the
final state `disputed_after_rebuttal`: the reviewer and you disagree, it is not your work, nothing
asks you about it again, and `respond` records nothing more on it. It is never clean either:
closure readiness lists `finding_disputed_after_rebuttal` as a standing limitation, the receipt
names it in a "Disputed after rebuttal" section, and the conclusion is at best
`insufficient_coverage`. A review that brings something new is still a finding you answer. Never
empty, shorten or delete a working deliverable because a finding is open; deliver it and disclose
its limits.

Two more things decide what the receipt will say, and status tells you before you ask for it:

- **Findings you rejected with a reason.** A rejection of an AI-powered finding is not settled by
  your word: the next check lets the reviewer rule. Until then it counts as awaiting a ruling
  (status says `finding_rejection_awaiting_ruling`, and the receipt reads
  `unresolved_findings_remain`); run `check` once, do not acknowledge it or repair what you
  rejected. If no review can rule (the route did not request one), the rejection is disclosed
  instead.
- **A limit a reviewer asks you to state.** When a challenge asks you to say plainly that something
  cannot be verified (a hidden evaluator, a private trace), that is not repair work, and your answer
  decides what it means. If the requirement may be met but cannot be verified here, answer once with
  `acknowledged` and say what cannot be verified. It is then final, the receipt lists it under
  "Verification limits", and the conclusion is at best `insufficient_coverage`; it never reads clean
  and it never reads `unresolved_findings_remain` for that item. A decision line
  `finishup-verification-limit:<obligation id>` covering the obligation the challenge concerns does the
  same. If you know the requirement is not met, answer `acknowledged_not_done` instead: the receipt
  then lists it with the requirements you acknowledged as not done and reads
  `unresolved_findings_remain`, exactly like any other requirement left undone. While the request is
  unanswered, the check's next step is `disclose_limitations` when it is all that is left.
- **A criterion you set yourself.** When the only work a finding cites is your own probe beyond the
  task's stated scope (your own stress sizes or configurations, while the task's own sample or
  verifier passes), the finding is `agent_criterion_unmet`, not a task requirement. You may fix it,
  or narrow the criterion by answering `acknowledged` with the reason: the receipt then lists it as
  a disclosed limitation and reads at best `insufficient_coverage`; it never blocks. Only your answer
  narrows it; a `finishup-verification-limit` decision does not. While it is open, the check's next
  step is `work_open_findings`, not `disclose_limitations`.
- **A command FinishUP saw fail.** When FinishUP observes a command fail, it records a finding
  ("Unresolved failed command observed") right away. Repeated observations of that same failed
  call keep its finding ID and original reason, so you answer it once. A task where an earlier
  FinishUP version already recorded the same failure twice keeps both copies: answering the ID
  the hook and the receipt name clears the receipt's blocker, the older copy can stay in the
  unanswered list, and a later passing run of the same command retires both. The receipt names
  the original triggering events beside its current resolution; a separate failed invocation is
  a separate concern. Rerun the same command after the fix, alone or
  inside a passing `&&` chain such as `cd /app && pytest -q`, exactly as written (`FOO=1 pytest -q`,
  or `pytest -q` behind `env`, `nohup` or `time`, is a different command; a chain whose earlier
  part can end the shell or runs text FinishUP cannot read, such as `exec CMD`, `exit`, `eval`, or
  `source`/`.` in `source .venv/bin/activate && pytest -q`, retires nothing and names no outcome
  for a planned command): when that run passes, the finding is
  retired by itself (`verified_resolved`, basis `retired_by_passing_run`) and stays in the history.
  A later passing run of a verification command your plan asks for retires it as well, together
  with every other earlier failed-command finding, even for a command you never reran (basis
  `retired_by_planned_verification`; the receipt says the planned verification passed, not the
  command that failed). It counts only when FinishUP classes the run as a test, build, lint or
  typecheck (a planned `true`, `ls` or `echo ok` retires nothing) and your plan already asked for
  it when the run passed (a plan you publish after the pass retires nothing; run it again). The
  planned command counts only run as written (no added `FOO=1`, `env` or `exec`, no input
  redirection), with an exit that is its own (a planned `pytest -q | tail -5` or
  `pytest -q || true` never counts), and only when it began after the failure. If you later waive
  it or acknowledge it as not done, what only it retired opens again; a later plan that replaces
  it does not reopen anything. An edit does not retire it, a passing run of an unplanned
  different command does not, a run whose outcome FinishUP never learned does not, and a check
  cannot prove it absent. If the failure is expected or
  will stay, answer `acknowledged` with the reason: the receipt lists it as a disclosed failed
  command and reads at best `insufficient_coverage`, and a later passing run still retires it. A
  failed read or inspection (including a chain of reads with banners and `cd`), a failed FinishUP
  status read, and a command that stopped the background job it started itself with exactly the
  exit that stop produces do not raise one at all. Your completion claim must still name in
  `limitation_refs` any failure that stays, and any failure only a planned verification retired:
  the failed command itself never passed.

While the work is in progress, the reviewer judges incomplete work only (something marked done that
is not, verification you planned and did not run, a missing or emptied output, a claim the record
does not show, an early stop). A correctness concern it raises then is an advisory note in the
review summary, not a finding. The closing review judges the work against the task in full. A
reviewer ruling that a finding is fixed, citing material you recorded after it, resolves it even when
the check records facts about the environment (verification run only as root, installs into a
private environment); those stay disclosed on the receipt.

Before you ask for a receipt, `closure_readiness.predicted_receipt` names the conclusion it would
carry and why. The receipt carries the same reasons (`conclusion_basis`) and opens its Summary with
the same counters (findings to do, awaiting a ruling, unmet requirements, disclosed items, limits to
disclose), then one sentence beginning "Why". The totals printed from the latest check are labelled
with that check's frontier, because they describe the check, not the final state.

**Acceptance provenance.** When an obligation you resolved names a requested item you never
attempted, or its evidence is not linked to a declared item or is only your own assertion, and no
observed verification run or recorded verification limit backs it, the receipt records
`unresolved_verification_limitation` as a coverage limit, so the conclusion is at best
`insufficient_coverage`. It says "Acceptance provenance not established for" those obligations.
FinishUP judges where the resolution came from, not whether the output is right, so this never
stops you at Stop and met work needs no action; status names the obligations once
(`closure_readiness.acceptance_risk`). Linking the observed run or recording the limit lifts it.
An output that does not meet its acceptance criteria is republished as acknowledged not done.

Three more things the receipt discloses in their own sections, by id only:


- **Assumptions and verification limits.** When you make a best-effort choice, or a check is
  inherently out of reach (a hidden verifier, a private trace), that is not a blocker: finish the
  work and record a decision whose statement holds the line `finishup-assumption:<obligation id>` or
  `finishup-verification-limit:<obligation id>`, with the assumption or limit as the rationale. Closure
  readiness lists `assumption_disclosed` or `verification_limit_disclosed` as standing
  limitations, and the receipt names each one under "Assumptions and verification limits the agent
  disclosed". Nothing is blocked or resolved by it; supersede the decision to withdraw it.
- **Obligations acknowledged as not done.** For an obligation you truly will not do, after
  trying to repair it, publish it again with `status: "acknowledged_not_done"` and an
  `acknowledged_not_done_reason` (event version 1.1.0). It is no longer open work, readiness lists
  it under `acknowledged_not_done`, and the receipt names it under "Obligations acknowledged as not
  done" and never reads clean. Leave it out of your completion claim: an acknowledged obligation
  is outside completion coverage, so omitting it is not a scope gap, while naming it in the claim
  is still flagged. Publishing the obligation again as `open` (or `resolved` with evidence) takes
  it back.
- **Emptied deliverables.** When a declared output file that held content (at an earlier check, or
  at the task base) is now empty or holds a small fraction of its earlier size,
  `declared_output_emptied` asks you once at Stop to restore it. It follows the file, not the
  obligation: acknowledging the obligation as not done, or declaring a new "empty file" obligation
  for the same file, does not clear it. Status, the Stop text and the receipt say why it fired:
  what the file held and at which check. A file created empty (an empty requirements list) never
  raises it; if the task really asked for that file to be empty whatever happens, record a
  `finishup-assumption` decision that names the file and run `check`.
- **Deliverables that load undeclared files.** When a delivered source file may read a file you
  created but did not declare (a model, a word list, a data table), a grader that receives only the
  declared files gets a program that cannot run. A file the deliverable provably only writes does
  not count. A bare file name that a declared file shares, or that nothing in the code ties to the
  file's folder, is not treated as a dependency, and the receipt says how many such files there
  were (`deliverable_references_ambiguous_name`), never which.
  `deliverable_references_undeclared_file` asks you at Stop to fix it and names the files; when
  your privacy settings withhold a name (FinishUP shows you only a name you published yourself), it
  says so and asks you to list the files your change created yourself. The receipt names them (a `default_local_export`
  or `redacted_share` receipt counts them instead) and stays below clean until you fix it. Embed
  the content in the deliverable, rebuild it at run time, or declare the file, or the directory
  holding it, as a delivered output (a requested `file` or `directory` item with role `output`; a
  file the task itself provides is role `input`), then run `check`. Disclosing the dependency does
  not resolve it.
- **Planned commands that matched only in part.** A planned command counts as run when an
  observed run matches it exactly, or after dropping wrappers such as `timeout`, `env` and
  `nice` and the interpreter alias `python3`. A run that only began with the planned arguments,
  or carried its program and flags in another order, also counts, and the receipt lists
  `planned_verification_matched_by_prefix` with the run it rests on: FinishUP cannot tell whether
  that run is what you meant.
- **Deliverables not reviewed.** When a review ran and a declared output is a file type the
  review never receives (a binary), the receipt lists `declared_output_not_reviewable`: the file
  is present, and was not reviewed. Verify it yourself and say how.
- **Findings the review says the task requires.** A finding you answered `acknowledged_not_done`
  whose review challenge says the task itself requires the work is listed as
  `finding_premise_disputed` and under "Not done although the review says the task requires it".
  A Stop asks you about it once.

`duplicate_of` is only for a genuine restatement: a new finding of the same origin and kind that
names the same issue as an earlier finding you already answered. It is not a final state of its own
and never resolves the new finding: the finding stays open until its own check proves it absent,
and it is counted once with the earlier finding meanwhile. It carries over only the earlier
finding's never-clean answers (acknowledged not done, self-verified), and the receipt lists each
link by ids in a "Linked duplicates" section. A later check that raises the finding again, or a
review that says it is still present, breaks the link; it then needs its own answer.
`rejection_accepted` no longer blocks the receipt's conclusion but is listed in its own "Rejection
accepted" section. Both sections name finding ids only. A review that restates a recorded AI-powered
finding without anything recorded since does not add a second item: it is seen again and suppressed,
and the check discloses `semantic_restatements_suppressed`.

The check result's `finding_checklist` and `status` with the `findings` view show each item's state
and how many later reviews left it open, against the owner's budget
(`verification.finding_attempt_budget`, default 5), for example `[ ] F-3 open (2/5)`. At the budget
FinishUP asks for a decision: repair with new evidence; if you repaired it and only a FinishUP limit keeps
it unproven, verify it yourself and respond `self_verified`; respond `acknowledged_not_done` with
the reason only if you truly will not or cannot do it. It never limits checks and never closes or acknowledges anything on anyone's behalf.

Repairing the record is therefore the way back to a stronger receipt: repair, recheck, and read the
finding's `resolved` state rather than assuming that absence alone qualified. If the issue re-fires,
or it does not re-fire but remains current because the recheck did not qualify, stop rechecking the
unchanged state; request the bounded receipt and disclose the current finding and limiting coverage.
Neither case supports a clean completion receipt.

Responding does not throw the check away. A recorded check still counts toward a later receipt when
nothing after it can have changed the work the check read: responses to findings that check itself
returned, acknowledgements of observation-authored non-actionable findings, and the records the
host and FinishUP itself add around any tool call. FinishUP does not count your own `status`,
`read_guidance`, `receipt` or `check` calls, read-only reads, the host's stream bookkeeping
(messages, reasoning, token counts) or a receipt you save into the workspace, so checking and then
asking for the receipt keeps a local receipt clean.

If something after the check might have changed the work and FinishUP cannot tell (a script run, a
test or build, a tool it cannot attribute), the receipt folds the check's coverage, including
`semantic_model_derived`, and carries the gap `check_current_as_of_earlier_frontier` naming the
subject frontier that was tested and the first such record. The verdict is current as of that
earlier frontier, not the receipt's, so the receipt is still coverage-incomplete. `status` keeps the
code among the standing limitations and names the first such record. One new `check` before the
receipt evaluates it; the code can return when the host observes the check itself in a way FinishUP
cannot attribute (some Cursor profiles, FinishUP run through a shell), so do not repeat checks for
it: the receipt discloses it.

An observed edit to the deliverable or the workspace after the check is different: it changes
what the check judged. The receipt then reports `check_not_applicable` and says which record did
it (the tool, its ledger record and the check's subject frontier); `status` shows the same cause
in `closure_readiness.check_cause`, and a closing AI-powered review is required again. Re-run
`check` after your last edit. The hook records the tool and whether the write left the workspace,
not the file path.

Any other material event after the check — published work, a new finding (including an
observation-authored finding), any other response to a finding the check did not return (a
rejection of an observation-authored finding included), or a response whose payload is redacted or
unreadable (it cannot prove which finding it answered) — requires a re-check first. The receipt
reports `check_not_applicable` and the check contributes nothing until it is re-run at the current
frontier. `status` applies the same rule, so status and a receipt at the same frontier never
disagree about what was checked. Lifecycle records such as `work_closed` are not material and never
require a re-check.

The cheapest finding is the one that never fires. Before the first `check`, confirm that every
requested item has an exact `attempted_items` entry on the `action_recorded` event that attempted
it — `attempted_items` belongs to that family alone, never a claim, and each entry copies the
obligation's `requested_items` `value` string exactly — that every claim has linked evidence, and
that every open obligation is either resolved or deliberately left open with a stated reason.

A review can have been requested and then stopped because repeated rounds could not assess the
available evidence. Its result is `unavailable / round_limit_unassessable`. Receipts retain that
reason in JSON, markdown and text; required review remains incomplete. A self-verified finding
records the agent's own verification and its limits. Concerns the agent rejected and reports
disproved appear separately; that wording does not assert that the implementation was repaired.

Keep incidental evidence reports and logs outside your project and its output directories, then
publish references through the ledger. Required reports remain deliverables. FinishUP can preserve
verification after a byte-identical shell rewrite when its trusted workspace comparison proves
no bytes changed. A report a shell command writes makes earlier verification stale only when it is
one of that verification's recorded inputs; when FinishUP cannot tell, it asks whether a rerun is
needed instead of demanding one. A report the verification itself wrote, declared as its output,
is not a reason to rerun. A report you write with your coding agent's file-edit tool records no
file path, so it still makes earlier verification stale unless it is documentation or notes; write
incidental reports outside the project instead.
