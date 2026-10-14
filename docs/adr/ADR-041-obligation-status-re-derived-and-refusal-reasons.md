# ADR-041 — Obligation status re-derived from current evidence, one obligation version rule, and refusals that say why

**Status:** Accepted for [issue #1022](https://github.com/TheGaySupreme123/yoetz/issues/1022)
(tb4n2 R2) and [issue #1023](https://github.com/TheGaySupreme123/yoetz/issues/1023) (tb4n2 R3,
R5). Maintainer acknowledgement (TheGaySupreme123, 2026-10-08): "all r been agreed" (R1-R10,
design changes included). It loosens one ingest validation rule, adds one public-error detail key
and two task-fact codes; it changes no egress and no storage, and grants no runtime, credential,
disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/kernel/completion_scope.py`, `src/yoetz/kernel/delivered_set.py`,
`src/yoetz/kernel/task_facts.py`, `src/yoetz/application/check.py`,
`src/yoetz/application/check_change.py`, `src/yoetz/adapters/git_change_capture.py`,
`src/yoetz/domain/events.py` (`obligation_schema_admits`, `obligation_schema_version`),
`src/yoetz/application/publish_work.py`, `src/yoetz/domain/closure.py`,
`src/yoetz/kernel/self_verification.py`, `src/yoetz/application/respond.py`,
`src/yoetz/protocol/errors.py`, `src/yoetz/cli/closure_gate.py`, `guidance/request-templates.md`,
`guidance/workflow.md`.
**Relates to:** ADR-032 slice C (acknowledged obligations), ADR-033 decision 2
(`obligation_published` 1.1.0), ADR-034 (`self_verified`), ADR-035 (declared delivered set).

## Context

Yoetz exists to catch incomplete work, and must never steer an agent wrong. TB4 run tb4n2 showed
three ways the closure path did the opposite:

- **Latched status.** An obligation acknowledged as not done stayed in the plan scope a completion
  claim must name. A claim naming it raised `completion_with_open_obligations`; a claim omitting
  it raised the agent-actionable `completion_plan_not_claimed`. Nothing honest cleared both
  (cargo, payments and vpp S; 11 of 22 `finding_not_proof_limited` refusals; false "unresolved"
  receipts). Conversely, a `resolved` obligation stayed resolved while its declared deliverable
  was emptied to 0 bytes (formal-crypto S).
- **A half-rolled-out version contract.** `obligation_published` 1.1.0 was accepted only with a
  1.1.0 feature, the only copyable template was 1.1.0, and the corrective hint was unreachable:
  24 of 28 attempts were refused at least once. `closure_prepare` drafted every resolution at
  1.0.0 and crashed with `INTERNAL_ERROR` on a role-bearing obligation (retro S).
- **Silent refusals.** `finding_not_proof_limited` never said which recorded reason disqualified
  the finding, nor that an inherent verification limit has its own disclosure line; agents retried
  2-5 times.

## Decision

1. **Acknowledged obligations are outside completion coverage.** `completion_scope_differences`
   subtracts every plan obligation whose *current* status is `acknowledged_not_done` from the
   "not claimed" set. Omitting it is the honest claim; naming it still raises
   `completion_with_open_obligations`, whose remediation now says to omit it. The acknowledgement
   stays disclosed (readiness `acknowledged_not_done`, the receipt's own section) and the receipt
   never reads clean while it stands. Status is read from the projection on every call, so a
   republish as `open` brings the obligation back into coverage.
2. **A resolved deliverable is re-checked.** `declared_output_emptied` (ADR-035 amendment) is an
   agent-actionable task fact and Stop-gate token: a declared `role: output` file of a resolved or
   completion-claimed obligation is now 0 bytes or kept under a tenth of its task-base lines. While
   it stands the obligation's `resolved` is not counted as delivered ("reopened" by derivation;
   the ledger is never rewritten). Restoring the file, republishing the obligation `open` or
   `acknowledged_not_done` clears it at the next check (a disclosure line does not). `deliverable_references_undeclared_file` is the matching fact for a
   deliverable that names an undeclared file the change created (a standing disclosure here; agent
   work and a Stop-gate token since #1044, whose only exits are embedding the file, rebuilding it
   at run time or declaring it: ADR-035 amendment).
3. **One obligation version rule.** `domain.events.obligation_schema_admits(payload, version)`:
   1.0.0 refuses a `role`, a `directory` item and `acknowledged_not_done`; 1.1.0 is a superset
   and admits every payload. The ingest validator, `closure_prepare` and every hint read it.
   `obligation_schema_version(payload)` is the writer choice (the lowest admitting version), so
   Yoetz-drafted plain obligations keep their released 1.0.0 bytes. The frozen JSON schemas
   already expressed exactly this; only the Python validator was stricter. The
   `invalid_event_schema` hint for `obligation_published` is now reachable from the decode path.
   A ledger holding a plain 1.1.0 obligation does not replay on a build older than this rule.
4. **`closure_prepare` never fails internally on its own draft.** A resolve draft takes its
   version from `obligation_schema_version`; a draft its request model refuses is
   `INVALID_REQUEST` `closure_draft_invalid` with a remediation. `closure_evidence_unavailable`
   says that `res_` ids go in `result_ids`.
5. **Refusals say why.** `kernel/self_verification.disqualifying_reasons` returns the recorded
   resolution-reason tokens that make a finding not proof-limited (`reasons_proof_limited` is its
   negation; eligibility is unchanged). The `finding_not_proof_limited` error carries
   `safe_details.blocking_reasons` (1-32 tokens matching `^(coverage:)?[a-z][a-z0-9_]{0,95}$`,
   recorded reasons only, never prose) and a message naming them with a next step per family and
   the `yoetz-verification-limit:<obligation id>` exit. `public-error` 1.0.0 already admits an
   array detail value, so no schema version changes. `_attempt_reasons` is the single seam where
   per-finding scoping of task-wide coverage codes (tb4n2 R4) plugs in.
6. **A resolution is not latched.** The reducer admits `resolved → open` and
   `resolved → acknowledged_not_done` (meaning fields still repeat; `resolved → resolved` is still
   refused), so the reopen and acknowledgement exits that `declared_output_emptied` and the Stop
   gate name are actually available. Earlier ledgers never held such a transition (it was refused
   at ingest), so replay is unchanged; a ledger holding one does not replay on an older build.
7. **An all-acknowledged claim can be withdrawn.** A completion claim whose every obligation is
   now `acknowledged_not_done` claims nothing; its `claim_recorded/1.1.0` replacement may name no
   obligation (the reducer's `scope_overlap_required` reads current obligation status).
8. **Wording.** The acknowledgement re-check names the reopen path on 1.1.0 (which keeps a role or
   directory item); the first-stop gate question (only when no obligation is open, so acknowledgement stays the
   challenged last resort beside open work, #997) asks the agent to compare each resolved
   obligation's `acceptance_criteria` with its final output and acknowledge, not resolve, one its
   own output contradicts (cargo D).

## Consequences

- An agent that honestly acknowledges an obligation can close with an `insufficient_coverage`
  receipt instead of a refusal loop and a false "unresolved findings" receipt.
- An emptied deliverable stops the agent once at Stop and blocks a clean receipt. Conventionally
  empty names (`__init__.py`, `py.typed`, `.gitkeep`, `.keep`, `.nojekyll`) are exempt; another
  deliverable a task truly wants empty keeps the fact standing (residual false positive, chosen
  over letting an unrelated disclosure hide an emptied output).
- Gap classification version "6" ("5" is the review lane's; status-result 1.4.0 admits both).
- Residual: an untracked deliverable truncated to a non-zero size is not detected (no earlier size
  is stored); `deliverable_references_undeclared_file` is a literal-matching heuristic.

## Amendment (2026-10-11): obligation closure classes (#1026, ADR-046)

Decision 7's rule that an acknowledged obligation is never open work is now one table
(`kernel/closure_class.OBLIGATION_BASES`) every surface reads:

| Basis | Class | Receipt effect |
|---|---|---|
| `open`, `blocker_claimed`, `resolved_deliverable_emptied` | agent_work | insufficient_coverage |
| `acknowledged_not_done` | settled_unmet | insufficient_coverage |
| `blocker_confirmed`, `externally_evaluated` | settled_disclosed | insufficient_coverage |
| `resolved` | resolved | none |

Only `agent_work` is recorded as work by the check's next step (`_recorded_work_refs`), so the
check no longer calls an acknowledged obligation open work while status calls it settled (cargo D).
Every non-`resolved` obligation reads below clean on the predicted receipt (reasons
`obligations_open`, `obligations_acknowledged`, `obligations_disclosed`), which names in the
conclusion what the receipt already did implicitly. `status view=obligations` rows carry
`closure_class` and `closure_basis`; `obligation_counts {open, acknowledged, disclosed}` is the same
on every surface. A `resolved` obligation whose declared deliverable the newest applicable check
found emptied (the path-keyed fact of ADR-045) reads `resolved_deliverable_emptied` until the file
is restored or a `yoetz-assumption` decision names the path (ADR-046). The once-per-frontier
re-reads the Stop gate may ask (resolved obligations' acceptance criteria, an acknowledgement, a
claimed blocker, an acknowledged finding the reviewer disputes) are computed statelessly from the
closures and announced on status as `rechecks`.
