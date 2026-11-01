# ADR-019 — Declared completion scope

**Status:** Accepted (2026-08-04), acknowledged in
[issue #130](https://github.com/TheGaySupreme123/finishup/issues/130).
**Implemented by:** `src/finishup/domain/events.py`, `src/finishup/kernel/plan_scope.py`,
`src/finishup/application/status.py`, `src/finishup/kernel/deterministic_checks.py`,
`src/finishup/kernel/receipt_builder.py`, and the public event/status schemas and guidance.
**Relates to:** ADR-002 (canonical protocol), ADR-010 (harness integration port), ADR-011
(structural subject-state capture), and ADR-032 (closure readiness classifies the completion-scope
gaps: `completion_plan_not_claimed`, `completion_claim_outside_plan` and
`completion_scope_undeclared` are agent-actionable; `completion_scope_declared_none` is a
disclosure).

## Context

FinishUP checks only the durable facts participants publish. An empty effective plan previously looked
the same whether the author had not declared completion obligations, had deliberately determined
that none applied, or had declared obligations and later resolved them. That ambiguity could make
an obligation-free completion appear scoped even though the ledger never recorded a scope decision.

Prompts, source code, workspace state, and agent memory cannot repair the ambiguity. They are not
authoritative ledger inputs, and inferring obligations from them would make replay nondeterministic.

## Decisions

1. **Empty scope is a typed plan declaration.** `plan_published` and `plan_revised` admit the
   optional closed `no_obligations_reason` values `no_material_change`, `single_atomic_change`, and
   `exploratory_scope_unknown`. The reason is valid only when the effective current plan has no
   obligation references. Unknown values and reason-plus-obligations contradictions fail closed.

2. **A revision restates the whole current declaration.** A plan revision may add, replace, or
   clear the reason. Omitting `no_obligations_reason` on a revision clears an earlier reason; the
   value is never inherited by omission. Existing events that omit the optional field keep their
   canonical bytes unchanged.

3. **One replay-derived state owns completion scope.** The readable current plan chain derives the
   effective obligation references, declared obligation count, and current empty-scope reason.
   Status, check, and receipt consume that same state. No component infers obligations from prompts,
   source code, workspace contents, or prose.

4. **Readiness distinguishes absence, empty declaration, and resolution.** No plan remains
   `no_plan_published`. A readable plan with zero declared obligations and no typed reason is blocked
   by `no_obligations_declared`. A typed empty-scope reason clears that readiness blocker and remains
   visible. A positive declared count has no scope blocker once every effective obligation is
   resolved. Redacted, unavailable, missing-reference, and unknown-event inputs remain unknown or
   conservatively blocked; unknown never collapses to zero.

5. **A declared-none reason does not purchase verification coverage.** When a completion claim
   exists and effective declared scope is zero, a check adds exactly one local-check case gap:
   `completion_scope_undeclared` without a reason or `completion_scope_declared_none` with one.
   Either gap forces coverage-incomplete, `insufficient_coverage`, and an insufficient-coverage
   receipt. A typed reason records the scope decision; it does not prove that the decision was
   correct.

6. **The existing policy and schema versions remain.** This is a pre-release 0.1 correction. Event
   and status schemas remain `1.0.0`, the work-integrity policy remains `0.1.0`, and no
   `FindingKind` is added. No storage migration is required because the declaration is carried in
   existing encrypted event payloads and projections are rebuildable.

## Consequences

Receipts can distinguish “scope was never declared”, “the plan declared none, reason: <closed
value>”, and “declared obligations are all resolved” without rendering caller-controlled prose.
Obligation-free work remains authorable, but its completion conclusion stays coverage-bounded.

Older plan bytes remain readable and byte-identical. Their omitted field means no typed empty-scope
declaration, not an inferred default. A later revision can repair the record either by declaring a
closed empty-scope reason or by declaring effective obligations and resolving them.

## Alternatives considered

**Treat every empty plan as “no obligations apply.”** Rejected: omission would silently buy a scope
declaration and preserve the ambiguity this decision removes.

**Infer obligations from the prompt or workspace.** Rejected: those sources are outside the durable
replay boundary and would make identical ledgers produce different conclusions.

**Make a typed reason sufficient for a clean verdict.** Rejected: a participant declaration records
intent but does not independently establish that no material obligations were omitted.

**Add a finding or bump the work-integrity policy.** Rejected: the distinction is a deterministic
coverage limitation and readiness fact, not a new actionable policy finding.

## Completion claim consistency (issue #679)

Maintainer acknowledgement: [issue #679](https://github.com/TheGaySupreme123/finishup/issues/679#issuecomment-5761526859).
Each readable effective completion claim is compared with the readable current plan. The shared
pure comparison reports `completion_claim_outside_plan` for claim refs outside that plan and
`completion_plan_not_claimed` for plan refs omitted by that claim. These are bounded coverage
limitations, not publication rejection or inferred obligations. Material and explicitly superseded
claims do not participate. Missing/redacted obligations and unreadable plans/claims retain their
existing unknown-input semantics rather than producing invented differences.

Comparisons are per claim: multiple partial claims do not implicitly combine into whole-plan
completion. An older unsuperseded claim remains a current assertion and is compared with a later
plan too; the author can explicitly supersede it. This includes a later explicit `waived` change:
waiver changes the current plan declaration, but it does not rewrite the historical claim, so the
claim remains outside the current plan until replaced. Narrowing a claim does not reopen a resolved
obligation or remove it from the plan. Its omitted scope stays visible as outside that claim's
completion coverage. A full-scope claim, explicit plan revision, or claim replacement is the
supported repair; the checker never edits these declarations itself.

Publication previews and committed responses expose the relation codes in existing coverage/gap
fields. Status (including closure readiness), local checks, and all receipt formats derive the
same limitations. Receipts retain bounded per-claim ID examples and total counts under normal
privacy projection. No new finding kind, storage table, or wire field is introduced. Historical
bytes remain unchanged; the new reader derives diagnostics from their accepted contents.
