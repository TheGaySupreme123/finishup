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
   live until explicitly acknowledged. Only service-stamped observations take part on either
   side: a cooperative failure keeps the exact duty above, and a cooperative success or edit
   never retires an observed failure. A retired result
   stays authorable in `limitation_refs`, and the receipt counts it once as history.
   `limitation_refs_complete`, `failed_work_omitted`, research-evidence limitations, and observation
   advice all read this one predicate, so admission and the packs cannot disagree. Loosening the
   required set cannot reject any history that the stricter rule accepted.

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
