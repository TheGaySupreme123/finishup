# ADR-020 — Typed evidence digest provenance

**Status:** Accepted (2026-08-09), acknowledged in
[issue #131](https://github.com/TheGaySupreme123/finishup/issues/131). Decision 7 amended
(2026-08-10) for [issue #176](https://github.com/TheGaySupreme123/finishup/issues/176); decisions
9–12 added (2026-08-30) for
[issue #302](https://github.com/TheGaySupreme123/finishup/issues/302). Decision 13 added (2026-09-30)
for [issue #912](https://github.com/TheGaySupreme123/finishup/issues/912).
**Implemented by:** `src/finishup/domain/events.py`, `src/finishup/application/publish_work.py`,
`src/finishup/application/observation_coordinator.py`, `src/finishup/kernel/deterministic_checks.py`,
`src/finishup/kernel/policies/work_integrity.py`, `src/finishup/kernel/receipt_builder.py`,
`src/finishup/application/semantic_case.py`, and the public event schemas and guidance.
**Relates to:** ADR-002 (canonical protocol), ADR-009 (data egress and privacy), ADR-010
(harness integration port), ADR-011 (structural subject-state capture), and ADR-032 (closure
readiness treats the evidence-provenance gaps as standing limitations, and records the direction
that service-verified capture, never caller-declared strength, may strengthen the coverage of the
evidence it backs).

## Context

An evidence digest previously identified bytes without recording what those bytes represented. A
caller could hash a source diff, publish it as `test_result`, describe successful tests in prose,
and satisfy the structural evidence link. The digest was real, but its asserted meaning was not
checkable. A digest also does not establish that a command ran, succeeded, was inspected, or was
observed by FinishUP.

Historical `evidence_recorded/1.0.0` records must remain readable without inventing provenance.
Approved checks and trusted imports additionally need stronger, capability-owned provenance that
ordinary cooperative publication cannot claim.

## Decisions

1. **New digest evidence uses `evidence_recorded/1.1.0`.** Every 1.1 payload with
   `content_digest` carries a closed `digest_binding`: exact `subject`, `content_availability`,
   `byte_count`, and `provenance`. A binding without a digest is invalid.

2. **Subjects and compatibility are closed.** Subjects are `approved_check_receipt`,
   `artifact_bytes`, `bounded_excerpt`, `command_stdout`, `import_report`, `source_diff`,
   `static_analysis_report`, `test_report`, and `test_stdout`. Each `evidence_kind` admits a fixed
   subset. In particular, `test_result` does not admit `source_diff`; the same digest is valid as
   artifact/source-diff evidence.

3. **Availability is explicit.** `captured` requires the mirrored captured object. `digest_only`
   and `withheld` forbid it. The digest always identifies the named bytes; availability states
   whether those bytes were retained, not whether their meaning was verified.

4. **Provenance cannot be self-awarded.** Ordinary publication may use only `caller_asserted`.
   `approved_check` requires a service-authenticated FinishUP-engine author on the engine-derived
   channel and binds both the approved-policy commitment and result digest. `import_observed`
   requires the trusted importer on the import channel. Envelope validation repeats these checks
   so bypassing the public application path cannot widen authority.

5. **Approved checks publish bounded ledger evidence.** The background verifier materializes an
   idempotent action/evidence/result graph. Its captured canonical receipt binds the approval,
   result, output digest and byte count, encrypted output object identity, before/after subject
   state, freshness, and recorded time. It contains no command output or broad log plaintext.

6. **Legacy and unavailable provenance weaken only linked work.** A referenced v1.0 digest adds
   `evidence_digest_subject_legacy_unknown`; referenced 1.1 `digest_only` or `withheld` evidence adds
   its exact limitation. Legacy-unknown evidence cannot silently satisfy a new completion claim.
   Case construction follows only the current claim/obligation/response support graph, so unrelated
   historical evidence does not weaken another conclusion. Redaction remains an independent
   availability limitation.

7. **AI-powered review never substitutes prose for digested bytes.** A typed digest contributes
   only bounded canonical provenance facts; unavailable legacy provenance becomes an explicit
   omission. Descriptions remain caller-authored narrative.

   *Amended 2026-08-10 (issue #176).* The original wording made the provenance facts **replace**
   the excerpt text, so publishing a digest made caller-authored narrative invisible to the
   reviewer — honest provenance cost legibility. Now, when a digest-bound evidence record also
   carries a bounded `description`, the excerpt item text is that description, and the digest
   identity facts travel alongside it as `digest_provenance` on the excerpt ref. Provenance is
   still never inferred from prose — it comes only from the typed binding — and the description is
   still never treated as the digested bytes. A digest-bound record without a description, and
   legacy provenance, behave exactly as before.

8. **No storage migration or projection-version bump was required for v1.1.** The new binding lives inside
   the existing encrypted event payload and current projection payload handle. Replay already
   preserves the exact schema version. `evidence_recorded/1.0.0` is frozen byte-for-byte and remains
   supported; non-observation digest producers introduced here use 1.1.

9. **Observation capture uses additive `evidence_recorded/1.2.0`.** Version 1.2 adds only the
   `observation_captured` digest provenance. Versions 1.0 and 1.1 remain byte-frozen and exact
   readable. The complete dispatch table accepts all three versions; the version manifest advertises
   1.2 as current. `outbound-case/1.1.0` adds the same provenance to typed excerpt metadata without
   changing frozen outbound-case v1.0 bytes. Released `event-draft/1.0.0` and
   `opaque-unknown-event-draft/1.0.0` remain byte-frozen; their additive `1.1.0` successors carry
   the exact evidence 1.2 pair and unknown-pair exclusion.

10. **The service, not an object reference, establishes capture.** `observation_captured` requires
    the exact observation coordinator author (`harness` + `harness_observed`) on `hook_observed`, a
    retained encrypted object, a digest and byte count of the secret-scanned inner bytes, and
    `immutable_snapshot` strength. Ordinary `publish_work`, trusted import, and an arbitrary
    `content_object_refs` value cannot mint it. Capture proves byte retention and identity; it never
    means `artifact_verified` or `independently_reproduced` and never proves that tool output is true.

11. **Eligibility is narrow and weakening is explicit.** Hook materialization admits only captured
    tool output, selected changed-file content, and workspace-diff content. Inspection facts and
    bounded excerpts materialize as their own evidence records. Visible messages, tool input,
    workspace locators, unsupported visible payloads, and approved-check output retain their
    existing paths and do not silently become captured ledger evidence. Missing descriptors,
    pre-migration rows without plaintext digest bindings, withheld or unavailable objects, and
    deleted objects, and scanner failure add `content_capture_unavailable`; deliberately
    ineligible retained content adds `content_unselected`; redacted retained bytes add
    `content_redacted`; and bounded inspection prefixes add `truncated_payload`. Excluded content
    never borrows a stronger eligible label.

12. **Retention is not disclosure authority.** Observation materialization records generic
    structural descriptions and typed digest provenance; materialization itself does not open or
    copy captured object bytes into AI-powered review. A later AI-powered review selection may carry
    retained
    bytes only when the service resolves the current consent arm for the exact closed host profile,
    task, session, and workspace, matches the durable evidence source event to the envelope's
    phase identity, verifies the object envelope/media type, the canonical inner wrapper, and its
    `text/plain` inner media, and proves the digest, byte count, source commitment, correlation,
    and complete multipart group. Redacted sanitized bytes remain usable with `content_redacted`;
    selection clipping remains visible as `truncated_payload`. The local consent store supplies a
    plaintext-free generation/runtime fence that combines a durable per-workspace epoch with a
    persisted runtime-gate nonce. Every real consent or runtime transition advances that fence,
    including transitions that return visible fields to their earlier values; legacy state is
    upgraded to a fresh epoch before the authority is accepted. The fence is rechecked before each
    object read and at the final provider gateway boundary whenever retained bytes are in the case,
    so a pause, disable, or revoke that wins before either boundary prevents a new captured-content
    disclosure even when task-store propagation is stale. A disclosure already in progress cannot
    be retracted.
    The resulting bounded values still pass ADR-009's independent classification, minimization,
    authorization, and egress path; the pre-approval case envelope remains metadata-only, and an
    arbitrary object reference never authorizes a read. Migration 0008 adds nullable digest/byte
    bindings to observation manifests and inspection snapshots plus durable inspection
    redaction/truncation flags. Existing NULL rows stay weak history and are never upgraded by
    inference.

13. **An unverified caller digest is a disclosed provenance label, not a finding.** The DeepSWE v2
    benchmark showed decision 6's limitation doubling as an unclearable local finding: following
    the "Making a change reviewable" recipe produced `caller_asserted` `digest_only` evidence, the
    `ledger_stale_or_incomplete` finding it raised asked for "content-bearing evidence" that
    ordinary publication cannot record, and each further excerpt grew the finding's subject set and
    minted a new id. Every service producer records `captured` availability, so a cited
    `digest_only` or `withheld` binding is always caller-asserted and nothing an agent can publish
    changes it. Those two codes therefore stay exact case and ref coverage gaps (decision 6 is
    unchanged: they still make the conclusion coverage-incomplete), but they are never subjects of
    the work-integrity ledger finding. The receipt's limitations section names them once, with the
    number of cited items, as caller-asserted digests FinishUP did not verify, and says no response or
    recheck changes that. It keeps the two retention facts apart: a digest-only item's bytes were
    not retained, while a withheld item records that the publisher withheld them, and a mixed
    count names how many items are of each kind. `evidence_digest_subject_legacy_unknown` still raises the finding; its
    text names only agent-performable actions (cite captured or typed evidence in a replacement
    claim). When provenance is the finding's only gap it says no repair or recheck is needed and
    one acknowledged response answers it; when other gaps remain it says an acknowledgement does
    not resolve the finding, which stays current until a qualifying check proves those gaps absent.
    Findings recorded under the old rule are not returned by the next check, so a qualifying check
    resolves them as history. Relatedly, a resolved finding's
    own coverage no longer folds into receipt coverage: it stays in the document as history, and
    only current rows bound the conclusion. The owner-approved service-side binding of a caller
    digest to a matching captured object or byte range (verified, not asserted, provenance) is not
    implemented yet; until it is, every caller digest takes this fallback label on every host.

## Consequences

FinishUP can reject a typed kind/subject contradiction at publication without pretending it inspected
the bytes. Receipts retain exact limitations for digest-only, withheld, redacted, and legacy
evidence; local findings retain them for legacy and redacted evidence, while an unverified caller
digest is disclosed on the receipt as a counted provenance label (decision 13). Capability-owned
approved-check/import/observation provenance stays unavailable to cooperative callers.

The subject taxonomy is intentionally finite. Adding a new byte class requires a reviewed protocol
change rather than a caller-defined string. Historical evidence may still be useful as weak context,
but its missing subject can never be repaired by inference from its description.

## Alternatives considered

**Infer the subject from `description` or `evidence_kind`.** Rejected: both are assertions and would
retroactively fabricate provenance.

**Recompute every digest by executing caller commands.** Rejected: arbitrary execution is outside
the evidence and consent boundary.

**Replace v1.0 in place.** Rejected: it would alter frozen wire bytes and make old ledgers ambiguous.

**Treat every digest as captured or inspected.** Rejected: identity, retention, inspection, and
authorization are separate facts.
