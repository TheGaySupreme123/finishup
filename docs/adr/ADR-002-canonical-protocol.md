# ADR-002 — Canonical protocol, identifiers, and golden vectors

**Status:** Working decision for spec drafting (2026-07-13). Ratification requires the golden
vectors plus an independent-implementation parity run.
**Implemented by:** `docs/INTERFACES.md`, `src/finishup/protocol/`,
`schemas/`, and `fixtures/canonical/`.

## Decisions

1. **Canonical bytes:** RFC 8785 JCS restricted to the FinishUP value profile.
   Because the profile forbids floats entirely, ECMAScript number rendering degenerates to
   base-10 integers in ±(2^53−1); larger values are canonical integer strings. We therefore
   implement a **FinishUP-owned canonicalizer** (`protocol/canonical.py`) for the narrow profile
   rather than adopting a third-party full-JCS package. Guardrails: all RFC 8785 vectors
   applicable to the profile, the negative-zero erratum, UTF-16 code-unit property ordering
   (including Hebrew/emoji/combining-mark cases), fuzzing, and a CI-only second-language oracle
   (Node `canonicalize` package or Rust `serde_jcs`) that must agree byte-for-byte on every
   fixture. No `json.dumps(sort_keys=True)` anywhere in the digest path.
2. **Digest algorithm:** SHA-256, rendered `sha256:<64 lowercase hex>`. Payload commitments are
   keyed: `hmac-sha256:<hex>` with domain separation (ADR-004 owns keys).
3. **Identifiers:** typed prefix + `_` + lowercase canonical UUIDv4 from the OS CSPRNG, per the
   registry in `docs/INTERFACES.md` §1. Server verifies spelling/version/variant/length and
   handles reuse via idempotency digests; it never claims to measure caller entropy.
4. **Idempotency scope:** post-start `(task_id, writer_id, request_id)`; `start` uses
   `(installation_id, request_id)` in the structural catalog. Two byte identities: publication
   request identity (caller headers + keyed payload commitments, no ledger-assigned fields) →
   `request_digest`; accepted entry bytes (structural envelope after assignment) →
   `entry_digest`. Retry re-encryption cannot change logical identity.
5. **Integer/Unicode rules:** I-JSON input, duplicate keys rejected,
   no Unicode normalization, floats forbidden, sequences/sizes as canonical integer strings,
   fixed-scale integer coefficients for any non-integral quantity, one spelling for
   IDs/digests/enums/timestamps (RFC 3339 UTC, 3 fractional digits), set-valued fields =
   ASCII-byte-sorted unique typed IDs/enums.
6. **Schema-version policy:** `protocol_version = "0.1"`; each request/result/event schema is
   independently SemVer'd starting `1.0.0`; unknown public request versions are rejected
   (`PROTOCOL_VERSION_UNSUPPORTED` / `INVALID_REQUEST`); unknown *event* schemas are preserved
   opaque. JSON Schema draft 2020-12 with `$id` under `https://schemas.yoetz.dev/0.1/`.
   Pre-1.0 result contracts may add reduced success branches when that is the honest outcome: the
   `publish_work` result is a three-way union of full success, reduced total acceptance
   (`response_completeness: "accepted_projection_unavailable"` after a durable append whose full
   privacy projection failed), and operation failure. The reduced branch is still `ok: true` and
   is constructible from ledger append facts alone.
7. **Golden vectors:** `fixtures/canonical/` freezes: canonicalization vectors (positive +
   rejection), request-digest vectors, accepted-envelope/entry-digest vectors, and ID-validation
   vectors. Released bytes are permanent compatibility obligations.

## Consequences

- Serializer changes can never rewrite identity: accepted `canonical_entry` bytes are stored and
  re-verified on read.
- The canonicalizer is small enough to audit but must be treated as consensus-critical code:
  100% branch coverage plus the oracle gate.
