# ADR-030 — Typed recovery directives for public errors

**Status:** Proposed for issue #739; the maintainer requested this scoped work on 2026-09-15,
including the four-tier classification, the evidence-driven subset plus ratchet, and the
pointer-with-directive decision. Surface coverage beyond MCP and CLI remains a review decision on
that issue. Amended for issue #741 (the CLI's own reason vocabulary ratchets too); the maintainer
requested that scoped work. Amended again for issue #741 on 2026-09-22 (CLI-owned JSON carries the
renderer-resolved directive); the maintainer requested the change and accepted this amendment.
Amended for issue #742 on 2026-09-23 (provider and AI-powered review outcomes resolve through
`continuation_for_semantic_outcome`; no new public SemanticReason values). Amended for issue
#739 on 2026-09-23 (hooks, TUI, and receipt human renderers resolve through the same registry;
compact receipt fixtures stay frozen). Remaining exemptions stay recorded on the issue.

**Relates to:** ADR-002, ADR-009, ADR-015, ADR-018, and issues #739, #740, #669, #741, #742.

## Context

An agent that hits a Yoetz error is told *that* something failed, not *what to do next*. The public
error identity — code, retryable flag, correlation ID — survives every surface. The recovery
instruction does not.

This is not a consequence of the egress fence. The fence is correct and stays: `CONTRIBUTING.md`
locks "nothing user-controlled ... appears in ... errors, or MCP text summaries", and
`summary_for_public_error` therefore projects only allowlisted structural content and never the
free-form `message`.

The defect is that facts which are **not user-controlled at all** were composed into prose at the
raising site, and prose is fenced wholesale. Two observations establish this:

- The typed `vault_initialization_required` continuation of ADR-015 and issue #512 carries frozen
  repository command literals in `safe_details`. Native text dropped all of them, so a flow
  explicitly designed not to dead-end reached the model as a dead end (issue #740).
- `_claim_revision_clause` recovered an invariant by regex-matching the service's own English
  message, then looked that invariant up in a closed correction table. The information had been
  structurally available three layers earlier.

Twelve closed issues repaired this one error class at a time (#266, #240, #579, #237, #220, #428,
#308, #342, #335, #326, #147, #93). The recurrence is the argument for a contract.

## Decisions

### The token travels; the text does not

A public error carries a typed `continuation` token in `safe_details`. Each renderer reconstructs
the directive text, guidance pointer, and nudge locally from a checked-in registry keyed by that
token.

Consequences that follow, and are the reason for this shape:

- Directive text is never data. It cannot be truncated, re-encoded, or replayed by a peer, and a
  compromised or buggy producer cannot author error prose that a renderer will repeat. This is the
  decisive reason: it is a property no additional wire field can provide.
- Prose changes cost nothing on the wire. Rewording a directive is a one-line registry edit with no
  schema, fixture, or golden-vector churn, and every surface moves together by construction.
- A third-party consumer reading structured JSON receives the token and resolves it through
  `docs/INTERFACES.md`. Serving such a consumer prose instead would mean versioning the schema for
  text that its own renderer could reconstruct.

**Not** a reason, recorded because an earlier draft of this ADR asserted it: the 32-key
`SAFE_DETAIL_KEYS` allowlist was not at a schema ceiling. `public-error-1.0.0` sets
`maxProperties: 32` on a `safe_details` *instance* and admits property names by pattern rather than
by an enumerated list, so the code-side allowlist may exceed 32 without a version bump. ADR-030
itself then added a 33rd key, `invariant`, under that unchanged schema. Adding a typed detail is
therefore a live option for facts a consumer genuinely needs structurally; it is simply the wrong
carrier for prose.

### The token is attached where the error is built

The first implementation mapped reason codes to tokens but attached them only in one MCP timeout
branch, so a real `unsorted_set_field` rejection reached the model with the registered directive
absent. A reason code determines its directive regardless of which producer raised it, so
`PublicOperationError` attaches the mapped token at construction, from a map held literally in the
dependency root beside the admitted token set. A producer that already chose a continuation is
never overridden; that is how the one boundary with more information than the reason (the MCP
bridge, for timeouts) says so. Raising sites still classify Tier-4 facts into tokens; they no
longer have to remember to attach the token a reason already implies.

### Rejected input is a correction, not a retry

`retryable: false` means "do not resend this body". It never meant "stop": a body the schema
validator refused before any write can only be fixed by sending a different body. The shipped
safety floor said only the former, and an agent that read it literally treated a malformed
`actor_id` as terminal. The bridge's argument validator, the sole producer of location-shaped
`safe_details`, therefore attaches `input_correction_new_identity`, whose directive names the
identity rule (a new `request_id`, once) and distinguishes the case from an ambiguous write; the
`publish_work` draft validator attaches it to every non-retryable `EVENT_INVALID` without a
directive of its own, classified there because the same reason tokens also describe corrupt stored
records where the instruction would be false. A
unique field-ownership repair and an unreachable recovery oracle are the two facts that override it
with their own directives. The guidance floor now states the same rule in the same words.

### A timed-out `start` is its own kind

The generic write directive (read `status view=operation`, replay only on `absent`) requires the
session and writer ids that a lost first `start` never returned. The recovery table has always
excepted that case with one exact replay under the same `request_id`; the directive registry now
carries the exception as `start_timeout_same_identity` rather than handing a first start a write
directive it cannot follow.

### A refused check admission is not a stranded operation (issue #838)

`operation_pending_inspect` describes a prior operation that is still pending, and the generic
guidance for an untyped `OPERATION_PENDING` is to read `status view=operation` once and replay only
on an exact continuation. A check refused before admission has no operation to inspect: two native
deterministic checks followed that rule, read `absent`, replayed once, and stopped with nothing
recorded. Every pre-admission branch therefore names its stage with a `check_admission_*` reason
code that maps to `check_admission_same_identity`: nothing is recorded under the `request_id`, so
wait `retry_after_ms` and replay the exact body, and after three refusals retain the request and
report the check as not admitted. The operation page carries the same stage on its `absent` page.
The directive bounds the replay rather than predicting admission, and an admitted pending check
keeps its untyped `OPERATION_PENDING`.

### Four tiers, classified at the raising site

Every fact in an error belongs to exactly one tier, decided where it is known:

| Tier | Example | Rule |
| --- | --- | --- |
| 1. Frozen directive | "Repeat the read with a NEW request_id." | Registry value keyed by token. |
| 2. Structural locator | `/event_drafts/0/payload/obligation_refs` | Allowlisted frozen schema vocabulary. |
| 3. Gated runtime value | `req_…`, `sha256:…`, counts, versions | Pattern-gated in `normalize_safe_details`. |
| 4. Never | payloads, paths, titles, provider and model output, raw exception text | Classified into a Tier-1 token at the raising site, then discarded. |

Tier 4 is load-bearing and is why this costs more code than echoing a message: classification
happens at each raising site rather than once at a renderer. What it buys is exhaustive
import-time testability, which prose cannot have.

### A directive is an instruction, never a prediction

"Read status view=operation before replaying" is admissible: the error establishes the condition.
"This will fix it" is not: the error cannot substantiate an outcome, and coverage-bounded language
forbids claiming one. Nudges attach per error class, so a schema-validation failure and a vault
refusal never receive the same unhelpful advice.

Guidance pointers are emitted only where a matching guidance section exists, and every pointer is
tested to resolve to a real document and heading. A pointer that leads nowhere teaches an agent to
ignore every pointer.

### Two disjoint reason vocabularies

Protocol reason codes (`PROTOCOL_REASON_CODES`) and local lifecycle, instance, and ceremony reasons
(`yoetz.cli.exits`) are separate namespaces and resolve through separate lookups. An overlap is an
import-time failure. Conflating them is a real hazard: three CLI lifecycle reasons were nearly
registered as protocol reasons while the registry was first written, and the gate is what caught it.

One reason is a genuine member of both namespaces. `service_draining` is a protocol reason code the
CLI also raises locally; it resolves through the protocol vocabulary, where its disposition is
already recorded, and is therefore absent from the local map rather than duplicated into it.

### Both reason vocabularies ratchet (issue #741)

The first ratchet covered protocol reason codes only, so the CLI's own vocabulary could still grow
a reason with nothing for an agent to do — and had: forty of the fifty-four reasons `yoetz.cli.exits`
could put in front of an operator carried a remediation sentence and no typed directive, so a
condition explained over MCP was unexplained in a shell. The local vocabulary now carries the same
obligation. A second import-time gate, in `yoetz.cli.exits` rather than `yoetz.protocol.recovery`
because that is where the vocabulary lives and layering forbids the protocol package importing the
CLI, requires every reason in the module's tables to resolve to a directive — through the local map,
or through the protocol vocabulary for the one reason that belongs to both.

A local reason is keyed to a continuation token like any other, so directive text stays keyed by
recovery *shape* rather than by reason: the thirteen tokens minted for these reasons cover
forty-five of them, because "correct the named configuration value and run this again" is one
instruction whatever field violated it. Only one family is matched by prefix rather than
enumerated, `vault_result_*`, because its members are generated from service conditions and
pretending it is a closed set would be a lie about a closed set.

`REMEDIATION_MESSAGES` is **not** retired into the registry, which the issue proposed. It stays as
the per-reason remedy half beneath the directive, for three reasons recorded here so the question
is not reopened without them:

- The registry is keyed by continuation token, and `yoetz.protocol.recovery` requires its token set
  to equal the set the protocol normalizer admits onto the wire. Moving fifty-two per-reason
  remedies into it would admit fifty-two local-only tokens to the wire vocabulary for reasons that
  never cross it — the opposite of the narrow-wire decision above.
- Directives are bounded at 232 ASCII bytes so identity, reason, directive, and pointer fit the
  text channel together (512 bytes when this was decided, 4,096 since ADR-043; the directive bound
  is unchanged). Five shipped remedies already exceed that bound, and the longest is 344
  bytes.
- Several remedy sentences are asserted byte-for-byte by CLI tests that lock what an operator sees.

The two layers say different things and both are kept: the remedy names *which* condition was hit
and the exact local command for it, the directive names the recovery rule that holds for the shape.
Where they overlap, the CLI wording is the better-developed one and stays first on the line.

### CLI-owned JSON carries the resolved directive (issue #741, 2026-09-22)

The first cut of this ADR kept directive prose out of every JSON rendering, reading "the text does
not travel" as "no JSON body holds the text". That reading was wider than the reason behind it. The
decisive property above is that a *producer* cannot author text a *renderer* repeats: the token
crosses the wire and the renderer supplies the words. The CLI is a renderer. When it resolves a
token through the checked-in registry and prints the result in its own JSON output, the text still
never crossed a wire and no producer wrote it. The property holds.

Keeping the text out of JSON also had a real cost: an agent reading `--json` or non-TTY output had
to hold the token table itself, while the same condition in a terminal came with its instruction.
The JSON consumer was the one left without the directive.

So:

- A JSON error body the CLI **owns** (not a schema-locked wire result) carries a `recovery` object
  when the error resolves to a directive. Its fields mirror the human lines one to one:
  `continuation`, `directive`, then `commands`, `guidance_uri`, and `nudge` when present. For a
  claim-revision rejection it carries `invariant` and `correction`. The observe verbs' typed failures
  and the control-failure JSON payloads are the bodies this covers today.
- `recovery.continuation` is the key a consumer branches on. The prose fields are advisory output:
  they may be reworded in any release without a schema change, and a consumer must never send them
  back as input or treat them as a stable identifier.
- A **frozen wire result** is not extended. The workflow commands print the exact
  `operation-result-1.0.0` failure body on stdout, and that schema admits no additional property.
  Adding `recovery` there would be a wire version bump, shared with MCP, to carry text the consumer's
  own renderer can supply. Instead, in JSON or non-TTY mode the CLI writes the same directive lines
  a terminal would show to stderr. stdout stays byte-identical to the wire result.
- Nothing changes on the wire: no new `safe_details` key and no schema version bump. Exit codes are
  unchanged. This amendment changes what the CLI *says*, never what it *returns*.

### Coverage grows by ratchet

Directives are populated for reason codes with demonstrated agent impact rather than by one
exhaustive pass. Every remaining reason code carries an explicit exemption, recorded as a decision:
a validation reason whose field pointer already names the repair, an internal invariant an agent
cannot act on, or a family owned by a later sub-issue.

An import-time gate requires every reason code to resolve to a directive or appear on that
exemption list, and requires the registry's token set to equal the set `normalize_safe_details`
admits. Adding a reason code without deciding what an agent should do fails the build.

### Budget priority

The MCP text channel is bounded at 4,096 ASCII bytes (it was 512 until tb4n3; see ADR-043) and a
text builder never raises: it composes its parts with `yoetz.domain.bounded_text`, reserving the
required core first and granting the optional clauses room by priority. Projection order is: error
identity, then reason and location, then continuation directive, then the typed remedy and carried
commands, then guidance pointer, then nudge. Parts shrink to a shorter variant and then drop from
the bottom (the directive shrinks to its bare continuation token before it is dropped). Error
identity is never sacrificed to fit advice.

A committed operation never becomes an error because its text could not be built (ADR-043): a
failing clause is omitted and named (`summary_render_failed:<builder>.<clause>`), a failing core is
replaced by the verdict or state token, the frontier and "read status view=compact", and the
failure is recorded as a service diagnostic. An `INTERNAL_ERROR` always carries a typed
`reason_code`; the stages added for it are exempt from a continuation directive and carry a fixed
remedy sentence (`REASON_REMEDIES`) that renders on the text channel beside the reason.

## Consequences

- Every human-rendered CLI error path renders directives from one helper: the public-error
  renderer, the bounded lifecycle line, the trusted-ceremony mapper, the interactive menu, the
  instance and path refusal line, the observe verbs, and the resource-integrity branch of
  `version`. A remedy visible on one of seven surfaces is the defect issue #741 reported.
  Hooks, the TUI blocked report, and receipt human text now use the same lookup. Hook intake keeps
  its host-specific prefix and appends only a continuation token (512-byte hook cue), resolved from the
  hook's own exact reason, never from a check's provider outcome; a hook context that stands for
  several reasons, or whose reason only shares a spelling with a CLI-local reason, appends none. The
  TUI appends the full directive lines. Receipt human text adds a Recovery section from recorded
  `semantic_provenance`. Compact receipt sentences stay fixture-stable; they do not gain prose.
  Workspace-fence, `service_unavailable`, `service_incompatible`, `storage_corrupt`, and “review was
  not run” coverage gaps remain exempt or hook-specific.
- JSON renderings carry the continuation token where they already carry `safe_details`. CLI-owned
  JSON error bodies also carry the renderer-resolved `recovery` object. A frozen wire result keeps
  its exact shape on stdout and gets the directive lines on stderr (see the 2026-09-22 amendment
  above). The human and JSON renderings share one resolver in `yoetz.cli.render`, so they cannot
  disagree about what an error says to do.
- Recovery rules now exist in two places — `guidance/*.md` and this registry — and must move
  together. The guidance-anchor test couples them; a directive that contradicts its own guidance
  section is a documentation bug, not a rendering one.
- The `frontier_refresh_required` directive follows the shipped replay semantics: `publish_work`
  stores a frontier conflict as a retryable failure under the original `request_id`, and the
  producer's own message directs an idempotent retry under that same id. A directive that told the
  agent to mint a new `request_id` would have contradicted the message beside it.
- Provider and AI-powered review failures gain typed failure tokens (issue #742) rather than an
  exemption from the Tier-4 rule. Classification happens at the adapter boundary into the closed
  `SemanticFailureClass` set. Renderers resolve frozen directives through
  `continuation_for_semantic_outcome` from the recorded `(semantic_status, semantic_reason)` pair
  and, when present, `failure_class`. A rejected credential is distinguished from transport
  failure by that class, not by public-reason expansion of frozen check-result schemas. Raw
  provider and model text is discarded at the adapter and never reaches a directive. Some
  diagnostic nuance is genuinely lost at the agent-facing boundary and remains recoverable
  locally through the `correlation_id`, which never crosses the wire. That is the intended trade.
- `_claim_revision_clause` is retired. `ClaimRevisionMismatch` already carried a closed-set
  `invariant`, which the builder placed only inside the message, so the MCP projector matched that
  whole sentence with a regex to recover it and validated the result against a second copy of the
  domain's frozenset. The invariant is now an allowlisted safe detail, the regex and the duplicated
  vocabulary are deleted, and the corrective phrases moved into the shared registry — which also
  gave the CLI a correction it never rendered. The clause no longer depends on message integrity,
  so rewording the message costs an agent nothing.
