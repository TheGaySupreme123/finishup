# ADR-005 — Codex capability, identity, and MCP transport edge cases

**Status:** Working decision for spec drafting (2026-07-13). Ratification requires the pinned
capability matrix run from an installed artifact.
**Implemented by:** `src/finishup/adapters/mcp_stdio.py`,
`src/finishup/adapters/importers/codex_jsonl.py`,
`src/finishup/adapters/importers/codex_rollout_jsonl.py`,
`src/finishup/adapters/integrations/codex_session_stream.py`,
`src/finishup/adapters/integrations/codex_capability_cells.py`, `src/finishup/mcp/`, the Codex
skill files under `skills/codex/`, and `tests/capability/`.

## Decisions

1. **Supported Codex range:** exact cells only, never a continuous range. The `codex exec --json`
   importer remains pinned at `0.139.0` (`codex-exec-jsonl/0.139.0/v1`). The session-stream
   reconciler is a different surface with one parser-only rollout grammar profile per exact
   release, each proven by its own constructed fixtures: `0.148.0`
   (`codex-rollout-jsonl/0.148.0/v1`, `legacy` and `paginated`, IMP-006..IMP-009) and `0.150.1`
   (`codex-rollout-jsonl/0.150.1/v1`, `paginated`, IMP-011..IMP-012). The profiles are keyed by
   exact `cli_version` in `SUPPORTED_ROLLOUT_PROFILES` and recorded as
   `CODEX_ROLLOUT_PARSER_PROOFS`; the session header selects the profile by exact key lookup, so
   no release is ever aliased to a neighbour by semver inference, and each profile's wrapper/item
   vocabulary is exactly what its fixture exercises (the two vocabularies are not supersets of
   each other). A header naming any other release, or a `history_mode` outside `legacy` /
   `paginated`, is refused as `unsupported_codex_profile` (IMP-013 proves `0.152.1`): the reader
   consumes the bytes, admits no event, and holds that refusal for the whole source generation
   without losing the cursor. An admitted profile with an unrecognized wrapper or item stays a
   bounded `unsupported_event` gap. Adding the next release is a fixture-plus-profile change: one
   new exact profile, one new parser-proof row, and its fixtures.
   The reader records the admitted profile per source generation (`stream_profiles` in the local
   observation store, cursor mapping `codex-obs-stream/1.3.0`); a pre-`1.3.0` cursor replays from
   its header instead of inheriting a default profile.
   Those fixtures are not an isolated installed-artifact capture and therefore do not populate
   `CODEX_HARNESS_PROFILE`, the skill manifest's tested/supported bounds, or `finishup version`
   capability profiles; parser proof and host support are distinct facts. The dogfood parity gate
   may advertise `session_stream` only for a parser-proven exact version and still records it
   `pass` only on actual reconciliation evidence. Neighbors including `0.149.1` stay untested. The
   full skill/MCP/hook matrix in `runtime-support.json` and issue #413 remain unfrozen until those
   facets have independent installed-artifact evidence.
2. **Integration posture:** Codex is the MCP client; FinishUP is a local stdio server registered via
   `codex mcp add finishup -- finishup mcp serve --host codex`, default `required = false`. FinishUP first runs `codex mcp
   get finishup --json`; because a nonzero named lookup is ambiguous, only a successful strict parse
   of `codex mcp list --json` with no matching name confirms absence. Duplicate keys/names,
   nonstandard constants, truncation, malformed output, and failed listing all fail closed. A
   same-name entry is never intentionally overwritten unless a separately reviewed flow proves it
   is the exact FinishUP-owned entry. Codex exposes no compare-and-add token, so this check cannot
   atomically exclude a non-cooperating global configuration writer inside the final subprocess
   window; operators must quiesce such writers during an accepted apply. Skill
   installed explicitly to `.agents/skills/finishup/` with preview/consent. Codex-readable
   `SKILL.md` frontmatter is limited to `name`, `description`, and optional
   `metadata.short-description`; FinishUP protocol/version compatibility remains in its private
   manifest and is not represented as Codex-readable frontmatter. MCP registration remains a
   separate previewed step, so v0.1 declares no `agents/openai.yaml` MCP dependency.
3. **MCP protocol/SDK:** protocol negotiated (latest published `2025-11-25`, never assumed); SDK
   pinned `mcp==1.30.0`, low-level `Server` surface, `validate_input=False`, direct
   `CallToolResult`, FinishUP-side jsonschema Draft 2020-12 output validation, nested constant
   fallback defined in the MCP error spec.
4. **Transport:** FinishUP-owned `bounded_stdio_server`: 1 MiB payload cap excluding
   LF, ≤64 KiB `os.read` chunks, strict UTF-8, BOM/NUL/duplicate-key rejection, sole stdout
   writer with partial-write loop, zero-capacity AnyIO streams for backpressure. Certified for
   macOS arm64 + glibc Linux x86_64 only; Windows needs a separate gate.
5. **Parse-error ID decision:** when a frame is malformed and no
   request ID is recoverable, FinishUP emits a **manually constructed JSON-RPC 2.0 error frame with
   `"id": null`** through the sole writer (bypassing the SDK's non-null-ID model), with the fixed
   transport error code. If the pinned Codex client is shown by transcript test to mishandle the
   null-ID frame, fallback is orderly transport termination. Never fabricate an ID.
6. **Actor identity:** actor identity is caller-asserted; the server assigns at most
   `self_asserted` for ordinary MCP callers in v0.1. `harness_observed` authorship (and the
   `hook_observed` publication/artifact classes) require a justified observation channel. For
   first-party Codex that channel is the v0.1 `ObservationPort` path — hooks primary, selective
   session-stream reconciliation secondary — once the exact capability cell proves observation and
   workspace-level observation consent is active (ADR-010). A trigger-only hook still observes
   nothing and cannot raise authorship or artifact observation. No inference from display names or
   transcript fields.
7. **Startup budget:** measured cold-start target < 2 s on reference hardware; the release binds
   the acceptable margin to the default observed in every advertised Codex capability cell rather
   than assuming an invariant timeout.

## Capability matrix (must pass from the installed artifact, per pinned version)

User & trusted-project MCP config; same-name config preflight; six tool calls (interactive +
`codex exec`); optional-server failure disclosure; required-server startup failure per supported
Codex surface; duplicate skill-name discovery across loaded roots; parent + subagents attribution; resume/
reattach without duplicates; `--json` JSONL import with unknown-event quarantine; skill discovery
(explicit `$finishup` and implicit); E-013 trigger and observation arms for exact passing profiles
(manual recovery / cooperative-only coverage for absent profiles); observation consent,
ingest/status/pause/resume/revoke, `hook_observed` only from real observation evidence, and
AdviceSnapshot via hooks plus ordinary `status`; cancellation/timeout ambiguous-write retry; stdout purity
under all of the above.

### Structural admission amendment (2026-09-08, issue #656)

Decision 1 is amended for the session-stream reconciler. Exact profiles remain certification:
`SUPPORTED_ROLLOUT_PROFILES`, `CODEX_ROLLOUT_PARSER_PROOFS`, the dogfood parity gate's
`ROLLOUT_PARSER_PROVEN_VERSIONS`, and `rollout_parser_proof()` still name exactly `0.148.0` and
`0.150.1`, and only those may advertise the `session_stream` facet or carry a parser proof. What
changes is admission:

- The session header's `cli_version` is diagnostic provenance, not the parsing gate. An exactly
  proven version selects its certified profile with provenance `exact`. Any other ASCII version
  selects the structural compatibility profile `codex-rollout-jsonl/compatible/v1` (cli_version
  token `compatible`, vocabulary = the union of the exact profiles) with provenance `structural`.
  Routine compatible upgrades therefore keep observation working without a FinishUP release.
- Refusal is structural. A header is refused (`unsupported_codex_profile` →
  `unsupported_format`, durable for the source generation, cursor kept) only when it is not
  `session_meta`, its payload is not an object, `cli_version` is not an ASCII string, or
  `history_mode` is outside `legacy`/`paginated`. IMP-013 now proves that case (unknown
  `history_mode` under a `0.152.1` label); it no longer proves refusal-by-version.
- Unknown structure degrades to bounded per-line gaps under an admitted profile: an unknown
  wrapper or nested item is `unsupported_event` (`unknown_wrapper_type` / `unknown_item_type`), a
  known wrapper with an incompatible payload shape is `wrapper_shape_unsupported`, and neither
  mints an action, result, or pairing identity. Independent known lines keep mapping. Additive
  fields never enter observation envelopes.
- The reader reports a closed admission state per pass beside the persisted profile id:
  `structurally_supported` (exact profile, every line understood), `partially_understood`
  (compatible profile, or any unknown/incompatible line, with the affected reason tokens),
  `incompatible` (refused header or unreadable surface), or `unadmitted`. None of these is host
  support, and none widens receipt or native-host support labels.
- Cursor mapping is `codex-obs-stream/1.4.0`: a cursor durably refused under the exact-version
  policy replays from its header under a fresh generation, reading the refused range once with
  no duplicate publication.
- IMP-014 (`rollout-compatible-0.153.4`) is the differential matrix: the `0.150.1` structure
  relabeled `0.153.4`, additive fields, an unknown independent event, incompatible known wrappers,
  and a truncated tail. Every variant is constructed from the `0.150.1` grammar. **No real
  `0.153.4` transcript was available when this amendment was written**, so the matrix proves the
  admission policy, not the actual `0.153.4` event families; those still need their own fixtures
  before `0.153.4` can become an exact profile or advertise `session_stream`.
- IMP-015 (`rollout-multi-agent-v2-0.153.4`, issue #754) adds those event families: its key shapes
  are transcribed from a real `0.153.4` multi-agent v2 run, with canary values only. Two policy
  consequences follow. `token_usage_record` joins the structural compatibility vocabulary as a
  family FinishUP reads no structural field from — the compatible profile is now the union of the
  exact profiles *plus* such proven ignored families, and no exact profile gains it. A fractional
  JSON leaf (`0.153.4` added `create_time` and `used_percent` to ordinary rows) is normalized to
  `null` in the mapped record instead of refusing its line as `json_profile_unsupported`: no
  structural field FinishUP maps is ever a float, and the line's commitment is still taken over its
  raw bytes. IMP-015 is compatibility evidence, not certification: `0.153.4` still has no exact
  profile, no parser proof, and no `session_stream` facet, and its admission stays
  `partially_understood`.
- Issue #1041 adds one proven ignored item family on the same terms: `HookPrompt`, the
  `event_msg.item_completed` item a Codex 0.159.3 rollout writes when a Stop hook continues the
  turn with a prompt (FinishUP's own closure gate text). It names no tool call and pairs with
  nothing; admitted on the compatibility profile only, it turns an `unsupported_event` gap on every
  gated attempt into a bookkeeping row. No exact profile gains it.

Parser compatibility grants no capture consent, no egress authority, and no AI-powered evaluator
authority.
