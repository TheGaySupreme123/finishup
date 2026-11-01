# ADR-014 — TOML as alternate settings surface and owner-declared OpenAI-compatible endpoints

**Status:** Working decision — implementing against [issue
#2](https://github.com/TheGaySupreme123/finishup/issues/2) under explicit product authorization to ship
the filed design (maintainer ack recorded as implement-now). **Implemented by:**
`src/finishup/config/models.py`, `src/finishup/config/privacy.py`, `src/finishup/config/load.py`,
`src/finishup/config/write.py`, `src/finishup/config/privacy_desired.py`,
`src/finishup/adapters/providers/openai_responses.py`, privacy-setup wizard contract, CLI setup/menu
specs, plus amendments to ADR-006 decision 2 and ADR-009 policy-authority text. **Relates to:**
ADR-006 (AI-powered review provider profiles), ADR-008 (vault), ADR-009 (egress/privacy), ADR-012
(setup wizard), ADR-013 (interactive menu).

## Context

Users asked for:

1. First-run / menu choice between official OpenAI and a custom OpenAI-API-compatible HTTPS URL +
   model, also editable later.
2. A broader guarantee that **TOML is an alternate settings surface**: anything nonsecret that the
   CLI can configure should be editable in `config.toml` without using the CLI.

Today, service-owned `config.toml` covers composition and bootstrap only. Durable privacy policy,
provider destination URLs, credentials, and harness MCP registration live elsewhere (policy store,
hardcoded official host, confidential ceremony, Codex external state). ADR-006 forbids trusting a
generic “OpenAI-compatible” URL; ADR-009 forbids treating post-bootstrap `[privacy]` TOML as
continuing disclosure authority.

## Decisions

1. **TOML holds declarative nonsecret desired state** for service-owned configuration under
   `config/paths.config_file_path()`. CLI and menu are editors/appliers of that state plus
   ceremony wrappers — not a second, richer authority.

2. **Ceremony-only surfaces remain non-TOML** (editing the file must not substitute for them):
   - provider credential bytes and vault passphrase / unlock / initialize;
   - human presence / trusted **widening** decisions for privacy policy;
   - Codex MCP registration and skill install (external-state mutation; preview→confirm→verify);
   - process lifecycle and workflow operations;
   - setup-wizard completion marker (operational state).

3. **Owner-declared OpenAI-compatible endpoint is an exact profile kind**, not a free `base_url`
   on ordinary `ProviderProfileConfig`. Identity:
   `endpoint_profile_id=owner-declared-openai-responses` with a versioned capability cell that
   reuses the Responses structured-judgment protocol. Owner supplies only a constrained
   `https_origin` (HTTPS, host, optional port; no userinfo/query/fragment; path fixed by profile
   to `/v1/responses`) plus `model` in TOML under `[provider.owner_declared_endpoint]`. Official
   OpenAI remains the bundled preset host `api.openai.com`. Data-use facts for owner-declared hosts
   default to `unknown` and never inherit the upstream `assisted` recommendation badge.

4. **Durable privacy policy gets a TOML desired-state path** (`finishup privacy export-desired` /
   `apply-desired`, schema `yoetz.privacy-desired/1`) that maps onto existing `propose` /
   `tighten` / `decide` gates. File edits alone never silently widen egress; tighten/equivalent
   classification is reported and routed to the existing tighten gate; widen always requires the
   trusted decide path. First-run `[privacy]` bootstrap seed remains generation-1-only and is not
   continuing disclosure authority.

5. **Setup UX:** the ADR-012 wizard (interactive) and ADR-013 menu “LLM provider” offer Official
   OpenAI vs Custom origin+model (nonsecret), write service TOML via `finishup provider endpoint` /
   shared helpers, then point at the existing credential ceremony. Neither surface accepts secrets.

## Consequences

Users can fully manage nonsecret install settings from an editor, including switching between
official OpenAI and a custom HTTPS origin, while secrets and widening stay honest. ADR-006 gains
one exact owner-declared profile kind; ADR-009 gains desired-state apply semantics that cannot
silently widen. Capability evidence for live owner-declared hosts remains an OPEN_QUESTIONS gate
(protocol cell + fail-closed URL validation ship now; live probe optional).

## Alternatives considered

**Free `base_url` on `ProviderProfileConfig`.** Rejected: contradicts ADR-006 decision 2 and the
current secret/locator denylist posture.

**Release-bundled alternate hosts only.** Rejected: does not meet self-serve custom URL.

**TOML silently overwrites durable privacy policy.** Rejected: would make a world-readable config
file into continuing egress authority without trusted-local widening.

## Evidence / remaining gates

- Config unit tests: constrained `https_origin`, secret rejection, official vs owner-declared
  mutual exclusion, TOML round-trip.
- Privacy desired-state round-trip + widen≠tighten classification.
- Live owner-declared host probe remains optional evidence; until present, releases must not claim
  verified interoperability beyond the protocol cell and destination validation.
