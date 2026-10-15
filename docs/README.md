# FinishUP documentation

## Start here

- [Using FinishUP](usage/) — install, first run, the six operations, privacy, providers, receipts.
- [Architecture](architecture.md) — how the system is put together and why.

## Authority

Resolve questions about public behavior in this order:

1. [`docs/adr/`](adr/) — the architecture decisions.
2. [`docs/INTERFACES.md`](INTERFACES.md) — shared names and trust boundaries: ID prefixes, error
   codes, event families, coverage enums, port signatures.
3. The code and its tests.

For exact wire shape and byte identity, the JSON Schemas under [`schemas/`](../schemas/) and the
golden vectors under [`fixtures/`](../fixtures/) win over any prose, including these pages.

## Reference

- [`docs/OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md) — the decision ledger: every decision taken, each
  release gate's dated disposition, including the current 0.2 release line, and what evidence a
  stronger claim would need.
- [`docs/protocol/`](protocol/) — the technical protocol: compatibility, data egress and privacy,
  local service security, the privacy setup wizard.
- [`docs/runbooks/`](runbooks/) — operational procedures: backup/restore, key recovery, migration
  rollback, quarantine recovery, Codex integration, Claude Code integration, Cursor integration,
  the Codex subscription AI-powered evaluator, portable plugin authoring/lifecycle, AI-powered
  review dogfood,
  exact-worktree Codex dogfood parity, influence dogfood, Linux/WSL host facts, and the
  transitional `yoetz` distribution release.
- [`docs/public-claims.json`](public-claims.json) — every public claim bound to its requirements,
  surfaces, tests, and honest release status. Enforced by `tests/conformance/claims/`.
- [`docs/releases/`](releases/) — curated release notes, one file per tag; the release workflow
  publishes the tag's file as the GitHub release title and body. Conventions in
  [`TEMPLATE.md`](releases/TEMPLATE.md).
- [`guidance/`](../guidance/) — agent-facing guidance, shipped byte-identically to every harness and
  over MCP.

## Root documents

[`README.md`](../README.md) · [`PRIVACY.md`](../PRIVACY.md) · [`SECURITY.md`](../SECURITY.md) ·
[`CONTRIBUTING.md`](../CONTRIBUTING.md) · [`AGENTS.md`](../AGENTS.md) ·
[`CHANGELOG.md`](../CHANGELOG.md) · [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md)
