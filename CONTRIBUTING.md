# Contributing to FinishUP

FinishUP was previously called Yoetz. Issues, pull requests and history from before the rename still apply.

Thank you for considering a contribution. External work is welcome when it meets a high bar: this
project is **open with rigor**, not invitation-only and not closed to contributions.

## Authority order

For anything touching public behavior, resolve in this order:

1. [`docs/adr/`](docs/adr/) — architecture decisions;
2. [`docs/INTERFACES.md`](docs/INTERFACES.md) — shared names, types, ports, and trust boundaries;
3. the code and the tests that lock it.

For exact wire shape and byte identity, the JSON Schemas under [`schemas/`](schemas/) and the golden
vectors under [`fixtures/`](fixtures/) win over any prose. [`docs/architecture.md`](docs/architecture.md)
is the fastest way to find which module owns what.

Do not invent behavior that contradicts those authorities. When behavior changes, update the ADR or
the affected `docs/` page in the same change — a new field, a changed error code, or a different
check outcome is a documentation change too.

## Before you write code

1. **Search for duplicates** in issues and pull requests. Do not open a second thread for the same
   problem.
2. **Open an issue first** using the bug report or change request form. A pull request without a
   linked issue is incomplete and may be closed or converted to an issue.
3. **Wait for acknowledgement** when the work is design-gated. Design-gated areas are:
   - protocol contracts;
   - privacy and data-egress behavior;
   - storage and durability;
   - release pipelines and packaging surfaces;
   - new ADRs or flips in [`docs/OPEN_QUESTIONS.md`](docs/OPEN_QUESTIONS.md).

   Maintainer acknowledgement on the issue is required before you open a PR in those areas. An
   explicit maintainer request for the scoped work counts: record it on the issue without asking
   again. It does not authorize runtime, credential, disclosure, or destructive actions. Docs
   clarifications, typo fixes, and narrowly scoped bugfixes outside those areas may proceed once the
   issue exists.
4. Use the exact names already registered in [`docs/INTERFACES.md`](docs/INTERFACES.md) for anything
   shared across modules; add a name there first if it doesn't exist yet.

## Local setup

This project uses `uv` for environment, lock, and build management, pinned per
[`pyproject.toml`](pyproject.toml). Typical loop:

```text
uv sync
uv run pytest <path-to-touched-tests>
```

The pinned toolchain is Ruff for lint/format and the official npm-distributed Pyright
(`npx --no-install pyright`) in strict mode for type checking; Node/npm are contributor and CI
prerequisites only, never an end-user runtime requirement.

### Testing against a real installed FinishUP without touching your own

When a change needs an installed launcher, a running service, a host registration, or an upgrade
path — not just `uv run pytest` — provision an independent test instance instead of using your
everyday installation:

```text
uv run python scripts/provision_test_instance.py create --tag <name> --lifecycle disposable
uv run python scripts/provision_test_instance.py dispose --tag <name>
```

It builds a wheel from the exact revision, installs it into its own runtime, and pins that runtime
to its own root, service, and vault, so it can never reach the everyday install even when a host
drops the environment. Procedure, constraints, and concurrency rules:
[`docs/runbooks/test-instances.md`](docs/runbooks/test-instances.md) (ADR-028).

### Packaged resource ripple

Resource inventory changes feed the package manifest, version-manifest schema, schema inventory,
runtime-support digest, packaged byte mirrors, and both committed Codex agent trees. Do not run those generators in a hand-selected
order — a wrong order leaves a stale artifact that is still internally byte-consistent, so no byte
parity check can see it. After adding, removing, or changing a packaged resource inventory entry
(or any file one of those entries points at), run:

```text
uv run python scripts/sync_resource_ripple.py --write
uv run python scripts/sync_resource_ripple.py --check
```

The write command repeats the complete dependency sequence until the owned bytes reach a fixed
point, then runs the same read-only checks as CI. Those checks include building the installed
version manifest and validating it against the generated version-manifest schema, which is what
catches a stale cardinality constant locally instead of in CI. When the number of inventory entries
changes, review and update the single `REVIEWED_RESOURCE_COUNT` tripwire in `src/finishup/version.py`
before running it; every per-kind count and generated cardinality is derived from the manifest
entries. Every file beneath `schemas/`, `migrations/`, `skills/`, `guidance/`, `fixtures/`, and
`support/` must be either an inventory entry or under a declared repository-only prefix in
`scripts/verify_resource_manifest.py`; otherwise the check fails with `source_unpackaged` rather
than letting a committed vector silently miss the wheel.

After the package digests converge, the same command renders `.agents/plugins/finishup` and
`.agents/skills/finishup` through the supported integration renderers, including their ownership
markers. Their complete file sets participate in the fixed point and in CI's `--check`. Edit
`guidance/`, `skills/codex/finishup/`, or the owning integration renderer, then run the command above.
Agent-only drift reports those canonical owners and the same remediation. Repository generation
uses only these two checkout-relative destinations. Preflight refuses linked paths and foreign
files before any package resources or committed agent trees are written;
obsolete generated members can be removed only when their previous marker still binds their
bytes. Normal installers retain their existing modified/foreign-tree protections.

## Making a change

- Make the smallest change that satisfies the decision and its tests.
- Run the tests for the area you touched, not the whole suite by default:
  - `tests/unit/` for the touched module family;
  - `tests/conformance/` when your change crosses a runtime or storage boundary;
  - `tests/packaging/` when your change affects release artifacts or public metadata;
  - `tests/property/`, `tests/integration/`, `tests/subprocess/` as the change warrants.
- Avoid mixing unrelated behavioral changes into one patch.
- Host payload contract: every host adapter has, for each event type it consumes, at least one
  test driven by a host payload fixture under `fixtures/`, fed to the real hook handler exactly
  as the host delivers it. Never test an adapter with a pre-normalized envelope or an invented
  field (such as a top-level `exit_status` Codex never sends). Each fixture states its
  provenance — a raw hook stdin capture, or a shape derived from a recorded rollout or the host's
  documentation — and whether a raw capture is still pending; a derived shape is replaced by a
  capture when one is made. `tests/unit/cli/test_host_outcome_contract.py` enforces this for
  every tool-result event (issue #910).
- Keep release-related and security-sensitive changes clearly labeled in your commit/PR description.
- Preserve the public/private boundary: nothing under `docs/architecture/` or any other gitignored
  local drafting input belongs in a public file. `scripts/scan_public_boundary.py` enforces this.
  The tracked root `CLAUDE.md` is a reviewed public alias only while its complete bytes remain
  exactly `@AGENTS.md\n`; changing its content, nesting another copy, or packaging it fails closed.

## Honesty rules that bind every change

These are not style preferences. They are why the product is worth using, and CI locks them.

- Verification language is coverage-bounded: "no issue detected at coverage X" is never rendered as
  "verified".
- Every retryable write has an idempotency identity; a timeout never proves failure.
- Nothing user-controlled — payloads, titles, paths, prompts, model output — appears in SQLite
  structural tables, logs, errors, or MCP text summaries.
- Local-check behavior depends only on canonical recorded inputs plus versioned policy/engine.
- AI-powered output is advisory, provenance-labeled, and deterministically fenced.
- `semantic_required` never erases a completed local-check result: unavailability returns that
  result as `incomplete_check` with an exact gap.
- Every network channel is independently authorized. No profile overrides the never-send set, and
  effective policy loosens only through a reauthenticated decision the user makes: the trusted local
  ceremony, or the user's explicit current-chat approval of one exact prepared consent target
  relayed by a capable agent.

## Pull request checklist

Use the repository pull request template. Every PR must:

1. Link the prior issue (`Fixes #N` or `Refs #N`).
2. Confirm duplicate search and, for design-gated work, maintainer acknowledgement on that issue.
3. List the docs updated when behavior changes (ADR, `docs/` page, `docs/INTERFACES.md` entry).
4. Paste the verification commands you ran.
5. Confirm the public/private boundary check.
6. Disposition every review comment before merge (see below).

## Review comment disposition

Every human reviewer comment and every code-review-agent comment must be handled before merge:

- **Fix it**, or
- **Reply** explaining why the comment is invalid or out of scope.

Silence, ignoring a thread, or "will do later" without maintainer agreement is not merge-ready.

## What not to do

- Don't open a PR without a linked issue and duplicate search.
- Don't hand-edit a generated or frozen artifact (a lock file, a generated schema mirror, a release
  manifest) — regenerate it through its owning script. For the resource/schema graph, the owning
  entrypoint is `scripts/sync_resource_ripple.py`.
- Don't invent a second formatter, linter, or type-checker configuration; the pinned tools in
  `pyproject.toml` and the development-only `package.json` are the only ones this project uses.
- Don't add a new distribution surface without design-gate acknowledgement. The end-user install
  path is Python/`uv` (see [`README.md`](README.md)); the one reviewed exception is the
  delegation-only npm launcher at `support/npm-launcher/` (ADR-012). Its deliberate public-release
  decision is recorded for v0.1.0 in issue #366; later changes must keep it version-locked to PyPI,
  dependency-free, and inside the protected tagged-release workflow.

## Security and conduct

Please don't file a security vulnerability as an ordinary issue — see [`SECURITY.md`](SECURITY.md).
Conduct concerns go to the contact in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), not a public issue
or the security channel.
