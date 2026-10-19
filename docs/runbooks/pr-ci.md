# Pull request CI

`.github/workflows/pr-ci.yml` runs on pull requests targeting any branch, including `0.3` and
feature branches in a stack. Opening, updating, reopening, marking ready, or editing a PR starts
the workflow; editing includes a change of base branch. Pushes to `main` and `0.3` also run it.
`pr-ci-required` is the stable aggregate: every predecessor, including each matrix cell, must
succeed. Skipped, cancelled, or failed predecessors fail the aggregate.

## Current coverage

- Contracts and resources: the generated resource fixed point, transitional distributions,
  append-only released contracts, public boundary, and protocol/kernel tests under two hash seeds.
- Format, lint, and types: repository-pinned Ruff and npm Pyright, metadata/JSON hygiene, and
  checksum-verified actionlint 1.7.12 for every workflow. Workflow validation failures are fatal.
- Unit, property, and conformance tests on CPython 3.14.6, plus Python 3.12 and 3.13.
- Candidate wheel and sdist installation on Python 3.12, 3.13, and 3.14.6 with uv 0.11.29 and
  0.13.1. Each cell checks the actual interpreter and runs the installed CLI outside the checkout.
- All integration families: storage, objects, application, closure, observation, providers,
  service, and privacy. Each family has its own job so new tests in these trees are included
  without maintaining a list of individual files.
- CLI/MCP subprocess parity, the glibc/Git image smoke, and package construction/inspection.
  The subprocess job also exercises the local MCP SDK/protocol capability cases against the
  installed candidate, excluding live host/model activation.
- The portable console boundary on Ubuntu, macOS, and Windows runners. This adapter-only check
  does not claim native Windows runtime support.

Fault, kill-matrix, soak, and live-provider cases stay outside the bounded PR integration profile.
Separate security/privacy checks retain their path filters and now accept every PR target.
Capability and nightly fault workflows keep their existing separate roles.

## Toolchain and isolation

ADR-007 permits Python `>=3.12,<3.15` and uv `>=0.11.29`. Ordinary correctness and reproducible
release jobs deliberately retain uv 0.11.29 and the certified CPython 3.14.6 release cell. The
installer matrix additionally exercises the current reviewed uv version; update that explicit pin
when reviewing newer uv behavior. Compatibility smoke success does not certify another release
cell or prove every future uv release works.

The MCP SDK pin is 1.30.0, including the fix for CVE-2026-59951. Exact required SDK cells use the
`v0.3-mcp-1.30.0` capability profile. The security workflow audits the source lock and an explicit
inventory of the installed candidate's dependencies, excluding only the unpublished FinishUP
distribution itself; it does not treat an empty virtualenv-root scan as dependency coverage.

`scripts/ci/prepare_test_environment.sh` gives each Linux test job a private home and mode-0700
pytest base directory under the runner's temporary directory. Packaging receives isolation before
any tests run. Commands that launch services or installed CLIs unset both inherited isolation-root
variables, leaving each test responsible for its own instance. No job uses the maintainer's live
installation or provider credentials.

The observation integration job installs Ubuntu's Bubblewrap package and proves that its real
no-network launch works. If Ubuntu's AppArmor user-namespace restriction still blocks that probe,
the job relaxes that restriction on its disposable runner and probes again. Failure still fails
the job; there is no unsandboxed fallback. Shared setup creates each scanned XDG directory before
the runtime privacy sweep, so an unused directory is empty rather than a missing scan target.

Synthetic privacy regression controls are assembled at runtime. Their runtime bytes and assertions
remain intact while the tracked source passes the public-boundary scanner. Do not exempt whole
test trees or weaken scanner rules to admit a test fixture.

## Dogfood and rollout

[Dogfood](dogfood-ci.md) is manually dispatched. PR events, labels, branch pushes, and schedules
do not start it. Do not require `dogfood-required` as an automatic merge check.

Workflow edits take effect on the refs that contain them. Existing PR branches need the updated
workflow in their candidate tree and a fresh PR event; editing a local workflow does not backfill
missing checks. The Dogfood schedule uses the default branch, so that branch must also receive the
manual-only workflow before automatic dogfood can be considered removed repository-wide. A
temporarily disabled GitHub workflow must be re-enabled before manual dispatch is available.
