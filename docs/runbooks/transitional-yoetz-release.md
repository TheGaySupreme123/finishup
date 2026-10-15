# Transitional `yoetz` distribution release

FinishUP shipped as Yoetz through 0.2.5. For one release after the rename, every tagged FinishUP
release also publishes a deprecated `yoetz` distribution to PyPI and npm at the same version
([ADR-048](../adr/ADR-048-finishup-rebrand-and-frozen-legacy-identifiers.md) §4). Released update
checks and 0.2.x upgrade commands still name `yoetz`; without the transitional distribution,
those paths cannot reach FinishUP. Exact-pinned installs additionally need the explicit
requirement replacement described in the [upgrade guide](../usage/upgrading.md#upgrading-from-yoetz).

This runbook is for the maintainer cutting a release. The account and registry steps it names are
also tracked on [issue #1056](https://github.com/TheGaySupreme123/finishup/issues/1056).

## What is published

| Artifact | Source | Contents |
|---|---|---|
| PyPI `yoetz==<V>` | `release/transitional-yoetz/python/` | Depends on exactly `finishup==<V>`, re-exports the `portable-recovery` and `semantic-openai` extras as `finishup[extra]==<V>`, declares only the `yoetz` console script (`finishup.cli.entry:main`), and ships a small `yoetz` import shim for `python -m yoetz` and the legacy release-runtime bootstrap. No product code. |
| npm `yoetz@<V>` | `release/transitional-yoetz/npm/` | A delegation-only launcher: `uv tool install yoetz==<V>` (never `--force`), then runs it. |

The `finishup` wheel and npm package must never declare a `yoetz` command, and the transitional
distribution must never declare `finishup`: either collision makes `uv tool install` of the other
name fail with "Executables already exist". The first FinishUP version must be greater than the last
Yoetz version (0.2.5).

## One-time registry setup

Do these once, before the first tag that carries the transitional jobs. Without them the publish
jobs fail and so does `release-required`.

1. **PyPI.** On the existing `yoetz` project, add a Trusted Publisher for this repository, workflow
   `release.yml`, environment `pypi` — the same triple the `finishup` project uses. After the
   repository rename, confirm both projects name `TheGaySupreme123/finishup`.
2. **npm.** Confirm the maintainer account still owns the `yoetz` package, then configure Trusted
   Publishing for it with workflow `release.yml` and environment `npm`. npm provenance compares
   `repository.url`, so publish only after the repository rename.
3. Keep `yoetz.dev` registered and serving `https://schemas.yoetz.dev/0.1/`: released schema `$id`s
   are immutable hosted routes (ADR-007), and the release workflow publishes and re-fetches them
   there.

## Release workflow jobs

`release.yml` adds four jobs; none of them rebuilds an approved artifact.

- **`build-transitional`** (after `build-candidate`): checks the transitional sources are in
  lockstep with the release (`scripts/check_transitional_yoetz.py`), builds the sdist and wheel
  twice from clean exports and records `TRANSITIONAL_REPRODUCIBILITY.txt`, inspects the members and
  the single alias script (`--dist`), smoke-tests an install from the exact local `finishup`
  candidate, attests build provenance, packs and inspects the npm tarball, and uploads
  `transitional-candidate-<V>` and `transitional-npm-candidate-<V>`.
- **`approve-publication`** binds the transitional Python and npm digests into the same approval as
  the `finishup` artifacts.
- **`publish-transitional-pypi`** runs after `publish-pypi` (the package pins `finishup==<V>`, which
  must already be live). It verifies the digest, refuses a version already on PyPI unless the bytes
  reconcile exactly for recovery, and publishes through Trusted Publishing.
- **`publish-transitional-npm`** runs after `publish-transitional-pypi`, with the same digest and
  registry preflight, and publishes the exact tarball with `--access public`.
- **`verify-transitional-published`** waits for both registries, compares the public bytes with the
  candidates, installs the public `yoetz` distribution and requires both `yoetz --version` and
  `finishup --version` to print exactly `<V>`, and checks that the public npm launcher delegates to
  the same version.

`publish-github-release` attaches `TRANSITIONAL_SHA256SUMS`, `TRANSITIONAL_NPM_SHA256SUMS` and
`TRANSITIONAL_REPRODUCIBILITY.txt`. Per-PR CI builds the transitional distribution and runs the
lockstep check on every change, and rejects symlinks under `release/`.

The publish jobs run only on a real tag. Before the first such tag, exercise `build-transitional`
with a `workflow_dispatch` dry run; until then the workflow is verified by inspection and static
contract tests only.

## After publishing

- Update the PyPI and npm `yoetz` project descriptions to point at `finishup`. Running `npm
  deprecate yoetz@<old versions>` is a separate maintainer decision.
- On separately pinned test instances representing both an unpinned and an exact-pinned 0.2.5
  uv tool, verify the released stop-first procedure and preserve the launcher path, settings,
  registrations and recorded data. The released command runs `uv tool upgrade yoetz`, retains
  an exact `==0.2.5` constraint and does not verify the result. Confirm that such a command does
  not establish an upgrade, then exercise the explicit `uv tool install --upgrade 'yoetz>=0.3.0'`
  route with the original extras, Python request and resolution options. For npm, exercise the
  current transitional `yoetz@<V>` launcher rather than an old installed or cached 0.2.x launcher.
  Do not apply these probes to the maintainer's live install; its separately authorized
  verification remains on #1056.
- After replacement, confirm the `yoetz` command runs FinishUP, `yoetz --version` prints the bare
  version, and hosts keep working before they are reconnected. On that install only `yoetz` is
  on `PATH`; also confirm that the update tip names `yoetz upgrade`, that a second `yoetz upgrade`
  ends with the *Move from the yoetz name* step and carries over the tool's extras, and that
  `yoetz consent catalog` prepare hints start with `yoetz`.

## Removing the alias

The alias ships for one release. A later release removes `release/transitional-yoetz/`, the four
transitional jobs, the per-PR step and the launcher alias recognition, and only after status reports
no host still bound to a legacy launcher. That release must also make status point a remaining
`yoetz` tool at the move to `finishup`, because that tool's own `yoetz upgrade` will report it is
already current from then on. The permanent legacy readers in ADR-048 §3 stay.
