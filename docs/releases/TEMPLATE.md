# FinishUP vX.Y.Z — one-line release name

<!--
Curated release-notes conventions (docs/releases/).

- One file per tag, named exactly `<tag>.md` (for example `v0.2.0.md`), committed before the tag
  is pushed. `validate-release-source` fails fast when the tagged commit does not carry the file,
  and the `github-release` job takes the GitHub release title from this file's first-line H1 and
  the release body from everything after it — never edit the workflow for a new release.
- This template file itself is never published; the workflow reads only the file matching the tag.
- Shape: summary on top, firehose below. Open with one short narrative paragraph — the concrete
  failure mode this release removes or the capability it adds — then curated Highlights, then the
  exhaustive per-PR list and compare link at the very bottom.
- "What this release does not claim" is not fine print. Keep the section, and keep it accurate
  against `docs/public-claims.json` and `docs/OPEN_QUESTIONS.md`; a claim absent from those files
  must not appear here as a stronger statement.
- Thank external contributors by name whenever there are any.
- Relative links do not resolve from a GitHub release body: link into the repository with
  absolute `https://github.com/TheGaySupreme123/finishup/blob/<tag>/...` URLs pinned to the tag.
-->

One short paragraph: what can no longer go wrong, or what is now possible, and for whom.

## Highlights

- **Bolded capability or fix:** one plain-English sentence on what it does and why it matters,
  with issue/PR references. (#NNN)

## What this release does not claim

- Bounded statements of what remains unverified, untested, or deferred, mirroring
  [`docs/public-claims.json`](https://github.com/TheGaySupreme123/finishup/blob/vX.Y.Z/docs/public-claims.json)
  and
  [`docs/OPEN_QUESTIONS.md`](https://github.com/TheGaySupreme123/finishup/blob/vX.Y.Z/docs/OPEN_QUESTIONS.md).

## Install

```text
uv tool install --managed-python --python 3.14.6 "finishup==X.Y.Z"
```

For a one-off run: `uvx "finishup==X.Y.Z"`. With `uv` already installed: `npx finishup@X.Y.Z` (the npm
package is a dependency-free launcher for the exact PyPI distribution).

## Release integrity

How to verify the artifacts: point at the attached `SHA256SUMS`, `NPM_SHA256SUMS`, SBOM, support
matrix, known limitations, release-evidence bundle, and `VERIFY.md`. While the deprecated `yoetz`
alias ships (ADR-048), also name `TRANSITIONAL_SHA256SUMS`, `TRANSITIONAL_NPM_SHA256SUMS` and
`TRANSITIONAL_REPRODUCIBILITY.txt`, and keep an "Upgrading from Yoetz" note under Install.

## Thanks

Thank you to the community contributors in this release: @name (#NNN).
(Delete this section when a release has no external contributions.)

## Full changelog

Curated notes above; the complete list of merged changes:

- Per-PR list (the GitHub "generate release notes" output is fine here).

**Full Changelog**: https://github.com/TheGaySupreme123/finishup/compare/vPREV...vX.Y.Z
