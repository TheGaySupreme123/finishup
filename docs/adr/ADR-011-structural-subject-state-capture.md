# ADR-011 — Structural subject-state capture has one narrow local owner

**Status:** Working decision for spec drafting (2026-07-17). Ratification requires the Git-state
capability matrix and privacy/path-canary tests from an installed artifact.
**Implemented by:** `src/finishup/ports/subject_state.py`,
`src/finishup/adapters/git_subject_state.py`, `src/finishup/domain/values.py`,
`src/finishup/domain/events.py`, and the CLI/capability/subprocess suites.
**Relates to:** ADR-002 (canonical protocol), ADR-005 (Codex capability identity), ADR-009
(local privacy boundary), and ADR-010 (harness integration).
**Amended by:** ADR-031, which lets the service read one check-time change for AI-powered review
through this adapter's hardened runner and root fences. This ADR's own capture stays
content-withholding and client-local.

## Context

The v0.1 integrity policy can detect verification evidence that predates a later material edit only
when both publications carry comparable `SubjectStateRef` digests. The protocol and kernel already
define that comparison, but the draft left production of those digests to cooperating agents. The
worked stale-evidence story therefore depended on a value with no deterministic capture owner.

General live repository inspection remains too broad for v0.1: it would need source-selection,
content-return, symlink/submodule, consent, redaction, and AI-powered review contracts. Freshness
does not require that breadth. It needs a local, content-withholding structural fingerprint that can
say whether two material actions referred to the same repository state.

## Decisions

1. **`SubjectStateCapturePort` owns structural capture.** The port accepts one explicit trusted
   local workspace handle plus closed capture options and returns a `SubjectStateRef` or a bounded
   unavailable result. `GitSubjectStateAdapter` is the only v0.1 implementation.
2. **Capture is a client-local support capability, not a seventh workflow operation.** The CLI
   exposes `finishup state capture`; it performs no ledger write and may be used by a harness before a
   normal `publish_work` call. MCP still exposes the six workflow tools plus read-only
   `read_guidance` and `closure_prepare` support tools; capture is not an MCP tool.
3. **The adapter reads only enough local Git/worktree state to hash it.** It emits no source bytes,
   diff, filename, absolute/relative path, branch, remote, author, commit message, environment, or
   command output. Intermediate Git output and file bytes are streamed into bounded hashers and
   discarded before the result is rendered.
4. **The digest algorithm is versioned and fail-closed.** `yoetz.git-subject-state/1` commits to the
   repository object-format identity, HEAD state, staged delta, tracked worktree delta, and included
   untracked-file set. The adapter disables external diff/textconv/fsmonitor behavior, never runs a
   shell, and returns `state_not_observed` for unsupported repositories, submodules, unsafe paths,
   changing input, or exceeded caps. Partial state never receives a `tree_digest`.
5. **Capture does not upgrade provenance.** Publishing the result over cooperative MCP remains
   `cooperative_mcp`/`self_asserted`; a trigger hook still earns no observation coverage. A complete
   local capture may justify `content_digest` evidence immutability, but never
   `harness_observed`, `artifact_verified`, or `independently_reproduced` by itself.
6. **General artifact inspection stays deferred.** This ADR authorizes no content-returning read,
   AI-powered review fetch, repository browser, broad source capture, or ambient workspace search. A
   future `ArtifactInspectionPort` still requires its own ADR. ADR-031 is that decision for exactly
   one object, the check-time change, and authorizes nothing broader.

## Consequences

The stale-after-edit policy has an explicit, testable source for comparable state digests without
turning FinishUP into a code-review or repository-browsing tool. Users and agents can decline or fail
capture; the receipt then reports weak/unknown freshness rather than fabricating unchanged state.

The CLI gains one local support command and two future Python modules. The command is intentionally
outside the trusted persistent service because the service owns task truth and secrets, not ambient
repository paths. The installed CLI import boundary allows only this exact read-only adapter in the
state-capture command path.


## Amendment (issue #1040 follow-up, tb4n5): no global configuration on any supported Git

The hardened runner's "no global or system config" relied on `GIT_CONFIG_GLOBAL=/dev/null`, which
only Git 2.32 and later honour, while it set `HOME` to the workspace root. On an older Git (2.25 is
the supported minimum, ADR-031's #1040 amendment) a `.gitconfig` committed to the repository was
therefore read as Git's global configuration, and a filter driver defined there ran during this
capture's `git diff` of the working tree. The runner now also sets `HOME` and `XDG_CONFIG_HOME`
to `os.devnull`, so no global configuration is read on any supported Git; a `~` in a repository's
own path settings expands under `os.devnull` and names nothing. `core.fsmonitor` is pinned to the
empty value, which disables it on every Git (`false` was run as a hook command before Git 2.36).
`rev-parse` queries no longer use `--path-format` (Git 2.31): `--show-toplevel` and
`--absolute-git-dir` print absolute paths on every supported Git. A system Git older than 2.25 is
refused as `git_version_unsupported` before the workspace is opened; `finishup state capture` prints
that token with its remedy.
