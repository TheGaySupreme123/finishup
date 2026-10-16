# ADR-031 — The service captures the check-time change as one reviewed object

**Status:** Accepted for issue #883. The maintainer asked for this scoped work in the issue's
2026-09-29 acceptance boundary (items 1 and 3) and recorded the design-gate acknowledgement for
the privacy/egress and storage changes it needs.
**Implemented by:** `src/finishup/ports/change_capture.py`,
`src/finishup/adapters/git_change_capture.py`, the public seam of
`src/finishup/adapters/git_subject_state.py`, `src/finishup/application/check_change.py`,
`CheckTimeChange` and `_check_time_change_reservation` in `src/finishup/application/semantic_case.py`,
the reason codes and sentences in `src/finishup/domain/receipts.py`, the semantic evaluator in
`src/finishup/service/ready_composition.py`, `start`/`check` in `src/finishup/application/service.py`,
the task-base root in `src/finishup/adapters/sqlite/repository.py` and
`src/finishup/adapters/memory/ledger.py`, the shown-file record (`CheckChangeShownFiles` in
`src/finishup/domain/events.py`) and resolution rule (`src/finishup/kernel/finding_resolution.py`,
`src/finishup/kernel/projections.py`), and the suites `tests/unit/adapters/test_git_change_capture.py`,
`tests/unit/application/test_semantic_case_check_change.py`,
`tests/unit/application/test_check_time_change_facade.py`,
`tests/unit/application/test_semantic_case_packet_completeness.py`,
`tests/integration/service/test_check_time_change.py` and the ledger conformance suite. The Git
range (#1040 amendment) is `src/finishup/adapters/git_version.py` and
`src/finishup/adapters/git_rev_parse.py`, held by `tests/unit/adapters/test_git_old_versions.py` and
`scripts/ci/service_image_smoke.sh`.
**Relates to:** ADR-006 (AI-powered review packet), ADR-008 (service trust boundary), ADR-009
(egress), ADR-011 (structural subject-state capture), and issues #883, #904, #907, #920, #1040,
#1045.

## Context

The review packet was built only from ledger text and observation captures. Captures cover the
edits a host exposes as visible tool input. They miss edits made by scripts (`sed -i`, Python
rewrites, `git apply <file>`), commits, hooks that did not fire or were not admitted, and every edit
under Cursor's ordinary profile, which does not subscribe `afterFileEdit`. In the DeepSWE v2 run a
repair made with 34 shell rewrites and no `apply_patch` reached the reviewer only as the agent's
digest, and the reviewer judged the pre-repair code.

ADR-006 decision 12 and ADR-011 decision 6 kept every repository read out of the service: a
content-returning read needed its own decision. This is that decision, for exactly one object.

## Decisions

1. **One object per check, captured by the service.** When a check's AI-powered review recipe
   selects diff excerpts (`targeted_excerpts`, a positive excerpt count and the `diff` kind), the
   service renders the change from the task base to the working tree: committed, staged and
   unstaged changes to tracked files, plus untracked files Git does not ignore (`.gitignore`,
   `.git/info/exclude` and the owner's global Git ignore file). A short header names the base,
   the counts and every changed file with its line counts, and says which files are not shown and
   why. This covers script edits, commits and missed hooks on every host at once. Because the base
   is a commit, uncommitted or untracked work that already existed when the task started is part of
   the change too, and the header says so. A recipe without diff excerpts captures nothing and
   reports nothing, exactly as it declines any other excerpt.
2. **Only the check's own repository.** The capture reads only the locator the check's
   authenticated control connection supplied at handshake. The service keeps that locator in
   memory beside the repository commitment it derived from it, for the life of the connection
   only; it is never stored, logged or returned. The capture runs only when that commitment equals
   the task route's own. Request bodies, environment variables and ambient discovery never select
   a directory.
3. **The task base is the commit HEAD named when the task was created.** A `start` that creates a
   task (including a delegated child) records it before its result returns, so no agent edit or
   commit precedes it. An empty repository records the empty tree. The base is an encrypted
   `change_capture` object; the task bundle keeps its pointer in `bundle_meta` and inventories the
   object as a root. Attach and resume never record a base, because a later base would silently
   hide the commits made in between. A task without one (created before this decision, or whose
   start base could not be recorded) gets it from its first check instead: that check records HEAD
   through the same seam as a `first_check` base, and every later check of the task diffs from it,
   so work committed between checks stays in the change and files keep matching across checks. The
   header names that commit, and every such check still reports
   `check_time_change_base_unavailable`, because work committed before that first check is not in
   the change. Only when no base can be kept or resolved is the change shown against HEAD.
4. **Read-only and bounded.** Git runs through the ADR-011 hardened runner: no shell, no global or
   system config, hooks, fsmonitor, external diff, textconv or credential helper, and every diff
   passes `--no-ext-diff --no-textconv`. Git transports are disabled, replace refs are ignored
   (`--no-replace-objects`) and partial clones are refused, so a capture never fetches. The ADR-011
   root and metadata fences apply (a real `.git` directory, no alternates). Because a diff against
   the working tree runs any `clean` filter the repository defines, the capture also asks Git for
   its whole effective configuration (`git config --list --name-only --includes --show-origin`) and
   refuses any `filter.*`, `include.*`, `includeIf.*` or partial-clone key, from whichever file or
   include it came; only the runner's own command-line values are exempt. A Git that cannot answer
   makes the capture unavailable rather than taken without the check. (This first used
   `--show-scope`, which needs Git 2.26; see the #1040 amendment.) The effective-config check and
   the diffs are separate Git calls, so a filter written into the repository config between them
   would run; only a process of the same user can do that, and that user can already run code as
   itself, so this window is low severity. The read has these fences:
   - **The validated root, and only it.** Discovery accepts a directory only when the repository
     Git finds for it has its `.git` directly beneath the top level it reports and the directory
     lies inside that top level, so a `core.worktree` that points one repository's metadata at
     another directory is `unsafe_root`. Every capture Git call then names the validated `.git`
     and working tree explicitly (`--git-dir`, `--work-tree`), Git must report exactly those two
     paths before anything is read, and an effective `core.worktree` at any level is refused as
     `unsupported_repository`. The runner's environment is fixed, so no `GIT_DIR`-style variable
     reaches Git. Git can still only be given pathnames, so the root is also pinned by identity:
     before and after every Git call the root pathname and its `.git` must be the device and inode
     that were validated, or the capture is `unsafe_root`. A directory renamed away and replaced at
     the same path between Git calls, even by a clone of the same base, is never read. The residual
     is a replacement made and undone entirely within one Git call, which no check outside that
     call can observe.
   - **No link content enters the change, tracked or untracked.** Untracked files honour
     `.gitignore`, `.git/info/exclude`, a repository-level `core.excludesFile` and the owner's
     global Git ignore file. They are opened one path component at a time beneath the validated
     root descriptor without following links; only regular files owned by the service user with a
     single link, at most 232 KiB each (the capture's 256 KiB bound less its header budget; 64 KiB
     before issue #983) and 500 in all, are read. A changed tracked file whose working
     copy is a link, a special file, another user's, multiply linked, or reachable only through a
     linked directory is named with `not_regular_file`, and neither its diff nor its line counts
     are shown. Git reads tracked files itself, so it may still open such a file's target while it
     produces the counts or the patch; that output is discarded and never enters the change. Each
     working copy's identity is taken after the raw file list (which reads no file or blob content)
     and before the counts, the patch and verification read anything, and is compared again at the
     end, so a link swapped in only while Git reads and then put back retakes the capture.
   - **Every object read is the one its name commits to.** Git trusts each blob it opens.
     `.git/objects` and its `info` and `pack` directories must be real directories of the service
     user and every fan-out directory a real directory; every pack-directory entry (packs, indexes
     and the rest) must be a regular file of the service user that no other user may write. A link
     there, or `objects/info/alternates` or `objects/info/http-alternates` (static or written later,
     matching the ADR-011 open fence), is `unsafe_root`; a `.git/commondir` is
     `unsupported_repository`. A second hard link is accepted, so a local `git clone` (which hard
     links its source's objects) is read normally: a link count proves nothing a plain copy would
     not defeat, and what makes a blob this repository's is that it hashes to the name the base
     tree or index gives it. So every blob a shown diff reads (the base side, and the index side Git
     uses for a file it did not re-read from the working tree) is verified: a loose object must be
     a regular, owner-only file reached without a link that still has the identity taken before
     the diff, and is inflated and hashed from that same open descriptor; and the blob is read
     again the way the diff read it (`git cat-file`, packs first) and hashed. Each must hash to its
     own name (at most 8 MiB each and 64 MiB in all). A blob that does not verify withholds that
     file's diff and line counts as `object_unverified`; one over the bound is `too_large`. Git
     itself rejects a tree or commit whose bytes do not match its name. The verification buffers
     the adapter owns are overwritten after use; the runner's returned bytes are immutable and are
     only dropped.
   - **One state, not a mix.** After assembling the change the adapter reads again the raw
     changed-file list; the identity (inode, size, modification and change times, link count) of
     every working copy, every loose blob a diff reads, every untracked file it read, every object
     directory (whose times move whenever an object file is created, renamed or removed in it) and
     every pack-directory entry; the untracked listing; HEAD; and the index. Each untracked file is
     also re-checked on its open descriptor after it is read. If anything moved, the whole capture
     is taken again, at most three times in all; a tree that never holds still is
     `changed_during_capture`.
   - **Credential names.** Files whose names follow common credential conventions (`.env`,
     `.env.*`, `.netrc`, `.npmrc`, `id_rsa`, `*.pem`, `*.key`, `*.tfvars` and similar), tracked or
     untracked, are listed by name only and their content is never shown. That list is a name
     heuristic, not a detector: it catches common conventions, and every shown line still passes
     redaction and the never-send scan.
   - **Size and time.** The stored text is at most 256 KiB and leaves an oversized file out whole
     rather than cutting it mid-hunk; the packet then splits that text on line boundaries. An
     untracked listing over 8 MiB keeps the names that fit and says the untracked count is a lower
     bound. One 20-second deadline bounds the whole capture: each Git call, and the read of the
     global ignore setting, gets at most 10 seconds and never more than what is left. Assembly may
     use the first 15 seconds; the last 5 are kept for the closing stability check. A deadline
     reached while the change is being read leaves the named files unshown and says so; one
     reached before the file list exists, or during the stability check, makes the capture
     unavailable.
5. **The same privacy path as every other excerpt.** The rendered text receives the capture-time
   redaction native observation content receives, with the same detector as the egress never-send
   scan, and is stored encrypted. Its parts are `repository_excerpt` case items, because this is
   the service's own repository read and not recorded evidence: the channel categories, the privacy
   gateway and the never-send scan apply to each one. A recipe that selects diff excerpts therefore
   requires `repository_excerpt`; an inference channel that does not allow it never receives a
   part, and the check reports `semantic_review_context_withheld`, as for any other category the
   recipe selects and the channel withholds. How a never-send match affects the review is owned by
   #920.
   Amendment (tb4n5 live-database-cutover): the capture-time redaction marks what it replaced by
   confidence. A concrete credential shape (a known token format, a private-key header, a password
   inside a URL), or a heuristic span that overlaps one, reads `[REDACTED]`; a value that only
   looks like a credential (an assignment to a name such as `password` or `*_token`) reads
   `[withheld-by-yoetz:possible-credential]`, the placeholder egress already uses (ADR-009,
   issue #982). The same bytes are withheld either way; only the marker text differs, and
   redaction still runs at capture whatever the owner's possible-credential opt-out says (owner
   decision, 2026-10-13). Task input files the read carries get the same treatment. The bare
   `[REDACTED]` had turned `password=config.POSTGRES_PASSWORD` into `password=[REDACTED]`, which a
   reviewer read as an undefined name and raised as a `code_defect`. The reviewer's standing
   instruction now names both markers as FinishUP's own substitutions for an unavailable original
   value or expression, never evidence of a syntax error, an undefined name or missing
   configuration, and the packet-limit glossary explains `check_time_change_redacted`. No
   check-side filter reads the reviewer's words for a marker premise: one keyed on wording near
   the marker also dropped real defects in the surrounding readable code ("beside the redacted
   password, DB_PORT is undefined"), so it was withdrawn in the tb4n5 fix review. A finding that
   still rests on a marker is answered by the agent as a FinishUP limit (agent guidance), and the
   existing hidden-source rule still applies. The
   shown-file record (item 9) and reviewer-quote proof treat both markers alike: each is a
   redaction, and a file holding either is never `fully_shown`. A change stored before this
   amendment holds `[REDACTED]` only, so its shown-file record, view commitments and replay are
   byte-identical. Known upgrade limitation: a new capture of a file whose look-alike value an
   older build marked `[REDACTED]` has a different view (the marker's length differs), so an
   AI-powered finding raised through a partial view of that file before the upgrade is not cleared
   by that file's new partial view, as for any moved redaction; it clears once the file is shown
   whole (the look-alike value gone) or through the ordinary finding responses. Only tasks carried
   across the upgrade are affected.
6. **A reserved share of the packet, first.** The change is admitted before every other excerpt, up
   to half of the recipe's excerpt count (at least one) and half of its excerpt bytes, rounded up to
   the change's first part. A part is never larger than the recipe's per-excerpt or total excerpt
   budget, so a captured change always reaches the packet ahead of every other excerpt unless that
   budget is too small for a readable part (256 bytes of change plus its marker), which is disclosed
   as `check_time_change_unavailable`. Room it does not use stays with the other excerpts. A part
   takes the recipe's per-excerpt bound (16 KiB under Expanded), not the 4 KiB structural prose
   bound (issue #983). Parts left over take every slot and byte the reserved excerpt classes (the
   newest captured edit per path, the latest verification runs, finding repair evidence) leave,
   ahead of older edit hunks and general output, and any still left backfill whatever the recipe
   has free after those. Because the case planner narrows the excerpt budget from the lowest rank
   up, older hunks and general output are narrowed before the change. Each part begins `[FinishUP
   check-time change, part i of n]`, its item ids sort ahead of every other item, and it links to
   the case's effective claims and obligations (else its latest plan). When a planned case leaves
   less room than one whole part, the first part is cut to that room (on a line end where one lies
   in its second half) and begins `[FinishUP check-time change, part 1 of n, cut to the packet's
   room]`, so the change still precedes every recorded excerpt; nothing follows a cut part, and the
   cut is disclosed as `check_time_change_truncated` (issue #983). The shown-file record counts the
   change bytes the carried parts hold, never a part count, so it stays exact whatever part size a
   narrowed selection chose. `_check_time_change_reservation` is the single seam for this share.
   Amendment (issue #1079): when the captured change does not fit that excerpt budget and its
   files are not all the same kind, parts are admitted so a file section that changes a decision
   (`if`, `return`, `raise`, and the same shape) comes before a section that only changes
   comments, imports or license text. A changed line that is itself a decision counts as one
   even when it names a license; only a license or copyright comment or header is boilerplate.
   The rest of the decision's own section is the rule that
   branch implements, and it is still sent from the section start, so the shown-file record stays
   a run from that start. A one-file change, a change whose sections are the same kind, and a
   change that fits the budget keep the historical leading prefix, byte-identical. The first part
   of a reordered change carries one fixed line saying decision-changing sections are shown ahead
   of boilerplate and that sections which do not fit are not shown; it names no path. Bytes of a
   part that are not a prefix of the stored change are not counted as leading bytes. They are
   reported with the served intervals, so a file shown out of prefix order is still recorded, and
   a file that was not carried is absent. `check_time_change_truncated` remains the disclosure
   that something was left out. Ceilings are unchanged.
   Inside the change, files are ordered by what the task delivers, not by path (tb4n2 R7, issue
   #1016): files at or under a requested `role: output` item come first (then requested files with
   no role, an `obligation_published` 1.0.0 deliverable), then files whose rendered section is at
   most 4 KiB in path order, then the rest by size (smallest first, path order breaking ties), then
   generated, build or minified output by size. The same order decides which untracked
   files the untracked-file limit reads (sized by a metadata-only stat of up to 4096 paths) and
   which tracked files the object-verification budget covers first. Before a tracked file's diff
   is read (the per-file fallback when the whole diff is too large), "small" means at most 64
   changed lines by Git's numstat, and size means that line count, since its byte size is not yet
   known. A cut change or a narrowed packet therefore keeps the deliverables and drops scratch
   first. Declared outputs outrank role-less requested files. The declared paths only order the
   change; they never widen what is read.
   Amendment (tb4n5 react-lead-form, issue #1045 follow-up): a 145 KB minified `dist/` bundle
   from `npm run build` sorted path-first ahead of `src/lib/leadStore.ts`, so no packet carried
   the central implementation. A file that is not a declared deliverable now ranks after every
   other file when a path component is a known build-output or cache directory (`dist`, `build`,
   `out`, `target`, `coverage`, `node_modules`, `__pycache__`, `.next`, `.nuxt`, `.output`,
   `.svelte-kit`, `.vite`, `.turbo`, `.parcel-cache`), when its name is a lockfile
   (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `uv.lock`
   and the like) or ends in `.min.js`, `.min.css` or `.map`, or, once its section is rendered,
   when a `.js`, `.mjs`, `.cjs` or `.css` file's section is at least 8 KiB with lines averaging
   over 1000 bytes (minified). Only those bundler suffixes are judged by line length: an
   undeclared data file kept on long lines (hand-maintained JSON, CSV, long Markdown paragraphs)
   may be a requested output or the work itself, so it keeps its place by size (decision of the
   tb4n5 fix review; a negative fixture locks it). Names are matched exactly and nothing is
   opened to decide. Such a file is never left out for being
   generated: it stays in the change, keeps its header line with the fixed note `generated, build
   or minified output, placed after the other files`, and is cut only by the bounds that cut any
   file, disclosed as `check_time_change_truncated`. A declared deliverable under `dist/` keeps
   its first place.
7. **Frozen with the job.** The object's pointer, or the fact that it was unavailable, is frozen
   into the job's semantic-case object. A recovered or resumed job reloads exactly that object and
   never re-reads a working tree that has since moved, so the case digest is unchanged. The object
   is check-scoped and not a ledger root. Known upgrade limitation (issue #983): a job frozen by a
   build that split the change into 4 KiB parts, or before the first part could be cut to the room
   a narrowed case leaves, rebuilds a different case after the upgrade. The
   `semantic_execution_case_changed` guard then ends that one review as `failed` /
   `coordinator_failure` and keeps its local-check result rather than sending bytes it did not
   freeze; the next check composes a fresh review. Recovery does not re-compose the frozen job.
8. **Disclosed limits.** `check_time_change_unavailable` (selected but nothing carried),
   `check_time_change_base_unavailable`, `check_time_change_truncated` (a file or part not shown)
   and `check_time_change_redacted` join the packet and check coverage. Beside
   `check_time_change_unavailable` the check records one closed reason code,
   `check_time_change_unavailable_<reason>` (`git_unavailable`, `git_version_unsupported`,
   `not_git`, `unsafe_root`,
   `unsupported_repository`, `git_failed`, `changed_during_capture`, `redaction_incomplete`,
   `repository_mismatch`, `capture_failed`, `no_linked_subject`, `no_packet_room`), frozen with the
   job so recovery reproduces it. Receipts (JSON detail, markdown and text), `check` and `status`
   text and the MCP check summary render one fixed sentence per code; no path, Git output or
   other user-controlled text is recorded. Files left out of a captured change keep their reason
   in the change's own header (`object_unverified`, `not_regular_file` and the rest) and report
   `check_time_change_truncated`. They describe AI-powered
   review input only, so they never weaken local absence proof. A check whose connection named no
   workspace has nothing to read and reports no check-time code; its review is the review of the
   time before this decision.
   Amendment (issue #1019, tb4n2): the local metadata-only read that structural accounting and
   requested-output facts use skips any changed path whose name holds a carriage return or line
   feed (Git allows both; a NUL never reaches a `-z` field) instead of failing the whole read. It
   counts each skipped path in `omitted_files` (so the read is `truncated`) and in
   `unrepresentable_files`, and the check records `check_time_change_path_unrepresentable`, a
   standing limitation with its own fixed sentence. The path itself is never logged or recorded.
9. **AI-powered finding resolution compares the files each review was shown.** A completed review
   whose packet carried the change records, on its `check_recorded` 1.3.0 event, keyed commitments
   to the changed files it carried. What it carried is counted from the bounded provider envelope,
   after `bounded_case_envelope` minimization (only the unbroken run of parts from the first whose
   catalog rows survived), and is nothing when the channel withholds `repository_excerpt`, so the
   record never claims a part the reviewer could not read. The files are `fully_shown` (the file's
   whole diff, unredacted and untruncated) and `partially_shown` (the rest it carried any of), each
   with `shown_bytes` (the bytes of the file's diff section that reached the packet, redaction
   markers included), `redactions` (the redacted spans among them), `section_admitted` (the whole
   section reached the packet, so only redaction made it partial), `clean_bytes` (where the first
   shown redaction marker starts; `shown_bytes` without one) and `view_commitment`. Each commitment
   is the task bundle's object commitment key over the change's base commit, the file's `diff --git`
   line and its change kind (binary, deleted), so no path is recorded, the same file under the
   task's fixed base commits the same way in every check of the task, and a file that turned binary
   or was deleted never stands in for the text diff it replaced. `view_commitment` is the same key
   over the view's structure: its shown length, whether its whole section was admitted, the offset
   of every redaction marker it showed, and the offset and header line of every hunk it showed. It
   is derived from exactly the parts the bounded envelope carried (the same count that decides which
   files were shown), and records no content, only the keyed digest. Only shown files count toward
   the 128-file bound; past it the record keeps the first 128 in change order and says it is
   incomplete. Amendment (tb4n5 fix review): a current-file section an in-check follow-up served
   (ADR-006, `change-section-NNN`) is a shown file too. The record counts the change bytes the
   sections whose catalog rows the bounded envelope kept carried, beside the leading run (none
   when the channel withholds `repository_excerpt`); a file is recorded through the run of its
   section, from its start, that the two together reached, with the same view commitment a
   leading-run view of those bytes would have. A file shown other than as one run from its
   section's start uses the interval-view representation below (issue #1079, F3).
   No wire field changes. Replay folds, onto the finding's projection row, the record of every completed review
   that raised or re-raised an AI-powered finding (R): whole files are united, a file any of them
   saw whole must be seen whole, a file they saw in part through one view keeps that view, and a
   file they saw in part through two different views must be seen whole. At most 64 contributing
   checks and 1024 files are kept on the finding's row (one event row still holds at most 128); past
   either bound R is unknown. A later repair review's `check_time_change_*` codes are tolerated for
   that finding exactly when the repair saw at least what R requires: every file R needs whole
   reached the repair whole, and every file R saw in part reached the repair whole or in part with
   the same `view_commitment`, so with the same length, the same redactions at the same offsets and
   the same hunks at the same offsets. A redaction that moved, or a packet-edge hunk that moved, is
   therefore not covered even when every count is equal. **Maintainer decision (2026-09-30,
   R945-02):** this replaces the earlier length-and-count rule, whose residual let a moved span or
   hunk clear a finding. The accepted liveness cost is that a finding whose raising review saw a
   file in part stays open until a repair shows that file whole (its redaction gone and within the
   packet) or with an identical view; a repair that changed that file's diff, or saw a longer or
   shorter cut of it, does not clear it. Backward compatibility: a raising partial view recorded
   before `view_commitment` existed is still compared by the earlier rule (at least n bytes or the
   whole section, and at most k redactions or a clean first n bytes), and a resolution that relied
   on such a view is disclosed on the receipt as `check_time_change_resolution_unverified`, never
   presented as verified. That disclosure is one task-wide receipt gap however many findings it
   covers, so it never exhausts the receipt's 64-gap bound; its detail and the limitations section
   name up to 16 affected findings and count the rest. Like every receipt gap it lowers the
   receipt's ledger freshness from current to partial, so a receipt that would otherwise conclude
   `no_unresolved_deterministic_findings` concludes `insufficient_coverage`. That downgrade is
   deliberate: the resolution really was not verified against where the spans and hunks lay. It can
   arise only for tasks carrying check records from 0.3 development builds of this change, because
   every other record carries view commitments; a repair record without a view commitment never
   covers a raising view that has one. The repair's record may be incomplete, since each entry it
   holds is still true. An empty R (reviews that carried no change, including every review from
   before this decision) is always tolerated. R is also unknown, which never tolerates, when a
   raising record is incomplete or when a raising review carried parts without a readable record
   (0.3 development builds). None of these codes is a capture baseline stamped on the finding.
   Redacting any contributing check makes R unknown and reopens a resolution that depended on it;
   redacting the resolving check reopens it as before. The relation is a pure fold over recorded
   checks, so the memory and SQLite ledgers replay it identically.

## Consequences

Every host and supported operating system gets the same capture, because it depends on the
repository, not on how the edit was made. The reviewer sees the actual change and the file list
it came from, within the existing per-item, count and total caps; #907 owns lifting those caps.

The capture is unavailable, and says so, for linked Git worktrees and a submodule checkout
opened as the root (in both, `.git` is a file pointing elsewhere, which the ADR-011 open fence
refuses as `unsafe_root`), roots another account can write (ADR-007 2026-10-14 amendment), repositories whose effective config
defines a filter or an include (for example a repository-local Git LFS or git-crypt setup),
partial clones, a system Git older than 2.25 (`git_version_unsupported`), an object store reached
through a link or borrowed through
`commondir` or alternates, a `core.worktree` redirection, a root replaced between Git calls, and a
working tree or object store that kept changing through every attempt. Tracked files that are
links or multiply linked are named but not shown. Hard-linked object files (a local `git clone`)
are read, because every blob shown is verified against its name.
Submodule changes appear as commit ids and binary files as a one-line description; a nested
repository's own change is read as the #1045 amendment below describes.

AI-powered finding resolution compares where each review's redactions and hunks lay, not only how
much it saw (decision 9, maintainer decision 2026-09-30). A finding whose raising review saw a file
only in part therefore stays open until a repair review shows that file whole or through an
identical view; a resolution that relied on a raising view recorded before view commitments is
disclosed as `check_time_change_resolution_unverified`.

This decision does not add an MCP tool, a repository browser or an `ArtifactInspectionPort`, and
does not change ADR-011's content-withholding structural capture. No content-returning read exists
outside a check's AI-powered review composition.

## Amendment (issue #1045, tb4n4): the task-start snapshot, nested repositories, task input files

tb4n4 showed the packet missing what the reviewer needed while carrying what it did not: the
implementation of live-database-cutover lived in a nested `/app/api` repository the change never
read; vba-userform-port's VBA source (a task input) was never in the packet; pretrain's
pre-existing untracked `index.json` was shown as added. The fix is selection, not more bytes: every
bound above (256 KiB stored text, the reserved share, the recipe's excerpt count and bytes) is
unchanged. The owner authorized the privacy/egress content-selection change on 2026-10-12.

1. **The task-start snapshot.** A `task_start` base also records, metadata only, the untracked files
   Git lists at that moment (the same ignore files as decision 1): each as its root-relative name
   and a SHA-256 digest of its link-free `stat` fields (file type and permission bits, inode, size,
   modification and change time), at most 4096 names and 256 KiB of names; and the HEAD of each
   nested repository: an untracked directory Git lists as its own repository, then each gitlink the
   index records (`git ls-files --stage`) whose directory holds its own `.git` directory, since an
   embedded repository's HEAD is often ahead of the commit the outer repository records for it. Each
   is opened with every fence of decision 4 (the borrowed-store and effective-config refusals
   included) before its HEAD is resolved, at most 8 in all, untracked ones first; one a fence
   refuses records no HEAD, so no other repository's commit can become its starting state. For each
   repository with a recorded HEAD, the same open repository's own untracked files are listed the
   same way (its own ignore files, names and `stat` digests relative to its directory). The nested
   listings share the outer listing's bounds: after the outer listing, each takes what is left of
   the 4096 names and 256 KiB, in place order, whole or not at all; one that does not fit, is cut
   short, holds a name the object cannot carry, lists a file whose `stat` fails (Git never lists a
   path behind a link, so that file may still be there) or runs out of time is recorded incomplete
   and names no file. No file is opened. Past a bound, with a name the object cannot hold, or with a
   listed file whose `stat` fails, the outer snapshot is incomplete; a snapshot that cannot be taken
   at all leaves the base exactly as before. The snapshot rides the same encrypted base object
   (`yoetz.task-change-base/1`, optional `untracked`, `untracked_complete`, `nested` and
   `nested_untracked` keys; `nested_untracked` holds `[directory, complete, [[path, digest], ...]]`
   rows in path order, written only when there is one; decoding accepts only what the encoder
   writes: the three snapshot keys together and never all empty, `nested_untracked` beside them and
   never empty or null; a base without these keys keeps its bytes). A `nested` row means the same
   for both kinds, the repository's HEAD when the task started, so a base recorded before gitlinked
   rows existed reads unchanged: its gitlinks simply have no row, and a base recorded before nested
   listings has no `nested_untracked`. A `first_check` pin never carries any of them: only the
   task's own start can say what predates it.
2. **Untracked files that predate the task are baseline.** An untracked file the snapshot names
   with an unchanged digest is the task's starting state: the content and metadata reads leave it
   out (its identity still joins the stability check), and the header counts it ("Untracked files
   that already existed when the task started and are unchanged since: N"). One whose digest
   changed is shown whole with status `M` and the note that it existed when the task started and its
   earlier content was not recorded; the metadata read lists it as a modification, never as a
   created file, so it is no candidate for `deliverable_references_undeclared_file`. The change
   time cannot be set back, so restoring a modification time does not hide a rewrite. An incomplete
   snapshot is stated in the header; a base without one keeps decision 1's wording.
3. **Nested repositories.** An untracked embedded repository, or a changed gitlink whose working
   directory is a repository, has its own change read: at most 8 per check, those holding a
   declared deliverable first. Each is opened with every fence of decision 4, and its directory must
   also be the one reached beneath the outer root descriptor without a link; a submodule checkout
   whose `.git` is a file is `unsupported_repository`. Each is its own stable state (the same retake
   rule), within the same deadline. Its change starts from the HEAD the snapshot recorded for it;
   else, for a gitlink, from the commit the outer base tree records for it, and the header says
   that any commits made in it before the task that the outer repository does not record are then
   included; else from its HEAD now (also when the recorded HEAD is gone), which the header says
   may miss commits made in it during the task. Its paths carry its directory (`a/api/server.py`), so
   the deliverable order, the 256 KiB bound, the packet split and the shown-file record treat its
   files as files of the change; the outer one-line entry for an untracked repository gives way to
   them. With a complete task-start listing of its untracked files, they are treated exactly as at
   the outer level (item 2): one the listing names with an unchanged digest is left out and counted
   in the same header line, any other is shown. Without one (a base recorded before nested
   listings, a repository whose HEAD was not recorded, or an incomplete listing) none of them can
   be told apart from a file that predates the task, so each is named and never read, marked "not
   shown: untracked inside a nested repository whose untracked files the task-start record does
   not fully list, so it may predate the task", counts as not shown
   (`check_time_change_truncated`), and the repository's header line says its untracked files are
   named but not shown and why. A repository that cannot be read keeps its outer entry
   (that one-line entry, or a changed gitlink's commit-id lines) marked "not shown: a nested Git
   repository whose own change was not read", counts as not shown (`check_time_change_truncated`),
   and the header names why in one fixed sentence (`nested_limit`, the deadline, or the closed
   reason of decision 8); no Git output is recorded. A repository nested inside a nested one is
   not read and counts as not shown the same way: its untracked entry or changed gitlink is marked
   so. The structural metadata read (requested-output states, test-edit accounting, the
   undeclared-reference candidates of `deliverable_references_undeclared_file`, and whether the
   workspace changed at all) selects and reads the same nested repositories the same way, names
   and status only: an untracked repository's directory is never a file entry; each repository
   read adds its changed paths under its directory from the same starting commit and task-start
   listing, so one unchanged since the task started adds nothing; and the directory of a
   repository it cannot read, a changed gitlink whose repository it cannot read, a repository
   nested inside a nested one and untracked files without a complete listing count as omitted
   (truncated), never as entries.
4. **Read-only task input files.** When the recipe carries the change, the task statement and the
   `repository` excerpt kind, the service names candidate inputs: the path-shaped words of the task
   statement in its order (a path with a slash, or a file name with a short extension holding a
   letter), then the `role: input` requested files of effective obligations, at most 16. The
   statement is read in process only to find these words. The adapter reads at most 4 of them, each
   only when it lies inside the repository, is unchanged since the task started (an untracked file
   the snapshot names unchanged; or, only when the change's base is the task's own start and never
   a first-check pin or HEAD, against which a file absent from the change may be the agent's
   committed work, a tracked file the change does not touch, whose index entry is an ordinary one by
   `git ls-files -v` on a literal pathspec (tag `H`: a skip-worktree or assume-unchanged entry,
   which Git never compares with its working copy, is not read) and whose bytes, read without any
   filter or line-ending conversion, hash to its blob in the base commit), lies outside every
   nested repository, is not credential-named, is a regular, singly linked file of the service user
   reached without a link, is at most 1 MiB and holds no NUL byte in its first 8000 bytes. An
   ignored file is never read: it is neither tracked nor listed. Each keeps at most 16 KiB, whole
   or head and tail with the cut marked. The read is point-in-time, after the change proved
   stable. Inputs are stored in the same encrypted
   check-change object (optional `inputs`, so every object without them keeps its bytes), redacted
   one by one with the same detector (one that cannot be fully redacted is dropped; any redaction
   or dropped input reports `check_time_change_redacted`, even when the change text needed none),
   frozen with the job, and never part of the change text or the shown-file record. Nothing about
   a skipped candidate is returned or recorded.
5. **In the packet.** Each input is one `repository_excerpt` item (`task-input-NN`, source kind
   `repository`, source ref `task-input`), linked to the statement event (else to the change's
   links), labelled as a task input the service read, unchanged since the task started and not the
   agent's work. It is offered first at the point where the change's remaining parts take the room
   the reserved classes leave (decision 6), within at most a quarter of the recipe's excerpt bytes,
   so it ranks ahead of older edit hunks and general output; inputs that did not fit that share
   backfill after the change's own backfill. The input manifest lists each under `caller_evidence`
   (partial when cut), and the privacy gateway and never-send scan apply to it as to any
   repository excerpt.

## Amendment (issue #1040 follow-up, tb4n5): Git 2.25 is the supported minimum

**Owner decision (2026-10-13):** the documented minimum Git is 2.25, the Git of Ubuntu 20.04 and
of images built on it (`condaforge/miniforge3:24.9.2-0`). It covers every Git FinishUP runs: the
repository identity the control handshake resolves, ADR-011 structural capture and this capture.
FinishUP always runs the system Git, the first `git` on `os.defpath` (`/bin:/usr/bin`); a newer Git
elsewhere on `PATH` (a conda environment's, for one) is never used.

**What changed.** tb4n5 showed that on Git 2.25 every connection closed once the vault was ready
and, after that was fixed, that the capture still could not run. Each Git argument newer than the
minimum is gone, replaced by one every supported Git answers the same way:

| Was | Needs | Older Git did | Now |
| --- | --- | --- | --- |
| `rev-parse --path-format=absolute` | 2.31 | echoed the option as an extra output line | `--show-toplevel`, `--absolute-git-dir` (2.13); a relative `--git-common-dir` is resolved against the directory Git ran in, canonicalised as `--path-format=absolute` does, so commitments do not change |
| `rev-parse --verify --end-of-options` | 2.30 | dropped the option unread (it then guarded nothing) | every revision is a fixed spelling or starts with an object id, and one starting with `-` is refused before Git runs |
| `diff --no-relative` | 2.28 | refused every diff (exit 129) | `-c diff.relative=false`, inert where the setting does not exist |
| `config --show-scope` | 2.26 | refused (exit 129) | `--show-origin` (2.8); only `command line:` entries are the runner's own |
| `GIT_CONFIG_GLOBAL=/dev/null` alone | 2.32 | ignored it and read `$HOME/.gitconfig` | the hardened runners also set `HOME` and `XDG_CONFIG_HOME` to `os.devnull` |
| `-c core.fsmonitor=false` | 2.36 | ran `false` as the fsmonitor hook | `-c core.fsmonitor=`, which disables it on every Git |

The `GIT_CONFIG_GLOBAL` row was a fence gap, not only a failure: the ADR-011 runner set `HOME` to
the workspace root, so on Git before 2.32 a `.gitconfig` committed to the repository was Git's
global configuration, and a filter driver defined there ran during structural capture's
`git diff`. No global configuration is read on any supported Git now.

**Below the minimum.** Each adapter reads `git --version` once per Git executable (cached by its
file identity). A known version older than 2.25 is refused with the closed token
`git_version_unsupported`: the repository-identity resolver refuses a directory Git would find a
repository for (a `.git` at or above it, or a bare repository or other Git directory it lies in,
recognised by Git's own `is_git_directory`/`validate_headref` rules: a `HEAD` that is a link into
`refs/`, or reads `ref:` and optional whitespace then `refs/`, or starts with a 40-digit object id
in either case, beside searchable `objects` and `refs` in its common directory), while a directory
with none keeps its plain directory identity, as without Git. The detector is deliberately not an
exact copy of Git's discovery where Git would follow a link or block: `HEAD` and `commondir` are
read without blocking and only when they are regular files. A `HEAD` that is a FIFO, socket or
device beside `objects` and `refs`, and a valid `HEAD` beside a `commondir` that is a link, a
special file, empty or holds a NUL byte, are not decided the way Git would decide them; they are
refused with `git_version_unsupported` (a supported Git refuses or resolves them as a repository,
never as a plain directory), so the detector errs only toward refusal. Structural capture refuses
to open the
workspace (`finishup state capture` prints the remedy), and this capture reports
`check_time_change_unavailable_git_version_unsupported` (one more recorded gap code, classified
exactly as its G7 siblings, so the gap table holds 216 recorded codes plus 3 readiness-only rows
under the unreleased classification version `"8"`). An unreadable version is not refused;
every later Git call still fails closed on output it does not expect. The continuation
`system_git_upgrade_required` tells an agent to ask the owner to install Git 2.25 or later as the
system Git. The handshake that resolves the identity closes without answering; the service records
`handshake_service_fault` with the closed reason, and the client reports `service_handshake_failed`
instead of `service_incompatible` (`docs/INTERFACES.md`, control handshake).

**Verification.** `tests/unit/adapters/test_git_old_versions.py` reproduces the `rev-parse`,
`diff`, `config` and `GIT_CONFIG_GLOBAL` behaviour of Git 2.25 with the real Git behind a shim,
holds every adapter to none of the replaced arguments, shows a committed `.gitconfig` filter and a
repository fsmonitor hook never run, and pins the commitment to the one `--path-format=absolute`
produced.
PR CI's conda-image smoke (`scripts/ci/service_image_smoke.sh`) runs the real Git 2.25 there:
ready status, `start` and a deterministic check whose change capture must succeed, inside a Git
repository.

## Amendment (issue #1077): a dropped synthetic excerpt names its linked subjects

A check-time change part and a current-file section an in-check follow-up serves both use the
synthetic source ref `check-time-change`. That token is a valid excerpt source and is not a ledger
subject. `ReviewOmission` still accepts only ledger subject ids. When selection or the aggregate
case bound drops one of those excerpts, the omission is recorded against each valid linked subject
(the edit the section answers, or the change's claims, obligations, or plan) with the same category
and `not_selected` reason. `content_unselected` remains. No linked ledger subject means no omission
row and no `coordinator_failure`. Subject validation is not relaxed, and nothing new is sent.

A follow-up whose packet adds no part the earlier packets lacked is not dispatched. The check keeps
the completed `insufficient_packet` review. A real `coordinator_failure` still fails the check; the
receipt limitations section names that fault inside FinishUP in a fixed sentence on every rendering.

## Amendment (issue #1079, F3): decisive intervals within one file

When a change does not fit, selection may place a decision-bearing interval inside a large
file ahead of its leading imports, comments, notices or generated boilerplate. The interval
includes nearby context and following rule lines. Small sections and changes that fit retain
their original representation. No excerpt, aggregate packet or policy ceiling increases.
Each interior excerpt labels the original file, original hunk header and byte interval, and
names the file intervals skipped in that excerpt. A cut narrows that label too. Truncation
remains an explicit coverage gap; selection is a heuristic, not a completeness judgment.

Shown-file accounting unions the original intervals that the provider actually received.
Contiguous leading views keep their existing bytes. Interior or disjoint views use the local
`yoetz/check-change-interval-view/v1` domain followed by each interval's original relative
start/end and length-prefixed structural view. Only the keyed view commitment is recorded.
The structural view also binds the preceding original hunk header repeated in the excerpt's
context label, including its original offset, even when it lies outside the selected interval.
Such a file is partial, `section_admitted=false`, with `clean_bytes=0` and `shown_bytes`
equal to the union's byte count. An identical view or a whole-file review can cover it;
a different partial view cannot. No wire field or schema changes.

## Amendment (2026-10-16, PR #1080): late captured evidence enriches replay

A hook and a Codex session-stream completion can describe one call with different captured-content
roles. The original call's agreeing action must already be committed. An intersection on evidence
alone cannot create a different call's core; an existing pre-action for that different call does
not permit borrowing the original evidence. Reused evidence is checked against its immutable
causal action and result association. After the committed core is validated, observation ingest
appends only the missing captured input/output or digest-only image evidence (#1078 class). It does not rewrite the original result
or its evidence-reference list; new evidence retains its causal action lineage. The existing
append-only outcome correction still supplies an explicit native outcome or discloses a conflict.

This reconciliation does not create eligibility for AI-powered review. Auto-supplied verification
output still needs the service-authenticated post-tool input/output phase binding, matching keyed
command identity, repository-excerpt permission, secret/path/environment screening and the existing
packet limits. Command input is local eligibility context and is never a provider excerpt. Missing
or mismatched binding still withholds output. Check-time diffs and current inspection snapshots
are not a per-command before/after comparison and cannot certify an arbitrary shell command harmless.

Late evidence uses the existing optional `evidence_recorded.reference` to name its original action
event after core and causal-parent validation. Selection follows that link only for service-stamped
observation-captured provenance and retains the original execution frontier. F1 authenticated
command/output binding remains required. A captured object already represented by agreeing evidence
is reused, so another delivery does not make its object-to-evidence association ambiguous. New
image source identities remain distinct; enrichment operation/claim roles bind the appended event
IDs. Existing schemas and frozen vectors retain their bytes.

## Amendment (2026-10-16, issue #1082): task inputs first, the oracle, summaries, outside roots

Maintainer approved 2026-10-16 (recorded on #1082). The read and the packet change as follows; the
ADR-009 amendment of the same date holds the consent and egress terms.

1. **Candidates.** `review_input_paths` returns the statement's path-shaped words, the
   `role: input` requested files, then absolute directories the statement names (ending in `/`),
   at most 16. The newest test, fixture or harness path a recorded verification command names
   (`verification_input_paths`: commands `command_is_verification` classes, split like a shell,
   pytest node ids reduced to their file, at most four) takes the fourth place, so a statement
   that names many files cannot crowd out every oracle. Only an input no task source named is
   labelled as the verification's (`TaskInputFile.origin = "verification"`).
2. **Binary and large inputs.** A candidate whose first 8000 bytes hold a NUL becomes FinishUP's
   own bounded summary (`TaskInputFile.summary`, at most 16 KiB; `finishup.adapters.input_summary`)
   instead of being skipped. An untracked candidate larger than 1 MiB is read from its two ends
   (the first 1 MiB and the last 8 KiB) without following a link and summarized or cut to head and
   tail; a tracked one still needs a whole read to prove it unchanged and is skipped.
3. **Outside roots.** After the repository read, an absolute candidate outside the workspace and
   beneath a root the repository grant admits (`PrivacyPolicy.admitted_input_roots`) is read by
   the service's outside reader (`finishup.adapters.task_input_read.read_outside_inputs`) into the
   room the four-input bound leaves, with `origin = "outside_workspace"` and its absolute path.
   A path inside the workspace is never read this way, even beneath an admitted root: only the
   repository read can prove a file unchanged since the task started.
4. **Storage.** `origin` and `summary` are optional keys of each stored input, written only when
   not the default, so every earlier check-change object keeps its bytes. All inputs take the same
   redaction as before and are frozen with the job.
5. **Packet.** Task inputs are admitted first, ahead of the change's reserved share, within a
   quarter of the packet's excerpt budget (the planned budget when the channel ceiling narrowed
   it); one that does not fit is skipped, not a stop, and backfills after every other excerpt.
   Each origin has its own label (`named by a recorded verification command`, `outside the
   workspace beneath a root the owner admitted`) and a summary reads `[FinishUP summary of task
   input file ...]`. A captured edit of only files whose every section the admitted change parts
   carry is ranked as an older edit with `superseded_by: ["check-time-change"]`.
