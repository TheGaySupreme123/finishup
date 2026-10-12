# ADR-031 — The service captures the check-time change as one reviewed object

**Status:** Accepted for issue #883. The maintainer asked for this scoped work in the issue's
2026-09-29 acceptance boundary (items 1 and 3) and recorded the design-gate acknowledgement for
the privacy/egress and storage changes it needs.
**Implemented by:** `src/yoetz/ports/change_capture.py`,
`src/yoetz/adapters/git_change_capture.py`, the public seam of
`src/yoetz/adapters/git_subject_state.py`, `src/yoetz/application/check_change.py`,
`CheckTimeChange` and `_check_time_change_reservation` in `src/yoetz/application/semantic_case.py`,
the reason codes and sentences in `src/yoetz/domain/receipts.py`, the semantic evaluator in
`src/yoetz/service/ready_composition.py`, `start`/`check` in `src/yoetz/application/service.py`,
the task-base root in `src/yoetz/adapters/sqlite/repository.py` and
`src/yoetz/adapters/memory/ledger.py`, the shown-file record (`CheckChangeShownFiles` in
`src/yoetz/domain/events.py`) and resolution rule (`src/yoetz/kernel/finding_resolution.py`,
`src/yoetz/kernel/projections.py`), and the suites `tests/unit/adapters/test_git_change_capture.py`,
`tests/unit/application/test_semantic_case_check_change.py`,
`tests/unit/application/test_check_time_change_facade.py`,
`tests/integration/service/test_check_time_change.py` and the ledger conformance suite.
**Relates to:** ADR-006 (AI-powered review packet), ADR-008 (service trust boundary), ADR-009
(egress), ADR-011 (structural subject-state capture), and issues #883, #904, #907, #920.

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
   its whole effective configuration (`git config --list --name-only --includes --show-scope`) and
   refuses any `filter.*`, `include.*`, `includeIf.*` or partial-clone key, from whichever file or
   include it came. That needs Git 2.26 or later; an older Git cannot answer, and the capture is
   unavailable rather than taken without the check. The effective-config check and the diffs are
   separate Git calls, so a filter written into the repository config between them would run; only
   a process of the same user can do that, and that user can already run code as itself, so this
   window is low severity. The read has these fences:
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
   up, older hunks and general output are narrowed before the change. Each part begins `[Yoetz
   check-time change, part i of n]`, its item ids sort ahead of every other item, and it links to
   the case's effective claims and obligations (else its latest plan). When a planned case leaves
   less room than one whole part, the first part is cut to that room (on a line end where one lies
   in its second half) and begins `[Yoetz check-time change, part 1 of n, cut to the packet's
   room]`, so the change still precedes every recorded excerpt; nothing follows a cut part, and the
   cut is disclosed as `check_time_change_truncated` (issue #983). The shown-file record counts the
   change bytes the carried parts hold, never a part count, so it stays exact whatever part size a
   narrowed selection chose. `_check_time_change_reservation` is the single seam for this share.
   Inside the change, files are ordered by what the task delivers, not by path (tb4n2 R7, issue
   #1016): files at or under a requested `role: output` item come first (then requested files with
   no role, an `obligation_published` 1.0.0 deliverable), then files whose rendered section is at
   most 4 KiB, then the rest, each group in path order. The same order decides which untracked
   files the untracked-file limit reads (sized by a metadata-only stat of up to 4096 paths) and
   which tracked files the object-verification budget covers first. Before a tracked file's diff
   is read (the per-file fallback when the whole diff is too large), "small" means at most 64
   changed lines by Git's numstat, since its byte size is not yet known. A cut change or a
   narrowed packet therefore keeps the deliverables and drops scratch first. Declared outputs
   outrank role-less requested files. The declared paths only order the change; they never widen
   what is read.
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
   `check_time_change_unavailable_<reason>` (`git_unavailable`, `not_git`, `unsafe_root`,
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
   incomplete. Replay folds, onto the finding's projection row, the record of every completed review
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
refuses as `unsafe_root`), group- or world-writable roots, repositories whose effective config
defines a filter or an include (for example a repository-local Git LFS or git-crypt setup),
partial clones, Git older than 2.26, an object store reached through a link or borrowed through
`commondir` or alternates, a `core.worktree` redirection, a root replaced between Git calls, and a
working tree or object store that kept changing through every attempt. Tracked files that are
links or multiply linked are named but not shown. Hard-linked object files (a local `git clone`)
are read, because every blob shown is verified against its name.
Submodule changes appear as commit ids and binary files as a one-line description.

AI-powered finding resolution compares where each review's redactions and hunks lay, not only how
much it saw (decision 9, maintainer decision 2026-09-30). A finding whose raising review saw a file
only in part therefore stays open until a repair review shows that file whole or through an
identical view; a resolution that relied on a raising view recorded before view commitments is
disclosed as `check_time_change_resolution_unverified`.

This decision does not add an MCP tool, a repository browser or an `ArtifactInspectionPort`, and
does not change ADR-011's content-withholding structural capture. No content-returning read exists
outside a check's AI-powered review composition.
