"""Privacy-preserving structural accounting for edits to existing test files.

The only input that can name a changed path is the encrypted, bounded repository capture.  This
module reads those names in process, reduces them to fixed counters and coverage codes, and never
returns a path.  Two structural relations justify an edit; unrelated prose never does:

* an effective obligation whose ``source_refs`` cite an event that recorded the current task
  statement content lists the test file as a ``requested_items`` entry with ``item_kind`` ``file``
  (the request asked for it);
* a later decision cites the exact edit action and a digest of the exact path.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal, cast

from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    DecisionRecordedPayload,
    RequestedItemKind,
    RequestedItemRole,
)
from finishup.domain.receipts import (
    PREEXISTING_TEST_BASELINE_UNKNOWN_GAP,
    PREEXISTING_TEST_DELETED_GAP,
    PREEXISTING_TEST_EDIT_UNJUSTIFIED_GAP,
    PREEXISTING_TEST_MODIFIED_GAP,
    PREEXISTING_TEST_RENAMED_GAP,
    PREEXISTING_TEST_SKIP_UNKNOWN_GAP,
    PREEXISTING_TEST_SKIPPED_GAP,
)
from finishup.domain.values import EventId
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import ProjectionState
from finishup.ports.change_capture import (
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
)

__all__ = [
    "PreExistingTestEdits",
    "check_change_header_entries",
    "check_change_sections",
    "preexisting_test_edits",
]

_HEADER_LINE: Final = re.compile(r"^  ([A-Z?]) (.+)$")
_SKIP_MARKER: Final = re.compile(
    rb"(?:pytest\.skip|pytest\.mark\.skip|unittest\.skip|"
    rb"(?:it|test|describe|suite|context)\.skip\b|"
    rb"\b(?:xit|xtest|xdescribe|xsuite|xcontext)\b|@skip\b)",
    re.IGNORECASE,
)
_DIFF_HEADER: Final = re.compile(rb"^diff --git (.+)$", re.MULTILINE)
_TEST_DIRS: Final = frozenset({"test", "tests", "spec", "specs", "__tests__"})
# The only accepted decision assertion is the whole line
# ``finishup:test-change:<edit-action-id>:sha256:<path-digest>``.  Guidance owns how agents learn this
# marker; this kernel keeps the parser exact and never stores the path behind the digest.
_TEST_CHANGE_MARKER: Final = "finishup:test-change"
# Frozen legacy identifier (ADR-048): decision statements recorded before the rename carry this
# spelling and are re-parsed on every projection rebuild, so the parser accepts it permanently.
_LEGACY_TEST_CHANGE_MARKER: Final = "yoetz:test-change"

TestEditKind = Literal["modified", "renamed", "deleted", "skipped"]


@dataclass(frozen=True, slots=True)
class PreExistingTestEdits:
    """Bounded counts and coverage facts; no path or content leaves this value."""

    modified: int = 0
    renamed: int = 0
    deleted: int = 0
    skipped: int = 0
    baseline_known: bool = True
    unjustified: int = 0
    unknown: int = 0
    unjustified_action_event_ids: tuple[EventId, ...] = ()
    # How many of ``unknown`` are only an unreadable skip marker: the edited pre-existing test was
    # seen and its justification read, but path metadata carries no diff body, so whether it gained
    # a skip marker is unknown. That never hides an edit, so it is not a baseline gap.
    skip_unknown: int = 0

    def __post_init__(self) -> None:
        for value in (
            self.modified,
            self.renamed,
            self.deleted,
            self.skipped,
            self.unjustified,
            self.unknown,
            self.skip_unknown,
        ):
            if type(value) is not int or value < 0 or value > 1_000_000:
                raise ValueError("preexisting_test_edits_invalid")
        if type(self.baseline_known) is not bool:
            raise ValueError("preexisting_test_edits_invalid")
        if self.unjustified > self.modified + self.renamed + self.deleted + self.skipped:
            raise ValueError("preexisting_test_edits_invalid")
        if self.skip_unknown > self.unknown:
            raise ValueError("preexisting_test_edits_invalid")
        if (
            type(self.unjustified_action_event_ids) is not tuple
            or any(type(item) is not str for item in self.unjustified_action_event_ids)
            or self.unjustified_action_event_ids
            != tuple(sorted(set(self.unjustified_action_event_ids), key=str.encode))
        ):
            raise ValueError("preexisting_test_edits_invalid")

    @property
    def any(self) -> bool:
        return bool(self.modified or self.renamed or self.deleted or self.skipped)

    @property
    def gaps(self) -> tuple[str, ...]:
        codes: set[str] = set()
        if not self.baseline_known:
            codes.add(PREEXISTING_TEST_BASELINE_UNKNOWN_GAP)
        if self.unknown > self.skip_unknown:
            codes.add(PREEXISTING_TEST_BASELINE_UNKNOWN_GAP)
        if self.skip_unknown:
            codes.add(PREEXISTING_TEST_SKIP_UNKNOWN_GAP)
        if self.modified:
            codes.add(PREEXISTING_TEST_MODIFIED_GAP)
        if self.renamed:
            codes.add(PREEXISTING_TEST_RENAMED_GAP)
        if self.deleted:
            codes.add(PREEXISTING_TEST_DELETED_GAP)
        if self.skipped:
            codes.add(PREEXISTING_TEST_SKIPPED_GAP)
        if self.unjustified:
            codes.add(PREEXISTING_TEST_EDIT_UNJUSTIFIED_GAP)
        return tuple(sorted(codes, key=str.encode))


def _is_test_path(path: str) -> bool:
    parts = tuple(part.lower() for part in path.replace("\\", "/").split("/"))
    name = parts[-1] if parts else ""
    return (
        bool(set(parts[:-1]) & _TEST_DIRS)
        or name.startswith("test_")
        or name.endswith(
            ("_test.py", ".test.js", ".test.ts", ".test.tsx", ".spec.js", ".spec.ts", ".spec.tsx")
        )
    )


def _decode_git_path(value: str) -> str | None:
    """Decode the bounded ASCII path spelling used by the capture header."""

    if value.endswith("..."):
        return None
    if not value.startswith('"'):
        return value
    if not value.endswith('"'):
        return None
    raw = value[1:-1].encode("ascii", errors="replace")
    out = bytearray()
    index = 0
    while index < len(raw):
        if raw[index] != ord("\\"):
            out.append(raw[index])
            index += 1
            continue
        if index + 1 >= len(raw):
            return None
        escaped = raw[index + 1]
        if ord("0") <= escaped <= ord("7") and index + 3 < len(raw):
            out.append(int(raw[index + 1 : index + 4], 8) & 0xFF)
            index += 4
        else:
            escapes = {ord("a"): 7, ord("b"): 8, ord("t"): 9, ord("n"): 10}
            escapes.update({ord("v"): 11, ord("f"): 12, ord("r"): 13})
            out.append(escapes.get(escaped, escaped))
            index += 2
    return out.decode("utf-8", errors="replace")


def _path_digest(path: str) -> str:
    """Return a safe structural identity without exposing the captured path."""

    return "sha256:" + hashlib.sha256(path.encode("utf-8")).hexdigest()


def _diff_side_path(token: bytes, prefix: str) -> str | None:
    """Decode one bounded ``a/`` or ``b/`` operand from a Git diff header."""

    try:
        decoded = _decode_git_path(token.decode("ascii", errors="strict"))
    except UnicodeError:
        return None
    if decoded is None or not decoded.startswith(prefix) or len(decoded) == len(prefix):
        return None
    return decoded[len(prefix) :]


def _unquoted_diff_header_paths(
    rest: bytes, destination_hint: str | None = None
) -> tuple[str | None, str | None]:
    """Split an unquoted header even when either path contains `` b/``.

    Git leaves ordinary spaces unquoted. A delimiter chosen by ``rfind`` is ambiguous when a
    path itself contains the byte sequence `` b/``; the unified diff's ``+++`` line gives us the
    destination identity, so choose the separator whose decoded right operand is that identity.
    For same-path edits, the candidate whose decoded operands are equal is unambiguous.
    """

    if not rest.startswith(b"a/"):
        return None, None
    candidates: list[tuple[str, str]] = []
    start = 0
    while True:
        separator = rest.find(b" b/", start)
        if separator < 0:
            break
        source = _diff_side_path(rest[:separator], "a/")
        destination = _diff_side_path(rest[separator + 1 :], "b/")
        if source is not None and destination is not None:
            candidates.append((source, destination))
        start = separator + 1
    if not candidates:
        return None, None
    if destination_hint is not None:
        matching = [item for item in candidates if item[1] == destination_hint]
        if matching:
            return matching[-1]
    equal = [item for item in candidates if item[0] == item[1]]
    if equal:
        return equal[-1]
    # A rename with omitted ``+++`` content cannot be disambiguated safely. Keep the path unknown
    # instead of guessing a source or destination from arbitrary prose bytes.
    return None, None


def _diff_header_paths(
    rest: bytes, destination_hint: str | None = None
) -> tuple[str | None, str | None]:
    """Split the two Git operands while honoring quoted paths and escaped quotes."""

    if not rest.startswith(b'"'):
        return _unquoted_diff_header_paths(rest, destination_hint)

    tokens: list[bytes] = []
    index = 0
    while index < len(rest) and len(tokens) < 2:
        while index < len(rest) and rest[index] == ord(" "):
            index += 1
        if index >= len(rest):
            break
        if rest[index] == ord('"'):
            start = index
            index += 1
            escaped = False
            while index < len(rest):
                byte = rest[index]
                index += 1
                if escaped:
                    escaped = False
                elif byte == ord("\\"):
                    escaped = True
                elif byte == ord('"'):
                    break
            else:
                return None, None
            tokens.append(rest[start:index])
        else:
            start = index
            while index < len(rest) and rest[index] != ord(" "):
                index += 1
            tokens.append(rest[start:index])
    if len(tokens) != 2:
        return None, None
    return _diff_side_path(tokens[0], "a/"), _diff_side_path(tokens[1], "b/")


def _diff_destination_from_body(body: bytes) -> str | None:
    """Read the exact destination operand from the unified diff's ``+++`` line."""

    for line in body.splitlines():
        if not line.startswith(b"+++ "):
            continue
        token = line[4:]
        if b"\t" in token:
            token = token.split(b"\t", 1)[0]
        if token == b"/dev/null":
            return None
        return _diff_side_path(token, "b/")
    return None


def _diff_source_from_body(body: bytes) -> str | None:
    """Read the exact source operand from a unified diff's ``---`` line."""

    for line in body.splitlines():
        if not line.startswith(b"--- "):
            continue
        token = line[4:]
        if b"\t" in token:
            token = token.split(b"\t", 1)[0]
        if token == b"/dev/null":
            return None
        return _diff_side_path(token, "a/")
    return None


def _diff_path_pairs(capture: CheckChangeCapture) -> tuple[tuple[str | None, str | None], ...]:
    """Return source/destination path pairs from each admitted diff section.

    The pair is reduced in process only. It lets us recognize a pre-existing test on either side
    of a rename; neither path leaves this structural reduction.
    """

    text = capture.text
    starts = [match.start() for match in _DIFF_HEADER.finditer(text)]
    pairs: list[tuple[str | None, str | None]] = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        header_end = text.find(b"\n", start, end)
        if header_end < 0:
            continue
        rest = text[start + len(b"diff --git ") : header_end]
        body = text[header_end + 1 : end]
        destination = _diff_destination_from_body(body)
        source, header_destination = _diff_header_paths(rest, destination)
        if destination is None:
            destination = header_destination
        if source is None:
            source = _diff_source_from_body(body)
        pairs.append((source, destination))
    return tuple(pairs)


def check_change_sections(
    capture: CheckChangeCapture,
) -> tuple[tuple[int, int, frozenset[str]], ...]:
    """``(start, end, paths)`` of each ``diff --git`` section of the stored change, in order.

    ``paths`` are the section's repository-relative source and destination (one path for an
    edit, the destination for an addition, the source for a deletion; empty when neither can be
    decoded safely). The section bounds are the ones ``check_time_change_shown_files`` uses. In
    process only (tb4n5: a follow-up serves the current section of a path a requested edit
    changed from the frozen change, never from a new read).
    """

    text = capture.text
    starts = [match.start() for match in _DIFF_HEADER.finditer(text)]
    sections: list[tuple[int, int, frozenset[str]]] = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        header_end = text.find(b"\n", start, end)
        if header_end < 0:
            sections.append((start, end, frozenset()))
            continue
        rest = text[start + len(b"diff --git ") : header_end]
        body = text[header_end + 1 : end]
        destination = _diff_destination_from_body(body)
        source, header_destination = _diff_header_paths(rest, destination)
        if destination is None:
            destination = header_destination
        if source is None:
            source = _diff_source_from_body(body)
        sections.append(
            (start, end, frozenset(path for path in (source, destination) if path is not None))
        )
    return tuple(sections)


def _diff_paths_with_skip_markers(capture: CheckChangeCapture) -> frozenset[str]:
    """Return only paths whose added diff lines contain an explicit skip marker."""

    text = capture.text
    starts = [match.start() for match in _DIFF_HEADER.finditer(text)]
    paths: set[str] = set()
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        header_end = text.find(b"\n", start, end)
        if header_end < 0:
            continue
        rest = text[start + len(b"diff --git ") : header_end]
        body = text[header_end + 1 : end]
        destination = _diff_destination_from_body(body)
        source, header_destination = _diff_header_paths(rest, destination)
        destination = destination or header_destination
        if source is None:
            source = _diff_source_from_body(body)
        paths_for_section = tuple(path for path in (source, destination) if path is not None)
        if not paths_for_section:
            continue
        added = b"\n".join(
            line
            for line in body.split(b"\n")
            if line.startswith(b"+") and not line.startswith(b"+++")
        )
        if _SKIP_MARKER.search(added) is not None:
            paths.update(paths_for_section)
    return frozenset(paths)


def _header_entries(capture: CheckChangeCapture) -> tuple[tuple[str, str | None], ...]:
    """Return ``(status, path)`` from the bounded header only."""

    try:
        text = capture.text.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ()
    entries: list[tuple[str, str | None]] = []
    in_files = False
    for line in text.splitlines():
        if line == "Files:":
            in_files = True
            continue
        if line == "End of header. The unified diff follows.":
            break
        if not in_files:
            continue
        match = _HEADER_LINE.match(line)
        if match is None:
            continue
        status, remainder = match.groups()
        # Header counts and fixed notes are service text.  A quoted Git path may itself contain
        # spaces or ``("`; find its closing quote before looking for annotations.  This is only
        # used in process and is never returned.
        if remainder.startswith('"'):
            escaped = False
            closing = None
            for position, character in enumerate(remainder[1:], start=1):
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    closing = position
                    break
            path = remainder if closing is None else remainder[: closing + 1]
        else:
            count = re.search(r" \(\+[0-9-]", remainder)
            path = remainder if count is None else remainder[: count.start()]
            # The first fixed note ends the path (``x untracked; not shown: ...``, and the tb4n5
            # note on a file ranked last as generated output).
            markers = [
                marker
                for note in (" not shown:", " untracked", " generated, build or minified output")
                if (marker := path.find(note)) >= 0
            ]
            if markers:
                path = path[: min(markers)]
        if path:
            entries.append((status, _decode_git_path(path)))
    return tuple(entries)


def check_change_header_entries(
    capture: CheckChangeCapture,
) -> tuple[tuple[str, str | None], ...]:
    """``(status, path)`` for each file the check-time change header lists, in listing order.

    ``path`` is ``None`` for a listed name that cannot be decoded. In process only (issue #1045:
    the review packet's declared-deliverable rows say whether the change lists each deliverable).
    """

    return _header_entries(capture)


def _statement_events(
    statement_event_id: EventId | Iterable[EventId] | None,
) -> frozenset[EventId]:
    if statement_event_id is None:
        return frozenset()
    if isinstance(statement_event_id, str):
        return frozenset({statement_event_id})
    return frozenset(statement_event_id)


def _statement_requested_files(
    projection: ProjectionState | None, statement_event_id: EventId | Iterable[EventId] | None
) -> frozenset[str]:
    """File items requested by effective obligations that cite the current task statement.

    ``statement_event_id`` is the current statement event or every event that recorded the same
    statement content (``RecordedTaskStatement.equivalent_event_ids``): a re-attach that repeats
    the unchanged statement does not orphan an obligation citing the earlier event.
    An obligation whose ``source_refs`` names a statement event is the agent's recorded mapping
    of the user's request (TB4 pilot). When it lists a test file in ``requested_items`` with
    ``item_kind`` ``file``, the request asked for that file to change, so the edit is attributable
    without the decision marker. Only that exact structural relation counts; obligation prose,
    plan text and the statement itself are never read.
    """

    events = _statement_events(statement_event_id)
    if projection is None or not events:
        return frozenset()
    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if not scope.readable or not scope.effective_obligation_refs:
        return frozenset()
    values: set[str] = set()
    for obligation in scope.effective_obligation_refs:
        row = projection.obligations.get(obligation)
        payload = None if row is None else row.payload
        if payload is None or events.isdisjoint(payload.source_refs):
            continue
        values.update(
            item.value
            for item in payload.requested_items
            # A declared input (#1002) is read, not asked to change, so it never justifies an
            # edit. A ``directory`` item never does either: only the exact file counts.
            if item.item_kind is RequestedItemKind.FILE and item.role is not RequestedItemRole.INPUT
        )
    return frozenset(values)


def _path_requested(path: str, requested: frozenset[str]) -> bool:
    """Match a captured repository-relative path against requested file items, exactly.

    Accepted spellings are the path itself, ``./`` plus the path, an absolute path ending in
    ``/`` plus the path (the workspace root is not recorded), or the path's digest. Nothing is
    normalized beyond those fixed forms.
    """

    if not requested:
        return False
    if path in requested or f"./{path}" in requested or _path_digest(path) in requested:
        return True
    suffix = f"/{path}"
    return any(value.startswith("/") and value.endswith(suffix) for value in requested)


def _path_justified(
    path: str,
    actions: Mapping[Any, Any],
    decisions: Mapping[Any, Any],
    requested: frozenset[str] = frozenset(),
) -> bool:
    if _path_requested(path, requested):
        return True
    latest = _latest_edit_action(path, actions)
    if latest is None:
        return False
    latest_action_id, latest_frontier = latest
    digest = _path_digest(path)
    for decision in decisions.values():
        payload = getattr(decision, "payload", None)
        if type(payload) is not DecisionRecordedPayload:
            continue
        decision_frontier = getattr(decision, "source_frontier", None)
        if type(decision_frontier) is not int or decision_frontier <= latest_frontier:
            continue
        # A fixed, line-delimited marker is required in the decision statement.  It carries only
        # a safe path digest and the newest matching edit action. Requiring the decision after that
        # action prevents a disposition for an earlier edit of the same path from clearing a later
        # edit. Matching arbitrary prose or a rationale that merely repeats a path would let an
        # unrelated decision clear the edit and would leak the path at a structural boundary.
        # Either spelling of the marker counts (ADR-048).
        markers = {
            f"{prefix}:{latest_action_id}:{digest}"
            for prefix in (_TEST_CHANGE_MARKER, _LEGACY_TEST_CHANGE_MARKER)
        }
        if any(line.strip() in markers for line in payload.statement.splitlines()):
            return True
    return False


def _latest_edit_action(path: str, actions: Mapping[Any, Any]) -> tuple[str, int] | None:
    digest = _path_digest(path)
    matches: list[tuple[str, int]] = []
    for action in actions.values():
        payload = getattr(action, "payload", None)
        frontier = getattr(action, "source_frontier", None)
        if (
            type(payload) is ActionRecordedPayload
            and payload.action_kind is ActionKind.EDIT
            and (path in payload.attempted_items or digest in payload.attempted_items)
            and type(frontier) is int
        ):
            matches.append((str(payload.action_id), frontier))
    if not matches:
        return None
    return max(matches, key=lambda item: (item[1], item[0]))


def _edit_action_refs(path: str, actions: Mapping[Any, Any]) -> tuple[set[str], set[EventId]]:
    digest = _path_digest(path)
    action_ids: set[str] = set()
    event_ids: set[EventId] = set()
    for action in actions.values():
        payload = getattr(action, "payload", None)
        if (
            type(payload) is ActionRecordedPayload
            and payload.action_kind is ActionKind.EDIT
            and (path in payload.attempted_items or digest in payload.attempted_items)
        ):
            action_ids.add(str(payload.action_id))
            source_event_id = getattr(action, "source_event_id", None)
            if type(source_event_id) is str:
                event_ids.add(cast(EventId, source_event_id))
    return action_ids, event_ids


def preexisting_test_edits(
    capture: CheckChangeCapture | CheckChangeMetadata,
    projection: ProjectionState | None = None,
    *,
    task_statement_event_id: EventId | Iterable[EventId] | None = None,
) -> PreExistingTestEdits:
    """Reduce one bounded change capture to privacy-safe pre-existing-test edit facts.

    Only ``task_start`` captures prove the task-start baseline.  ``first_check``, ``head`` and
    ``empty`` captures do not prove what existed before the first check, so they produce the
    explicit baseline coverage gap and never create an unjustified-edit count.
    ``task_statement_event_id`` names the current statement event; a test file requested by a
    statement-sourced obligation is justified without the decision marker.
    """

    if type(capture) is CheckChangeMetadata:
        return _preexisting_test_edits_from_metadata(
            capture, projection, task_statement_event_id=task_statement_event_id
        )
    if type(capture) is not CheckChangeCapture:
        raise TypeError("preexisting_test_capture_invalid")
    baseline_known = capture.base == "task_start"
    if not baseline_known:
        return PreExistingTestEdits(baseline_known=False)
    counts: dict[TestEditKind, int] = {
        "modified": 0,
        "renamed": 0,
        "deleted": 0,
        "skipped": 0,
    }
    unjustified_paths: set[str] = set()
    unjustified_action_event_ids: set[EventId] = set()
    # A bounded capture can list only a prefix of changed files.  Visible entries remain useful,
    # but omitted/truncated files keep the aggregate explicitly unknown instead of looking clean.
    unknown = capture.omitted_files if capture.omitted_files else int(capture.truncated)
    actions: Mapping[Any, Any] = {} if projection is None else projection.actions
    decisions: Mapping[Any, Any] = {} if projection is None else projection.decisions
    requested = _statement_requested_files(projection, task_statement_event_id)
    skip_paths = _diff_paths_with_skip_markers(capture)
    diff_pairs = list(_diff_path_pairs(capture))
    used_pairs: set[int] = set()
    for status, path in _header_entries(capture):
        if path is None:
            unknown += 1
            continue
        kind: TestEditKind | None = cast(
            dict[str, TestEditKind],
            {
                "M": "modified",
                "R": "renamed",
                "D": "deleted",
            },
        ).get(status)
        if kind is None:
            continue  # added and untracked tests are new, not pre-existing edits
        pair_index = next(
            (
                index
                for index, pair in enumerate(diff_pairs)
                if index not in used_pairs and path in pair
            ),
            None,
        )
        if pair_index is None:
            candidate_paths = (path,)
        else:
            used_pairs.add(pair_index)
            candidate_paths_list: list[str] = [path]
            candidate_paths_list.extend(
                candidate for candidate in diff_pairs[pair_index] if candidate is not None
            )
            candidate_paths = tuple(dict.fromkeys(candidate_paths_list))
        if not any(_is_test_path(candidate) for candidate in candidate_paths):
            continue
        counts[kind] += 1
        if any(candidate in skip_paths for candidate in candidate_paths):
            counts["skipped"] += 1
        if projection is not None and not any(
            _path_justified(candidate, actions, decisions, requested)
            for candidate in candidate_paths
        ):
            # The destination/header identity is only an in-process aggregate key; no path is
            # returned by this reducer.
            unjustified_paths.add(path)
            for candidate in candidate_paths:
                _, action_event_ids = _edit_action_refs(candidate, actions)
                unjustified_action_event_ids.update(action_event_ids)
    return PreExistingTestEdits(
        modified=counts["modified"],
        renamed=counts["renamed"],
        deleted=counts["deleted"],
        skipped=counts["skipped"],
        unjustified=len(unjustified_paths),
        unknown=unknown,
        unjustified_action_event_ids=tuple(sorted(unjustified_action_event_ids, key=str.encode)),
    )


def _preexisting_test_edits_from_metadata(
    capture: CheckChangeMetadata,
    projection: ProjectionState | None,
    *,
    task_statement_event_id: EventId | Iterable[EventId] | None = None,
) -> PreExistingTestEdits:
    """Reduce path/status metadata without treating missing content as a clean skip result."""

    baseline_known = capture.base == "task_start"
    if not baseline_known:
        return PreExistingTestEdits(baseline_known=False)
    counts: dict[TestEditKind, int] = {
        "modified": 0,
        "renamed": 0,
        "deleted": 0,
        "skipped": 0,
    }
    unjustified_paths: set[str] = set()
    unjustified_action_event_ids: set[EventId] = set()
    unknown = capture.omitted_files if capture.omitted_files else int(capture.truncated)
    actions: Mapping[Any, Any] = {} if projection is None else projection.actions
    decisions: Mapping[Any, Any] = {} if projection is None else projection.decisions
    requested = _statement_requested_files(projection, task_statement_event_id)
    test_edit_present = False
    for entry in capture.entries:
        if type(entry) is not ChangeMetadataEntry:
            continue
        kind = cast(
            dict[str, TestEditKind],
            {"M": "modified", "R": "renamed", "D": "deleted"},
        ).get(entry.status)
        if kind is None:
            continue
        candidate_paths_list = [entry.path]
        if entry.original_path is not None:
            candidate_paths_list.append(entry.original_path)
        candidate_paths = tuple(dict.fromkeys(candidate_paths_list))
        if not any(_is_test_path(candidate) for candidate in candidate_paths):
            continue
        test_edit_present = True
        counts[kind] += 1
        if projection is not None and not any(
            _path_justified(candidate, actions, decisions, requested)
            for candidate in candidate_paths
        ):
            unjustified_paths.add(entry.path)
            for candidate in candidate_paths:
                _, action_event_ids = _edit_action_refs(candidate, actions)
                unjustified_action_event_ids.update(action_event_ids)
    # Metadata intentionally contains no diff body.  A pre-existing test may therefore have
    # acquired a skip marker that cannot be observed on this path; keep that uncertainty visible
    # as its own code. The edit set and each edit's justification were read in full, so this is
    # not a baseline gap and never hides an unjustified edit.
    skip_unknown = 0
    if test_edit_present and not capture.content_available:
        skip_unknown = 1
        unknown += 1
    return PreExistingTestEdits(
        modified=counts["modified"],
        renamed=counts["renamed"],
        deleted=counts["deleted"],
        skipped=counts["skipped"],
        baseline_known=True,
        unjustified=len(unjustified_paths),
        unknown=unknown,
        unjustified_action_event_ids=tuple(sorted(unjustified_action_event_ids, key=str.encode)),
        skip_unknown=skip_unknown,
    )
