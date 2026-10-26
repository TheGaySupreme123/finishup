"""The agent's declared decisive tests, listed for the closing reviewer (issue #1220, ADR-006).

A test manifest on ``result_recorded`` may name the test file that produced it (``test_file``,
#1170). At most three such files, task criteria first, are listed in the review packet as
structural metadata: the path as declared, the content digest FinishUP observed when the check
ran, and the criterion they declare against. The content itself never enters the packet; the
reviewer may read a listed file through ``read_file`` beneath the service-issued ``t1`` root, and
only while its bytes still match that digest. The list is offered at the closing review and at the
first review after a listed digest is new; an unchanged digest is never offered twice.

Entries are JSON objects so later manifest fields can join them without changing this shape:
the agent's own ``expected_from`` tag (#1219) rides an entry when the manifest declared one
(#1145), so the reviewer checks the agent's claim; an entry without a tag keeps its exact bytes.

#1145: the reviewer may answer with up to two ``declared_test_verdicts`` rows (where it observed
each listed test's expected value come from, and one runnable counter-example). A row that finds
the expected value shared with the implementation, or a test that cannot fail, becomes one
tracked, non-blocking advisory keyed on the test's digest: never raised twice for the same bytes,
at most two per task.
"""

from __future__ import annotations

import posixpath
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

from finishup.domain.privacy import system_directory_path
from finishup.domain.repository_excerpt import credential_named_path
from finishup.domain.verification_coverage import criterion_quote_pattern
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import effective_obligations
from finishup.kernel.verification_coverage import criterion_obligations
from finishup.protocol.canonical import JsonValue

__all__ = [
    "ADVISED_TEST_VERDICTS",
    "DECLARED_TEST_EXPECTED_FROM",
    "DECLARED_TEST_QUESTION",
    "DECLARED_TEST_VERDICT_OBSERVATIONS",
    "MAX_COUNTER_EXAMPLE_CHARS",
    "MAX_DECLARED_TEST_ADVICE_PER_TASK",
    "MAX_DECLARED_TEST_VERDICTS",
    "DECLARED_TEST_READ_BYTES",
    "DECLARED_TEST_ROOT",
    "MAX_DECLARED_TESTS",
    "DeclaredTest",
    "DeclaredTestCandidate",
    "declared_test_candidates",
    "declared_test_criterion_quote",
    "declared_test_location",
    "declared_tests_from_json",
    "declared_tests_to_json",
    "offered_declared_tests",
]

MAX_DECLARED_TESTS: Final = 3
# What one read of a listed file may carry to the reviewer, its result envelope included.
DECLARED_TEST_READ_BYTES: Final = 4096
# The one ``read_file`` alias that serves listed files, by ref, never by filesystem path.
DECLARED_TEST_ROOT: Final = "t1"
# A longer declared path is not listed: it would cost the packet more than the entry it names.
_MAX_LISTED_PATH: Final = 256
_MAX_DECLARED_PATH: Final = 1024
# Asked only beside the list (fixed text, at most 250 bytes; ADR-006 #1220). #1145 names the tag
# and the optional reply field here; the field's own guidance rides the reply schema.
DECLARED_TEST_QUESTION: Final = (
    "Read listed declared_tests as needed (read_file root_id t1, path=its ref) and judge whether "
    "each expected value comes from the task, an independent source or the implementation, "
    "versus its expected_from tag; answer in declared_test_verdicts."
)


# #1219's closed tag vocabulary (``VerificationExpectedFrom``), restated so this kernel module stays
# free of the event codec; ``test_declared_test_verdicts`` pins the two sets equal.
DECLARED_TEST_EXPECTED_FROM: Final = frozenset(
    {
        "task_text",
        "independent_source",
        "own_reimplementation",
        "implementation_output",
        "hand_computed",
    }
)
# #1145: the reviewer's own reading of a listed test, at most two rows per review.
DECLARED_TEST_VERDICT_OBSERVATIONS: Final = (
    "task_text",
    "independent_source",
    "shared_with_implementation",
    "cannot_fail",
    "not_visible",
)
# The observations that become a tracked advisory when the row also names a counter-example.
ADVISED_TEST_VERDICTS: Final = frozenset({"shared_with_implementation", "cannot_fail"})
MAX_DECLARED_TEST_VERDICTS: Final = 2
MAX_COUNTER_EXAMPLE_CHARS: Final = 300
MAX_DECLARED_TEST_ADVICE_PER_TASK: Final = 2


@dataclass(frozen=True, slots=True)
class DeclaredTestCandidate:
    """One declared test file the ledger names, before FinishUP has looked at it."""

    path: str
    criterion_ref: str
    expected_from: str | None = None


@dataclass(frozen=True, slots=True)
class DeclaredTest:
    """One listed declared test: its ref, the declared path, the pinned digest, its criterion."""

    ref: str
    path: str
    content_digest: str
    criterion_ref: str
    # #1145: the agent's own ``expected_from`` tag on the manifest that named this file, if any.
    expected_from: str | None = None

    def __post_init__(self) -> None:
        if (
            self.expected_from is not None
            and (
                type(self.expected_from) is not str
                or self.expected_from not in DECLARED_TEST_EXPECTED_FROM
            )
        ) or (
            type(self.ref) is not str
            or self.ref not in {f"dt{n}" for n in range(1, MAX_DECLARED_TESTS + 1)}
            or type(self.path) is not str
            or not 0 < len(self.path) <= _MAX_LISTED_PATH
            or type(self.content_digest) is not str
            or len(self.content_digest) != 71
            or not self.content_digest.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in self.content_digest[7:])
            or type(self.criterion_ref) is not str
            or not 0 < len(self.criterion_ref) <= 64
        ):
            raise ValueError("declared_test_invalid")

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "content_digest": self.content_digest,
            "criterion_ref": self.criterion_ref,
            # #1145: present only when the agent tagged the test, so untagged entries keep bytes.
            **({} if self.expected_from is None else {"expected_from": self.expected_from}),
            "path": self.path,
            "ref": self.ref,
        }


def declared_tests_to_json(tests: Sequence[DeclaredTest]) -> list[JsonValue]:
    return [cast(JsonValue, test.to_json()) for test in tests]


def declared_tests_from_json(value: object) -> tuple[DeclaredTest, ...]:
    """The listed tests a stored case object recorded; ``()`` for an older object."""

    if value is None:
        return ()
    if type(value) is not list or len(cast(list[object], value)) > MAX_DECLARED_TESTS:
        raise ValueError("declared_test_invalid")
    tests: list[DeclaredTest] = []
    for row in cast(list[object], value):
        if type(row) is not dict or set(cast(dict[str, object], row)) - {"expected_from"} != {
            "content_digest",
            "criterion_ref",
            "path",
            "ref",
        }:
            raise ValueError("declared_test_invalid")
        body = cast(Mapping[str, object], row)
        if "expected_from" in body and body["expected_from"] is None:
            raise ValueError("declared_test_invalid")
        tests.append(
            DeclaredTest(
                cast(str, body["ref"]),
                cast(str, body["path"]),
                cast(str, body["content_digest"]),
                cast(str, body["criterion_ref"]),
                cast(str | None, body.get("expected_from")),
            )
        )
    if [test.ref for test in tests] != [f"dt{n}" for n in range(1, len(tests) + 1)]:
        raise ValueError("declared_test_invalid")
    return tuple(tests)


def _occurs(quote: str, text: str) -> bool:
    pattern = criterion_quote_pattern(quote)
    return quote in text if pattern is None else pattern.search(text) is not None


def declared_test_candidates(
    projection: ProjectionState, task_statement: str | None
) -> tuple[DeclaredTestCandidate, ...]:
    """Up to three distinct declared test files, task criteria first, then the newest.

    Only a manifest that names ``test_file`` and whose criterion quote the task statement (or,
    second, an effective obligation's criteria) still states is considered; each path once, at
    its best rank. The criterion ref is the first obligation that states the quote, else the
    declaring result. Pure over the frozen projection, so recovery names the same candidates.
    """

    obligation_texts = tuple(
        text
        for obligation in effective_obligations(projection)
        if (payload := projection.obligations[obligation].payload) is not None
        and (text := payload.acceptance_criteria)
    )
    best: dict[str, tuple[tuple[int, int], DeclaredTestCandidate]] = {}
    for row in projection.results.values():
        payload = row.payload
        manifest = None if payload is None else payload.verification
        if payload is None or manifest is None or manifest.test_file is None:
            continue
        quote = manifest.criterion_quote
        if task_statement is not None and _occurs(quote, task_statement):
            source = 0
        elif any(_occurs(quote, text) for text in obligation_texts):
            source = 1
        else:
            continue
        rank = (source, -row.source_frontier)
        if manifest.test_file in best and best[manifest.test_file][0] <= rank:
            continue
        obligations = criterion_obligations(projection, quote)
        action = projection.actions.get(payload.action_id)
        linked = () if action is None or action.payload is None else action.payload.obligation_refs
        criterion_ref = str(
            obligations[0] if obligations else linked[0] if linked else payload.result_id
        )
        best[manifest.test_file] = (
            rank,
            DeclaredTestCandidate(
                manifest.test_file,
                criterion_ref,
                None if manifest.expected_from is None else manifest.expected_from.value,
            ),
        )
    ordered = sorted(best.values(), key=lambda pair: (pair[0], pair[1].path.encode()))
    return tuple(candidate for _rank, candidate in ordered[:MAX_DECLARED_TESTS])


def declared_test_location(path: str, workspace_root: str | None) -> str | None:
    """The absolute path a listed test is read at, or ``None`` when it may never be read.

    A relative path is beneath the workspace. Refused by shape alone, before any filesystem
    probe: a path too long to list, an empty, ``.``, ``..`` or hidden component, a backslash,
    a NUL or control character, a credential-named component, or a system directory.
    """

    if (
        type(path) is not str
        or not 0 < len(path) <= min(_MAX_LISTED_PATH, _MAX_DECLARED_PATH)
        or "\\" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        return None
    relative = not path.startswith("/")
    parts = path.split("/")[(0 if relative else 1) :]
    if any(part in {"", ".", ".."} or part.startswith(".") for part in parts):
        return None
    if any(credential_named_path(part) for part in parts):
        return None
    if relative:
        if workspace_root is None or not workspace_root.startswith("/"):
            return None
        location = posixpath.normpath(posixpath.join(workspace_root, path))
    else:
        location = posixpath.normpath(path)
    # Case-folded too: on a case-insensitive volume ``/ETC`` is ``/etc``. The read also refuses
    # by device and inode (``adapters.task_input_read.read_declared_test``).
    if system_directory_path(location) or system_directory_path(location.casefold()):
        return None
    return location


def offered_declared_tests(
    tests: Sequence[DeclaredTest], *, final: bool, offered: Collection[str]
) -> tuple[DeclaredTest, ...]:
    """The list to offer: all of it at the closing review; otherwise only the tests whose digest
    no earlier review was offered (#1220 review), each keeping the ref it was pinned under, so the
    packet, the ``t1`` root and the stored job list name a test alike."""

    if final:
        return tuple(tests)
    return tuple(test for test in tests if test.content_digest not in offered)


def declared_test_criterion_quote(projection: ProjectionState, path: str) -> str | None:
    """The criterion quote of the newest manifest that names ``path`` as its test file (#1145).

    The agent's own words, for the advisory that tells it which of its tests a verdict is about.
    Pure over the frozen projection, so a recovered check words the advisory the same.
    """

    newest: tuple[int, str] | None = None
    for row in projection.results.values():
        manifest = None if row.payload is None else row.payload.verification
        if manifest is None or manifest.test_file != path:
            continue
        if newest is None or row.source_frontier > newest[0]:
            newest = (row.source_frontier, manifest.criterion_quote)
    return None if newest is None else newest[1]
