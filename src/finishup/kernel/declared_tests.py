"""The agent's declared decisive tests, listed for the closing reviewer (issue #1220, ADR-006).

A test manifest on ``result_recorded`` may name the test file that produced it (``test_file``,
#1170). At most three such files, task criteria first, are listed in the review packet as
structural metadata: the path as declared, the content digest FinishUP observed when the check
ran, and the criterion they declare against. The content itself never enters the packet; the
reviewer may read a listed file through ``read_file`` beneath the service-issued ``t1`` root, and
only while its bytes still match that digest. The list is offered at the closing review and at the
first review after a listed digest is new; an unchanged digest is never offered twice.

Entries are JSON objects so later manifest fields (#1219: ``checks``, ``expected_from``) can join
them without changing this shape.
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
    "DECLARED_TEST_QUESTION",
    "DECLARED_TEST_READ_BYTES",
    "DECLARED_TEST_ROOT",
    "MAX_DECLARED_TESTS",
    "DeclaredTest",
    "DeclaredTestCandidate",
    "declared_test_candidates",
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
# Asked only beside the list (fixed text, at most 250 bytes; ADR-006 #1220).
DECLARED_TEST_QUESTION: Final = (
    "For each listed declared test (declared_tests; read_file root_id t1, path=its ref), read "
    "it if needed and judge whether its expected value comes from the task or an independent "
    "source, or from the implementation."
)


@dataclass(frozen=True, slots=True)
class DeclaredTestCandidate:
    """One declared test file the ledger names, before FinishUP has looked at it."""

    path: str
    criterion_ref: str


@dataclass(frozen=True, slots=True)
class DeclaredTest:
    """One listed declared test: its ref, the declared path, the pinned digest, its criterion."""

    ref: str
    path: str
    content_digest: str
    criterion_ref: str

    def __post_init__(self) -> None:
        if (
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
        if type(row) is not dict or set(cast(dict[str, object], row)) != {
            "content_digest",
            "criterion_ref",
            "path",
            "ref",
        }:
            raise ValueError("declared_test_invalid")
        body = cast(Mapping[str, object], row)
        tests.append(
            DeclaredTest(
                cast(str, body["ref"]),
                cast(str, body["path"]),
                cast(str, body["content_digest"]),
                cast(str, body["criterion_ref"]),
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
        best[manifest.test_file] = (rank, DeclaredTestCandidate(manifest.test_file, criterion_ref))
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
    if system_directory_path(location):
        return None
    return location


def offered_declared_tests(
    tests: Sequence[DeclaredTest], *, final: bool, offered: Collection[str]
) -> tuple[DeclaredTest, ...]:
    """The list to offer: all of it at the closing review or when a digest is new, else none."""

    if not tests:
        return ()
    if final or any(test.content_digest not in offered for test in tests):
        return tuple(tests)
    return ()
