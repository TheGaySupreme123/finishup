"""Service-side redaction of the check-time change (ADR-031, issue #883)."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, Final, cast

import pytest

from finishup.adapters.privacy.local_enforcer import scan_exact_bytes
from finishup.application import check_change as check_change_module
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
from finishup.ports.change_capture import (
    ChangeCaptureUnavailable,
    CheckChangeCapture,
    CheckWorkspaceSource,
)

_redacted = getattr(check_change_module, "_redacted")


def _capture(text: bytes) -> CheckChangeCapture:
    return CheckChangeCapture(
        base="task_start",
        text=text,
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
    )


def test_parser_source_with_more_matches_than_one_scan_reports_is_fully_redacted() -> None:
    """A change can repeat credential-shaped ``token = ...`` lines far past one scan's cap.

    The meriyah parser shape (``token = parser.getToken()``) is source code and no longer
    matches (issue #982), so the repeated line is a quoted credential-shaped literal.
    """

    lines = b"".join(
        f'+  const token = "a8F3kL9q{index:04d}Zx";\n'.encode() for index in range(600)
    )
    text = b"diff --git a/src/parser.ts b/src/parser.ts\n" + lines

    redacted = _redacted(_capture(text))

    assert redacted.redacted
    assert scan_exact_bytes(redacted.text) == ()
    # Heuristic-only values read as the self-describing placeholder, never a bare [REDACTED].
    assert redacted.text.count(EGRESS_CREDENTIAL_PLACEHOLDER) == 600
    assert b"[REDACTED]" not in redacted.text
    assert b"src/parser.ts" in redacted.text


def test_a_value_that_only_looks_like_a_credential_reads_as_withheld_not_as_code() -> None:
    """tb4n5 live-database-cutover: ``password=config.POSTGRES_PASSWORD`` reached the reviewer
    as ``password=[REDACTED]``, which it read as an undefined name (a NameError finding)."""

    line = (
        b"+    return URL.create('postgresql+psycopg',username=config.POSTGRES_USER,"
        b"password=config.POSTGRES_PASSWORD,host=config.POSTGRES_HOST)\n"
    )
    token = b"ghp_" + b"Q" * 36
    text = b"diff --git a/api/db.py b/api/db.py\n" + line + b"+TOKEN = '" + token + b"'\n"

    redacted = _redacted(_capture(text))

    assert redacted.redacted
    assert b"password=" + EGRESS_CREDENTIAL_PLACEHOLDER + b"," in redacted.text
    assert b"config.POSTGRES_PASSWORD" not in redacted.text
    # A concrete credential shape still reads [REDACTED]; both converge to a clean scan.
    assert token not in redacted.text and b"TOKEN = '[REDACTED]'" in redacted.text
    assert scan_exact_bytes(redacted.text) == ()
    assert _redacted(redacted) is redacted


def test_clean_change_is_returned_unchanged() -> None:
    capture = _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    assert _redacted(capture) is capture


def test_change_that_cannot_be_fully_redacted_is_withheld(monkeypatch: pytest.MonkeyPatch) -> None:
    def never_clean(data: bytes, **_: object) -> tuple[bytes, bool]:
        return data + b".", True

    monkeypatch.setattr(check_change_module, "redact_sensitive_content", never_clean)

    with pytest.raises(ChangeCaptureUnavailable) as caught:
        _redacted(_capture(b"+token = forever-matching\n"))
    assert caught.value.reason == "redaction_incomplete"


@pytest.mark.anyio
async def test_unavailable_reason_is_frozen_in_the_binding_and_recovered() -> None:
    from finishup.application.check_change import CheckChangeOutcome, recover_check_time_change

    outcome = CheckChangeOutcome(unavailable=True, reason="changed_during_capture")
    binding = outcome.binding_json()
    assert isinstance(binding, dict) and binding["reason"] == "changed_during_capture"

    recovered = await recover_check_time_change(cast(Any, None), dict(binding))

    assert recovered == outcome
    legacy = {key: value for key, value in binding.items() if key != "reason"}
    assert await recover_check_time_change(cast(Any, None), legacy) == CheckChangeOutcome(
        unavailable=True
    )
    with pytest.raises(ValueError):
        await recover_check_time_change(cast(Any, None), {**binding, "reason": "free text"})
    with pytest.raises(ValueError):
        CheckChangeOutcome(unavailable=False, reason="git_failed")


@pytest.mark.anyio
async def test_structural_capture_does_not_fallback_to_legacy_content_port() -> None:
    from finishup.application.check_change import capture_structural_check_change

    class LegacyPort:
        def capture(self, workspace: str, base: object) -> CheckChangeCapture:
            raise AssertionError("legacy content capture must not be called")

    source = CheckWorkspaceSource("/workspace", "hmac-sha256:" + "a" * 64)
    result = await capture_structural_check_change(
        runtime=cast(Any, SimpleNamespace(ledger=SimpleNamespace())),
        source=source,
        route_repository_commitment=source.repository_commitment,
        port=cast(Any, LegacyPort()),
        clock=cast(Any, None),
        request_id="req_30000000-0000-4000-8000-000000000001",
    )

    assert result == (None, "metadata_unavailable")


def test_declared_deliverables_reach_the_port_and_a_plain_port_keeps_working() -> None:
    """tb4n2 R7: the ordering hint is passed only when there is one, so older ports still work."""

    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    seen: list[tuple[str, ...]] = []

    class OrderingPort:
        def capture(
            self, workspace: str, base: object, *, priority_paths: tuple[str, ...] = ()
        ) -> CheckChangeCapture:
            seen.append(priority_paths)
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    class PlainPort:
        def capture(self, workspace: str, base: object) -> CheckChangeCapture:
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    _capture_redacted(OrderingPort(), "/repo", None, ("out.json",))
    _capture_redacted(PlainPort(), "/repo", None)

    assert seen == [("out.json",)]


# --- Issue #1045: task input files and the task-start snapshot -----------------------------------


def test_task_input_paths_are_the_files_the_statement_names_then_declared_inputs() -> None:
    from builders.policy_cases import make_case, obl, obligation_record, plan_record
    from finishup.application.check_change import task_input_paths
    from finishup.domain.events import (
        ObligationPublishedPayload,
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Port the form",
            "form.py behaves like the VBA form",
            ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(
                    RequestedItemKind.FILE, "rules/RULEBOOK.txt", RequestedItemRole.INPUT
                ),
                RequestedItem(RequestedItemKind.FILE, "form.py", RequestedItemRole.OUTPUT),
            ),
        ),
        1,
    )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Port the form", (obl(1),)), 1)},
        obligations={obl(1): obligation},
        extra_refs=(obl(1),),
    )
    statement = (
        "Port the VBA UserForm in /app/vba/UserForm1.frm to Python (see `DESIGN.md` and "
        "spec/rules.txt). Use main.c, e.g. numpy 3.10, i.e. https://example.invalid/x.md. "
        "Write the result to /app/out/ and DESIGN.md again."
    )

    paths = task_input_paths(case.projection, statement)

    assert paths == (
        "/app/vba/UserForm1.frm",
        "DESIGN.md",
        "spec/rules.txt",
        "main.c",
        "rules/RULEBOOK.txt",
        # Issue #1082: an absolute directory the statement names comes last. Issue #1102: the
        # repository read lists one inside the repository; outside it, only an admitted root does.
        "/app/out/",
    )
    assert task_input_paths(case.projection, None) == ("rules/RULEBOOK.txt",)


def test_a_quoted_or_escaped_path_with_spaces_is_one_candidate() -> None:
    """Issue #1102 (RC6d): a path with spaces was split into words that name nothing."""

    from builders.policy_cases import make_case
    from finishup.application.check_change import task_input_paths

    projection = make_case().projection

    # The words the spaces cut from an absolute spaced path name nothing the task named, so
    # they never count (review goal-r1-2): ``/app/My`` could be an unrelated folder.
    assert task_input_paths(projection, 'Read "/app/My Documents/spec.md" and write out.txt') == (
        "/app/My Documents/spec.md",
        "out.txt",
    )
    # An escaped space is unambiguous: one value.
    assert task_input_paths(projection, "Read /app/My\\ Documents/spec.md and write out.txt") == (
        "/app/My Documents/spec.md",
        "out.txt",
    )
    assert task_input_paths(
        projection,
        "Read '/app/data files/input.csv' then write report.md; don't touch it's John's.",
    ) == ("/app/data files/input.csv", "report.md")
    # A relative spaced path keeps its last word, which a quoted command needs: the file
    # ``cat docs/spec.md`` names must not be lost. Its head word never counts.
    assert task_input_paths(projection, 'Read "My Docs/spec.md" and run `cat docs/rules.md`') == (
        "My Docs/spec.md",
        "Docs/spec.md",
        "cat docs/rules.md",
        "docs/rules.md",
    )
    # A span with an option-like word is a command, never one path; its file still counts.
    assert task_input_paths(projection, "Run `pytest -q tests/test_a.py` then read a.md") == (
        "tests/test_a.py",
        "a.md",
    )
    # Prose ahead of an absolute path is not part of it; a span listing whole files is prose.
    assert task_input_paths(projection, 'Use "see /app/My Docs/spec.md" now')[0] == (
        "/app/My Docs/spec.md"
    )
    assert task_input_paths(projection, '"see docs/a.md and docs/b.md"') == (
        "docs/a.md",
        "docs/b.md",
    )
    assert (
        task_input_paths(
            projection, 'Run `pip install -e .` then "make test" and read "the README file"'
        )
        == ()
    )
    # A quoted command or quoted prose is never one path, so the folder it names is kept
    # (review correctness-r2-1): shell operators, a word ending in ``/`` ahead of more words, a
    # word joining two paths, and a spaced last component that is no file name all mark it.
    assert task_input_paths(projection, "Run `cd /app/vllm && pytest` to reproduce.") == (
        "/app/vllm",
    )
    assert task_input_paths(projection, "Fix it: `cd /app/src && make` fails.") == ("/app/src",)
    assert task_input_paths(projection, "Run `cat a/b.log | grep x` and `make > out/r.txt`") == (
        "a/b.log",
        "out/r.txt",
    )
    assert task_input_paths(
        projection, 'The issue says "the parser in /app/parser/ fails on empty input".'
    ) == ("/app/parser/",)
    # Only the disk can tell a spaced folder from prose or one path from two (review
    # surfaces-r3-1, correctness-r3-4): the whole value comes first and every word still counts;
    # the read drops those words when the whole value names something (``drop_space_cut_words``).
    assert task_input_paths(projection, 'Note: "/app/config is read-only"') == (
        "/app/config is read-only",
        "/app/config",
    )
    assert task_input_paths(projection, "Summarise the CSVs in '/app/test data' now.") == (
        "/app/test data",
        "/app/test",
    )
    assert task_input_paths(projection, 'Look at "src/dedup and src/util" for context.') == (
        "src/dedup and src/util",
        "src/dedup",
        "src/util",
    )
    assert task_input_paths(projection, 'Read "/app/Terms and Conditions/terms.pdf".') == (
        "/app/Terms and Conditions/terms.pdf",
        "/app/Terms",
        "Conditions/terms.pdf",
    )
    assert task_input_paths(projection, "See `docs/Makefile docs/Dockerfile` first.") == (
        "docs/Makefile docs/Dockerfile",
        "docs/Makefile",
        "docs/Dockerfile",
    )
    # A quoted command naming two paths keeps both operands (review goal-r3-2).
    assert task_input_paths(projection, "Run `ls /app/data /app/models` first.") == (
        "/app/data",
        "/app/models",
    )
    assert task_input_paths(projection, "Read `cat /app/Dockerfile /app/Makefile` first.") == (
        "/app/Dockerfile",
        "/app/Makefile",
    )
    assert task_input_paths(projection, "Compare `diff src/dedup src/util` output.") == (
        "src/dedup",
        "src/util",
    )
    # The last word of a relative spaced folder is never a folder the task names (review
    # goal-r3-1, correctness-r3-2), nor that of a path whose earlier words hold ``/``.
    assert task_input_paths(projection, "Use the cases in 'src/test data/' to verify.") == (
        "src/test data/",
    )
    assert task_input_paths(projection, 'Fix "src/integration tests/" and "input files/".') == (
        "src/integration tests/",
        "input files/",
    )
    assert task_input_paths(projection, "Open 'docs/My Notes.md'.") == ("docs/My Notes.md",)
    # A quoted command's folder operand with a directory part still counts.
    assert task_input_paths(projection, "Run `ls src/data/` first.") == (
        "ls src/data/",
        "src/data/",
    )
    assert task_input_paths(projection, "Run `cd /shared/legacy_app && make` first.") == (
        "/shared/legacy_app",
    )
    # A spaced folder still is one: a ``/`` follows its spaced component.
    assert task_input_paths(projection, 'The data is in "/app/My Docs/" and "/app/My Docs/x"') == (
        "/app/My Docs/x",
        "/app/My Docs/",
    )


def test_unquoted_statements_tokenize_exactly_as_before() -> None:
    """Issue #1102: text holding no quoted or escaped spaced path splits exactly as before."""

    from finishup.application import check_change

    statements = (
        "Port the VBA UserForm in /app/vba/UserForm1.frm to Python (see `DESIGN.md` and "
        "spec/rules.txt). Use main.c, e.g. numpy 3.10, i.e. https://example.invalid/x.md.",
        "Fix the bug in /app/vllm so that the sampler respects min_tokens.",
        "Implement [the interface] {described} in <app/interface/>; keep a,b,c working!",
        "Don't break it's tests: run `pytest -q tests/test_a.py` and 'make lint'.",
        'Quoted "tests/test_b.py" stays one word, as does "x".',
        "Tabs\tand\nnewlines and  double  spaces split words.",
        "A path/with/dirs and a.b and 3.10 and e.g and v1.2.3.",
        "Back\\slash\\words without spaces keep their backslashes.",
        "Edge: ./setup.py, ../up.txt, /abs/, src/, and *.py globs.",
        "Unbalanced \"quote and 'apostrophe and `tick here.",
    )
    for statement in statements:
        tokens = check_change._statement_words(statement)  # pyright: ignore[reportPrivateUsage]
        words = [word for word, split in tokens if not split]
        assert len(words) == len(tokens), statement
        before = check_change._STATEMENT_WORD.findall(  # pyright: ignore[reportPrivateUsage]
            statement
        )
        assert words == before, statement


def test_a_relative_directory_the_statement_names_is_a_candidate_after_files() -> None:
    from builders.policy_cases import make_case
    from finishup.application.check_change import task_input_paths

    projection = make_case().projection

    assert task_input_paths(
        projection, "The code lives in src/dedup/ ; see the dedup package in /app/dedup."
    ) == ("/app/dedup", "src/dedup/")
    # The workspace named whole is a directory candidate too; ``/`` and ``./`` never are.
    assert task_input_paths(projection, "Everything is in /app. Do not touch / or ./ at all.") == (
        "/app",
    )


def test_a_declared_input_with_a_space_is_a_candidate_but_a_requested_output_is_not_probed() -> (
    None
):
    from builders.policy_cases import make_case, obl, obligation_record, plan_record
    from finishup.application.check_change import declared_output_paths, task_input_paths
    from finishup.domain.events import (
        ObligationPublishedPayload,
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Summarize the spec",
            "the summary covers the spec",
            ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(RequestedItemKind.FILE, "My Docs/spec.md", RequestedItemRole.INPUT),
                RequestedItem(RequestedItemKind.DIRECTORY, "data sets/", RequestedItemRole.INPUT),
                RequestedItem(RequestedItemKind.FILE, "My Out/sum.md", RequestedItemRole.OUTPUT),
            ),
        ),
        1,
    )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Summarize", (obl(1),)), 1)},
        obligations={obl(1): obligation},
        extra_refs=(obl(1),),
    )

    assert task_input_paths(case.projection, None) == ("My Docs/spec.md", "data sets/")
    assert declared_output_paths(case.projection) == ()


def test_a_verification_operand_with_a_space_is_an_oracle_candidate() -> None:
    from finishup.application.check_change import verification_input_paths

    case = _verification_case(('pytest -q "tests/my test.py"', "success"))

    assert verification_input_paths(cast(Any, case).projection) == ("tests/my test.py",)


def test_only_words_the_spaces_cut_may_give_way_to_a_spaced_candidate() -> None:
    """PR #1112 review: a path the statement also names on its own, a ``role: input`` item or a
    verification operand is never a space-cut word, so no read drops it for the spaced value."""

    from builders.policy_cases import make_case, obl, obligation_record, plan_record
    from finishup.application.check_change import space_cut_input_paths, task_input_paths
    from finishup.domain.events import (
        ObligationPublishedPayload,
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )

    projection = make_case().projection

    def both(statement: str) -> tuple[tuple[str, ...], frozenset[str]]:
        return (
            task_input_paths(projection, statement),
            space_cut_input_paths(projection, statement),
        )

    # The review's case: ``Notes.md`` is named on its own beside the quoted spaced path.
    assert both('Read "docs/My Notes.md" and Notes.md') == (
        ("docs/My Notes.md", "Notes.md"),
        frozenset(),
    )
    # A word of a span only the disk can tell apart is a cut word, unless named alone too.
    assert both("Summarise the CSVs in '/app/test data' now.") == (
        ("/app/test data", "/app/test"),
        frozenset({"/app/test"}),
    )
    assert both("Summarise '/app/test data', then fix /app/test too.") == (
        ("/app/test data", "/app/test"),
        frozenset(),
    )
    assert both("Summarise '/app/test data' and the folder /app/test/.") == (
        ("/app/test data", "/app/test", "/app/test/"),
        frozenset({"/app/test"}),
    )
    # Prose ahead of a spaced value is no word of it.
    assert space_cut_input_paths(projection, "Note 'see docs/a.md /app/test data'") == {"/app/test"}
    assert space_cut_input_paths(projection, None) == frozenset()
    # A quote opening on an edge character the value loses still cuts its first word.
    assert both("Summarise '*src/test data*' now.") == (
        ("src/test data", "src/test"),
        frozenset({"src/test"}),
    )
    # A sure span keeps none of its cut words, edge character or not.
    assert both("Port '*/shared/legacy app/main.c*'") == (
        ("/shared/legacy app/main.c",),
        frozenset(),
    )

    statement = 'Compare "src/test and src/x.py" first.'
    assert both(statement) == (
        ("src/test and src/x.py", "src/test", "src/x.py"),
        frozenset({"src/test", "src/x.py"}),
    )
    # A recorded verification operand names ``src/x.py`` on its own.
    verified = _verification_case(("pytest -q src/x.py", "success"))
    assert space_cut_input_paths(cast(Any, verified).projection, statement) == {"src/test"}
    # So does a ``role: input`` item.
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Compare",
            "the comparison is written",
            ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(RequestedItemKind.FILE, "src/x.py", RequestedItemRole.INPUT),
                RequestedItem(RequestedItemKind.DIRECTORY, "src/test", RequestedItemRole.INPUT),
            ),
        ),
        1,
    )
    requested = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Compare", (obl(1),)), 1)},
        obligations={obl(1): obligation},
        extra_refs=(obl(1),),
    )
    assert space_cut_input_paths(requested.projection, statement) == frozenset()


def test_the_capture_hands_the_port_and_reader_only_the_space_cut_words() -> None:
    """PR #1112 review: the provenance reaches the repository read and the outside reader, in
    process only; a port is still called without it when there is none."""

    from finishup.application.check_change import (
        _capture_redacted,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.ports.change_capture import TaskInputFile

    asked: list[tuple[tuple[str, ...], frozenset[str] | None]] = []
    read: list[frozenset[str]] = []

    class CutPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
            space_cut_paths: frozenset[str] | None = None,
        ) -> CheckChangeCapture:
            del workspace, base, priority_paths
            # ``None``: the port was called without the option at all.
            asked.append((input_paths, space_cut_paths))
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/a.py b/a.py\n+x\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
            )

    def reader(
        values: tuple[str, ...], room: int, workspace: str, space_cut: frozenset[str]
    ) -> tuple[TaskInputFile, ...]:
        del values, room, workspace
        read.append(space_cut)
        return ()

    paths = ("/shared/test data", "/shared/test", "docs/My Notes.md", "docs/My")
    cut = frozenset({"/shared/test", "docs/My", "never/offered.md"})
    port = cast(Any, CutPort())
    _capture_redacted(port, "/repo", None, (), paths, frozenset(), reader, space_cut_paths=cut)
    _capture_redacted(port, "/repo", None, (), paths, frozenset(), reader)

    assert asked == [(paths, frozenset({"/shared/test", "docs/My"})), (paths, None)]
    assert read == [frozenset({"/shared/test"}), frozenset()]


def test_the_outside_decision_keeps_a_path_named_alone_beside_a_spaced_one() -> None:
    """PR #1112 review: ``/shared/new`` named on its own still counts when ``/shared/new data``
    is there; only the word the spaces cut gives way."""

    from finishup.application.check_change import outside_inputs_not_admitted

    probe = _probe(_ON_DISK)
    candidates = ("/shared/new data", "/shared/new")

    def decide(cut: frozenset[str]) -> bool:
        return outside_inputs_not_admitted(
            candidates,
            frozenset(),
            "/app",
            (),
            (),
            task_started_at=_STARTED,
            probe=probe,
            space_cut=cut,
        )

    assert not decide(frozenset({"/shared/new"}))
    assert decide(frozenset())
    # Compared normalized: a lone ``/shared/new/`` names the same folder, so it still counts.
    assert outside_inputs_not_admitted(
        ("/shared/new data", "/shared/new", "/shared/new/"),
        frozenset(),
        "/app",
        (),
        (),
        task_started_at=_STARTED,
        probe=probe,
        space_cut=frozenset({"/shared/new"}),
    )


_STARTED = 1_000_000.0


def _probe(found: dict[str, tuple[str, float]]) -> Callable[[str], os.stat_result | None]:
    """A metadata probe over ``found``: path -> (``file``, ``dir`` or ``link``, change time)."""

    kinds = {"file": stat.S_IFREG, "dir": stat.S_IFDIR, "link": stat.S_IFLNK}

    def probe(path: str) -> os.stat_result | None:
        if path not in found:
            return None
        kind, when = found[path]
        return os.stat_result((kinds[kind] | 0o644, 1, 1, 1, 0, 0, 10, when, when, when))

    return probe


_ON_DISK: Final = {
    "/shared/spec.md": ("file", _STARTED - 60),
    "/shared/legacy_app": ("dir", _STARTED - 60),
    "/shared/legacy_app/": ("dir", _STARTED - 60),
    "/shared/legacy app/main.c": ("file", _STARTED - 60),
    "/shared/out.json": ("file", _STARTED - 60),
    "/shared/linked": ("link", _STARTED - 60),
    "/root/model.pt": ("file", _STARTED + 5),
    "/output/answer.txt": ("file", _STARTED + 5),
    "/home/user/venv": ("dir", _STARTED + 5),
    "/opt/conda/bin/python": ("file", _STARTED - 60),
    "/opt/conda/lib/python3.12/site-packages/numpy": ("dir", _STARTED - 60),
    "/tmp/result.json": ("file", _STARTED - 60),
    "/var/log/app/server.log": ("file", _STARTED - 60),
    "/var/run/app.sock": ("file", _STARTED - 60),
    "/usr/bin/python3": ("file", _STARTED - 60),
    "/shared/secrets.pem": ("file", _STARTED - 60),
    "/data": ("dir", _STARTED - 60),
    "/legacy": ("dir", _STARTED - 60),
    "/opt": ("dir", _STARTED - 60),
    "/home": ("dir", _STARTED - 60),
    "/var/folders/x1/T/in.csv": ("file", _STARTED - 60),
    "/spec.md": ("file", _STARTED - 60),
    "/output": ("dir", _STARTED - 60),
    "/logs": ("dir", _STARTED - 60),
    "/results": ("dir", _STARTED - 60),
    "/media": ("dir", _STARTED - 60),
    "/shared/new data": ("dir", _STARTED + 5),
    "/shared/new": ("dir", _STARTED - 60),
}


@pytest.mark.parametrize(
    ("candidates", "roots", "outputs", "expected"),
    [
        (("/shared/spec.md",), (), (), True),
        (("/shared/legacy_app/",), (), (), True),
        (("/shared/legacy_app",), (), (), True),
        (("/shared/legacy app/main.c",), (), (), True),
        (("/shared/spec.md",), ("/shared",), (), False),
        (("/shared/legacy_app",), ("/shared/legacy_app",), (), False),
        (("/shared/legacy app/main.c",), ("/shared",), (), False),
        # Nothing on disk there: a route, not an input (review r1-1, surfaces-r1-3, goal-r1-1).
        (("/api/v1/users", "/api/orders", "/v1/chat/completions", "/models/x.pkl"), (), (), False),
        # Written during the task: the agent's output, not an input.
        (("/root/model.pt", "/output/answer.txt", "/home/user/venv"), (), (), False),
        # Scratch, log, tool and package trees; a final link; system trees.
        (("/tmp/result.json", "/var/log/app/server.log"), (), (), False),
        (("/opt/conda/bin/python", "/opt/conda/lib/python3.12/site-packages/numpy"), (), (), False),
        (("/shared/linked",), (), (), False),
        (("/var/run/app.sock", "/proc/1/status", "/run/user/notes.md"), (), (), False),
        (("/shared/out.json",), (), ("/shared/out.json",), False),
        (("/usr/bin/python3", "/lib/x.so"), (), (), False),
        (("/etc/app/config.yaml", "/home/me/.ssh/notes"), (), (), False),
        (("/shared/secrets.pem",), (), (), False),
        (("/app/src/x.py", "/app/My Docs/spec.md", "/APP/other.md"), (), (), False),
        (("/tmp", "/opt"), (), (), False),
        # A top-level folder named whole is an input folder (review correctness-r2-2); a tree of
        # homes or installed software is not, nor the macOS per-user scratch tree.
        (("/data/",), (), (), True),
        (("/data",), (), (), True),
        (("/legacy",), (), (), True),
        (("/data",), ("/data",), (), False),
        (("/home", "/opt", "/"), (), (), False),
        (("/var/folders/x1/T/in.csv", "/private/var/folders/x1/T/in.csv"), (), (), False),
        # No root the owner may admit covers a top-level file (review correctness-r3-1), and a
        # top-level output tree or mount container is no input (review goal-r3-4).
        (("/spec.md",), (), (), False),
        (("/output/", "/logs", "/results", "/media"), (), (), False),
        # The word the spaces cut from a spaced folder that is there never counts.
        (("/shared/new data", "/shared/new"), (), (), False),
        (("/shared/new",), (), (), True),
        (("spec.md", "src/dedup/"), (), (), False),
    ],
)
def test_outside_inputs_not_admitted_is_closed_and_bounded(
    candidates: tuple[str, ...], roots: tuple[str, ...], outputs: tuple[str, ...], expected: bool
) -> None:
    """Issue #1102 (RC6f): a yes or no only, never a path; only for an existing input."""

    from finishup.application.check_change import outside_inputs_not_admitted

    probe = _probe(_ON_DISK)

    # Every unspaced candidate may be a word the spaces cut (``space_cut_input_paths``).
    cut = frozenset(value for value in candidates if " " not in value)

    def decide(oracle: frozenset[str], started: float | None) -> bool:
        return outside_inputs_not_admitted(
            candidates,
            oracle,
            "/app",
            roots,
            outputs,
            task_started_at=started,
            probe=probe,
            space_cut=cut,
        )

    assert decide(frozenset(), _STARTED) is expected
    # A path only a verification command named is never read outside, so it never counts.
    assert not decide(frozenset(candidates), _STARTED)
    # Without the task's start time FinishUP cannot tell an input from an output.
    assert not decide(frozenset(), None)


def test_the_outside_decision_probes_metadata_only_and_never_a_rejected_path() -> None:
    from finishup.application.check_change import outside_inputs_not_admitted

    probed: list[str] = []

    def probe(path: str) -> os.stat_result | None:
        probed.append(path)
        return None

    outside_inputs_not_admitted(
        ("/usr/bin/python3", "/tmp/x.txt", "src/a.py", "/app/b.py", "/shared/c.md"),
        frozenset(),
        "/app",
        (),
        (),
        task_started_at=_STARTED,
        probe=probe,
    )

    assert probed == ["/shared/c.md"]


def _verification_case(*commands: tuple[str, str]) -> object:
    """A case whose recorded command runs are ``(command, outcome)`` pairs, oldest first."""

    from builders.policy_cases import act, make_case, record, res
    from finishup.domain.events import (
        ActionKind,
        ActionRecordedPayload,
        ResultOutcome,
        ResultRecordedPayload,
    )

    actions: dict[Any, Any] = {}
    results: dict[Any, Any] = {}
    for index, (command, outcome) in enumerate(commands, start=1):
        actions[act(index)] = record(
            ActionRecordedPayload(act(index), ActionKind.COMMAND, "verify", command=command),
            2 * index,
        )
        results[res(index)] = record(
            ResultRecordedPayload(res(index), act(index), ResultOutcome(outcome)),
            2 * index + 1,
        )
    return make_case(actions=actions, results=results)


def test_verification_commands_name_their_test_files_newest_first() -> None:
    """Issue #1082: the test a verification ran is the oracle the reviewer needs."""

    from finishup.application.check_change import review_input_paths, verification_input_paths

    case = _verification_case(
        ("pytest -q tests/test_old.py", "failure"),
        ("cat notes/answer.txt", "success"),
        ("python -m pytest tests/test_parser.py::TestBurst::test_order -x", "success"),
        ("node --test ./test/stream.test.mjs", "success"),
        ("pytest 'tests/broken.py", "success"),
    )
    projection = cast(Any, case).projection

    assert verification_input_paths(projection) == (
        "test/stream.test.mjs",
        "tests/test_parser.py",
        "tests/test_old.py",
    )
    statement = "Fix the parser in a.py, b.py, c.py, d.py and e.py."
    ordered, oracle = review_input_paths(projection, statement)
    # Three task files, then the newest oracle, then the rest.
    assert ordered[:5] == ("a.py", "b.py", "c.py", "test/stream.test.mjs", "d.py")
    assert oracle == frozenset(
        {"test/stream.test.mjs", "tests/test_parser.py", "tests/test_old.py"}
    )


def test_a_rerun_command_ranks_by_its_latest_run() -> None:
    """Runs A, B, A: the test behind the latest run takes the oracle place, not B's."""

    from finishup.application.check_change import review_input_paths, verification_input_paths

    case = _verification_case(
        ("pytest -q tests/test_a.py", "failure"),
        ("pytest -q tests/test_b.py", "success"),
        ("pytest -q tests/test_a.py", "success"),
    )
    projection = cast(Any, case).projection

    assert verification_input_paths(projection) == ("tests/test_a.py", "tests/test_b.py")
    ordered, _oracle = review_input_paths(projection, "Fix x.py, y.py and z.py.")
    assert ordered[:4] == ("x.py", "y.py", "z.py", "tests/test_a.py")


def test_an_input_only_a_verification_named_is_labelled_as_its_oracle() -> None:
    from finishup.ports.change_capture import TaskInputFile

    _capture_redacted = getattr(check_change_module, "_capture_redacted")

    class InputPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
                inputs=(
                    TaskInputFile("DESIGN.md", b"# Design\n", 9),
                    TaskInputFile("tests/test_parser.py", b"def test_x(): pass\n", 19),
                ),
            )

    capture = _capture_redacted(
        InputPort(),
        "/repo",
        None,
        (),
        ("DESIGN.md", "/repo/tests/test_parser.py"),
        frozenset({"/repo/tests/test_parser.py"}),
    )

    design, oracle = capture.inputs
    assert design.origin == "task"
    assert oracle.origin == "verification"


def test_outside_inputs_join_the_capture_in_the_room_left_and_are_redacted() -> None:
    """Issue #1082: inputs beneath an admitted root take the same redaction as repository ones,
    fill only the four-input room the repository read left, and need a reader at all."""

    from finishup.ports.change_capture import TaskInputFile

    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    asked: list[tuple[tuple[str, ...], int, str]] = []

    class InputPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
                inputs=tuple(
                    TaskInputFile(name, b"# Design\n", 9) for name in ("a.md", "b.md", "c.md")
                ),
            )

    secret = b'password = "a8F3kL9qZx7Pw2Rt"\n'

    def reader(
        values: tuple[str, ...], room: int, workspace: str, space_cut: frozenset[str]
    ) -> tuple[TaskInputFile, ...]:
        assert space_cut == frozenset()
        asked.append((values, room, workspace))
        return (
            # A reader that returns a workspace file, in any spelling, is not trusted with it.
            TaskInputFile("/REPO/inside/notes.md", b"inside\n", 7, origin="outside_workspace"),
            TaskInputFile("/shared/spec.md", b"spec\n" + secret, 30, origin="outside_workspace"),
            TaskInputFile("/shared/more.md", b"more\n", 5, origin="outside_workspace"),
            # A reader that returns anything else is not trusted with it.
            TaskInputFile("inside.md", b"inside\n", 7),
        )

    paths = (
        "a.md",
        "/shared/spec.md",
        "/repo/inside/notes.md",
        "/Repo/inside/other.md",
        "/shared/legacy/",
    )
    capture = _capture_redacted(InputPort(), "/repo", None, (), paths, frozenset(), reader)

    assert asked == [(("/shared/spec.md", "/shared/legacy/"), 1, "/repo")]
    assert [item.path for item in capture.inputs][-1] == "/shared/spec.md"
    assert len(capture.inputs) == 4
    outside = capture.inputs[-1]
    assert outside.origin == "outside_workspace" and outside.redacted
    assert b"a8F3kL9qZx7Pw2Rt" not in outside.text
    assert capture.redacted
    # Without a reader, nothing outside the repository is read.
    plain = _capture_redacted(InputPort(), "/repo", None, (), paths, frozenset(), None)
    assert all(item.origin == "task" for item in plain.inputs)


def test_a_named_outside_input_outranks_directory_material_the_read_chose() -> None:
    """Issue #1102: a task-named outside file is a named file; a task-named directory's listing
    and the members FinishUP picked beneath it give way to it, keeping only the room left."""

    from finishup.ports.change_capture import TaskInputFile

    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    asked: list[int] = []
    listing = b"FinishUP listing of dedup/: 3 files\ndedup/a.py\ndedup/b.py\ndedup/c.py\n"

    class DirectoryPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
                inputs=(
                    TaskInputFile("DESIGN.md", b"# Design\n", 9),
                    TaskInputFile("dedup/", listing, len(listing), summary=True),
                    TaskInputFile("dedup/a.py", b"A = 1\n", 6, origin="task_directory"),
                    TaskInputFile("dedup/b.py", b"B = 1\n", 6, origin="task_directory"),
                ),
            )

    def reader(
        values: tuple[str, ...], room: int, workspace: str, space_cut: frozenset[str]
    ) -> tuple[TaskInputFile, ...]:
        assert space_cut == frozenset()
        del values, workspace
        asked.append(room)
        return (TaskInputFile("/shared/spec.md", b"spec\n", 5, origin="outside_workspace"),)

    paths = ("DESIGN.md", "/shared/spec.md", "dedup/")
    capture = _capture_redacted(DirectoryPort(), "/repo", None, (), paths, frozenset(), reader)

    assert asked == [3]
    assert [item.path for item in capture.inputs] == [
        "DESIGN.md",
        "/shared/spec.md",
        "dedup/",
        "dedup/a.py",
    ]


def test_the_outside_decision_is_taken_against_the_read_root_and_frozen_into_the_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #1102 review r1-8: the read decides against the root it read (the connection's
    locator), never the session's optional workspace label, and stores one closed flag, so a
    recovered job decodes the same decision and an object without the flag keeps its bytes."""

    from finishup.ports.change_capture import decode_check_change, encode_check_change

    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    monkeypatch.setattr(
        check_change_module, "_lstat_or_none", _probe({"/shared/spec.md": ("file", 1.0)})
    )

    class Port:
        def capture(
            self, workspace: str, base: object, *, input_paths: tuple[str, ...] = ()
        ) -> CheckChangeCapture:
            del workspace, base, input_paths
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
            )

    def run(workspace: str, roots: tuple[str, ...], started: float | None) -> CheckChangeCapture:
        return _capture_redacted(
            Port(),
            workspace,
            None,
            (),
            ("/shared/spec.md",),
            frozenset(),
            None,
            admitted_roots=roots,
            task_started_at=started,
        )

    flagged = run("/app", (), 100.0)
    assert flagged.outside_inputs_not_admitted is True
    encoded = encode_check_change(flagged)
    assert b'"outside_inputs_not_admitted":true' in encoded
    assert b"/shared" not in encoded
    assert decode_check_change(encoded) == flagged
    # The read's own root holds the file, an admitted root covers it, or no start time is known.
    for capture in (
        run("/shared", (), 100.0),
        run("/app", ("/shared",), 100.0),
        run("/app", (), None),
    ):
        assert capture.outside_inputs_not_admitted is False
        assert b"outside_inputs_not_admitted" not in encode_check_change(capture)
    # A present default is not canonical.
    with pytest.raises(ValueError):
        decode_check_change(
            encoded.replace(
                b'"outside_inputs_not_admitted":true', b'"outside_inputs_not_admitted":false'
            )
        )


def test_an_outside_path_only_a_verification_command_names_is_never_read() -> None:
    """PR #1086 review R1-05 probe: with ``/shared`` admitted, a task naming only ``form.py``
    and ``DESIGN.md`` and an agent-recorded ``pytest /shared/unrelated_test.py`` run must not
    read that file; outside reads are for paths the task itself names."""

    from builders.policy_cases import act, make_case, record, res
    from finishup.application.check_change import review_input_paths
    from finishup.domain.events import (
        ActionKind,
        ActionRecordedPayload,
        ResultOutcome,
        ResultRecordedPayload,
    )
    from finishup.ports.change_capture import TaskInputFile

    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    oracle_path = "/shared/unrelated_test.py"
    case = make_case(
        actions={
            act(20): record(
                ActionRecordedPayload(
                    act(20), ActionKind.COMMAND, "Run tests", command=f"pytest {oracle_path}"
                ),
                20,
            )
        },
        results={
            res(20): record(
                ResultRecordedPayload(res(20), act(20), ResultOutcome.SUCCESS, summary="passed"),
                21,
            )
        },
    )
    statement = "Implement form.py following DESIGN.md and /shared/spec.md."
    paths, oracle = review_input_paths(case.projection, statement)
    assert oracle_path in oracle and oracle_path in paths and "/shared/spec.md" in paths
    asked: list[tuple[str, ...]] = []

    class EmptyPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/form.py b/form.py\n+x\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
            )

    def reader(
        values: tuple[str, ...], room: int, workspace: str, space_cut: frozenset[str]
    ) -> tuple[TaskInputFile, ...]:
        assert space_cut == frozenset()
        asked.append(values)
        return tuple(
            TaskInputFile(value, b"OUTSIDE\n", 8, origin="outside_workspace") for value in values
        )

    capture = _capture_redacted(EmptyPort(), "/app", None, (), paths, oracle, reader)

    assert asked == [("/shared/spec.md",)]
    assert [item.path for item in capture.inputs] == ["/shared/spec.md"]


def test_an_input_the_reader_already_redacted_marks_the_capture_redacted() -> None:
    """PR #1086 review R1-04: a summary that withheld a value arrives ``redacted``; the capture
    discloses it even though this pass found nothing left to redact."""

    from dataclasses import replace

    from finishup.ports.change_capture import TaskInputFile

    redacted = getattr(check_change_module, "_redacted")
    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+x\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        inputs=(
            TaskInputFile(
                "book.xlsx", b"format: XLSX workbook\n  [REDACTED]\n", 900, True, summary=True
            ),
        ),
    )
    assert redacted(capture).redacted
    clean = replace(capture, inputs=(replace(capture.inputs[0], redacted=False),))
    assert not redacted(clean).redacted


def test_task_input_files_are_redacted_one_by_one_and_dropped_when_they_cannot_be() -> None:
    from finishup.ports.change_capture import TaskInputFile

    secret = b'password = "a8F3kL9qZx7Pw2Rt"\n'
    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        inputs=(
            TaskInputFile("spec.md", b"# Spec\n" + secret, 7 + len(secret)),
            TaskInputFile("rules.md", b"# Rules\nno secrets here\n", 24),
        ),
    )

    redacted = _redacted(capture)

    spec, rules = redacted.inputs
    assert spec.redacted and b"a8F3kL9qZx7Pw2Rt" not in spec.text
    assert b'password = "' + EGRESS_CREDENTIAL_PLACEHOLDER + b'"' in spec.text
    assert rules == capture.inputs[1]
    # The change itself was clean and stays as it was, but review content was still altered, so
    # the capture discloses it (``check_time_change_redacted``; review of #1045).
    assert redacted.text == capture.text and redacted.redacted
    assert not redacted.truncated


def test_a_task_input_withheld_whole_is_disclosed_as_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review of #1045: an input that cannot be fully redacted is dropped, and that is said."""

    from finishup.ports.change_capture import TaskInputFile

    original = check_change_module.redact_sensitive_content

    def never_clean_for_the_input(data: bytes, **options: bytes | None) -> tuple[bytes, bool]:
        if b"WITHHELD_INPUT_MARKER" in data:
            return data + b".", True
        return original(data, **options)

    monkeypatch.setattr(check_change_module, "redact_sensitive_content", never_clean_for_the_input)
    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        inputs=(TaskInputFile("spec.md", b"WITHHELD_INPUT_MARKER\n", 22),),
    )

    redacted = _redacted(capture)

    assert redacted.inputs == ()
    assert redacted.text == capture.text and redacted.redacted


def test_clean_task_inputs_leave_the_capture_unmarked() -> None:
    from finishup.ports.change_capture import TaskInputFile

    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        inputs=(TaskInputFile("rules.md", b"# Rules\nno secrets here\n", 24),),
    )

    assert _redacted(capture) == capture


def test_task_inputs_reach_the_port_only_when_asked_for() -> None:
    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    seen: list[tuple[str, ...]] = []

    class InputPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            seen.append(input_paths)
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    class PlainPort:
        def capture(self, workspace: str, base: object) -> CheckChangeCapture:
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    _capture_redacted(InputPort(), "/repo", None, (), ("DESIGN.md",))
    _capture_redacted(PlainPort(), "/repo", None, (), ())

    assert seen == [("DESIGN.md",)]


@pytest.mark.anyio
async def test_first_check_pin_drops_a_task_start_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the task's own start says which untracked files predate it (#1045)."""

    from finishup.ports.change_capture import (
        NestedUntrackedBaseline,
        TaskChangeBase,
        UntrackedBaselineFile,
    )

    _pin = getattr(check_change_module, "_pin_first_check_base")
    stored: list[bytes] = []

    class Port:
        def read_task_base(self, workspace: str) -> TaskChangeBase:
            return TaskChangeBase(
                "sha1",
                "a" * 40,
                untracked=(UntrackedBaselineFile("x.txt", "sha256:" + "0" * 64),),
                untracked_complete=True,
                nested=(("api", "b" * 40),),
                nested_untracked=(
                    NestedUntrackedBaseline(
                        "api", True, (UntrackedBaselineFile("notes.md", "sha256:" + "1" * 64),)
                    ),
                ),
            )

    class Ledger:
        async def record_task_change_base(self, ref: object) -> bool:
            return True

        async def load_task_change_base(self) -> object:
            return None

    async def store(runtime: object, data: bytes, media_type: str, clock: object) -> object:
        stored.append(data)
        return object()

    monkeypatch.setattr(check_change_module, "_store", store)
    runtime = SimpleNamespace(ledger=Ledger())

    pinned = await _pin(runtime, Port(), "/repo", object(), "req_x")

    assert pinned == TaskChangeBase("sha1", "a" * 40, "first_check")
    assert b"untracked" not in stored[0] and b"nested" not in stored[0]
