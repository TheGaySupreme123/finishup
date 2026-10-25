"""#1220: the closing reviewer reads the agent's declared test file, bounded and hash-pinned.

The real ``_privacy_gated_semantic_evaluator`` drives the real privacy coordinator over a durable
SQLite job, as in ``test_reviewer_conversation_composition``; only the provider is scripted. The
declared test lives outside the workspace (where TB4 agents kept theirs, in ``/tmp``): the packet
lists it by path, pinned digest and criterion ref, and the reviewer reads it through ``t1``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.application.semantic_case as semantic_case_module
import finishup.service.ready_composition as ready_composition_module
from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import with_llm
from finishup.domain.privacy import ApprovedOutboundCase, DataCategory
from finishup.domain.reviewer_reads import render_reviewer_lines
from finishup.kernel.declared_tests import DECLARED_TEST_QUESTION, DeclaredTestCandidate
from finishup.ports.semantic import ProviderAttemptProvenance, SemanticResultReply
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import SemanticStatus
from integration.service import test_reviewer_conversation_composition as composition

pytestmark = pytest.mark.anyio

_FINAL = composition._FINAL  # pyright: ignore[reportPrivateUsage]
_ROOMY = composition._ROOMY  # pyright: ignore[reportPrivateUsage]
_TEST_TEXT = (
    "from batched import generate\n"
    "\n"
    "def test_stop_rule():\n"
    "    # expected value copied from the implementation's own rule\n"
    "    assert generate(min_new_tokens=4).stopped_at == 4\n"
)


def _declared(path: str = "dt1", **args: JsonValue) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "root_id": "t1",
        "path": path,
        "mode": "text",
        "start_line": 1,
        "line_count": 20,
        **args,
    }
    return {"reply": {"action": "read_file", "args": body}}


def _outside(tmp_path: Path, text: str = _TEST_TEXT) -> Path:
    folder = tmp_path.resolve() / "scratch"
    folder.mkdir(mode=0o700)
    test = folder / "test_stop_rule.py"
    test.write_text(text)
    test.chmod(0o600)
    return test


def _declare(monkeypatch: pytest.MonkeyPatch, *paths: str) -> None:
    candidates = tuple(DeclaredTestCandidate(path, "res_criterion") for path in paths)

    def declared(_projection: object, _statement: str | None) -> tuple[DeclaredTestCandidate, ...]:
        return candidates

    monkeypatch.setattr(ready_composition_module, "declared_test_candidates", declared)


class _Categories:
    """A scripted reply that also records the approved categories each exchange carried."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, ...]] = []

    def __call__(
        self, reply: dict[str, JsonValue], before: Callable[[], None] = lambda: None
    ) -> Callable[..., object]:
        def answer(case: ApprovedOutboundCase, provenance: ProviderAttemptProvenance) -> object:
            self.seen.append(tuple(category.value for category in case.approved_categories))
            before()
            return SemanticResultReply(reply, provenance)

        return answer


def _history(gateway: Any, index: int) -> tuple[tuple[str, str], ...]:  # noqa: ANN401
    return cast(tuple[tuple[str, str], ...], gateway.exchanges[index][1])


async def test_the_reviewer_reads_a_declared_test_outside_the_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test = _outside(tmp_path)
    _declare(monkeypatch, str(test))
    categories = _Categories()
    result, gateway, runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, categories(_declared()), categories(_FINAL), policy=_ROOMY
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    first = _history(gateway, 0)
    packet = json.loads(first[1][1])
    listed = packet["review_packet"]["declared_tests"]
    assert [(row["ref"], row["path"]) for row in listed] == [("dt1", str(test))]
    assert listed[0]["content_digest"].startswith("sha256:")
    assert packet["question_set"][-1] == DECLARED_TEST_QUESTION
    # Never the content in the packet: only the reviewer's own read carries it.
    assert "copied from the implementation" not in first[1][1]
    catalog = json.loads(first[2][1])["reviewer_catalog"]["read_file_roots"]
    assert {
        "root_id": "t1",
        "standing": "declared_test",
        "baseline": "check_time",
        "covers": ["dt1"],
    } in catalog
    observation = json.loads(_history(gateway, 1)[4][1])
    assert observation["status"] == "ok"
    assert "copied from the implementation" in observation["data"]["text"]
    assert observation["data"]["provenance"]["standing"] == "declared_test"
    assert observation["result_utf8_bytes"] <= 4096
    # The receipt of the exchange that carries the read shows the distinct category; the first
    # exchange, which carries only the list, does not.
    assert "declared_test_excerpt" not in categories.seen[0]
    assert "declared_test_excerpt" in categories.seen[1]
    record = result.reviewer
    assert record is not None and len(record.reads) == 1
    read = record.reads[0]
    assert (read.status, read.root, read.standing, read.baseline) == (
        "ok",
        "t1",
        "declared_test",
        "check_time",
    )
    rendered = json.dumps(record.as_wire()) + "\n".join(render_reviewer_lines(record))
    assert str(test) not in rendered and "copied" not in rendered
    manifest = result.review_input_manifest
    assert manifest is not None and manifest.test_check_offered
    assert manifest.test_check_digests == (listed[0]["content_digest"],)
    # The job froze the pinned list, so a recovered job rebuilds the same case without a read.
    job = await runtime.ledger.load_semantic_job(
        runtime.writer_id or "", composition.frozen_request()
    )
    assert job is not None
    stored = await ready_composition_module._read_semantic_case(  # pyright: ignore[reportPrivateUsage]
        runtime, job.case_object_ref
    )
    assert stored[-1] == listed


async def test_a_declared_test_changed_after_it_was_listed_is_not_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test = _outside(tmp_path)
    _declare(monkeypatch, str(test))
    categories = _Categories()

    def edit() -> None:
        test.write_text(_TEST_TEXT + "# tuned after the review listed it\n")

    result, gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        categories(_declared(), before=edit),
        categories(_FINAL),
        policy=_ROOMY,
    )
    assert result.status is SemanticStatus.SUCCEEDED
    observation = json.loads(_history(gateway, 1)[4][1])
    assert (observation["status"], observation["reason"], observation["data"]) == (
        "unavailable",
        "declared_test_changed",
        None,
    )
    assert "not visible to this review" in observation["continuation"]
    assert "tuned after" not in json.dumps(gateway.exchanges)
    assert "declared_test_excerpt" not in categories.seen[1]


async def test_a_declared_test_holding_a_credential_is_withheld(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "ghp_" + "a1B2" * 9
    test = _outside(tmp_path, _TEST_TEXT + f'TOKEN = "{token}"\n')
    _declare(monkeypatch, str(test))
    result, gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, _declared(line_count=200), _FINAL, policy=_ROOMY
    )
    assert result.status is SemanticStatus.SUCCEEDED
    observation = json.loads(_history(gateway, 1)[4][1])
    # The existing admission scan refuses the whole read; nothing of the file is sent.
    assert (observation["status"], observation["reason"], observation["data"]) == (
        "denied",
        "privacy_withheld",
        None,
    )
    assert token not in json.dumps(gateway.exchanges)


@pytest.mark.parametrize(
    "action",
    [
        pytest.param(_declared("dt2"), id="unlisted-ref"),
        pytest.param(_declared("scratch/test_stop_rule.py"), id="a-path"),
        pytest.param(
            {
                "reply": {
                    "action": "read_file",
                    "args": {"root_id": "t1", "path": ".", "mode": "list", "cursor": None},
                }
            },
            id="a-listing",
        ),
    ],
)
async def test_the_declared_root_serves_listed_refs_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: dict[str, JsonValue]
) -> None:
    test = _outside(tmp_path)
    _declare(monkeypatch, str(test))
    result, gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, action, _FINAL, policy=_ROOMY
    )
    assert result.status is SemanticStatus.SUCCEEDED
    observation = json.loads(_history(gateway, 1)[4][1])
    assert (observation["status"], observation["data"]) == ("denied", None)
    assert "declared_tests, by ref" in observation["continuation"]
    assert "copied from the implementation" not in json.dumps(gateway.exchanges)


async def test_one_declared_read_is_at_most_four_kilobytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    long = "".join(f"assert case_{n:04d}() == {n}  # expected from the spec\n" for n in range(300))
    test = _outside(tmp_path, long)
    _declare(monkeypatch, str(test))
    result, gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, _declared(line_count=200), _FINAL, policy=_ROOMY
    )
    assert result.status is SemanticStatus.SUCCEEDED and result.reviewer is not None
    observation = json.loads(_history(gateway, 1)[4][1])
    assert observation["status"] == "partial" and observation["truncated"] is True
    assert observation["result_utf8_bytes"] <= 4096
    assert result.reviewer.reads[0].result_bytes <= 4096


async def test_no_list_and_no_root_where_policy_withholds_repository_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test = _outside(tmp_path)
    _declare(monkeypatch, str(test))
    llm = next(
        channel for channel in _ROOMY.channel_policies if channel.provider_binding is not None
    )
    policy = with_llm(
        _ROOMY,
        allowed_categories=tuple(
            category
            for category in llm.allowed_categories
            if category is not DataCategory.REPOSITORY_EXCERPT
        ),
    )
    result, gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, _FINAL, policy=policy
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    first = _history(gateway, 0)
    assert "declared_tests" not in first[1][1] and DECLARED_TEST_QUESTION not in first[1][1]
    assert '"t1"' not in first[2][1] and str(test) not in json.dumps(gateway.exchanges)
    assert result.review_input_manifest is not None
    assert not result.review_input_manifest.test_check_offered


async def test_no_declared_test_leaves_the_first_exchange_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same review with and without a declared test that cannot be read (missing file):
    the first exchange is byte-identical, so no packet of a task without one changes."""

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    without, gateway_without, _ = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path / "a", monkeypatch, _FINAL
    )
    _declare(monkeypatch, str(tmp_path.resolve() / "missing" / "test_gone.py"))
    with_missing, gateway_missing, _ = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path / "b", monkeypatch, _FINAL
    )
    assert without.status is with_missing.status is SemanticStatus.SUCCEEDED

    def normalized(gateway: Any, folder: str) -> str:  # noqa: ANN401
        # The two runs differ only in their temporary workspace and their fresh ids/digests.
        text = json.dumps(_history(gateway, 0)).replace(str(tmp_path.resolve() / folder), "TMP")
        text = re.sub(r"[a-z]{3}_[0-9a-f]{8}-[0-9a-f-]{27}", "ID", text)
        return re.sub(r"sha256:[0-9a-f]{64}", "DIGEST", text)

    first_without, first_missing = (
        normalized(gateway_without, "a"),
        normalized(gateway_missing, "b"),
    )
    assert "declared_tests" not in first_missing and '"t1"' not in first_missing
    assert first_without == first_missing


@pytest.mark.parametrize(
    ("phase", "asked_for"),
    [
        pytest.param(None, {}, id="routine"),
        pytest.param("final", {"linked_verification": True}, id="closing-linked-check"),
    ],
)
async def test_the_minimal_policy_review_is_planned_exactly_as_before(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str | None,
    asked_for: dict[str, bool],
) -> None:
    """#1173 budget (ADR-006): at the minimal policy (4,096 tokens) the fixed packet already
    fills the first exchange's plan, so the list would eat the frame a read needs (a closing
    review with the linked-check question then ended ``case_capacity_exceeded`` in a probe).
    The list is offered only when the planned exchange still fits; here it never does, and the
    review is the one it was before: same questions, no ``t1`` root, same outcome."""

    asked = semantic_case_module.review_question_set

    def with_question(*args: Any, **kwargs: Any) -> tuple[str, ...]:  # noqa: ANN401
        if phase is not None:
            args = (phase, *args[1:])
        return asked(*args, **{**kwargs, **asked_for})

    monkeypatch.setattr(semantic_case_module, "review_question_set", with_question)
    test = _outside(tmp_path)
    _declare(monkeypatch, str(test))
    replies = (composition._read_file("calc.py"), _FINAL)  # pyright: ignore[reportPrivateUsage]
    result, gateway, _runtime = await composition._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path, monkeypatch, *replies, policy=minimal_external_policy()
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    first = _history(gateway, 0)
    assert "declared_tests" not in first[1][1] and '"t1"' not in first[2][1]
    assert result.review_input_manifest is not None
    assert not result.review_input_manifest.test_check_offered
    assert result.reviewer is not None and result.reviewer.as_wire()["reads_used"] == "1"
