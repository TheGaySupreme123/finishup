"""The agent's declared tests in the closing review packet (issue #1220, ADR-006).

A packet with no declared test to offer keeps its exact bytes (golden digests computed on the
base revision before this change). An offered list is structural metadata that survives the
capacity narrowing which drops obligation rows, and is offered at the closing review and at the
first review after a digest is new, never again for an unchanged one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from builders.policy_cases import (
    act,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from finishup.application.semantic_case import (
    build_semantic_case,
    review_input_manifest_to_json,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    ResultVerification,
    VerificationDataSource,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.review_input_render import render_review_input_manifest_lines
from finishup.domain.task_statement import RecordedTaskStatement
from finishup.kernel.declared_checks import (
    DECLARED_TEST_QUESTION,
    DeclaredTest,
    declared_test_candidates,
    declared_test_location,
    declared_tests_from_json,
    declared_tests_to_json,
)
from finishup.kernel.deterministic_checks import (
    DeterministicCase,
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from finishup.ports.semantic import SemanticCase
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import ReviewInputManifestModel

_CRITERION = "Every prediction must be within 20 mm."
_DIGEST = "sha256:" + "d" * 64
_TEST = DeclaredTest("dt1", "/tmp/test_accuracy.py", _DIGEST, str(obl(1)))


def _frozen(test_file: str | None) -> DeterministicCase:
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Deliver predictions", (obl(1),)), 1)},
        obligations={
            obl(1): obligation_record(
                ObligationPublishedPayload(
                    obl(1), "Prediction accuracy", _CRITERION, ObligationStatus.OPEN
                ),
                2,
            )
        },
        actions={
            act(1): record(
                ActionRecordedPayload(
                    act(1), ActionKind.COMMAND, "Run the probe", "python /tmp/test_accuracy.py"
                ),
                3,
            )
        },
        results={
            res(1): record(
                ResultRecordedPayload(
                    res(1),
                    act(1),
                    ResultOutcome.SUCCESS,
                    summary="100/100 passed.",
                    verification=ResultVerification(
                        _CRITERION,
                        VerificationDataSource.OWN_GENERATED,
                        100,
                        0,
                        test_file=test_file,
                        results_file=None if test_file is None else "/tmp/results.json",
                        report_digest=None if test_file is None else "sha256:" + "c" * 64,
                    ),
                ),
                4,
            )
        },
        extra_refs=(obl(1), act(1), res(1), evt(1)),
    )
    return replace(
        case, task_statement=RecordedTaskStatement(_CRITERION, evt(1), "plan_published", 1)
    )


def _build(
    frozen: DeterministicCase,
    *,
    final: bool,
    declared: tuple[DeclaredTest, ...] = (),
    ceiling: int | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        final_review=final,
        declared_tests=declared,
        prepared_byte_ceiling=ceiling,
    )


def _prepared(case: SemanticCase) -> bytes:
    return semantic_case_to_prepared_payload(case, frozenset(item.item_id for item in case.items))


# Computed on origin/work/n7-reviewer-integrated @ 9b51cca40, before #1220.
_GOLDEN = {
    False: (
        "sha256:2fc8eaf321aaac6f8e7380d81ad2ad34ceb8c22fbd28815f1494dab6959cc2f4",
        "sha256:5f6872bf39f82862211588333f2ebd896d02395064b75019f4e9c17c7edf1fe8",
    ),
    True: (
        "sha256:0ef6cc16cd180ea704b01428a0f9999c5add4507eff4f355678223236d71ca51",
        "sha256:121d0f9bae590788c8727fe61f5cc1474c7e6a7311db2bcbd828b10ada8dfc7b",
    ),
}


@pytest.mark.parametrize("final", [False, True])
@pytest.mark.parametrize("test_file", [None, "/tmp/test_accuracy.py"])
def test_a_packet_with_no_declared_test_to_offer_keeps_its_exact_bytes(
    final: bool, test_file: str | None
) -> None:
    case = _build(_frozen(test_file), final=final)
    prepared = _prepared(case)
    assert (case.case_digest, "sha256:" + hashlib.sha256(prepared).hexdigest()) == _GOLDEN[final]
    assert b"declared_test" not in prepared and b"test_check" not in prepared
    assert DECLARED_TEST_QUESTION not in case.question_set


@pytest.mark.parametrize("final", [False, True])
def test_an_unchanged_digest_is_not_offered_again_except_at_the_closing_review(
    final: bool,
) -> None:
    frozen = replace(_frozen(_TEST.path), offered_test_digests=(_DIGEST,))
    case = _build(frozen, final=final, declared=(_TEST,))
    if final:
        assert case.packet.declared_tests == (_TEST,)
        return
    # Routine and unchanged: the case is exactly the case that offers nothing.
    prepared = _prepared(case)
    assert (case.case_digest, "sha256:" + hashlib.sha256(prepared).hexdigest()) == _GOLDEN[False]


def test_a_new_or_changed_digest_is_offered_at_a_routine_review() -> None:
    frozen = replace(_frozen(_TEST.path), offered_test_digests=("sha256:" + "e" * 64,))
    case = _build(frozen, final=False, declared=(_TEST,))
    assert case.packet.declared_tests == (_TEST,)
    assert case.question_set[-1] == DECLARED_TEST_QUESTION


def test_the_offered_list_is_structural_metadata_with_the_flag_and_one_question() -> None:
    base = _prepared(_build(_frozen(_TEST.path), final=True))
    case = _build(_frozen(_TEST.path), final=True, declared=(_TEST,))
    prepared = _prepared(case)
    document = json.loads(prepared)
    packet = document["review_packet"]
    assert packet["declared_tests"] == [
        {
            "content_digest": _DIGEST,
            "criterion_ref": str(obl(1)),
            "path": "/tmp/test_accuracy.py",
            "ref": "dt1",
        }
    ]
    assert document["question_set"][-1] == DECLARED_TEST_QUESTION
    assert len(DECLARED_TEST_QUESTION.encode()) <= 250
    for name in ("review_input_manifest", "provider_input_manifest"):
        manifest = packet[name]
        assert manifest["test_check_offered"] is True
        assert manifest["test_check_digests"] == [_DIGEST]
        ReviewInputManifestModel.model_validate(manifest)
    # Measured cost of one listed test: the entry, the flag in both manifests and the question.
    assert len(prepared) - len(base) < 800
    assert case.packet.input_manifest is not None
    lines = render_review_input_manifest_lines(
        review_input_manifest_to_json(case.packet.input_manifest)
    )
    assert "declared tests offered 1; " in lines[0]


def test_the_list_survives_the_narrowing_that_drops_obligation_rows() -> None:
    """Root cause A (#1220): the capacity narrowing drops goal, obligation and claim rows, so
    a question gated on them never fires. The list rides the structural envelope instead."""

    base = _frozen(_TEST.path)
    # Enough obligation prose that the packet is above the minimal channel (16 KiB), where a
    # declared test is never listed (PR #1221 review).
    obligations = dict(base.projection.obligations)
    for number in range(2, 10):
        obligations[obl(number)] = obligation_record(
            ObligationPublishedPayload(
                obl(number), "Prediction detail " * 100, "Probe passes", ObligationStatus.OPEN
            ),
            10 + number,
        )
    frozen = replace(
        make_case(
            plans=dict(base.projection.plans),
            obligations=obligations,
            actions=dict(base.projection.actions),
            results=dict(base.projection.results),
            extra_refs=(evt(1),),
        ),
        task_statement=base.task_statement,
    )
    full = _build(frozen, final=True, declared=(_TEST,))
    assert full.packet.obligation_item_ids
    ceiling = len(_prepared(full)) - 64  # just too small: primary_material_selection narrows
    assert ceiling > 16_384
    narrowed = _build(frozen, final=True, declared=(_TEST,), ceiling=ceiling)
    assert narrowed.packet.obligation_item_ids == ()
    assert narrowed.packet.declared_tests == (_TEST,)
    assert narrowed.question_set[-1] == DECLARED_TEST_QUESTION


def test_candidates_put_task_criteria_first_and_name_each_file_once() -> None:
    frozen = _frozen("/tmp/test_accuracy.py")
    results = dict(frozen.projection.results)
    actions = dict(frozen.projection.actions)
    for number, (quote, path) in enumerate(
        (
            ("within 20 mm", "tests/test_newer.py"),
            (_CRITERION, "/tmp/test_accuracy.py"),  # the same file again, newer
            ("Prediction accuracy is unrelated text", "tests/test_unquoted.py"),
            (_CRITERION, "tests/a.py"),
            (_CRITERION, "tests/b.py"),
        ),
        start=2,
    ):
        actions[act(number)] = record(
            ActionRecordedPayload(act(number), ActionKind.COMMAND, "Run", f"python {path}"),
            10 + number,
        )
        results[res(number)] = record(
            ResultRecordedPayload(
                res(number),
                act(number),
                ResultOutcome.SUCCESS,
                verification=ResultVerification(
                    quote,
                    VerificationDataSource.OWN_GENERATED,
                    1,
                    0,
                    test_file=path,
                    results_file="out.json",
                    report_digest="sha256:" + "c" * 64,
                ),
            ),
            10 + number,
        )
    obligation = ObligationPublishedPayload(
        obl(1), "Prediction accuracy", "Probe passes", ObligationStatus.OPEN, _CRITERION
    )
    case = make_case(
        plans=dict(frozen.projection.plans),
        obligations={obl(1): obligation_record(obligation, 2)},
        actions=actions,
        results=results,
        extra_refs=(evt(1),),
    )
    candidates = declared_test_candidates(case.projection, _CRITERION)
    # Every quote the task states ranks alike, newest first; a file once, at its newest; the
    # unquoted manifest is dropped; at most three.
    assert [c.path for c in candidates] == ["tests/b.py", "tests/a.py", "/tmp/test_accuracy.py"]
    assert {c.criterion_ref for c in candidates} == {str(obl(1))}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_x.py", "/work/tests/test_x.py"),
        ("/tmp/test_x.py", "/tmp/test_x.py"),
        ("../outside.py", None),
        ("tests/./x.py", None),
        ("/home/u/.ssh/id_test.py", None),
        ("/tmp/.hidden/test.py", None),
        ("/tmp/credentials.json", None),
        ("/etc/passwd", None),
        ("/private/etc/hosts", None),
        ("/proc/self/environ", None),
        ("tests\\x.py", None),
        ("/tmp/" + "a" * 300 + ".py", None),
        ("/tmp/x\x00.py", None),
    ],
)
def test_a_declared_path_is_refused_by_shape_before_any_read(
    path: str, expected: str | None
) -> None:
    assert declared_test_location(path, "/work") == expected


def test_a_relative_path_needs_the_workspace() -> None:
    assert declared_test_location("tests/test_x.py", None) is None


def test_the_job_record_round_trips_and_rejects_a_reordered_list() -> None:
    tests = (_TEST, DeclaredTest("dt2", "tests/b.py", "sha256:" + "f" * 64, str(res(1))))
    assert declared_tests_from_json(declared_tests_to_json(tests)) == tests
    assert declared_tests_from_json(None) == ()
    with pytest.raises(ValueError, match="declared_test_invalid"):
        declared_tests_from_json(list(reversed(declared_tests_to_json(tests))))


def test_offered_digests_freeze_with_the_case() -> None:
    frozen = replace(_frozen(None), offered_test_digests=(_DIGEST,))
    restored = deterministic_case_from_json(deterministic_case_to_json(frozen))
    assert restored.offered_test_digests == (_DIGEST,)
    # Absent on every case that offered nothing, so its frozen bytes are unchanged.
    assert b"offered_test_digests" not in canonical_encode(
        deterministic_case_to_json(_frozen(None))
    )
    with pytest.raises(ValueError):
        replace(frozen, offered_test_digests=("sha256:" + "f" * 64, _DIGEST))


def test_a_routine_review_offers_only_the_changed_test() -> None:
    """PR #1221 review: A and B were offered; only B changed, so only B is listed again, under
    the ref it was pinned with. The closing review still lists both."""

    a = _TEST
    b = DeclaredTest("dt2", "tests/b.py", "sha256:" + "b" * 64, str(res(1)))
    changed = replace(b, content_digest="sha256:" + "c" * 64)
    frozen = replace(
        _frozen(_TEST.path),
        offered_test_digests=tuple(sorted((a.content_digest, b.content_digest))),
    )
    routine = _build(frozen, final=False, declared=(a, changed))
    assert routine.packet.declared_tests == (changed,)
    assert routine.question_set[-1] == DECLARED_TEST_QUESTION
    assert routine.packet.input_manifest is not None
    assert routine.packet.input_manifest.test_check_digests == (changed.content_digest,)
    packet = json.loads(_prepared(routine))["review_packet"]
    assert [row["ref"] for row in packet["declared_tests"]] == ["dt2"]
    closing = _build(frozen, final=True, declared=(a, changed))
    assert closing.packet.declared_tests == (a, changed)


def test_a_frozen_manifest_with_declared_tests_decodes_and_recovers() -> None:
    """PR #1221 review: a recorded (frozen) provider-bound manifest holds tuples, not lists; it
    must decode with its declared-test fields, so a recovered review keeps its sent excerpts."""

    from finishup.application.semantic_case import (
        _decode_review_input_manifest,  # pyright: ignore[reportPrivateUsage]
        sent_excerpt_content_refs,
    )
    from finishup.domain.values import JsonObject, freeze_json

    case = _build(_frozen(_TEST.path), final=True, declared=(_TEST,))
    wire = json.loads(_prepared(case))["review_packet"]["provider_input_manifest"]
    frozen = freeze_json(wire)
    assert type(frozen) is JsonObject
    assert type(frozen["test_check_digests"]) is tuple
    decoded = _decode_review_input_manifest(frozen, expected_phase="provider_bound")
    assert decoded is not None
    assert decoded.test_check_offered and decoded.test_check_digests == (_DIGEST,)
    assert decoded == _decode_review_input_manifest(wire, expected_phase="provider_bound")
    assert sent_excerpt_content_refs(case, frozen) == sent_excerpt_content_refs(case, wire)
    assert sent_excerpt_content_refs(case, frozen) is not None
    # Other validation is unchanged: one field without the other, or a non-array, is refused.
    for broken in (
        {k: v for k, v in wire.items() if k != "test_check_digests"},
        {**wire, "test_check_digests": _DIGEST},
        {**wire, "test_check_offered": False},
    ):
        assert _decode_review_input_manifest(broken, expected_phase="provider_bound") is None


@pytest.mark.parametrize("final", [False, True])
def test_a_minimal_channel_case_never_lists_declared_tests(final: bool) -> None:
    """PR #1221 review: at the minimal policy's prepared ceiling (16 KiB, ``small_channel``) the
    builder lists nothing, whatever the caller passes, so planning, the excerpt budget and the
    case digest are exactly those of a case without declared tests."""

    frozen = _frozen(_TEST.path)
    plain = _build(frozen, final=final, ceiling=16_384)
    declared = _build(frozen, final=final, declared=(_TEST,), ceiling=16_384)
    assert declared.packet.declared_tests == ()
    assert DECLARED_TEST_QUESTION not in declared.question_set
    assert declared.case_digest == plain.case_digest
    assert _prepared(declared) == _prepared(plain)
    # One byte over the small-channel bound, the same case does list it.
    roomy = _build(frozen, final=True, declared=(_TEST,), ceiling=16_385)
    assert roomy.packet.declared_tests == (_TEST,)
