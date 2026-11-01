"""Declared-test verdicts (issue #1145): parsed, capped, recovered, and byte-neutral when absent.

The reviewer may answer a packet that lists the agent's declared tests with up to two verdict
rows. They are optional and advisory: a malformed row costs only itself, a judgment without any
keeps its stored bytes, and an untagged declared test keeps its listed entry's bytes.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from finishup.adapters.providers.openai_responses import normalize_judgment
from finishup.domain.correctness_advisories import validate_advisories
from finishup.domain.events import VerificationExpectedFrom
from finishup.domain.values import JsonObject
from finishup.kernel.declared_checks import (
    DECLARED_TEST_EXPECTED_FROM,
    DECLARED_TEST_QUESTION,
    DeclaredTest,
    declared_tests_from_json,
    declared_tests_to_json,
)
from finishup.ports.semantic import DeclaredTestVerdict, SemanticJudgment
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.service.ready_composition import (
    _judgment_from_response_json,  # pyright: ignore[reportPrivateUsage]
    _judgment_to_response_json,  # pyright: ignore[reportPrivateUsage]
)

_DIGEST = "sha256:" + "d" * 64
_OBLIGATION = "obl_00000000-0000-4000-8000-000000000001"


def _judgment(verdicts: Any) -> SemanticJudgment:  # noqa: ANN401
    return normalize_judgment(
        {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Checked.",
            "verified": [],
            "reviewer_challenges": [],
            "prior_finding_verdicts": [],
            "strongest_remaining_check": None,
            "declared_test_verdicts": verdicts,
        },
        require_part2=True,
    )


def _row(ref: str, observed: str = "cannot_fail", probe: str = "f(0)") -> dict[str, Any]:
    return {"test_ref": ref, "expected_from_observed": observed, "counter_example": probe}


def test_verdict_rows_are_parsed_and_capped_at_two_well_formed_rows() -> None:
    judgment = _judgment(
        [
            _row("dt1"),
            _row("dt1", "task_text"),  # a second row for the same test
            _row("dt4"),  # not a listable ref
            _row("dt2", "unknown_origin"),
            _row("dt2", probe="x" * 301),  # over the 300-character bound
            _row("dt2", "shared_with_implementation"),
            _row("dt3", "task_text", ""),  # past the cap
        ]
    )
    assert judgment.declared_test_verdicts == (
        DeclaredTestVerdict("dt1", "cannot_fail", "f(0)"),
        DeclaredTestVerdict("dt2", "shared_with_implementation", "f(0)"),
    )
    # Absent, null and a non-list all read as no rows, never as a failed judgment.
    absent_forms: tuple[object, ...] = (None, [], "dt1")
    for absent in absent_forms:
        assert _judgment(absent).declared_test_verdicts == ()


def test_the_domain_value_refuses_more_than_two_rows_or_an_unknown_observation() -> None:
    rows = tuple(DeclaredTestVerdict(f"dt{n}", "task_text", "") for n in (1, 2, 3))
    with pytest.raises(ValueError, match="semantic_judgment_invalid"):
        SemanticJudgment("no_material_discrepancy", (), declared_test_verdicts=rows)
    with pytest.raises(ValueError, match="semantic_judgment_invalid"):
        DeclaredTestVerdict("dt1", "implementation_output", "")


def test_recovery_reads_the_stored_verdicts_and_a_judgment_without_any_keeps_its_bytes() -> None:
    plain = SemanticJudgment("no_material_discrepancy", (), review_summary="Checked.")
    stored = _judgment_to_response_json(plain)
    assert "declared_test_verdicts" not in stored
    with_rows = replace(
        plain,
        declared_test_verdicts=(DeclaredTestVerdict("dt1", "shared_with_implementation", "f(0)"),),
    )
    encoded = _judgment_to_response_json(with_rows)
    assert {key: value for key, value in encoded.items() if key != "declared_test_verdicts"} == (
        stored
    )
    assert _judgment_from_response_json(encoded) == with_rows
    assert _judgment_from_response_json(stored) == plain
    with pytest.raises(ValueError, match="semantic_response_judgment_invalid"):
        _judgment_from_response_json(
            {**encoded, "declared_test_verdicts": [{**_row("dt1"), "extra": 1}]}
        )


def test_an_untagged_entry_keeps_its_bytes_and_a_tag_is_one_more_key() -> None:
    untagged = DeclaredTest("dt1", "/tmp/test_rule.py", _DIGEST, _OBLIGATION)
    tagged = replace(untagged, expected_from="task_text")
    # The #1220 entry, byte for byte.
    assert canonical_encode(untagged.to_json()) == (
        b'{"content_digest":"'
        + _DIGEST.encode()
        + b'","criterion_ref":"'
        + _OBLIGATION.encode()
        + b'","path":"/tmp/test_rule.py","ref":"dt1"}'
    )
    assert set(tagged.to_json()) - set(untagged.to_json()) == {"expected_from"}
    # A stored job's list round-trips either way, so recovery lists the same tag.
    stored = declared_tests_to_json((untagged, replace(tagged, ref="dt2")))
    assert declared_tests_from_json(stored) == (untagged, replace(tagged, ref="dt2"))
    with pytest.raises(ValueError, match="declared_test_invalid"):
        replace(untagged, expected_from="shared_with_implementation")
    with pytest.raises(ValueError, match="declared_test_invalid"):
        declared_tests_from_json([{**untagged.to_json(), "expected_from": None}])


def test_the_tag_vocabulary_is_the_manifest_enum_and_the_question_stays_small() -> None:
    assert frozenset(item.value for item in VerificationExpectedFrom) == (
        DECLARED_TEST_EXPECTED_FROM
    )
    assert "declared_test_verdicts" in DECLARED_TEST_QUESTION
    assert "expected_from" in DECLARED_TEST_QUESTION
    assert len(DECLARED_TEST_QUESTION.encode()) <= 250


def test_a_verdict_row_carries_its_test_digest_and_only_that_origin_may() -> None:
    row = {
        "summary": "Your test ...",
        "detail": "Your test ...",
        "subject_refs": (_OBLIGATION,),
        "origin": "declared_test_verdict",
        "test_digest": _DIGEST,
    }
    validate_advisories((JsonObject(row),))
    for broken in (
        {key: value for key, value in row.items() if key != "test_digest"},
        {**row, "origin": "strongest_remaining_check"},
        {**row, "test_digest": "sha256:short"},
        {key: value for key, value in row.items() if key != "origin"},
    ):
        with pytest.raises(ProtocolValueError):
            validate_advisories((JsonObject(broken),))


def test_tagged_and_untagged_entries_validate_on_the_outbound_case_packet() -> None:
    import json
    from importlib import resources

    import jsonschema

    document = json.loads(
        resources.files("finishup")
        .joinpath("resources", "schemas", "privacy", "outbound-case-1.2.0.schema.json")
        .read_bytes()
    )
    entries = document["$defs"]["review_packet"]["properties"]["declared_tests"]
    validator = jsonschema.Draft202012Validator({"$defs": document["$defs"], **entries})
    untagged = DeclaredTest("dt1", "/tmp/test_rule.py", _DIGEST, _OBLIGATION)
    tagged = replace(untagged, ref="dt2", expected_from="implementation_output")
    validator.validate(declared_tests_to_json((untagged, tagged)))  # pyright: ignore[reportUnknownMemberType]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(  # pyright: ignore[reportUnknownMemberType]
            [{**untagged.to_json(), "expected_from": "cannot_fail"}]
        )


@pytest.mark.parametrize("final", [False, True])
def test_a_tagged_test_on_a_minimal_channel_changes_no_byte(final: bool) -> None:
    """The small-channel gate (PR #1221 review) holds for a tagged entry too: no list, no
    question naming the verdict field, and the same case and prepared bytes as no declared test."""

    from unit.application.test_declared_test_packet import (
        _TEST,  # pyright: ignore[reportPrivateUsage]
        _build,  # pyright: ignore[reportPrivateUsage]
        _frozen,  # pyright: ignore[reportPrivateUsage]
        _prepared,  # pyright: ignore[reportPrivateUsage]
    )

    frozen = _frozen(_TEST.path)
    tagged = replace(_TEST, expected_from="task_text")
    plain = _build(frozen, final=final, ceiling=16_384)
    declared = _build(frozen, final=final, declared=(tagged,), ceiling=16_384)
    assert declared.packet.declared_tests == ()
    assert not any("declared_test_verdicts" in question for question in declared.question_set)
    assert (declared.case_digest, _prepared(declared)) == (plain.case_digest, _prepared(plain))


def test_every_closed_result_enum_admits_the_new_values() -> None:
    """PR #1224 review: #1221 recorded ``standing: declared_test`` that the check result model
    refused. The wire models' closed sets match the domain's, so no new value is refused again."""

    from typing import get_args

    from finishup.domain.correctness_advisories import ADVISORY_ORIGINS
    from finishup.domain.reviewer_reads import (
        _STANDINGS,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.protocol.models import (
        CheckCorrectnessAdvisoryModel,
        ReviewerReadModel,
        StatusCheckOutcomeAdvisoryModel,
    )

    def literal_values(annotation: object) -> set[str]:
        """The string members of a ``Literal``, through any ``| None``."""

        values: set[str] = set()
        for arg in get_args(annotation):
            if type(arg) is str:
                values.add(arg)
            else:
                values |= literal_values(arg)
        return values

    assert literal_values(ReviewerReadModel.model_fields["standing"].annotation) == set(_STANDINGS)
    for model in (CheckCorrectnessAdvisoryModel, StatusCheckOutcomeAdvisoryModel):
        assert literal_values(model.model_fields["origin"].annotation) == (
            set(ADVISORY_ORIGINS) | {"routine_correctness_note"}
        )
