"""Built-in policy-pack identities: current versions run, earlier ones stay readable."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast, get_args

from yoetz.domain.findings import FindingKind, finding_policy_identity
from yoetz.protocol.models import (
    CurrentPolicyPackWire,
    RecordedPolicyPackWire,
    RecordedPolicyVersionWire,
    RecordedVersionSlicePackWire,
)
from yoetz.protocol.policy_packs import (
    CURRENT_POLICY_PACKS,
    RECORDED_POLICY_PACKS,
    RECORDED_POLICY_VERSION_VALUES,
    is_current_policy_identity,
    is_recorded_policy_identity,
    policy_version_supersedes_or_equals,
)
from yoetz.protocol.schemas import schema_document_for
from yoetz.version import (
    COORDINATION_POLICY_VERSION,
    RESEARCH_EVIDENCE_POLICY_VERSION,
    WORK_INTEGRITY_POLICY_VERSION,
)


def test_current_pack_versions_are_the_bumped_identities() -> None:
    assert CURRENT_POLICY_PACKS == (
        "coordination/0.1.0",
        "research-evidence/0.2.0",
        "work-integrity/0.3.0",
    )
    assert (
        COORDINATION_POLICY_VERSION,
        RESEARCH_EVIDENCE_POLICY_VERSION,
        WORK_INTEGRITY_POLICY_VERSION,
    ) == CURRENT_POLICY_PACKS


def test_earlier_versions_stay_recorded_but_not_current() -> None:
    assert RECORDED_POLICY_PACKS == (
        "coordination/0.1.0",
        "research-evidence/0.1.0",
        "research-evidence/0.2.0",
        "work-integrity/0.1.0",
        "work-integrity/0.2.0",
        "work-integrity/0.3.0",
    )
    assert is_recorded_policy_identity("work-integrity", "0.1.0")
    assert not is_current_policy_identity("work-integrity", "0.1.0")
    assert is_recorded_policy_identity("work-integrity", "0.2.0")
    assert not is_current_policy_identity("work-integrity", "0.2.0")
    assert is_current_policy_identity("work-integrity", "0.3.0")
    assert not is_recorded_policy_identity("coordination", "0.2.0")
    assert not is_recorded_policy_identity("semantic-review", "0.1.0")


def test_a_pack_lineage_orders_its_versions() -> None:
    assert policy_version_supersedes_or_equals("work-integrity", "0.2.0", "0.1.0")
    assert policy_version_supersedes_or_equals("work-integrity", "0.1.0", "0.1.0")
    assert not policy_version_supersedes_or_equals("work-integrity", "0.1.0", "0.2.0")
    assert policy_version_supersedes_or_equals("work-integrity", "0.3.0", "0.2.0")
    assert not policy_version_supersedes_or_equals("work-integrity", "0.4.0", "0.1.0")


def test_wire_literals_match_the_registry() -> None:
    assert get_args(CurrentPolicyPackWire) == CURRENT_POLICY_PACKS
    assert get_args(RecordedPolicyPackWire) == RECORDED_POLICY_PACKS
    assert get_args(RecordedVersionSlicePackWire) == tuple(
        pack for pack in RECORDED_POLICY_PACKS if not pack.startswith("coordination/")
    )
    assert get_args(RecordedPolicyVersionWire) == RECORDED_POLICY_VERSION_VALUES


def test_new_findings_carry_the_current_version_of_their_pack() -> None:
    assert finding_policy_identity(FindingKind.TASK_REQUIREMENT_UNMET) == (
        "research-evidence",
        "0.2.0",
    )
    assert finding_policy_identity(FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE) == (
        "work-integrity",
        "0.3.0",
    )
    assert finding_policy_identity(FindingKind.COORDINATION_OVERLAP) == ("coordination", "0.1.0")


def _path(document: object, *keys: str) -> object:
    node = document
    for key in keys:
        assert isinstance(node, Mapping)
        node = cast(Mapping[str, object], node)[key]
    return list(cast(tuple[object, ...], node)) if isinstance(node, tuple) else node


def test_requests_select_current_packs_and_results_admit_recorded_ones() -> None:
    request = schema_document_for("check-request", "1.1.0").json_schema
    assert _path(request, "properties", "policy_packs", "items", "enum") == list(
        CURRENT_POLICY_PACKS
    )
    result = schema_document_for("check-result", "1.4.0").json_schema
    assert _path(
        result, "$defs", "version_slice", "properties", "policy_packs", "items", "enum"
    ) == list(RECORDED_POLICY_PACKS)
    assert _path(
        result, "$defs", "policy_execution", "properties", "policy_version", "enum"
    ) == list(RECORDED_POLICY_VERSION_VALUES)
    event = schema_document_for("check-recorded", "1.4.0").json_schema
    assert _path(
        event, "$defs", "research_evidence_policy", "properties", "policy_version", "enum"
    ) == ["0.1.0", "0.2.0"]
    assert _path(
        event, "$defs", "work_integrity_policy", "properties", "policy_version", "enum"
    ) == ["0.1.0", "0.2.0", "0.3.0"]
    # The released publish result keeps its frozen identities; 1.1.0 names the current ones.
    released = schema_document_for("publish-work-result", "1.0.0").json_schema
    assert _path(
        released, "$defs", "version_slice", "properties", "policy_packs", "items", "enum"
    ) == ["research-evidence/0.1.0", "work-integrity/0.1.0"]
    current = schema_document_for("publish-work-result", "1.1.0").json_schema
    assert _path(
        current, "$defs", "version_slice", "properties", "policy_packs", "items", "enum"
    ) == [pack for pack in RECORDED_POLICY_PACKS if not pack.startswith("coordination/")]
