"""Executable classification locks for exact-worktree Codex dogfood parity (#464, #518, #567)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import cast

import pytest

_FIXTURE = (
    Path(__file__).parents[2] / "fixtures" / "codex-dogfood" / "worktree-without-exact-consent.json"
)
_SCRIPT = Path(__file__).parents[3] / "scripts" / "check_codex_dogfood_parity.py"
_SPEC = importlib.util.spec_from_file_location("check_codex_dogfood_parity", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
POSTFLIGHT_FACETS = _MODULE.POSTFLIGHT_FACETS
PREFLIGHT_FACETS = _MODULE.PREFLIGHT_FACETS
DogfoodGateError = _MODULE.DogfoodGateError
classify_codex_dogfood_report = _MODULE.classify_codex_dogfood_report
_DIGEST = "sha256:" + ("a" * 64)
_NORMAL_DIGEST = "sha256:" + ("b" * 64)


def _gate(status: str = "pass") -> dict[str, object]:
    if status == "pass":
        return {
            "status": "pass",
            "reason": None,
            "evidence_digest": _DIGEST,
            "next_action": "none",
        }
    return {
        "status": status,
        "reason": "not_exercised",
        "evidence_digest": None,
        "next_action": "complete_postflight",
    }


def _report() -> dict[str, object]:
    return {
        "schema": "yoetz.codex-dogfood-parity/4",
        "identity": {
            "source_ref": "a" * 40,
            "package_digest": _DIGEST,
            "codex_executable_digest": _DIGEST,
            "codex_version": "0.148.0",
            "codex_home_digest": _DIGEST,
            "launcher_digest": _DIGEST,
            "route_profile": "policy",
            "worktree_digest": _DIGEST,
            "finishup_isolation": {
                "mode": "isolated",
                "normal_mode": "ambient",
                "state_path_digest": _DIGEST,
                "endpoint_path_digest": _DIGEST,
                "storage_path_digest": _DIGEST,
                "config_path_digest": _DIGEST,
                "executable_path_digest": _DIGEST,
                "normal_state_path_digest": _NORMAL_DIGEST,
                "normal_endpoint_path_digest": _NORMAL_DIGEST,
                "normal_storage_path_digest": _NORMAL_DIGEST,
                "normal_config_path_digest": _NORMAL_DIGEST,
                "normal_executable_path_digest": _NORMAL_DIGEST,
            },
        },
        "scope": {
            "hooks_advertised": True,
            "session_stream_advertised": True,
            "semantic_required": True,
            "influence_required": True,
        },
        "observed": {
            "activation_state": "active",
            "finishup_isolation_state": "isolated",
            "mcp_registration_state": "yoetz_owned",
            "mcp_isolation_binding": "isolated_exact",
            "mcp_child_state": "ready",
            "exact_worktree_consent": "active",
            "primary_checkout_consent": "active",
            "controls_workspace_match": True,
            "mapping_present": True,
            "accepted_envelope_count": 4,
            "undelivered_count": 0,
            "drain_succeeded": True,
            "hook_coverage": True,
            "stream_coverage": True,
        },
        "normal_target": None,
        "facets": {name: _gate() for name in (*PREFLIGHT_FACETS, *POSTFLIGHT_FACETS)},
    }


def _facets(report: dict[str, object]) -> dict[str, dict[str, object]]:
    return cast(dict[str, dict[str, object]], report["facets"])


def _observed(report: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], report["observed"])


def test_every_required_layer_passes_before_full_gate_can_pass() -> None:
    result = classify_codex_dogfood_report(_report())

    assert result["preflight_outcome"] == "pass"
    assert result["launch_allowed"] is True
    assert result["full_outcome"] == "pass"
    assert result["failed_facets"] == []


def test_installed_not_activated_is_disqualifying_and_actionable() -> None:
    report = _report()
    _observed(report)["activation_state"] = "installed_not_activated"
    _facets(report)["plugin_activation"] = {
        "status": "fail",
        "reason": "installed_not_activated",
        "evidence_digest": _DIGEST,
        "next_action": "finishup_recommend_list_exact_target",
    }

    result = classify_codex_dogfood_report(report)

    assert result["preflight_outcome"] == "fail"
    assert result["launch_allowed"] is False
    assert result["failed_facets"] == ["plugin_activation"]


def test_primary_checkout_consent_cannot_cover_the_exact_worktree_fixture() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    report = _report()
    observed = _observed(report)
    observed["primary_checkout_consent"] = fixture["primary_checkout_consent"]
    observed["exact_worktree_consent"] = fixture["exact_worktree_consent"]
    _facets(report)["observation_consent"] = fixture["observation_consent"]

    result = classify_codex_dogfood_report(report)

    assert result["preflight_outcome"] == fixture["expected_preflight_outcome"]
    assert result["launch_allowed"] is fixture["expected_launch_allowed"]
    assert result["blocked_facets"] == ["observation_consent"]


def test_registration_or_tools_without_model_call_cannot_pass_full_gate() -> None:
    report = _report()
    _facets(report)["model_mcp_call"] = {
        "status": "not_run",
        "reason": "model_call_not_observed",
        "evidence_digest": _DIGEST,
        "next_action": "complete_postflight",
    }

    result = classify_codex_dogfood_report(report)

    assert result["preflight_outcome"] == "pass"
    assert result["full_outcome"] == "not_run"
    assert result["not_run_facets"] == ["model_mcp_call"]


def test_advertised_hooks_require_mapping_envelopes_and_a_clean_drain() -> None:
    report = _report()
    _observed(report)["mapping_present"] = False
    with pytest.raises(DogfoodGateError, match="mapping_observation_missing"):
        classify_codex_dogfood_report(report)

    report = _report()
    _observed(report)["undelivered_count"] = 1
    with pytest.raises(DogfoodGateError, match="drain_observation_mismatch"):
        classify_codex_dogfood_report(report)


def test_unadvertised_session_stream_is_explicitly_unsupported_not_green() -> None:
    report = _report()
    scope = cast(dict[str, object], report["scope"])
    scope["session_stream_advertised"] = False
    _observed(report)["stream_coverage"] = False
    _facets(report)["session_stream"] = {
        "status": "unsupported",
        "reason": "capability_not_advertised",
        "evidence_digest": _DIGEST,
        "next_action": "none",
    }

    result = classify_codex_dogfood_report(report)

    assert result["full_outcome"] == "pass"
    assert result["unsupported_facets"] == ["session_stream"]


def test_out_of_scope_failure_cannot_be_ignored_by_full_aggregation() -> None:
    report = _report()
    scope = cast(dict[str, object], report["scope"])
    scope["influence_required"] = False
    _facets(report)["corrective_influence"] = {
        "status": "fail",
        "reason": "influence_failed",
        "evidence_digest": _DIGEST,
        "next_action": "do_not_launch",
    }

    with pytest.raises(DogfoodGateError, match="out_of_scope_facet_not_not_run"):
        classify_codex_dogfood_report(report)


def _identity(report: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], report["identity"])


def _isolation(report: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], _identity(report)["finishup_isolation"])


def test_shared_finishup_identity_cannot_pass_the_isolation_facet() -> None:
    report = _report()
    _isolation(report)["state_path_digest"] = _NORMAL_DIGEST

    with pytest.raises(DogfoodGateError, match="service_isolation_identity_shared"):
        classify_codex_dogfood_report(report)


def test_shared_finishup_executable_cannot_pass_the_isolation_facet() -> None:
    report = _report()
    _isolation(report)["executable_path_digest"] = _NORMAL_DIGEST

    with pytest.raises(DogfoodGateError, match="service_isolation_identity_shared"):
        classify_codex_dogfood_report(report)


def test_ambient_or_unknown_isolation_state_contradicts_a_passing_facet() -> None:
    for state in ("ambient", "shared", "unknown"):
        report = _report()
        _observed(report)["finishup_isolation_state"] = state
        with pytest.raises(DogfoodGateError, match="service_isolation_state_mismatch"):
            classify_codex_dogfood_report(report)


def test_ambient_identity_mode_contradicts_a_passing_isolation_facet() -> None:
    report = _report()
    _isolation(report)["mode"] = "ambient"

    with pytest.raises(DogfoodGateError, match="service_isolation_identity_mismatch"):
        classify_codex_dogfood_report(report)


def test_nonambient_normal_snapshot_contradicts_a_passing_isolation_facet() -> None:
    report = _report()
    _isolation(report)["normal_mode"] = "isolated"

    with pytest.raises(DogfoodGateError, match="service_isolation_identity_mismatch"):
        classify_codex_dogfood_report(report)


def test_failed_isolation_refuses_launch_with_the_provisioning_continuation() -> None:
    report = _report()
    _observed(report)["finishup_isolation_state"] = "shared"
    _facets(report)["service_isolation"] = {
        "status": "fail",
        "reason": "finishup_identity_shared",
        "evidence_digest": _DIGEST,
        "next_action": "provision_isolated_finishup_root",
    }

    result = classify_codex_dogfood_report(report)

    assert result["preflight_outcome"] == "fail"
    assert result["launch_allowed"] is False
    assert result["failed_facets"] == ["service_isolation"]


def test_failed_isolation_without_the_provisioning_continuation_is_invalid() -> None:
    report = _report()
    _observed(report)["finishup_isolation_state"] = "unknown"
    _facets(report)["service_isolation"] = {
        "status": "blocked",
        "reason": "finishup_identity_unknown",
        "evidence_digest": None,
        "next_action": "do_not_launch",
    }

    with pytest.raises(DogfoodGateError, match="service_isolation_continuation_missing"):
        classify_codex_dogfood_report(report)


@pytest.mark.parametrize(
    ("field", "value", "next_action"),
    [
        ("mcp_registration_state", "absent", "reregister_isolated_mcp"),
        ("mcp_isolation_binding", "missing", "reregister_isolated_mcp"),
        ("mcp_isolation_binding", "different", "reregister_isolated_mcp"),
        ("mcp_child_state", "failed", "recapture_isolated_mcp_child"),
        ("mcp_child_state", "unknown", "recapture_isolated_mcp_child"),
    ],
)
def test_mcp_child_isolation_fails_closed_before_launch(
    field: str, value: str, next_action: str
) -> None:
    report = _report()
    _observed(report)[field] = value
    _facets(report)["mcp_child_isolation"] = {
        "status": "fail" if value != "unknown" else "blocked",
        "reason": "mcp_child_isolation_unproven",
        "evidence_digest": _DIGEST if value != "unknown" else None,
        "next_action": next_action,
    }

    result = classify_codex_dogfood_report(report)

    assert result["preflight_outcome"] in {"fail", "blocked"}
    assert result["launch_allowed"] is False
    assert result["failed_facets"] == (["mcp_child_isolation"] if value != "unknown" else [])


@pytest.mark.parametrize(
    ("field", "value", "rejected_action"),
    [
        ("mcp_isolation_binding", "missing", "do_not_launch"),
        # An exact owned binding is not repaired by re-registering it.
        ("mcp_child_state", "failed", "reregister_isolated_mcp"),
        # A wrong binding is not repaired by recapturing the child.
        ("mcp_isolation_binding", "different", "recapture_isolated_mcp_child"),
    ],
)
def test_mcp_child_isolation_requires_the_matching_continuation(
    field: str, value: str, rejected_action: str
) -> None:
    report = _report()
    _observed(report)[field] = value
    _facets(report)["mcp_child_isolation"] = {
        "status": "fail",
        "reason": "mcp_child_isolation_unproven",
        "evidence_digest": _DIGEST,
        "next_action": rejected_action,
    }

    with pytest.raises(DogfoodGateError, match="mcp_child_isolation_continuation_missing"):
        classify_codex_dogfood_report(report)


def test_report_inventory_rejects_transcript_or_path_extensions() -> None:
    report = _report()
    report["transcript"] = "must never be admitted"
    with pytest.raises(DogfoodGateError, match="report_fields_invalid"):
        classify_codex_dogfood_report(report)

    report = _report()
    identity = cast(dict[str, object], report["identity"])
    identity["worktree_path"] = "/private/path"
    with pytest.raises(DogfoodGateError, match="identity_fields_invalid"):
        classify_codex_dogfood_report(report)


def test_cli_preflight_refuses_launch_on_a_failed_required_facet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report()
    _observed(report)["activation_state"] = "installed_not_activated"
    _facets(report)["plugin_activation"] = {
        "status": "fail",
        "reason": "installed_not_activated",
        "evidence_digest": _DIGEST,
        "next_action": "finishup_recommend_list_exact_target",
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    assert _MODULE.main([str(path), "--phase", "preflight"]) == 20
    result = json.loads(capsys.readouterr().out)
    assert result["launch_allowed"] is False
    assert result["preflight_outcome"] == "fail"


def test_session_stream_scope_requires_exact_parser_proven_codex_version() -> None:
    from finishup.adapters.importers.codex_rollout_jsonl import SUPPORTED_ROLLOUT_PROFILES
    from finishup.adapters.integrations.codex_capability_cells import (
        rollout_parser_proven_versions,
    )

    assert _MODULE.ROLLOUT_PARSER_PROVEN_VERSIONS == frozenset(rollout_parser_proven_versions())
    assert _MODULE.ROLLOUT_PARSER_PROVEN_VERSIONS == frozenset(SUPPORTED_ROLLOUT_PROFILES)

    for version in ("0.150.1", "0.148.0"):
        report = _report()
        cast(dict[str, object], report["identity"])["codex_version"] = version
        assert classify_codex_dogfood_report(report)["full_outcome"] == "pass"

    # A neighbouring release is never aliased to a proven profile: advertising the stream facet
    # for it is a scope error, and the only valid posture is explicit ``unsupported``.
    report = _report()
    cast(dict[str, object], report["identity"])["codex_version"] = "0.152.1"
    with pytest.raises(DogfoodGateError, match="session_stream_scope_unproven_codex_version"):
        classify_codex_dogfood_report(report)

    report = _report()
    cast(dict[str, object], report["identity"])["codex_version"] = "0.152.1"
    cast(dict[str, object], report["scope"])["session_stream_advertised"] = False
    _observed(report)["stream_coverage"] = False
    _facets(report)["session_stream"] = {
        "status": "unsupported",
        "reason": "capability_not_advertised",
        "evidence_digest": _DIGEST,
        "next_action": "none",
    }
    result = classify_codex_dogfood_report(report)
    assert result["full_outcome"] == "pass"
    assert result["unsupported_facets"] == ["session_stream"]


# --- Normal-target byte-content lane (issue #567) --------------------------------------------

_CONFIG_PATH = "sha256:" + ("c" * 64)
_MOVED_PATH = "sha256:" + ("d" * 64)
_BYTES_A = "sha256:" + ("e" * 64)
_BYTES_B = "sha256:" + ("f" * 64)


def _observation(
    *,
    path: str = _CONFIG_PATH,
    presence: str = "present",
    digest: str | None = _BYTES_A,
    size: int | None = 42,
    at: str = "2026-09-22T12:00:00.000Z",
) -> dict[str, object]:
    if presence != "present":
        digest, size = None, None
    return {
        "path_digest": path,
        "presence": presence,
        "content_digest": digest,
        "size_bytes": size,
        "observed_at": at,
    }


def _with_lane(
    before: dict[str, object], after: dict[str, object] | None, *, slot: str = "codex_config"
) -> dict[str, object]:
    report = _report()
    report["normal_target"] = {"files": [{"slot": slot, "before": before, "after": after}]}
    return report


def _later(**overrides: object) -> dict[str, object]:
    return _observation(at="2026-09-22T12:30:00.000Z", **overrides)  # type: ignore[arg-type]


def _unchanged_fail(reason: str) -> dict[str, object]:
    return {
        "status": "fail",
        "reason": reason,
        "evidence_digest": _DIGEST,
        "next_action": "complete_postflight",
    }


def test_unchanged_bytes_and_path_let_the_unchanged_facet_pass() -> None:
    result = classify_codex_dogfood_report(_with_lane(_observation(), _later()))

    assert result["full_outcome"] == "pass"


def test_path_stable_byte_change_cannot_pass_normal_target_unchanged() -> None:
    """The #567 regression: identical path identity no longer passes as an unchanged proof."""

    report = _with_lane(_observation(), _later(digest=_BYTES_B, size=43))
    with pytest.raises(DogfoodGateError, match="normal_target_unchanged_content_mismatch"):
        classify_codex_dogfood_report(report)

    # A generic drift token is not enough: the failure must name the derived cause.
    _facets(report)["normal_target_unchanged"] = _unchanged_fail("normal_target_drift")
    with pytest.raises(DogfoodGateError, match="normal_target_unchanged_content_mismatch"):
        classify_codex_dogfood_report(report)

    _facets(report)["normal_target_unchanged"] = _unchanged_fail("normal_target_content_changed")
    result = classify_codex_dogfood_report(report)
    assert result["full_outcome"] == "fail"
    assert result["failed_facets"] == ["normal_target_unchanged"]


def test_same_size_byte_change_is_still_a_content_change() -> None:
    report = _with_lane(_observation(), _later(digest=_BYTES_B))
    _facets(report)["normal_target_unchanged"] = _unchanged_fail("normal_target_content_changed")

    assert classify_codex_dogfood_report(report)["failed_facets"] == ["normal_target_unchanged"]


def test_path_move_with_identical_bytes_is_distinguishable_from_content_drift() -> None:
    report = _with_lane(_observation(), _later(path=_MOVED_PATH))
    _facets(report)["normal_target_unchanged"] = _unchanged_fail("normal_target_content_changed")
    with pytest.raises(DogfoodGateError, match="normal_target_unchanged_content_mismatch"):
        classify_codex_dogfood_report(report)

    _facets(report)["normal_target_unchanged"] = _unchanged_fail("normal_target_path_moved")
    assert classify_codex_dogfood_report(report)["failed_facets"] == ["normal_target_unchanged"]

    both = _with_lane(_observation(), _later(path=_MOVED_PATH, digest=_BYTES_B))
    _facets(both)["normal_target_unchanged"] = _unchanged_fail(
        "normal_target_path_and_content_changed"
    )
    assert classify_codex_dogfood_report(both)["failed_facets"] == ["normal_target_unchanged"]


def test_absent_file_that_stays_absent_is_unchanged_and_creation_is_drift() -> None:
    absent = _observation(presence="absent")
    assert (
        classify_codex_dogfood_report(_with_lane(absent, _later(presence="absent")))["full_outcome"]
        == "pass"
    )

    created = _with_lane(absent, _later())
    with pytest.raises(DogfoodGateError, match="normal_target_unchanged_content_mismatch"):
        classify_codex_dogfood_report(created)
    _facets(created)["normal_target_unchanged"] = _unchanged_fail("normal_target_content_changed")
    assert classify_codex_dogfood_report(created)["failed_facets"] == ["normal_target_unchanged"]

    deleted = _with_lane(_observation(), _later(presence="absent"))
    _facets(deleted)["normal_target_unchanged"] = _unchanged_fail("normal_target_content_changed")
    assert classify_codex_dogfood_report(deleted)["failed_facets"] == ["normal_target_unchanged"]


def test_missing_after_snapshot_cannot_pass_but_may_be_not_run() -> None:
    report = _with_lane(_observation(), None)
    with pytest.raises(DogfoodGateError, match="normal_target_after_snapshot_missing"):
        classify_codex_dogfood_report(report)

    _facets(report)["normal_target_unchanged"] = {
        "status": "not_run",
        "reason": "normal_target_after_snapshot_missing",
        "evidence_digest": None,
        "next_action": "complete_postflight",
    }
    assert classify_codex_dogfood_report(report)["full_outcome"] == "not_run"


def test_unstable_or_unreadable_observation_is_a_specific_failure() -> None:
    for presence in ("unstable", "unreadable", "not_regular", "oversized"):
        report = _with_lane(_observation(), _later(presence=presence))
        with pytest.raises(DogfoodGateError, match="normal_target_unchanged_content_mismatch"):
            classify_codex_dogfood_report(report)
        _facets(report)["normal_target_unchanged"] = _unchanged_fail(
            "normal_target_content_unobservable"
        )
        assert classify_codex_dogfood_report(report)["failed_facets"] == ["normal_target_unchanged"]


def test_snapshot_facet_cannot_pass_over_an_unobservable_before_snapshot() -> None:
    report = _with_lane(_observation(presence="unstable"), _later())
    _facets(report)["normal_target_unchanged"] = _unchanged_fail(
        "normal_target_content_unobservable"
    )
    with pytest.raises(DogfoodGateError, match="normal_target_snapshot_unobservable"):
        classify_codex_dogfood_report(report)


def test_content_reason_is_refused_when_the_lane_shows_no_change() -> None:
    report = _with_lane(_observation(), _later())
    _facets(report)["normal_target_unchanged"] = _unchanged_fail("normal_target_content_changed")

    with pytest.raises(DogfoodGateError, match="normal_target_unchanged_content_mismatch"):
        classify_codex_dogfood_report(report)


def test_strongest_change_across_slots_decides_the_reason() -> None:
    report = _report()
    report["normal_target"] = {
        "files": [
            {"slot": "codex_config", "before": _observation(), "after": _later(path=_MOVED_PATH)},
            {
                "slot": "codex_hooks",
                "before": _observation(path=_MOVED_PATH),
                "after": _later(path=_MOVED_PATH, digest=_BYTES_B),
            },
        ]
    }
    _facets(report)["normal_target_unchanged"] = _unchanged_fail("normal_target_content_changed")

    assert classify_codex_dogfood_report(report)["failed_facets"] == ["normal_target_unchanged"]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("content", "plaintext", "normal_target_observation_fields_invalid"),
        ("path_digest", "/synthetic/codex-home", "normal_target_path_digest_invalid"),
        ("presence", "maybe", "normal_target_presence_invalid"),
        ("size_bytes", -1, "normal_target_size_invalid"),
        ("observed_at", "yesterday", "normal_target_observed_at_invalid"),
    ],
)
def test_content_observation_shape_is_closed(field: str, value: object, reason: str) -> None:
    after = _later()
    after[field] = value
    with pytest.raises(DogfoodGateError, match=reason):
        classify_codex_dogfood_report(_with_lane(_observation(), after))


def test_absent_observation_cannot_carry_byte_evidence() -> None:
    after = _later(presence="absent")
    after["content_digest"] = _BYTES_A
    with pytest.raises(DogfoodGateError, match="normal_target_absent_shape_invalid"):
        classify_codex_dogfood_report(_with_lane(_observation(), after))


def test_after_snapshot_cannot_predate_before_snapshot() -> None:
    report = _with_lane(
        _observation(at="2026-09-22T12:30:00.000Z"), _observation(at="2026-09-22T12:00:00.000Z")
    )
    with pytest.raises(DogfoodGateError, match="normal_target_observation_order_invalid"):
        classify_codex_dogfood_report(report)


def test_duplicate_or_malformed_slots_are_rejected() -> None:
    report = _report()
    entry = {"slot": "codex_config", "before": _observation(), "after": _later()}
    report["normal_target"] = {"files": [entry, dict(entry)]}
    with pytest.raises(DogfoodGateError, match="normal_target_slot_duplicate"):
        classify_codex_dogfood_report(report)

    with pytest.raises(DogfoodGateError, match="normal_target_slot_invalid"):
        classify_codex_dogfood_report(_with_lane(_observation(), _later(), slot="Codex Config"))

    report = _report()
    report["normal_target"] = {"files": []}
    with pytest.raises(DogfoodGateError, match="normal_target_files_invalid"):
        classify_codex_dogfood_report(report)


def test_version_three_reports_with_ambiguous_config_digest_are_refused() -> None:
    report = _report()
    report["schema"] = "yoetz.codex-dogfood-parity/3"
    with pytest.raises(DogfoodGateError, match="report_fields_invalid"):
        classify_codex_dogfood_report(report)

    report = _report()
    isolation = _isolation(report)
    isolation["config_digest"] = isolation.pop("config_path_digest")
    with pytest.raises(DogfoodGateError, match="finishup_isolation_fields_invalid"):
        classify_codex_dogfood_report(report)


def _real_lane(
    before: list[dict[str, object]], after: list[dict[str, object]]
) -> dict[str, object]:
    report = _report()
    report["normal_target"] = {
        "files": [
            {"slot": f"slot_{index}", "before": first, "after": second}
            for index, (first, second) in enumerate(zip(before, after, strict=True))
        ]
    }
    return report


def _classify_real(before: list[dict[str, object]], after: list[dict[str, object]]) -> str | None:
    """Derived change reason for observations captured from real files."""

    report = _real_lane(before, after)
    try:
        classify_codex_dogfood_report(report)
    except DogfoodGateError as error:
        assert str(error) == "normal_target_unchanged_content_mismatch"
    else:
        return None
    for reason in _MODULE.NORMAL_TARGET_CONTENT_REASONS:
        _facets(report)["normal_target_unchanged"] = _unchanged_fail(reason)
        try:
            classify_codex_dogfood_report(report)
        except DogfoodGateError:
            continue
        return reason
    raise AssertionError("no content reason accepted")


def test_real_files_atomic_replacement_symlink_retarget_and_concurrent_change(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config.toml"
    config.write_bytes(b"model = 'a'\n")
    before = _MODULE.observe_normal_target([config])

    # Atomic replacement with identical bytes: unchanged.
    staged = tmp_path / "config.toml.new"
    staged.write_bytes(b"model = 'a'\n")
    os.replace(staged, config)
    assert _classify_real(before, _MODULE.observe_normal_target([config])) is None

    # Atomic replacement with different bytes at the same path: content drift.
    staged.write_bytes(b"model = 'b'\n")
    os.replace(staged, config)
    assert (
        _classify_real(before, _MODULE.observe_normal_target([config]))
        == "normal_target_content_changed"
    )

    # Symlink retargeted to another file with identical bytes: a path move, not drift.
    first = tmp_path / "first.toml"
    second = tmp_path / "second.toml"
    first.write_bytes(b"x = 1\n")
    second.write_bytes(b"x = 1\n")
    link = tmp_path / "linked.toml"
    link.symlink_to(first)
    link_before = _MODULE.observe_normal_target([link])
    link.unlink()
    link.symlink_to(second)
    assert (
        _classify_real(link_before, _MODULE.observe_normal_target([link]))
        == "normal_target_path_moved"
    )

    # A concurrent writer (for example desktop plugin materialization) changes the normal
    # config between the before and after snapshots of a run.
    watched = tmp_path / "watched.toml"
    watched.write_bytes(b"[plugins]\n")
    run_before = _MODULE.observe_normal_target([watched])
    with watched.open("ab") as handle:
        handle.write(b"materialized = true\n")
    assert (
        _classify_real(run_before, _MODULE.observe_normal_target([watched]))
        == "normal_target_content_changed"
    )

    # Absent before and after: unchanged; nothing to digest.
    missing = tmp_path / "never.toml"
    assert (
        _classify_real(
            _MODULE.observe_normal_target([missing]), _MODULE.observe_normal_target([missing])
        )
        is None
    )


def test_observe_cli_prints_digest_only_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.toml"
    config.write_bytes(b"token = 'never-printed'\n")

    assert _MODULE.main(["--observe", str(config), "--observe", str(tmp_path / "gone")]) == 0
    output = capsys.readouterr().out
    rows = json.loads(output)

    assert [row["presence"] for row in rows] == ["present", "absent"]
    assert rows[0]["content_digest"] == (
        "sha256:" + hashlib.sha256(b"token = 'never-printed'\n").hexdigest()
    )
    assert "never-printed" not in output
    assert str(tmp_path) not in output
