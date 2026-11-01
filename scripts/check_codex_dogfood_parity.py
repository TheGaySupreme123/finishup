"""Validate the retained exact-worktree Codex dogfood parity gate (issues #463/#464/#518/#561/#567).

The input is a bounded structural report assembled from the runbook's named commands. It carries
digests and closed states only: no paths, prompts, transcripts, credentials, or provider payloads.
Run ``--phase preflight`` before launching Codex; a non-zero result forbids the launch.

Two digest kinds stay apart (issue #567). ``*_path_digest`` fields bind canonical path identity
only and cannot prove that a file's bytes stayed the same. The optional ``normal_target`` lane
binds normal-target file bytes as before/after content observations (SHA-256, size, existence,
observation time — never content); when present, it decides whether ``normal_target_unchanged``
may pass and which specific reason a failure must carry. ``--observe PATH`` prints those
observations for the operator to copy into the report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Final, Literal, TypedDict, cast

GateStatus = Literal["pass", "fail", "unsupported", "blocked", "not_run"]

_SCHEMA: Final = "yoetz.codex-dogfood-parity/4"
_MAX_REPORT_BYTES: Final = 131_072
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_SOURCE_REF = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$", re.ASCII)
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$", re.ASCII)
_OBSERVED_AT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$", re.ASCII
)
_MAX_NORMAL_TARGET_FILES: Final = 32
_CONTENT_BYTE_LIMIT: Final = 16_777_216
_OBSERVABLE_PRESENCE: Final = frozenset({"present", "absent"})
_CONTENT_PRESENCE: Final = frozenset(
    {"present", "absent", "not_regular", "oversized", "unreadable", "unstable"}
)
# Specific ``normal_target_unchanged`` failure reasons the content lane derives, strongest first.
NORMAL_TARGET_CONTENT_REASONS: Final = (
    "normal_target_content_unobservable",
    "normal_target_path_and_content_changed",
    "normal_target_content_changed",
    "normal_target_path_moved",
)
# Exact Codex releases with a fixture-proven rollout parser profile (mirrors
# ``codex_capability_cells.CODEX_ROLLOUT_PARSER_PROOFS``; a unit test keeps them equal). The
# stream facet may be advertised only for one of these; a neighbouring release stays
# ``unsupported`` even when hooks and MCP work, because parser proof is per exact version.
ROLLOUT_PARSER_PROVEN_VERSIONS: Final = frozenset({"0.148.0", "0.150.1"})

PREFLIGHT_FACETS: Final = (
    "source_identity",
    "package_identity",
    "service_isolation",
    "mcp_child_isolation",
    "workspace_binding",
    "observation_consent",
    "plugin_source",
    "plugin_installation",
    "plugin_discovery",
    "plugin_inventory",
    "plugin_enablement",
    "plugin_rendered_bytes",
    "plugin_cache",
    "plugin_activation",
    "normal_target_snapshot",
)

POSTFLIGHT_FACETS: Final = (
    "skill_delivery",
    "mcp_runtime",
    "model_mcp_call",
    "hook_lifecycle",
    "mapping",
    "accepted_envelopes",
    "diagnostics",
    "drain",
    "session_stream",
    "semantic_dispatch",
    "semantic_provenance",
    "receipt",
    "corrective_influence",
    "rollback",
    "normal_target_unchanged",
)

_ALL_FACETS: Final = frozenset((*PREFLIGHT_FACETS, *POSTFLIGHT_FACETS))
_HOOK_FACETS: Final = frozenset(
    {"hook_lifecycle", "mapping", "accepted_envelopes", "diagnostics", "drain"}
)
_NEXT_ACTIONS: Final = frozenset(
    {
        "none",
        "do_not_launch",
        "provision_isolated_finishup_root",
        "reregister_isolated_mcp",
        "recapture_isolated_mcp_child",
        "finishup_observe_grant_exact_worktree",
        "finishup_recommend_list_exact_target",
        "manual_activation_review",
        "complete_postflight",
    }
)


class DogfoodGateError(ValueError):
    """One bounded report validation failure."""


class GateRow(TypedDict):
    status: GateStatus
    reason: str | None
    evidence_digest: str | None
    next_action: str


class DogfoodScope(TypedDict):
    hooks_advertised: bool
    session_stream_advertised: bool
    semantic_required: bool
    influence_required: bool


class DogfoodFinishUpIsolation(TypedDict):
    """Path-identity digests only: equal digests mean a shared target, not unchanged bytes."""

    mode: Literal["isolated", "ambient", "unknown"]
    normal_mode: Literal["isolated", "ambient", "unknown"]
    state_path_digest: str
    endpoint_path_digest: str
    storage_path_digest: str
    config_path_digest: str
    executable_path_digest: str
    normal_state_path_digest: str
    normal_endpoint_path_digest: str
    normal_storage_path_digest: str
    normal_config_path_digest: str
    normal_executable_path_digest: str


class ContentObservation(TypedDict):
    """One file's bytes as SHA-256, size, existence, and time; never the content itself."""

    path_digest: str
    presence: str
    content_digest: str | None
    size_bytes: int | None
    observed_at: str


class NormalTargetFile(TypedDict):
    slot: str
    before: ContentObservation
    after: ContentObservation | None


class DogfoodIdentity(TypedDict):
    source_ref: str
    package_digest: str
    codex_executable_digest: str
    codex_version: str
    codex_home_digest: str
    launcher_digest: str
    route_profile: Literal["strict", "policy"]
    worktree_digest: str
    finishup_isolation: DogfoodFinishUpIsolation


class DogfoodObserved(TypedDict):
    activation_state: str
    finishup_isolation_state: str
    mcp_registration_state: str
    mcp_isolation_binding: str
    mcp_child_state: str
    exact_worktree_consent: str
    primary_checkout_consent: str
    controls_workspace_match: bool
    mapping_present: bool
    accepted_envelope_count: int
    undelivered_count: int
    drain_succeeded: bool
    hook_coverage: bool
    stream_coverage: bool


class DogfoodGateResult(TypedDict):
    schema: str
    preflight_outcome: GateStatus
    launch_allowed: bool
    full_outcome: GateStatus
    failed_facets: list[str]
    blocked_facets: list[str]
    unsupported_facets: list[str]
    not_run_facets: list[str]
    report_digest: str


def _error(reason: str) -> DogfoodGateError:
    return DogfoodGateError(reason)


def _require_digest(value: object, reason: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _error(reason)
    return value


def _require_bool(value: object, reason: str) -> bool:
    if type(value) is not bool:
        raise _error(reason)
    return value


def _parse_finishup_isolation(value: object) -> DogfoodFinishUpIsolation:
    if type(value) is not dict:
        raise _error("finishup_isolation_invalid")
    row = cast(dict[str, object], value)
    digest_fields = (
        "state_path_digest",
        "endpoint_path_digest",
        "storage_path_digest",
        "config_path_digest",
        "executable_path_digest",
        "normal_state_path_digest",
        "normal_endpoint_path_digest",
        "normal_storage_path_digest",
        "normal_config_path_digest",
        "normal_executable_path_digest",
    )
    if set(row) != {"mode", "normal_mode", *digest_fields}:
        raise _error("finishup_isolation_fields_invalid")
    mode = row["mode"]
    normal_mode = row["normal_mode"]
    if mode not in {"isolated", "ambient", "unknown"}:
        raise _error("finishup_isolation_mode_invalid")
    if normal_mode not in {"isolated", "ambient", "unknown"}:
        raise _error("finishup_isolation_normal_mode_invalid")
    digests = {
        name: _require_digest(row[name], "finishup_isolation_digest_invalid")
        for name in digest_fields
    }
    return DogfoodFinishUpIsolation(
        mode=cast(Literal["isolated", "ambient", "unknown"], mode),
        normal_mode=cast(Literal["isolated", "ambient", "unknown"], normal_mode),
        state_path_digest=digests["state_path_digest"],
        endpoint_path_digest=digests["endpoint_path_digest"],
        storage_path_digest=digests["storage_path_digest"],
        config_path_digest=digests["config_path_digest"],
        executable_path_digest=digests["executable_path_digest"],
        normal_state_path_digest=digests["normal_state_path_digest"],
        normal_endpoint_path_digest=digests["normal_endpoint_path_digest"],
        normal_storage_path_digest=digests["normal_storage_path_digest"],
        normal_config_path_digest=digests["normal_config_path_digest"],
        normal_executable_path_digest=digests["normal_executable_path_digest"],
    )


def _parse_content_observation(value: object) -> ContentObservation:
    if type(value) is not dict:
        raise _error("normal_target_observation_invalid")
    row = cast(dict[str, object], value)
    if set(row) != {"path_digest", "presence", "content_digest", "size_bytes", "observed_at"}:
        raise _error("normal_target_observation_fields_invalid")
    presence = row["presence"]
    observed_at = row["observed_at"]
    content_digest = row["content_digest"]
    raw_size = row["size_bytes"]
    size_bytes: int | None = None
    if presence not in _CONTENT_PRESENCE:
        raise _error("normal_target_presence_invalid")
    if type(observed_at) is not str or _OBSERVED_AT.fullmatch(observed_at) is None:
        raise _error("normal_target_observed_at_invalid")
    if presence == "present":
        _require_digest(content_digest, "normal_target_content_digest_invalid")
        if type(raw_size) is not int or not 0 <= raw_size <= _CONTENT_BYTE_LIMIT:
            raise _error("normal_target_size_invalid")
        size_bytes = raw_size
    elif content_digest is not None or raw_size is not None:
        # Only a complete, stable read of a present regular file may carry byte evidence.
        raise _error("normal_target_absent_shape_invalid")
    return ContentObservation(
        path_digest=_require_digest(row["path_digest"], "normal_target_path_digest_invalid"),
        presence=cast(str, presence),
        content_digest=cast(str | None, content_digest),
        size_bytes=size_bytes,
        observed_at=observed_at,
    )


def _parse_normal_target(value: object) -> tuple[NormalTargetFile, ...] | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise _error("normal_target_invalid")
    row = cast(dict[str, object], value)
    if set(row) != {"files"}:
        raise _error("normal_target_fields_invalid")
    files = row["files"]
    if type(files) is not list:
        raise _error("normal_target_files_invalid")
    items = cast(list[object], files)
    if not items or len(items) > _MAX_NORMAL_TARGET_FILES:
        raise _error("normal_target_files_invalid")
    parsed: list[NormalTargetFile] = []
    for item in items:
        if type(item) is not dict:
            raise _error("normal_target_file_invalid")
        entry = cast(dict[str, object], item)
        if set(entry) != {"slot", "before", "after"}:
            raise _error("normal_target_file_fields_invalid")
        slot = entry["slot"]
        if type(slot) is not str or _TOKEN.fullmatch(slot) is None:
            raise _error("normal_target_slot_invalid")
        before = _parse_content_observation(entry["before"])
        after = None if entry["after"] is None else _parse_content_observation(entry["after"])
        if after is not None and after["observed_at"] < before["observed_at"]:
            raise _error("normal_target_observation_order_invalid")
        parsed.append(NormalTargetFile(slot=slot, before=before, after=after))
    slots = [entry["slot"] for entry in parsed]
    if len(set(slots)) != len(slots):
        raise _error("normal_target_slot_duplicate")
    return tuple(parsed)


def _content_equal(before: ContentObservation, after: ContentObservation) -> bool:
    return (
        before["presence"] == after["presence"]
        and before["content_digest"] == after["content_digest"]
        and before["size_bytes"] == after["size_bytes"]
    )


def normal_target_file_change(entry: NormalTargetFile) -> str | None:
    """Classify one normal-target slot; ``None`` means path identity and bytes both held.

    Path identity and byte content are compared independently, so a retargeted or moved file
    with identical bytes (``normal_target_path_moved``) stays distinguishable from a path-stable
    byte change (``normal_target_content_changed``).
    """

    before = entry["before"]
    after = entry["after"]
    if after is None:
        return "normal_target_after_snapshot_missing"
    if (
        before["presence"] not in _OBSERVABLE_PRESENCE
        or after["presence"] not in _OBSERVABLE_PRESENCE
    ):
        return "normal_target_content_unobservable"
    path_moved = before["path_digest"] != after["path_digest"]
    content_changed = not _content_equal(before, after)
    if path_moved and content_changed:
        return "normal_target_path_and_content_changed"
    if content_changed:
        return "normal_target_content_changed"
    if path_moved:
        return "normal_target_path_moved"
    return None


def _normal_target_reason(files: tuple[NormalTargetFile, ...]) -> str | None:
    changes = {normal_target_file_change(entry) for entry in files}
    if "normal_target_after_snapshot_missing" in changes:
        return "normal_target_after_snapshot_missing"
    for reason in NORMAL_TARGET_CONTENT_REASONS:
        if reason in changes:
            return reason
    return None


def _parse_identity(value: object) -> DogfoodIdentity:
    if type(value) is not dict:
        raise _error("identity_invalid")
    row = cast(dict[str, object], value)
    expected = {
        "source_ref",
        "package_digest",
        "codex_executable_digest",
        "codex_version",
        "codex_home_digest",
        "launcher_digest",
        "route_profile",
        "worktree_digest",
        "finishup_isolation",
    }
    if set(row) != expected:
        raise _error("identity_fields_invalid")
    source_ref = row["source_ref"]
    version = row["codex_version"]
    route = row["route_profile"]
    if type(source_ref) is not str or _SOURCE_REF.fullmatch(source_ref) is None:
        raise _error("source_ref_invalid")
    if type(version) is not str or _VERSION.fullmatch(version) is None:
        raise _error("codex_version_invalid")
    if route not in {"strict", "policy"}:
        raise _error("route_profile_invalid")
    return DogfoodIdentity(
        source_ref=source_ref,
        package_digest=_require_digest(row["package_digest"], "package_digest_invalid"),
        codex_executable_digest=_require_digest(
            row["codex_executable_digest"], "codex_executable_digest_invalid"
        ),
        codex_version=version,
        codex_home_digest=_require_digest(row["codex_home_digest"], "codex_home_digest_invalid"),
        launcher_digest=_require_digest(row["launcher_digest"], "launcher_digest_invalid"),
        route_profile=cast(Literal["strict", "policy"], route),
        worktree_digest=_require_digest(row["worktree_digest"], "worktree_digest_invalid"),
        finishup_isolation=_parse_finishup_isolation(row["finishup_isolation"]),
    )


def _parse_scope(value: object) -> DogfoodScope:
    if type(value) is not dict:
        raise _error("scope_invalid")
    row = cast(dict[str, object], value)
    expected = {
        "hooks_advertised",
        "session_stream_advertised",
        "semantic_required",
        "influence_required",
    }
    if set(row) != expected:
        raise _error("scope_fields_invalid")
    return DogfoodScope(
        hooks_advertised=_require_bool(row["hooks_advertised"], "hooks_scope_invalid"),
        session_stream_advertised=_require_bool(
            row["session_stream_advertised"], "session_stream_scope_invalid"
        ),
        semantic_required=_require_bool(row["semantic_required"], "semantic_scope_invalid"),
        influence_required=_require_bool(row["influence_required"], "influence_scope_invalid"),
    )


def _parse_observed(value: object) -> DogfoodObserved:
    if type(value) is not dict:
        raise _error("observed_invalid")
    row = cast(dict[str, object], value)
    expected = {
        "activation_state",
        "finishup_isolation_state",
        "mcp_registration_state",
        "mcp_isolation_binding",
        "mcp_child_state",
        "exact_worktree_consent",
        "primary_checkout_consent",
        "controls_workspace_match",
        "mapping_present",
        "accepted_envelope_count",
        "undelivered_count",
        "drain_succeeded",
        "hook_coverage",
        "stream_coverage",
    }
    if set(row) != expected:
        raise _error("observed_fields_invalid")
    activation = row["activation_state"]
    isolation_state = row["finishup_isolation_state"]
    mcp_registration_state = row["mcp_registration_state"]
    mcp_isolation_binding = row["mcp_isolation_binding"]
    mcp_child_state = row["mcp_child_state"]
    exact_consent = row["exact_worktree_consent"]
    primary_consent = row["primary_checkout_consent"]
    if activation not in {
        "active",
        "installed_not_activated",
        "not_installed",
        "foreign",
        "unknown",
    }:
        raise _error("activation_state_invalid")
    if isolation_state not in {"isolated", "shared", "ambient", "unknown"}:
        raise _error("finishup_isolation_state_invalid")
    if mcp_registration_state not in {"yoetz_owned", "absent", "foreign_present", "unknown"}:
        raise _error("mcp_registration_state_invalid")
    if mcp_isolation_binding not in {
        "ambient",
        "isolated_exact",
        "missing",
        "different",
        "unknown",
    }:
        raise _error("mcp_isolation_binding_invalid")
    if mcp_child_state not in {"ready", "failed", "unknown"}:
        raise _error("mcp_child_state_invalid")
    consent_states = {"active", "missing", "paused", "revoked", "unknown"}
    if exact_consent not in consent_states or primary_consent not in consent_states:
        raise _error("consent_state_invalid")
    for name in (
        "accepted_envelope_count",
        "undelivered_count",
    ):
        if type(row[name]) is not int or cast(int, row[name]) < 0:
            raise _error(f"{name}_invalid")
    return DogfoodObserved(
        activation_state=cast(str, activation),
        finishup_isolation_state=cast(str, isolation_state),
        mcp_registration_state=cast(str, mcp_registration_state),
        mcp_isolation_binding=cast(str, mcp_isolation_binding),
        mcp_child_state=cast(str, mcp_child_state),
        exact_worktree_consent=cast(str, exact_consent),
        primary_checkout_consent=cast(str, primary_consent),
        controls_workspace_match=_require_bool(
            row["controls_workspace_match"], "controls_workspace_match_invalid"
        ),
        mapping_present=_require_bool(row["mapping_present"], "mapping_present_invalid"),
        accepted_envelope_count=cast(int, row["accepted_envelope_count"]),
        undelivered_count=cast(int, row["undelivered_count"]),
        drain_succeeded=_require_bool(row["drain_succeeded"], "drain_succeeded_invalid"),
        hook_coverage=_require_bool(row["hook_coverage"], "hook_coverage_invalid"),
        stream_coverage=_require_bool(row["stream_coverage"], "stream_coverage_invalid"),
    )


def _parse_gate_row(name: str, value: object) -> GateRow:
    if type(value) is not dict:
        raise _error(f"{name}_row_invalid")
    row = cast(dict[str, object], value)
    if set(row) != {"status", "reason", "evidence_digest", "next_action"}:
        raise _error(f"{name}_fields_invalid")
    status = row["status"]
    reason = row["reason"]
    evidence = row["evidence_digest"]
    next_action = row["next_action"]
    if status not in {"pass", "fail", "unsupported", "blocked", "not_run"}:
        raise _error(f"{name}_status_invalid")
    if reason is not None and (type(reason) is not str or _TOKEN.fullmatch(reason) is None):
        raise _error(f"{name}_reason_invalid")
    if next_action not in _NEXT_ACTIONS:
        raise _error(f"{name}_next_action_invalid")
    if status == "pass":
        if reason is not None or next_action != "none":
            raise _error(f"{name}_pass_shape_invalid")
        _require_digest(evidence, f"{name}_evidence_invalid")
    else:
        if reason is None:
            raise _error(f"{name}_reason_required")
        if evidence is not None:
            _require_digest(evidence, f"{name}_evidence_invalid")
    return GateRow(
        status=cast(GateStatus, status),
        reason=reason,
        evidence_digest=cast(str | None, evidence),
        next_action=cast(str, next_action),
    )


def _aggregate(names: tuple[str, ...], facets: Mapping[str, GateRow]) -> GateStatus:
    statuses = {facets[name]["status"] for name in names}
    if "fail" in statuses:
        return "fail"
    if "blocked" in statuses:
        return "blocked"
    if "unsupported" in statuses:
        return "unsupported"
    if "not_run" in statuses:
        return "not_run"
    return "pass"


def _required_postflight(scope: DogfoodScope) -> tuple[str, ...]:
    names = [
        "skill_delivery",
        "mcp_runtime",
        "model_mcp_call",
        "receipt",
        "rollback",
        "normal_target_unchanged",
    ]
    if scope["hooks_advertised"]:
        names.extend(sorted(_HOOK_FACETS))
    if scope["session_stream_advertised"]:
        names.append("session_stream")
    if scope["semantic_required"]:
        names.extend(("semantic_dispatch", "semantic_provenance"))
    if scope["influence_required"]:
        names.append("corrective_influence")
    return tuple(names)


def _validate_out_of_scope_facets(
    scope: DogfoodScope, facets: Mapping[str, GateRow], required: tuple[str, ...]
) -> None:
    required_set = frozenset(required)
    for name in POSTFLIGHT_FACETS:
        if name in required_set:
            continue
        status = facets[name]["status"]
        if name in _HOOK_FACETS or name == "session_stream":
            if status != "unsupported":
                raise _error("unadvertised_capability_facet_not_unsupported")
        elif status != "not_run":
            # Optional AI-powered review/influence work cannot carry an ignored pass, fail, or block. The
            # scope must be revised first so every performed or failed cell participates in the
            # aggregate conclusion.
            raise _error("out_of_scope_facet_not_not_run")


def _validate_normal_target(
    files: tuple[NormalTargetFile, ...], facets: Mapping[str, GateRow]
) -> None:
    """Bind the snapshot and unchanged facets to the byte-content lane (issue #567)."""

    snapshot = facets["normal_target_snapshot"]
    if snapshot["status"] == "pass" and any(
        entry["before"]["presence"] not in _OBSERVABLE_PRESENCE for entry in files
    ):
        raise _error("normal_target_snapshot_unobservable")
    unchanged = facets["normal_target_unchanged"]
    reason = _normal_target_reason(files)
    if reason == "normal_target_after_snapshot_missing":
        if unchanged["status"] == "pass":
            raise _error("normal_target_after_snapshot_missing")
        return
    if reason is not None:
        # A path-stable byte change (or move, or unobservable file) cannot pass, and its failure
        # names the derived cause instead of a generic drift token.
        if unchanged["status"] != "fail" or unchanged["reason"] != reason:
            raise _error("normal_target_unchanged_content_mismatch")
        return
    if unchanged["reason"] in NORMAL_TARGET_CONTENT_REASONS:
        raise _error("normal_target_unchanged_content_mismatch")


def classify_codex_dogfood_report(document: object) -> DogfoodGateResult:
    """Validate one report and derive the preflight/full outcomes without score collapsing."""

    if type(document) is not dict:
        raise _error("report_invalid")
    report = cast(dict[str, object], document)
    if (
        set(report) != {"schema", "identity", "scope", "observed", "normal_target", "facets"}
        or report["schema"] != _SCHEMA
    ):
        raise _error("report_fields_invalid")
    identity = _parse_identity(report["identity"])
    scope = _parse_scope(report["scope"])
    observed = _parse_observed(report["observed"])
    normal_target = _parse_normal_target(report["normal_target"])
    raw_facets = report["facets"]
    if type(raw_facets) is not dict:
        raise _error("facet_inventory_invalid")
    facet_rows = cast(dict[str, object], raw_facets)
    if frozenset(facet_rows) != _ALL_FACETS:
        raise _error("facet_inventory_invalid")
    facets = {name: _parse_gate_row(name, raw) for name, raw in facet_rows.items()}

    if (facets["workspace_binding"]["status"] == "pass") != observed["controls_workspace_match"]:
        raise _error("workspace_binding_observation_mismatch")
    if (facets["observation_consent"]["status"] == "pass") != (
        observed["exact_worktree_consent"] == "active"
    ):
        raise _error("observation_consent_state_mismatch")
    if (facets["plugin_activation"]["status"] == "pass") != (
        observed["activation_state"] == "active"
    ):
        raise _error("activation_state_mismatch")
    isolation = identity["finishup_isolation"]
    if (facets["service_isolation"]["status"] == "pass") != (
        observed["finishup_isolation_state"] == "isolated"
    ):
        raise _error("service_isolation_state_mismatch")
    if facets["service_isolation"]["status"] == "pass":
        if isolation["mode"] != "isolated" or isolation["normal_mode"] != "ambient":
            raise _error("service_isolation_identity_mismatch")
        shared_identity_pairs = (
            (isolation["state_path_digest"], isolation["normal_state_path_digest"]),
            (isolation["endpoint_path_digest"], isolation["normal_endpoint_path_digest"]),
            (isolation["storage_path_digest"], isolation["normal_storage_path_digest"]),
            (isolation["config_path_digest"], isolation["normal_config_path_digest"]),
            (isolation["executable_path_digest"], isolation["normal_executable_path_digest"]),
        )
        if any(resolved == normal for resolved, normal in shared_identity_pairs):
            raise _error("service_isolation_identity_shared")
    mcp_child_exact = (
        observed["mcp_registration_state"] == "yoetz_owned"
        and observed["mcp_isolation_binding"] == "isolated_exact"
        and observed["mcp_child_state"] == "ready"
    )
    if (facets["mcp_child_isolation"]["status"] == "pass") != mcp_child_exact:
        raise _error("mcp_child_isolation_state_mismatch")
    if facets["mapping"]["status"] == "pass" and not observed["mapping_present"]:
        raise _error("mapping_observation_missing")
    if (
        facets["accepted_envelopes"]["status"] == "pass"
        and observed["accepted_envelope_count"] == 0
    ):
        raise _error("accepted_envelope_observation_missing")
    if facets["drain"]["status"] == "pass" and (
        not observed["drain_succeeded"] or observed["undelivered_count"] != 0
    ):
        raise _error("drain_observation_mismatch")
    if facets["hook_lifecycle"]["status"] == "pass" and not observed["hook_coverage"]:
        raise _error("hook_coverage_missing")
    if facets["session_stream"]["status"] == "pass" and not observed["stream_coverage"]:
        raise _error("stream_coverage_missing")
    if normal_target is not None:
        _validate_normal_target(normal_target, facets)

    consent = facets["observation_consent"]
    if consent["status"] != "pass" and consent["next_action"] != (
        "finishup_observe_grant_exact_worktree"
    ):
        raise _error("observation_consent_continuation_missing")
    isolation_row = facets["service_isolation"]
    if isolation_row["status"] != "pass" and isolation_row["next_action"] != (
        "provision_isolated_finishup_root"
    ):
        raise _error("service_isolation_continuation_missing")
    mcp_child = facets["mcp_child_isolation"]
    if mcp_child["status"] != "pass":
        # An exact owned binding cannot be repaired by re-registering it; only the child
        # start or its capture is unproven there. Every other non-pass shape needs the
        # reviewed registration redone before the child is worth capturing again.
        mcp_binding_exact = (
            observed["mcp_registration_state"] == "yoetz_owned"
            and observed["mcp_isolation_binding"] == "isolated_exact"
        )
        expected_action = (
            "recapture_isolated_mcp_child" if mcp_binding_exact else "reregister_isolated_mcp"
        )
        if mcp_child["next_action"] != expected_action:
            raise _error("mcp_child_isolation_continuation_missing")
    activation = facets["plugin_activation"]
    if activation["reason"] == "installed_not_activated" and activation["next_action"] != (
        "finishup_recommend_list_exact_target"
    ):
        raise _error("activation_recovery_continuation_missing")
    if (
        activation["reason"] in {"foreign", "modified", "ambiguous"}
        and activation["next_action"] != "manual_activation_review"
    ):
        raise _error("activation_manual_review_missing")

    for name in _HOOK_FACETS:
        if not scope["hooks_advertised"] and facets[name]["status"] != "unsupported":
            raise _error("unadvertised_hook_facet_not_unsupported")
    if (
        not scope["session_stream_advertised"]
        and facets["session_stream"]["status"] != "unsupported"
    ):
        raise _error("unadvertised_stream_facet_not_unsupported")
    if (
        scope["session_stream_advertised"]
        and identity["codex_version"] not in ROLLOUT_PARSER_PROVEN_VERSIONS
    ):
        raise _error("session_stream_scope_unproven_codex_version")

    preflight = _aggregate(PREFLIGHT_FACETS, facets)
    required_postflight = _required_postflight(scope)
    _validate_out_of_scope_facets(scope, facets, required_postflight)
    postflight = _aggregate(required_postflight, facets)
    full: GateStatus = preflight if preflight != "pass" else postflight
    encoded = json.dumps(report, separators=(",", ":"), sort_keys=True).encode("utf-8")
    report_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return DogfoodGateResult(
        schema=_SCHEMA,
        preflight_outcome=preflight,
        launch_allowed=preflight == "pass",
        full_outcome=full,
        failed_facets=sorted(name for name, row in facets.items() if row["status"] == "fail"),
        blocked_facets=sorted(name for name, row in facets.items() if row["status"] == "blocked"),
        unsupported_facets=sorted(
            name for name, row in facets.items() if row["status"] == "unsupported"
        ),
        not_run_facets=sorted(name for name, row in facets.items() if row["status"] == "not_run"),
        report_digest=report_digest,
    )


def _load(path: Path) -> object:
    if path.is_symlink() or not path.is_file():
        raise _error("report_path_invalid")
    raw = path.read_bytes()
    if not raw or len(raw) > _MAX_REPORT_BYTES:
        raise _error("report_size_invalid")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("report_json_invalid") from exc


def observe_normal_target(paths: list[Path]) -> list[dict[str, object]]:
    """Digest-only content observations for ``normal_target`` before/after rows.

    Reuses the product's bounded observer so the report and ``finishup service isolation
    --content-digests`` share one shape. Paths are hashed into ``path_digest``, never echoed.
    """

    from finishup.cli.isolation_status import observe_file_content

    return [dict(observe_file_content(path)) for path in paths]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, nargs="?")
    parser.add_argument("--phase", choices=("preflight", "full"), default="full")
    parser.add_argument(
        "--observe",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help="Print a digest-only content observation of PATH instead of validating a report.",
    )
    args = parser.parse_args(argv)
    if args.observe:
        if args.report is not None:
            parser.error("--observe does not take a report")
        print(json.dumps(observe_normal_target(args.observe), separators=(",", ":")))
        return 0
    if args.report is None:
        parser.error("a report path is required")
    try:
        result = classify_codex_dogfood_report(_load(args.report))
    except DogfoodGateError as exc:
        print(f"codex_dogfood_report_invalid:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    outcome = result["preflight_outcome"] if args.phase == "preflight" else result["full_outcome"]
    return 0 if outcome == "pass" else 20


if __name__ == "__main__":
    raise SystemExit(main())
