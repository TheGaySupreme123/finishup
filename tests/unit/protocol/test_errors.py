from __future__ import annotations

import ast
import importlib
import importlib.util
import subprocess
import sys
from collections.abc import AsyncGenerator, Generator, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import FrozenInstanceError, fields, is_dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import TypeAliasType, cast

import pytest

import yoetz.protocol.errors as errors_module
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import (
    PROTOCOL_REASON_CODES,
    SAFE_DETAIL_KEYS,
    ProtocolValueError,
    PublicErrorCode,
    PublicOperationError,
    SafeDetailValue,
    normalize_safe_details,
)
from yoetz.protocol.schemas import validate_schema_instance

_VALID_CORRELATION_ID = "err_00000000-0000-4000-8000-000000000000"
_OTHER_CORRELATION_ID = "err_00000000-0000-4000-8000-000000000001"

_EXPECTED_REASON_CODES = tuple(
    """accepted_but_unresponsive
accepted_record_shape_invalid
actor_id_malformed
actor_id_not_generated
ambiguous_binding
attach_handle_expired
attach_handle_invalid
attach_handle_reused
attach_handle_revoked
attach_result_invalid
byte_order_mark_forbidden
catalog_busy
catalog_maintenance_busy
check_admission_capture_pending
check_admission_contended
check_admission_import_pending
check_admission_in_progress
child_check_frontier_ahead_of_child
child_check_frontier_missing
child_check_frontier_without_check
child_dependencies_not_canonical
child_dependency_count_invalid
child_finding_count_invalid
child_findings_not_canonical
child_frontier_missing
child_gap_frontier_mismatch
claim_revision_invalid
claim_revision_mismatch
commitment_only_object_kind
coordination_admission_required
coordination_consent_required
coordination_declaration_invalid
coordination_detection_mismatch
coordination_disposition_invalid
coordination_evidence_missing
coordination_generation_mismatch
coordination_generation_revoked
coordination_generation_superseded
coordination_grant_required
coordination_invalid
coordination_obligation_conflict
coordination_obligation_mismatch
coordination_participants_unavailable
coordination_recipient_mismatch
coordination_resource_count_invalid
coordination_route_unavailable
coordination_runtime_unavailable
coordination_source_policy_denied
coordination_source_unavailable
coordination_task_pair_invalid
coordination_tasks_not_canonical
cross_repository_lineage_requires_grant
cursor_mcp_route_invalid
cursor_project_mcp_command_invalid
cursor_project_mcp_invalid
cursor_project_mcp_preview_required
dependency_changed
duplicate_has_duplicates
duplicate_link_broken
duplicate_object_key
duplicate_set_member
duplicate_target_different_issue
duplicate_target_is_duplicate
duplicate_target_not_earlier
duplicate_target_same_finding
duplicate_target_unknown
empty_check_types
empty_publication_channels
empty_subject_state
endpoint_unsafe
engine_family_wrong_author
entry_digest_mismatch
event_family_not_admitted
event_integer_out_of_range
event_text_out_of_bounds
evidence_digest_availability_invalid
evidence_digest_binding_invalid
evidence_digest_binding_required
evidence_digest_provenance_invalid
evidence_digest_subject_incompatible
evidence_strength_unsupported
expected_frontier_required
finding_actionable_mismatch
finding_json_shape_invalid
finding_not_proof_limited
finding_not_rechecked
finding_priority_mismatch
finding_resolution_mismatch
finding_terminal
float_forbidden
frame_invalid
frame_too_large
frontier_changed
frontier_digest_mismatch
general_project_membership_conflict
host_lineage_annotation_invalid
id_malformed_uuid
id_not_ascii
id_uuid_not_version_4
id_uuid_wrong_variant
id_wrong_length
id_wrong_prefix
id_wrong_type
implicit_project_requires_opt_out
import_publication_authority_required
import_report_invalid
input_not_bytes
integer_out_of_safe_range
integer_out_of_sqlite_range
internal_error
invalid_actor_type
invalid_approved_check
invalid_approved_check_policy
invalid_chain
invalid_check_types
invalid_commitment
invalid_continuation_expiry
invalid_continuation_kind
invalid_continuation_pending_id
invalid_continuation_repository_setup
invalid_continuation_review_input
invalid_cost_fields
invalid_coverage_value
invalid_digest
invalid_duration
invalid_event_enum
invalid_event_schema
invalid_event_value_type
invalid_external_runtime_authority
invalid_finding_kind
invalid_finding_origin
invalid_finding_policy_identity
invalid_finding_provenance
invalid_finding_subject_refs
invalid_frontier
invalid_json_pointer
invalid_known_gap
invalid_payload_ref
invalid_projection_locator
invalid_publication_channels
invalid_ranked_findings
invalid_receipt_child_finding
invalid_receipt_child_outcome
invalid_receipt_children
invalid_receipt_conclusion
invalid_receipt_document
invalid_receipt_gap
invalid_receipt_obligation
invalid_receipt_redaction
invalid_receipt_response
invalid_receipt_section
invalid_receipt_section_order
invalid_receipt_version_slice
invalid_runtime_attempt_evidence
invalid_sampling_params
invalid_semantic_dispatch_kind
invalid_semantic_failure_class
invalid_semantic_fallback_origin
invalid_semantic_outcome_type
invalid_semantic_provenance
invalid_semantic_status_reason_pair
invalid_start_internal_result
invalid_subject_state
invalid_timestamp
invalid_token_usage
invalid_utf8
invalid_workspace_inspect
ledger_assigned_field_in_request_identity
lineage_acceptance_transition
lineage_catalog_busy
lineage_catalog_migration_required
lineage_child_missing
lineage_child_not_found
lineage_close_authority
lineage_cycle
lineage_depth_limit
lineage_event_contradiction
lineage_event_invalid
lineage_event_operation_conflict
lineage_event_operation_pending
lineage_event_result_invalid
lineage_fanout_limit
lineage_handle_conflict
lineage_handle_key_invalid
lineage_handle_key_unavailable
lineage_handle_missing
lineage_manifest_stale
lineage_operation_conflict
lineage_operation_lease_expired
lineage_operation_not_found
lineage_operation_phase
lineage_operation_quarantined
lineage_parent_not_found
lineage_parent_session_invalid
lineage_parent_work_terminal
lineage_phase_transition
lineage_repository_mismatch
lineage_request_identity_conflict
lineage_reservation_conflict
lineage_resume_work_terminal
lineage_root_conflict
lineage_root_dependency
lineage_service_unavailable
lineage_session_conflict
lineage_session_not_active
lineage_session_not_found
lineage_session_scope
lineage_task_conflict
lineage_task_missing
lineage_task_not_found
lineage_transition_conflict
lineage_work_terminal
lineage_work_transition
lone_surrogate
malformed_json
method_forbidden
missing_payload_field
nesting_too_deep
no_obligations_reason_conflict
noncanonical_integer_string
noncanonical_json
not_an_accepted_envelope
nul_byte_forbidden
object_key_not_string
obligation_change_invalid
obligation_resolution_invalid
obligation_resolution_mismatch
observation_selection_session_limit
opaque_item_id_invalid
operation_recovery_unavailable
ownership_contended
payload_redaction_mismatch
payload_too_large
peer_untrusted
plan_version_conflict
privacy_audit_unreadable
privacy_projection_unavailable
privacy_receipt_not_durable
project_dissolved
project_member_already_unbound
project_member_not_found
project_not_found
projection_unavailable
protocol_mismatch
provider_attempt_provenance_is_not_final
public_error_invalid_correlation_id
public_error_invalid_message
public_error_missing_correlation_id
read_projection_failed
receipt_child_manifest_mismatch
receipt_children_not_canonical
receipt_children_schema_version
receipt_coverage_mismatch
receipt_gap_not_in_coverage
receipt_json_projection_blocked
receipt_json_shape_invalid
receipt_semantic_withheld_items_not_canonical
redaction_target_required
ref_mirror_mismatch
repository_identity_mismatch
repository_identity_required
request_identity_conflict
request_timeout
requested_command_placeholder
resolution_attempt_required
response_fields_invalid
response_projection_failed
runtime_attempt_evidence_json_shape_invalid
runtime_opening_authority
runtime_rebind_busy
schema_artifact_role_invalid
schema_artifact_role_mismatch
schema_bytes_invalid
schema_catalog_incomplete
schema_digest_mismatch
schema_draft_unsupported
schema_duplicate_identity
schema_id_mismatch
schema_instance_invalid
schema_kind_mismatch
schema_manifest_duplicate_path
schema_manifest_invalid
schema_manifest_member_mismatch
schema_manifest_missing
schema_name_invalid
schema_not_found
schema_path_unsafe
schema_reference_unresolved
schema_version_mismatch
selector_conflict
semantic_provenance_json_shape_invalid
semantic_redacted_values_invalid
service_draining
service_generation_changed
service_incompatible
service_stamp_required
service_unavailable
session_lineage_fields_incomplete
session_superseded
set_member_not_ascii
start_busy_retry_ready
start_catalog_retry_ready
start_lease_pending
start_runtime_rebind_retry_ready
stored_result_shape_invalid
timestamp_not_utc
timestamp_out_of_range
timestamp_submillisecond_precision
timestamp_timezone_missing
unknown_event_schema
unknown_payload_field
unsorted_set_field
unsupported_json_type
unsupported_payload_type
workspace_task_exists""".splitlines()
)


class _SafeEnum(Enum):
    READY = "ready"


class _UnsafeEnum(Enum):
    UPPER = "NOT_SAFE"


class _LowerSnake64Enum(Enum):
    VALUE = "a" * 64


class _LowerSnake65Enum(Enum):
    VALUE = "a" * 65


class _NonStringValueEnum(Enum):
    VALUE = 1


class _StringSubclass(str):
    pass


class _IntegerSubclass(int):
    pass


class _SubclassValueEnum(Enum):
    VALUE = _StringSubclass("ready")


class _SingleReadEnum(Enum):
    READY = "stored-value"

    @property
    def value(self) -> str:
        reads = getattr(self, "_test_value_reads", 0) + 1
        object.__setattr__(self, "_test_value_reads", reads)
        if reads != 1:
            raise AssertionError("enum value was read more than once")
        return "ready"


class _SpoofedEnum:
    value = "ready"

    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[Enum]:
        return Enum


class _SpoofedMapping:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[dict[object, object]]:
        return dict

    def __getitem__(self, key: object) -> object:
        if key == "count":
            return 5
        raise KeyError(key)


class _SpoofedPublicErrorCode:
    value = "UNREGISTERED"

    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[PublicErrorCode]:
        return PublicErrorCode


class _RaisingClass:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[object]:
        raise KeyboardInterrupt("class inspection")


class _ExplosiveValue:
    def __repr__(self) -> str:
        raise AssertionError("unknown value was rendered")

    def __str__(self) -> str:
        raise AssertionError("unknown value was stringified")


class _KnownKeyOnlyMapping(Mapping[object, object]):
    def __init__(self) -> None:
        self.accessed: list[object] = []

    def __getitem__(self, key: object) -> object:
        self.accessed.append(key)
        if key == "count":
            return 3
        if key == "secret":
            return _ExplosiveValue()
        raise KeyError(key)

    def __iter__(self) -> Iterator[object]:
        raise AssertionError("normalizer iterated hostile mapping")

    def __len__(self) -> int:
        raise AssertionError("normalizer measured hostile mapping")


class _RaisingMapping(Mapping[object, object]):
    def __getitem__(self, key: object) -> object:
        raise KeyboardInterrupt(key)

    def __iter__(self) -> Iterator[object]:
        return iter(())

    def __len__(self) -> int:
        return 0


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)
    assert str(exc_info.value) == reason


def test_public_error_code_membership() -> None:
    expected = (
        "INVALID_REQUEST",
        "PROTOCOL_VERSION_UNSUPPORTED",
        "SESSION_NOT_FOUND",
        "SESSION_CONFLICT",
        "IDEMPOTENCY_CONFLICT",
        "REQUEST_IDENTITY_CONFLICT",
        "OPERATION_PENDING",
        "FRONTIER_CONFLICT",
        "EVENT_INVALID",
        "LIMIT_EXCEEDED",
        "BUNDLE_BUSY",
        "STORAGE_UNSAFE",
        "STORAGE_CORRUPT",
        "MIGRATION_REQUIRED",
        "SERVICE_UNAVAILABLE",
        "VAULT_LOCKED",
        "PRIVACY_AUTHORITY_REQUIRED",
        "PROVIDER_UNAVAILABLE",
        "PROVIDER_REFUSED",
        "PROVIDER_TIMEOUT",
        "SEMANTIC_RESULT_INVALID",
        "CANCELLED",
        "INTERNAL_ERROR",
    )
    assert PublicErrorCode.__bases__ == (str, Enum)
    assert tuple(member.name for member in PublicErrorCode) == expected
    assert tuple(member.value for member in PublicErrorCode) == expected
    assert isinstance(SafeDetailValue, TypeAliasType)
    assert SafeDetailValue.__value__ == str | int | tuple[str, ...]


def test_protocol_reason_registry_is_exact_and_import_order_independent() -> None:
    source_values = cast(tuple[str, ...], getattr(errors_module, "_PROTOCOL_REASON_CODE_VALUES"))
    assert source_values == _EXPECTED_REASON_CODES
    assert len(source_values) == 315
    assert source_values == tuple(sorted(source_values, key=str.encode))
    assert len(source_values) == len(set(source_values))
    assert PROTOCOL_REASON_CODES == frozenset(_EXPECTED_REASON_CODES)
    assert isinstance(PROTOCOL_REASON_CODES, frozenset)
    assert not hasattr(errors_module, "register_protocol_reason")
    before = PROTOCOL_REASON_CODES
    for name in (
        "yoetz.protocol.canonical",
        "yoetz.protocol.ids",
        "yoetz.protocol.coverage",
        "yoetz.protocol.schemas",
    ):
        if importlib.util.find_spec(name) is not None:
            importlib.import_module(name)
            assert errors_module.PROTOCOL_REASON_CODES is before
    with pytest.raises(ValueError, match="^unregistered_protocol_reason_code$"):
        ProtocolValueError("not_registered")
    with pytest.raises(ValueError, match="^unregistered_protocol_reason_code$"):
        ProtocolValueError(_StringSubclass("invalid_digest"))

    consumers = tuple(
        name
        for name in (
            "yoetz.protocol.canonical",
            "yoetz.protocol.ids",
            "yoetz.protocol.coverage",
            "yoetz.protocol.schemas",
        )
        if importlib.util.find_spec(name) is not None
    )
    orders = [("yoetz.protocol.errors", *consumers)]
    orders.extend(
        (consumer, "yoetz.protocol.errors", *(name for name in consumers if name != consumer))
        for consumer in consumers
    )
    for order in dict.fromkeys(orders):
        script = "\n".join(
            (
                "import importlib",
                f"order = {order!r}",
                "for name in order: importlib.import_module(name)",
                "import yoetz.protocol.errors as errors",
                f"expected = {_EXPECTED_REASON_CODES!r}",
                "actual = tuple(sorted(errors.PROTOCOL_REASON_CODES, key=lambda value: value.encode('ascii')))",
                "assert actual == expected",
                "assert not hasattr(errors, 'register_protocol_reason')",
            )
        )
        completed = subprocess.run(  # noqa: S603 - no shell and a fixed interpreter
            [sys.executable, "-I", "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr


def test_dependency_root_has_no_internal_imports() -> None:
    module_file = errors_module.__file__
    assert module_file is not None
    tree = ast.parse(Path(module_file).read_text(encoding="utf-8"))
    imported_modules: list[str] = []
    relative_imports = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            relative_imports += node.level
            if node.module is not None:
                imported_modules.append(node.module)
    assert relative_imports == 0
    assert not any(module == "yoetz" or module.startswith("yoetz.") for module in imported_modules)


def test_literal_protocol_refusals_use_registered_reasons() -> None:
    """An unregistered refusal raises ValueError before the typed boundary can catch it."""
    module_file = errors_module.__file__
    assert module_file is not None
    package_root = Path(module_file).parent.parent
    unregistered: list[str] = []
    for source in package_root.rglob("*.py"):
        if "resources" in source.relative_to(package_root).parts:
            continue
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            public_reasons: list[str] = []
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_error"
            ):
                public_reasons.extend(
                    keyword.value.value
                    for keyword in node.keywords
                    if keyword.arg == "reason"
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                )
            if isinstance(node, ast.Dict):
                public_reasons.extend(
                    value.value
                    for key, value in zip(node.keys, node.values, strict=True)
                    if isinstance(key, ast.Constant)
                    and key.value == "reason_code"
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                )
            for reason in public_reasons:
                assert isinstance(node, ast.Call | ast.Dict)
                if reason not in PROTOCOL_REASON_CODES:
                    unregistered.append(
                        f"{source.relative_to(package_root)}:{node.lineno}:{reason}"
                    )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ProtocolValueError"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value not in PROTOCOL_REASON_CODES
            ):
                unregistered.append(
                    f"{source.relative_to(package_root)}:{node.lineno}:{node.args[0].value}"
                )
    assert not unregistered, unregistered


def test_registered_refusal_reason_survives_public_error_projection() -> None:
    for reason in PROTOCOL_REASON_CODES:
        error = PublicOperationError(
            PublicErrorCode.SESSION_CONFLICT,
            "The operation was refused.",
            False,
            safe_details={"reason_code": reason},
        )
        expected_details = {"reason_code": reason}
        if reason in errors_module.REASON_CODE_CONTINUATIONS:
            expected_details["continuation"] = errors_module.REASON_CODE_CONTINUATIONS[reason]
        assert error.safe_details == expected_details


def test_operation_error_is_bounded() -> None:
    one_byte = PublicOperationError(PublicErrorCode.INTERNAL_ERROR, "x", False)
    assert one_byte.message == "x"
    valid = PublicOperationError(
        PublicErrorCode.BUNDLE_BUSY,
        "é" * 2048,
        True,
        _VALID_CORRELATION_ID,
        {"count": 1},
    )
    assert len(valid.message.encode()) == 4096
    for invalid in (
        "",
        "é" * 2049,
        "line\nfeed",
        "tab\tvalue",
        "delete\x7f",
        "nul\0",
        _StringSubclass("Safe message"),
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            PublicOperationError(PublicErrorCode.INTERNAL_ERROR, invalid, False)
        _assert_reason(exc_info, "public_error_invalid_message")
    with pytest.raises(ProtocolValueError) as surrogate_exc:
        PublicOperationError(PublicErrorCode.INTERNAL_ERROR, "\ud800", False)
    _assert_reason(surrogate_exc, "public_error_invalid_message")
    for invalid_id in (
        "bad_00000000-0000-4000-8000-000000000000",
        "err_00000000-0000-4000-8000-00000000000",
        "err_000000000000-4000-8000-000000000000",
        "err_00000000-0000-3000-8000-000000000000",
        "err_00000000-0000-4000-7000-000000000000",
        "err_00000000-0000-4000-8000-00000000000A",
        _StringSubclass(_VALID_CORRELATION_ID),
        1,
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            PublicOperationError(
                PublicErrorCode.INTERNAL_ERROR,
                "Safe message",
                False,
                cast(str, invalid_id),
            )
        _assert_reason(exc_info, "public_error_invalid_correlation_id")


def test_operation_error_exception_value_contract() -> None:
    original = {"count": 2, "unknown": _ExplosiveValue()}
    error = PublicOperationError(
        PublicErrorCode.LIMIT_EXCEEDED, "Bounded message", False, safe_details=original
    )
    original["count"] = 99
    assert is_dataclass(error)
    assert PublicOperationError.__slots__ == (
        "code",
        "message",
        "retryable",
        "correlation_id",
        "safe_details",
    )
    assert tuple(field.name for field in fields(error)) == PublicOperationError.__slots__
    assert error.args == ("Bounded message",)
    assert str(error) == "Bounded message"
    assert error.correlation_id is None
    assert dict(error.safe_details) == {"count": 2}
    assert isinstance(error.safe_details, MappingProxyType)
    rendered = repr(error)
    assert [rendered.index(name) for name in PublicOperationError.__slots__] == sorted(
        rendered.index(name) for name in PublicOperationError.__slots__
    )
    assert "unknown" not in rendered
    with pytest.raises(FrozenInstanceError):
        setattr(error, "message", "changed")


@pytest.mark.anyio
async def test_public_failure_survives_sync_and_async_resource_cleanup() -> None:
    error = PublicOperationError(PublicErrorCode.BUNDLE_BUSY, "The task is temporarily busy.", True)
    cleaned: list[str] = []

    @contextmanager
    def synchronous() -> Generator[None]:
        try:
            yield
        finally:
            cleaned.append("sync")

    @asynccontextmanager
    async def asynchronous() -> AsyncGenerator[None]:
        try:
            yield
        finally:
            cleaned.append("async")

    with pytest.raises(PublicOperationError) as caught:
        async with asynchronous():
            with synchronous():
                raise error
    assert caught.value is error
    assert cleaned == ["sync", "async"]
    assert error.__traceback__ is not None
    error.add_note("bounded internal cleanup note")
    assert error.__notes__ == ["bounded internal cleanup note"]
    with pytest.raises(FrozenInstanceError):
        error.message = "changed"
    with pytest.raises(FrozenInstanceError):
        del error.safe_details


def test_safe_details_allowlist_and_types_are_exact() -> None:
    expected_keys = (
        "actual_version",
        "authorize_command",
        "availability",
        "availability_inherited",
        "availability_request_id",
        "blocking_reasons",
        "component",
        "continuation",
        "count",
        "expected_version",
        "field",
        "head_digest",
        "host_profile",
        "invariant",
        "limit",
        "method",
        "operation",
        "pending_ttl_seconds",
        "phase",
        "prepare_command",
        "quarantine_code",
        "reason_code",
        "replay_request_id",
        "retry_after_ms",
        "review_command",
        "route_profile",
        "schema_name",
        "sequence",
        "session_id",
        "state",
        "status",
        "task_id",
        "view",
        "writer_id",
    )
    assert SAFE_DETAIL_KEYS == expected_keys
    # Issue #469: the bridge's host-binding availability facts are closed tokens, one boolean,
    # and one request id; anything else for those keys is dropped, never passed through.
    availability = normalize_safe_details(
        {
            "availability": "terminal_unavailable",
            "availability_inherited": True,
            "availability_request_id": "req_00000000-0000-4000-8000-000000000001",
            "host_profile": "cursor",
            "route_profile": "policy",
        }
    )
    assert dict(availability) == {
        "availability": "terminal_unavailable",
        "availability_inherited": True,
        "availability_request_id": "req_00000000-0000-4000-8000-000000000001",
        "host_profile": "cursor",
        "route_profile": "policy",
    }
    assert (
        dict(
            normalize_safe_details(
                {
                    "availability": "unavailable",
                    "availability_inherited": "true",
                    "availability_request_id": "ses_00000000-0000-4000-8000-000000000001",
                    "host_profile": "vscode",
                    "route_profile": "open",
                }
            )
        )
        == {}
    )
    accepted = normalize_safe_details(
        {
            "actual_version": "1.0.0+local",
            "blocking_reasons": ("issue_returned_again",),
            "authorize_command": "yoetz consent authorize",
            "availability": "terminal_unavailable",
            "availability_inherited": True,
            "availability_request_id": "req_00000000-0000-4000-8000-000000000001",
            "host_profile": "cursor",
            "route_profile": "policy",
            "component": _SafeEnum.READY,
            "continuation": "vault_initialization_required",
            "count": 0,
            "invariant": "scope_overlap_required",
            "expected_version": "V2-rc.1",
            "field": "/payload/~0/~1//",
            "head_digest": "genesis",
            "limit": 9_007_199_254_740_991,
            "method": _SafeEnum.READY,
            "operation": _SafeEnum.READY,
            "pending_ttl_seconds": 900,
            "phase": _SafeEnum.READY,
            "prepare_command": "yoetz consent prepare vault_initialize",
            "quarantine_code": "operation_lease_shape_invalid",
            "reason_code": "invalid_digest",
            "replay_request_id": "req_00000000-0000-4000-8000-000000000001",
            "retry_after_ms": 1,
            "review_command": "yoetz consent review",
            "schema_name": "accepted-event",
            "sequence": 5,
            "session_id": "ses_00000000-0000-4000-8000-000000000001",
            "state": _SafeEnum.READY,
            "status": _SafeEnum.READY,
            "task_id": "tsk_00000000-0000-4000-8000-000000000001",
            "view": _SafeEnum.READY,
            "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        }
    )
    assert tuple(accepted) == expected_keys
    assert accepted["component"] == "ready"
    assert normalize_safe_details({"phase": "projection"}) == {"phase": "projection"}
    assert normalize_safe_details({"phase": "user_supplied_value"}) == {}
    assert all(type(value) in {str, int, bool, tuple} for value in accepted.values())
    assert isinstance(accepted, MappingProxyType)
    hostile = _KnownKeyOnlyMapping()
    assert dict(normalize_safe_details(hostile)) == {"count": 3}
    assert "secret" not in hostile.accessed
    assert normalize_safe_details(_RaisingMapping()) is normalize_safe_details(None)
    assert normalize_safe_details(_RaisingClass()) is normalize_safe_details(None)
    assert normalize_safe_details(_SpoofedMapping()) is normalize_safe_details(None)
    rejected_values: tuple[object, ...] = (
        True,
        -1,
        9_007_199_254_740_992,
        1.0,
        "1",
        _IntegerSubclass(1),
    )
    for integer_key in ("count", "limit", "pending_ttl_seconds", "retry_after_ms", "sequence"):
        for rejected in rejected_values:
            assert not normalize_safe_details({integer_key: rejected})
    # head_digest is a frontier recovery field: accept genesis and exact sha256, nothing else.
    assert normalize_safe_details({"head_digest": "genesis"})["head_digest"] == "genesis"
    exact_digest = "sha256:" + "0123456789abcdef" * 4
    assert normalize_safe_details({"head_digest": exact_digest})["head_digest"] == exact_digest
    for malformed_digest in (
        "sha256:" + "0" * 63,
        "sha256:" + "0" * 65,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
        "sha512:" + "0" * 64,
        "0" * 64,
        " sha256:" + "0" * 64,
        "sha256:" + "0" * 64 + " ",
        "GENESIS",
        "",
    ):
        assert not normalize_safe_details({"head_digest": malformed_digest})
    for rejected in (True, 1, 1.0, None):
        assert not normalize_safe_details({"head_digest": rejected})
    assert not normalize_safe_details({"component": "ready"})
    assert not normalize_safe_details({"component": _UnsafeEnum.UPPER})
    assert normalize_safe_details({"component": _LowerSnake64Enum.VALUE})
    assert not normalize_safe_details({"component": _LowerSnake65Enum.VALUE})
    assert not normalize_safe_details({"component": _NonStringValueEnum.VALUE})
    assert not normalize_safe_details({"component": _SubclassValueEnum.VALUE})
    assert not normalize_safe_details({"component": _SpoofedEnum()})
    assert normalize_safe_details({"component": _SingleReadEnum.READY}) == {"component": "ready"}
    assert not normalize_safe_details({"reason_code": "unknown"})
    assert not normalize_safe_details({"quarantine_code": "unknown"})
    quarantine_codes = (
        "operation_event_range_mismatch",
        "operation_kind_state_contradiction",
        "operation_lease_shape_invalid",
        "operation_result_digest_mismatch",
        "operation_resume_object_invalid",
    )
    for quarantine_code in quarantine_codes:
        assert normalize_safe_details({"quarantine_code": quarantine_code}) == {
            "quarantine_code": quarantine_code
        }
    assert normalize_safe_details({"field": ""})["field"] == ""
    assert normalize_safe_details({"field": "/"})["field"] == "/"
    assert normalize_safe_details({"field": "/" + "a" * 255})["field"] == "/" + "a" * 255
    for pointer in ("field", "/~", "/~2", "/\n", "/\x7f", "/é", "/" + "a" * 256):
        assert not normalize_safe_details({"field": pointer})
    assert normalize_safe_details({"actual_version": "a" * 64})
    assert not normalize_safe_details({"actual_version": "a" * 65})
    for version_key in ("actual_version", "expected_version"):
        for invalid_version in ("", "-1", "1 0", "é", "1\n"):
            assert not normalize_safe_details({version_key: invalid_version})
    assert normalize_safe_details({"schema_name": "a" * 128})
    assert not normalize_safe_details({"schema_name": "a" * 129})
    for invalid_schema_name in ("", "A", "a--b", "a-", "a_b", "é"):
        assert not normalize_safe_details({"schema_name": invalid_schema_name})
    subclass_details = {
        "actual_version": _StringSubclass("1.0.0"),
        "expected_version": _StringSubclass("1.0.0"),
        "field": _StringSubclass("/payload"),
        "quarantine_code": _StringSubclass("operation_lease_shape_invalid"),
        "reason_code": _StringSubclass("invalid_digest"),
        "schema_name": _StringSubclass("accepted-event"),
    }
    for key, value in subclass_details.items():
        assert not normalize_safe_details({key: value})


def test_initialization_continuation_details_are_closed_literals() -> None:
    """Issue #512: the initialization-required continuation admits only repository constants.

    Every command an agent is told to run rides an exact-literal token set, so no caller- or
    service-derived string can steer an agent toward a different command through these keys.
    """

    accepted = normalize_safe_details(
        {
            "authorize_command": "yoetz consent authorize",
            "continuation": "vault_initialization_required",
            "pending_ttl_seconds": 900,
            "prepare_command": "yoetz consent prepare vault_initialize",
            "replay_request_id": "req_00000000-0000-4000-8000-000000000001",
            "review_command": "yoetz consent review",
        }
    )
    assert dict(accepted) == {
        "authorize_command": "yoetz consent authorize",
        "continuation": "vault_initialization_required",
        "pending_ttl_seconds": 900,
        "prepare_command": "yoetz consent prepare vault_initialize",
        "replay_request_id": "req_00000000-0000-4000-8000-000000000001",
        "review_command": "yoetz consent review",
    }
    hostile = (
        # A plausible near-miss of the admitted token, chosen so it stays unregistered: issue
        # #741 minted a real ``vault_unlock_required``, which is no longer hostile.
        ("continuation", "vault_initialization_optional"),
        ("continuation", "vault_initialization_required "),
        ("prepare_command", "yoetz consent prepare vault_passphrase_rotate"),
        ("prepare_command", "rm -rf /; yoetz consent prepare vault_initialize"),
        ("review_command", "yoetz consent review --yolo"),
        ("authorize_command", "yoetz consent authorize --warning-acknowledged"),
        ("replay_request_id", "ses_00000000-0000-4000-8000-000000000001"),
        ("replay_request_id", "req_not_a_uuid"),
        ("pending_ttl_seconds", "900"),
    )
    for key, value in hostile:
        assert not normalize_safe_details({key: value})


def test_constructor_validation_order_is_exact() -> None:
    with pytest.raises(TypeError, match="^public_error_code_wrong_type$"):
        PublicOperationError(cast(PublicErrorCode, "INTERNAL_ERROR"), "", cast(bool, 1))
    with pytest.raises(TypeError, match="^public_error_code_wrong_type$"):
        PublicOperationError(cast(PublicErrorCode, _SpoofedPublicErrorCode()), "Safe", False)
    with pytest.raises(TypeError, match="^public_error_code_wrong_type$"):
        PublicOperationError(cast(PublicErrorCode, _RaisingClass()), "Safe", False)
    with pytest.raises(ProtocolValueError) as message_exc:
        PublicOperationError(PublicErrorCode.INTERNAL_ERROR, "", cast(bool, 1))
    _assert_reason(message_exc, "public_error_invalid_message")
    with pytest.raises(TypeError, match="^public_error_retryable_wrong_type$"):
        PublicOperationError(
            PublicErrorCode.INTERNAL_ERROR,
            "Safe",
            cast(bool, 1),
            "not-an-id",
        )
    with pytest.raises(ProtocolValueError) as correlation_exc:
        PublicOperationError(
            PublicErrorCode.INTERNAL_ERROR,
            "Safe",
            False,
            "not-an-id",
            _RaisingMapping(),
        )
    _assert_reason(correlation_exc, "public_error_invalid_correlation_id")


def test_correlation_binding_lifecycle() -> None:
    unbound = PublicOperationError(PublicErrorCode.OPERATION_PENDING, "Still running", True)
    with pytest.raises(ProtocolValueError) as missing_exc:
        unbound.as_public_dict()
    _assert_reason(missing_exc, "public_error_missing_correlation_id")
    bound = unbound.bind_correlation_id(_VALID_CORRELATION_ID)
    assert bound is not unbound
    assert bound.correlation_id == _VALID_CORRELATION_ID
    assert bound.bind_correlation_id(_VALID_CORRELATION_ID) is bound
    with pytest.raises(ProtocolValueError) as different_exc:
        bound.bind_correlation_id(_OTHER_CORRELATION_ID)
    _assert_reason(different_exc, "public_error_invalid_correlation_id")
    with pytest.raises(ProtocolValueError) as type_exc:
        unbound.bind_correlation_id(cast(str, 1))
    _assert_reason(type_exc, "public_error_invalid_correlation_id")
    enum_detailed = PublicOperationError(
        PublicErrorCode.INTERNAL_ERROR,
        "Component failed",
        False,
        None,
        {"component": _SafeEnum.READY, "count": 3},
    )
    assert enum_detailed.safe_details == {"component": "ready", "count": 3}
    enum_bound = enum_detailed.bind_correlation_id(_VALID_CORRELATION_ID)
    assert enum_bound.safe_details == enum_detailed.safe_details
    assert enum_bound.correlation_id == _VALID_CORRELATION_ID


def test_public_dict_shape_and_copy_are_exact() -> None:
    error = PublicOperationError(
        PublicErrorCode.INVALID_REQUEST,
        "Invalid request",
        False,
        _VALID_CORRELATION_ID,
        {"state": _SafeEnum.READY, "count": 2},
    )
    first = error.as_public_dict()
    assert tuple(first) == ("code", "message", "retryable", "correlation_id", "safe_details")
    assert first["code"] == "INVALID_REQUEST"
    details = cast(dict[str, SafeDetailValue], first["safe_details"])
    assert type(details) is dict
    assert tuple(details) == ("count", "state")
    first["message"] = "changed"
    details["count"] = 99
    second = error.as_public_dict()
    assert second["message"] == "Invalid request"
    assert second["safe_details"] == {"count": 2, "state": "ready"}
    empty = PublicOperationError(
        PublicErrorCode.INTERNAL_ERROR,
        "Internal error",
        False,
        _VALID_CORRELATION_ID,
    ).as_public_dict()
    assert tuple(empty) == ("code", "message", "retryable", "correlation_id")


def test_blocking_reasons_detail_admits_only_bounded_closed_tokens() -> None:
    """Issue #1023: the self_verified refusal names its closed reason tokens, never prose."""

    accepted = normalize_safe_details(
        {
            "reason_code": "finding_not_proof_limited",
            "blocking_reasons": ("coverage:completion_plan_not_claimed", "issue_returned_again"),
        }
    )
    assert accepted["blocking_reasons"] == (
        "coverage:completion_plan_not_claimed",
        "issue_returned_again",
    )
    for bad in (
        (),
        ("Fix the bug please",),
        ("coverage:" + "a" * 97,),
        tuple(f"reason_{index}" for index in range(33)),
        "issue_returned_again",
        (1,),
    ):
        assert "blocking_reasons" not in normalize_safe_details({"blocking_reasons": bad})
    error = PublicOperationError(
        PublicErrorCode.INVALID_REQUEST,
        "refused",
        False,
        safe_details={"blocking_reasons": ("issue_returned_again",)},
        correlation_id="err_00000000-0000-4000-8000-000000000001",
    )
    public = error.as_public_dict()
    assert public["safe_details"] == {"blocking_reasons": ["issue_returned_again"]}
    validate_schema_instance("public-error", "1.0.0", cast(JsonValue, public))
