"""Locks the public error-code mapping, retryability, and safe-detail bounding.

These are pure-helper tests: they exercise ``protocol/errors.py`` (the sole vocabulary of public
error codes and the ``PublicOperationError``/``normalize_safe_details`` contract),
``cli/exits.py`` (the sole CLI exit mapping), and ``application/service.py`` (the frozen
``ProjectedControlBody`` union that proves errors never leak into a result type). End-to-end
operation orchestration is out of scope here; it belongs to integration/conformance suites.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import get_args

import pytest

from finishup.application.service import ProjectedControlBody
from finishup.cli.exits import PUBLIC_EXIT_CODES, exit_code_for
from finishup.ports.control import ControlMethod
from finishup.protocol.errors import (
    PROTOCOL_REASON_CODES,
    SAFE_DETAIL_KEYS,
    ProtocolValueError,
    PublicErrorCode,
    PublicOperationError,
    normalize_safe_details,
)

_APPLICATION_SRC: Path = Path(__file__).parents[3] / "src/finishup/application"

# The five behavioral classes named by the owning spec, plus the last-resort fallback code.
# Every ``PublicErrorCode`` member belongs to exactly one bucket below.
_VALIDATION_CODES: frozenset[PublicErrorCode] = frozenset(
    {
        PublicErrorCode.INVALID_REQUEST,
        PublicErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
        PublicErrorCode.EVENT_INVALID,
        PublicErrorCode.LIMIT_EXCEEDED,
    }
)
_FRONTIER_CODES: frozenset[PublicErrorCode] = frozenset(
    {
        PublicErrorCode.SESSION_NOT_FOUND,
        PublicErrorCode.SESSION_CONFLICT,
        PublicErrorCode.IDEMPOTENCY_CONFLICT,
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
        PublicErrorCode.OPERATION_PENDING,
        PublicErrorCode.FRONTIER_CONFLICT,
    }
)
_STORAGE_CODES: frozenset[PublicErrorCode] = frozenset(
    {
        PublicErrorCode.BUNDLE_BUSY,
        PublicErrorCode.STORAGE_UNSAFE,
        PublicErrorCode.STORAGE_CORRUPT,
        PublicErrorCode.MIGRATION_REQUIRED,
        PublicErrorCode.SERVICE_UNAVAILABLE,
        PublicErrorCode.VAULT_LOCKED,
        PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
    }
)
_PROVIDER_CODES: frozenset[PublicErrorCode] = frozenset(
    {
        PublicErrorCode.PROVIDER_UNAVAILABLE,
        PublicErrorCode.PROVIDER_REFUSED,
        PublicErrorCode.PROVIDER_TIMEOUT,
        PublicErrorCode.SEMANTIC_RESULT_INVALID,
    }
)
_CANCELLATION_CODES: frozenset[PublicErrorCode] = frozenset({PublicErrorCode.CANCELLED})
_FALLBACK_CODES: frozenset[PublicErrorCode] = frozenset({PublicErrorCode.INTERNAL_ERROR})

_EXPECTED_EXIT_CODES: dict[PublicErrorCode, int] = {
    PublicErrorCode.INVALID_REQUEST: 2,
    PublicErrorCode.PROTOCOL_VERSION_UNSUPPORTED: 20,
    PublicErrorCode.SESSION_NOT_FOUND: 10,
    PublicErrorCode.SESSION_CONFLICT: 10,
    PublicErrorCode.IDEMPOTENCY_CONFLICT: 10,
    PublicErrorCode.REQUEST_IDENTITY_CONFLICT: 10,
    PublicErrorCode.OPERATION_PENDING: 11,
    PublicErrorCode.FRONTIER_CONFLICT: 10,
    PublicErrorCode.EVENT_INVALID: 2,
    PublicErrorCode.LIMIT_EXCEEDED: 2,
    PublicErrorCode.BUNDLE_BUSY: 20,
    PublicErrorCode.STORAGE_UNSAFE: 20,
    PublicErrorCode.STORAGE_CORRUPT: 40,
    PublicErrorCode.MIGRATION_REQUIRED: 20,
    PublicErrorCode.SERVICE_UNAVAILABLE: 20,
    PublicErrorCode.VAULT_LOCKED: 20,
    PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED: 20,
    PublicErrorCode.PROVIDER_UNAVAILABLE: 30,
    PublicErrorCode.PROVIDER_REFUSED: 30,
    PublicErrorCode.PROVIDER_TIMEOUT: 30,
    PublicErrorCode.SEMANTIC_RESULT_INVALID: 30,
    PublicErrorCode.CANCELLED: 130,
    PublicErrorCode.INTERNAL_ERROR: 70,
}

# The exact closed set of public codes each six-operation module and its status classifier
# is known to raise. A module
# widening this set (inventing a new mapping) or narrowing it silently both fail this lock.
_MODULE_CODE_INVENTORY: dict[str, frozenset[PublicErrorCode]] = {
    "start.py": frozenset(
        {
            PublicErrorCode.BUNDLE_BUSY,
            PublicErrorCode.INVALID_REQUEST,
            PublicErrorCode.OPERATION_PENDING,
            PublicErrorCode.SERVICE_UNAVAILABLE,
            PublicErrorCode.SESSION_CONFLICT,
            PublicErrorCode.SESSION_NOT_FOUND,
            PublicErrorCode.STORAGE_CORRUPT,
            PublicErrorCode.STORAGE_UNSAFE,
        }
    ),
    "publish_work.py": frozenset(
        {
            PublicErrorCode.EVENT_INVALID,
            PublicErrorCode.FRONTIER_CONFLICT,
            PublicErrorCode.IDEMPOTENCY_CONFLICT,
            PublicErrorCode.INVALID_REQUEST,
            PublicErrorCode.LIMIT_EXCEEDED,
            PublicErrorCode.OPERATION_PENDING,
            PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
            PublicErrorCode.SESSION_CONFLICT,
            PublicErrorCode.STORAGE_CORRUPT,
        }
    ),
    "check.py": frozenset(
        {
            PublicErrorCode.INTERNAL_ERROR,
            PublicErrorCode.OPERATION_PENDING,
            PublicErrorCode.SESSION_CONFLICT,
            PublicErrorCode.STORAGE_CORRUPT,
        }
    ),
    "respond.py": frozenset(
        {
            PublicErrorCode.FRONTIER_CONFLICT,
            PublicErrorCode.IDEMPOTENCY_CONFLICT,
            PublicErrorCode.INVALID_REQUEST,
            PublicErrorCode.OPERATION_PENDING,
            PublicErrorCode.SESSION_CONFLICT,
            PublicErrorCode.STORAGE_CORRUPT,
        }
    ),
    "status.py": frozenset(
        {
            PublicErrorCode.FRONTIER_CONFLICT,
            PublicErrorCode.INVALID_REQUEST,
            PublicErrorCode.SERVICE_UNAVAILABLE,
            PublicErrorCode.SESSION_CONFLICT,
        }
    ),
    "status_faults.py": frozenset(
        {PublicErrorCode.INTERNAL_ERROR, PublicErrorCode.STORAGE_CORRUPT}
    ),
    "receipt.py": frozenset(
        {
            PublicErrorCode.FRONTIER_CONFLICT,
            PublicErrorCode.IDEMPOTENCY_CONFLICT,
            PublicErrorCode.INVALID_REQUEST,
            PublicErrorCode.LIMIT_EXCEEDED,
            PublicErrorCode.OPERATION_PENDING,
            PublicErrorCode.SESSION_CONFLICT,
            PublicErrorCode.STORAGE_CORRUPT,
            PublicErrorCode.STORAGE_UNSAFE,
        }
    ),
}


def _application_source(name: str) -> str:
    return (_APPLICATION_SRC / name).read_text(encoding="utf-8")


def _referenced_codes(source: str) -> frozenset[PublicErrorCode]:
    names = frozenset(re.findall(r"PublicErrorCode\.([A-Z_]+)", source))
    return frozenset(PublicErrorCode[name] for name in names)


def _call_windows(source: str, code_name: str) -> tuple[str, ...]:
    """Return the exact ``(...)`` call slice around each ``PublicErrorCode.<code_name>`` use."""

    windows: list[str] = []
    needle = f"PublicErrorCode.{code_name}"
    search_from = 0
    while True:
        index = source.find(needle, search_from)
        if index < 0:
            break
        call_start = source.rfind("(", 0, index)
        assert call_start >= 0
        depth = 1
        cursor = call_start + 1
        while depth > 0 and cursor < len(source):
            if source[cursor] == "(":
                depth += 1
            elif source[cursor] == ")":
                depth -= 1
            cursor += 1
        if cursor <= index:
            # The token may be a comparison outside the call whose opening parenthesis happens to
            # precede it. It is not an error-construction window, and retrying from the closing
            # parenthesis would rediscover the same token forever.
            search_from = index + len(needle)
            continue
        windows.append(source[call_start:cursor])
        search_from = cursor
    return tuple(windows)


def _is_retryable_call(window: str) -> bool:
    return bool(re.search(r"retryable\s*=\s*True", window)) or bool(
        re.search(r",\s*True\s*,?\s*\)\s*$", window)
    )


def test_known_failure_families_map_to_expected_public_codes() -> None:
    families = (
        _VALIDATION_CODES,
        _FRONTIER_CODES,
        _STORAGE_CODES,
        _PROVIDER_CODES,
        _CANCELLATION_CODES,
        _FALLBACK_CODES,
    )
    union: set[PublicErrorCode] = set()
    for family in families:
        assert union.isdisjoint(family), "failure classes must not overlap"
        union |= family
    assert union == set(PublicErrorCode), "every public code belongs to exactly one class"
    assert sum(len(family) for family in families) == len(PublicErrorCode)

    # The application facade never invents a new public error code: the CLI exit table is
    # exhaustive over the exact same closed enum, and this test freezes every exact exit value.
    assert set(PUBLIC_EXIT_CODES) == set(PublicErrorCode)
    assert dict(PUBLIC_EXIT_CODES) == _EXPECTED_EXIT_CODES
    for code, expected_exit in _EXPECTED_EXIT_CODES.items():
        assert exit_code_for(code) == expected_exit
    assert exit_code_for("success") == 0
    assert exit_code_for("cancelled") == 130

    # Each six-operation module raises only codes drawn from validation/frontier/storage/fallback;
    # a provider or cancellation code appearing here would mean a module invented a new mapping
    # instead of degrading gracefully (AI-powered review failure folds into ``incomplete_check`` and never
    # becomes a public error; cancellation propagates as ``asyncio.CancelledError``, not a code).
    allowed = _VALIDATION_CODES | _FRONTIER_CODES | _STORAGE_CODES | _FALLBACK_CODES
    for name, expected_codes in _MODULE_CODE_INVENTORY.items():
        actual_codes = _referenced_codes(_application_source(name))
        assert actual_codes == expected_codes, name
        assert actual_codes <= allowed, name
        assert actual_codes.isdisjoint(_PROVIDER_CODES | _CANCELLATION_CODES), name


def test_retryability_tracks_operation_state() -> None:
    # Retryable is a fact about durable operation state (an ambiguous append/commit that may
    # still resolve unchanged), never a guess about a crashed process. ``OPERATION_PENDING`` is
    # always retryable across every operation that can observe it, while an outright conflict or
    # corruption is never retryable: retrying would not change the durable outcome.
    for name in ("publish_work.py", "respond.py", "receipt.py", "check.py"):
        source = _application_source(name)
        pending_windows = _call_windows(source, "OPERATION_PENDING")
        assert pending_windows, name
        for window in pending_windows:
            assert _is_retryable_call(window), (name, window)

    for name in ("publish_work.py", "respond.py", "receipt.py"):
        source = _application_source(name)
        for code_name in ("IDEMPOTENCY_CONFLICT", "STORAGE_CORRUPT"):
            for window in _call_windows(source, code_name):
                assert not _is_retryable_call(window), (name, code_name, window)

    receipt_unsafe = _call_windows(_application_source("receipt.py"), "STORAGE_UNSAFE")
    assert receipt_unsafe
    for window in receipt_unsafe:
        assert _is_retryable_call(window), window

    for name in ("check.py", "status.py", "start.py"):
        source = _application_source(name)
        for window in _call_windows(source, "STORAGE_CORRUPT"):
            assert not _is_retryable_call(window), (name, window)

    # status is a read-only projection: its bounded error helper hardcodes ``retryable=False``
    # for every code, so no ``status`` failure can ever claim the operation may continue. START's
    # storage-unsafe result-object replay path is the one intentional retryable exception.
    assert "retryable=True" not in _application_source("status.py")
    start_unsafe = _call_windows(_application_source("start.py"), "STORAGE_UNSAFE")
    assert start_unsafe
    for window in start_unsafe:
        assert _is_retryable_call(window), window


def test_safe_details_stay_bounded() -> None:
    hostile_payload = {
        "count": 3,
        "limit": True,  # bool is not int; must be rejected even though bool subclasses int
        "reason_code": "invalid_utf8",
        "quarantine_code": "operation_lease_shape_invalid",
        "quarantine_code_bad": "DROP TABLE users;",
        "field": "/response/disposition",
        "schema_name": "start-request",
        "actual_version": "1.0.0",
        "method": ControlMethod.RESPOND,
        "operation": PublicErrorCode.INVALID_REQUEST,  # enum value is upper snake, must be dropped
        "sql_statement": "DROP TABLE users; -- not an allowlisted key",
        "secret": "sk-super-secret-token",
        "raw_payload": {"nested": "content that must never leak"},
    }

    normalized = normalize_safe_details(hostile_payload)

    assert dict(normalized) == {
        "count": 3,
        "reason_code": "invalid_utf8",
        "quarantine_code": "operation_lease_shape_invalid",
        "field": "/response/disposition",
        "schema_name": "start-request",
        "actual_version": "1.0.0",
        "method": "respond",
    }
    assert set(normalized) <= set(SAFE_DETAIL_KEYS)
    assert all(type(value) in (str, int) for value in normalized.values())
    assert all(type(value) is not bool for value in normalized.values())
    with pytest.raises(TypeError):
        normalized["method"] = "tampered"  # type: ignore[index]

    # Only registered reason codes survive; free text never reaches the wire.
    assert "reason_code" not in normalize_safe_details({"reason_code": "not_a_real_reason"})
    assert "invalid_utf8" in PROTOCOL_REASON_CODES

    # A hostile mapping (raises on lookup, spoofs its own class) degrades to the bounded empty
    # mapping rather than raising or leaking partial state.
    class _RaisingMapping(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            raise RuntimeError(f"boom for {key!r}")

        def __iter__(self) -> Iterator[str]:
            return iter(())

        def __len__(self) -> int:
            return 0

    assert dict(normalize_safe_details(_RaisingMapping())) == {}
    assert dict(normalize_safe_details(None)) == {}
    assert dict(normalize_safe_details("not-a-mapping")) == {}
    assert dict(normalize_safe_details([("count", 1)])) == {}

    # The public exception itself only ever exposes the same bounded, safe mapping.
    error = PublicOperationError(
        PublicErrorCode.INVALID_REQUEST,
        "The request is invalid.",
        False,
        safe_details=hostile_payload,
    )
    assert dict(error.safe_details) == dict(normalized)
    bound = error.bind_correlation_id("err_00000000-0000-4000-8000-000000000001")
    public = bound.as_public_dict()
    assert public["safe_details"] == dict(normalized)
    assert "sql_statement" not in public["safe_details"]  # type: ignore[operator]
    assert "secret" not in public["safe_details"]  # type: ignore[operator]


def test_last_resort_fallback_is_constructible() -> None:
    # The last-resort fallback is a plain, direct construction of the frozen exception with
    # literal values; it does not call any per-module ``_error`` factory or other helper, and it
    # must still succeed even when arbitrary/hostile detail input is supplied.
    correlation_id = "err_00000000-0000-4000-8000-00000000000a"
    fallback = PublicOperationError(
        PublicErrorCode.INTERNAL_ERROR,
        "An internal error occurred.",
        False,
        correlation_id=correlation_id,
        safe_details=None,
    )
    assert fallback.code is PublicErrorCode.INTERNAL_ERROR
    assert fallback.message == "An internal error occurred."
    assert fallback.retryable is False
    assert fallback.correlation_id == correlation_id
    assert fallback.safe_details == {}
    assert fallback.as_public_dict() == {
        "code": "INTERNAL_ERROR",
        "message": "An internal error occurred.",
        "retryable": False,
        "correlation_id": correlation_id,
    }
    assert str(fallback) == "An internal error occurred."
    assert fallback.args == ("An internal error occurred.",)

    class _ExplodingMapping(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            raise RuntimeError("helper code is broken")

        def __iter__(self) -> Iterator[str]:
            return iter(())

        def __len__(self) -> int:
            return 0

    # Even a fully broken/hostile detail source cannot block the fallback from validating.
    broken_helper_fallback = PublicOperationError(
        PublicErrorCode.INTERNAL_ERROR,
        "An internal error occurred.",
        False,
        safe_details=_ExplodingMapping(),
    )
    assert broken_helper_fallback.safe_details == {}

    with pytest.raises(TypeError):
        PublicOperationError("INTERNAL_ERROR", "wrong type", False)  # type: ignore[arg-type]
    with pytest.raises(ProtocolValueError):
        PublicOperationError(PublicErrorCode.INTERNAL_ERROR, "", False)

    # Public errors are always raised as exceptions and are never smuggled into a workflow result.
    result_members = get_args(ProjectedControlBody.__value__)
    assert PublicOperationError not in result_members
