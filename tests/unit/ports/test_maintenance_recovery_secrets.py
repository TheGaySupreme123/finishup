"""Typed portable-recovery acquisition authority tests."""

from __future__ import annotations

import inspect
from typing import get_type_hints

import pytest

from finishup.domain.values import request_id
from finishup.ports.keys import RecoverySecret
from finishup.ports.maintenance import (
    RecoveryOperation,
    RecoverySecretAcquirer,
    RecoverySecretAcquisition,
)

_REQUEST_ID = "req_00000000-0000-4000-8000-000000000001"
_PLAN_DIGEST = f"sha256:{'a' * 64}"


def test_recovery_secret_acquisition_freezes_exact_confirmed_binding() -> None:
    acquisition = RecoverySecretAcquisition(
        request_id=request_id(_REQUEST_ID),
        confirmed_plan_digest=_PLAN_DIGEST,
        service_generation=7,
        operation=RecoveryOperation.CREATE,
    )

    assert acquisition.request_id == _REQUEST_ID
    assert acquisition.confirmed_plan_digest == _PLAN_DIGEST
    assert acquisition.service_generation == 7
    assert acquisition.operation is RecoveryOperation.CREATE
    assert not hasattr(acquisition, "secret")
    assert not hasattr(acquisition, "source")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", "not-a-request-id"),
        ("confirmed_plan_digest", "not-a-digest"),
        ("service_generation", 0),
        ("operation", "create"),
    ],
)
def test_recovery_secret_acquisition_rejects_untyped_or_unbound_fields(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "request_id": _REQUEST_ID,
        "confirmed_plan_digest": _PLAN_DIGEST,
        "service_generation": 7,
        "operation": RecoveryOperation.RESTORE,
    }
    values[field] = value

    with pytest.raises((TypeError, ValueError)):
        RecoverySecretAcquisition(**values)  # type: ignore[arg-type]


def test_recovery_secret_acquirer_surface_is_typed_and_least_authority() -> None:
    method = inspect.signature(RecoverySecretAcquirer.acquire_recovery_secret)
    assert tuple(method.parameters) == ("self", "acquisition")

    hints = get_type_hints(RecoverySecretAcquirer.acquire_recovery_secret)
    assert hints == {
        "acquisition": RecoverySecretAcquisition,
        "return": RecoverySecret,
    }
