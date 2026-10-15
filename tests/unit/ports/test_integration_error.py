"""IntegrationError stays frozen yet propagates through a contextmanager unmasked."""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Generator

import pytest

from finishup.ports.integrations import IntegrationError, IntegrationReason


@contextlib.contextmanager
def _passthrough() -> Generator[None]:
    yield


def test_error_raised_through_a_contextmanager_is_not_masked() -> None:
    # Python 3.14 contextlib assigns ``exc.__traceback__``; a frozen dataclass exception used to
    # turn that into FrozenInstanceError and hide the real reason.
    with pytest.raises(IntegrationError) as caught, _passthrough():
        raise IntegrationError(IntegrationReason.SOURCE_INVALID, {})
    assert caught.value.reason is IntegrationReason.SOURCE_INVALID


def test_error_fields_stay_frozen_and_equality_is_by_value() -> None:
    error = IntegrationError(IntegrationReason.SOURCE_INVALID, {"a": 1})
    with pytest.raises(dataclasses.FrozenInstanceError):
        error.reason = IntegrationReason.VERSION_INCOMPATIBLE  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        error.safe_details = {}  # type: ignore[misc]
    assert error == IntegrationError(IntegrationReason.SOURCE_INVALID, {"a": 1})
    assert str(error) == IntegrationReason.SOURCE_INVALID.value
