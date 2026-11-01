"""Public start contract checks at the application operation boundary."""

from __future__ import annotations

import pytest

from builders.start_application import start_composition, start_request
from finishup.application.start import execute_start
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio


async def test_attach_requires_route_identity_before_catalog_reservation() -> None:
    app, runtime, _, _ = start_composition()
    valid = start_request(801, mode="create_or_attach")
    request = valid.model_copy(update={"mode": "attach"})

    with pytest.raises(PublicOperationError) as failure:
        await execute_start(app, request)

    assert failure.value.code is PublicErrorCode.INVALID_REQUEST
    assert runtime.provisions == []


async def test_same_request_id_with_changed_public_input_is_idempotency_conflict() -> None:
    app, _, _, _ = start_composition()
    first = start_request(802, title="First title")
    changed = StartRequest.model_validate(
        {**first.model_dump(mode="json", exclude_none=True), "task_title": "Changed title"}
    )
    await execute_start(app, first)

    with pytest.raises(PublicOperationError) as failure:
        await execute_start(app, changed)

    assert failure.value.code is PublicErrorCode.IDEMPOTENCY_CONFLICT
