"""Observation support refusals use valid, bounded control-channel reasons."""

from typing import cast

import pytest

from finishup.application.observation_control import build_observation_support_handlers
from finishup.ports.control import ControlError, ControlMethod
from finishup.ports.observation import ObservationPort


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "method",
    (
        ControlMethod.OBSERVATION_INGEST,
        ControlMethod.OBSERVATION_STATUS,
        ControlMethod.OBSERVATION_PAUSE,
        ControlMethod.OBSERVATION_RESUME,
        ControlMethod.OBSERVATION_REVOKE,
    ),
)
async def test_malformed_observation_requests_refuse_before_port_access(
    method: ControlMethod,
) -> None:
    handlers = build_observation_support_handlers(cast(ObservationPort, object()))
    with pytest.raises(ControlError) as rejected:
        await handlers[method](["malformed"])
    assert rejected.value.reason == "frame_invalid"
    assert rejected.value.retryable is False
