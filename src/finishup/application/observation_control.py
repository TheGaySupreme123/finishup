"""Ordinary-control support handlers for ObservationPort / ObservationCoordinator."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Protocol, cast

from finishup.domain.observation import (
    ObservationControlCommand,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationRevokeCommand,
    ObservationStatus,
    ObservationStatusQuery,
    observation_control_command_from_json,
    observation_envelope_from_json,
    observation_ingest_request_from_json,
    observation_ingest_result_to_json,
    observation_revoke_command_from_json,
    observation_status_query_from_json,
    observation_status_to_json,
)
from finishup.domain.values import JsonObject, freeze_json
from finishup.ports.control import ControlError, ControlMethod
from finishup.ports.observation import ObservationPort
from finishup.protocol.errors import ProtocolValueError, PublicOperationError

__all__ = ["ObservationIngestPort", "build_observation_support_handlers"]

type _SupportHandler = Callable[[object], Awaitable[JsonObject]]


class ObservationIngestPort(Protocol):
    """Port or coordinator that accepts redacted ObservationIngestRequest bodies."""

    async def ingest_request(
        self, request: ObservationIngestRequest
    ) -> ObservationIngestResult: ...

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus: ...

    async def pause(self, command: ObservationControlCommand) -> ObservationStatus: ...

    async def resume(self, command: ObservationControlCommand) -> ObservationStatus: ...

    async def revoke(self, command: ObservationRevokeCommand) -> ObservationStatus: ...


def _as_json_object(request: object) -> JsonObject:
    try:
        normalized = freeze_json(request)
    except ProtocolValueError as exc:
        raise ControlError("frame_invalid") from exc
    if type(normalized) is not JsonObject:
        raise ControlError("frame_invalid")
    return normalized


def _support_argument(request: object, *, field: str) -> tuple[JsonObject, str | None]:
    """Accept the versioned control body while retaining the direct app-port shape.

    The daemon validates the outer ``*_body`` schema before invoking the application.  Direct
    application callers historically pass the nested query/command itself, so keep that port
    useful while unwrapping the schema-owned envelope at the support boundary.
    """

    body = _as_json_object(request)
    if field not in body:
        if "schema_version" in body or "request_id" in body:
            raise ControlError("frame_invalid")
        return body, None
    if set(body) != {"schema_version", "request_id", field}:
        raise ControlError("frame_invalid")
    if body.get("schema_version") != "1.0.0":
        raise ControlError("frame_invalid")
    request_id = body.get("request_id")
    if type(request_id) is not str:
        raise ControlError("frame_invalid")
    return _as_json_object(body[field]), request_id


def _support_result(status: ObservationStatus, *, request_id: str | None) -> JsonObject:
    result = observation_status_to_json(status)
    if request_id is None:
        return result
    return JsonObject(
        {
            "schema_version": "1.0.0",
            "request_id": request_id,
            "status": result,
        }
    )


def _map_public_error(error: PublicOperationError) -> ControlError:
    code = error.code.value.lower()
    if code in {"invalid_request", "session_conflict"}:
        return ControlError("frame_invalid", retryable=False)
    if code in {"service_unavailable", "vault_locked"}:
        return ControlError(code, retryable=error.retryable)
    return ControlError("internal_error", retryable=error.retryable)


def build_observation_support_handlers(
    port: ObservationPort | ObservationIngestPort,
) -> Mapping[ControlMethod, _SupportHandler]:
    """Bind the five observation_* control methods to one ObservationPort/coordinator."""

    async def ingest(request: object) -> JsonObject:
        body = _as_json_object(request)
        try:
            if "codex_session_id" in body and hasattr(port, "ingest_request"):
                ingest_request = observation_ingest_request_from_json(body)
                if type(ingest_request) is not ObservationIngestRequest:
                    raise ControlError("frame_invalid")
                result = await cast(ObservationIngestPort, port).ingest_request(ingest_request)
            else:
                envelope = observation_envelope_from_json(body)
                if type(envelope) is not ObservationEnvelope:
                    raise ControlError("frame_invalid")
                result = await cast(ObservationPort, port).ingest(envelope)
        except ProtocolValueError as exc:
            raise ControlError("frame_invalid") from exc
        except PublicOperationError as exc:
            raise _map_public_error(exc) from exc
        return observation_ingest_result_to_json(result)

    async def status(request: object) -> JsonObject:
        try:
            argument, request_id = _support_argument(request, field="query")
            query = observation_status_query_from_json(argument)
        except ProtocolValueError as exc:
            raise ControlError("frame_invalid") from exc
        if type(query) is not ObservationStatusQuery:
            raise ControlError("frame_invalid")
        try:
            result = await port.status(query)
        except PublicOperationError as exc:
            raise _map_public_error(exc) from exc
        return _support_result(result, request_id=request_id)

    async def pause(request: object) -> JsonObject:
        try:
            argument, request_id = _support_argument(request, field="command")
            command = observation_control_command_from_json(argument)
        except ProtocolValueError as exc:
            raise ControlError("frame_invalid") from exc
        if type(command) is not ObservationControlCommand:
            raise ControlError("frame_invalid")
        try:
            result = await port.pause(command)
        except PublicOperationError as exc:
            raise _map_public_error(exc) from exc
        return _support_result(result, request_id=request_id)

    async def resume(request: object) -> JsonObject:
        try:
            argument, request_id = _support_argument(request, field="command")
            command = observation_control_command_from_json(argument)
        except ProtocolValueError as exc:
            raise ControlError("frame_invalid") from exc
        if type(command) is not ObservationControlCommand:
            raise ControlError("frame_invalid")
        try:
            result = await port.resume(command)
        except PublicOperationError as exc:
            raise _map_public_error(exc) from exc
        return _support_result(result, request_id=request_id)

    async def revoke(request: object) -> JsonObject:
        try:
            argument, request_id = _support_argument(request, field="command")
            command = observation_revoke_command_from_json(argument)
        except ProtocolValueError as exc:
            raise ControlError("frame_invalid") from exc
        if type(command) is not ObservationRevokeCommand:
            raise ControlError("frame_invalid")
        try:
            result = await port.revoke(command)
        except PublicOperationError as exc:
            raise _map_public_error(exc) from exc
        return _support_result(result, request_id=request_id)

    return {
        ControlMethod.OBSERVATION_INGEST: ingest,
        ControlMethod.OBSERVATION_STATUS: status,
        ControlMethod.OBSERVATION_PAUSE: pause,
        ControlMethod.OBSERVATION_RESUME: resume,
        ControlMethod.OBSERVATION_REVOKE: revoke,
    }
