"""``yoetz privacy receipts`` renders the real decoded receipt values (issue #731).

The CLI's one result converter had no ``datetime`` case, so every successfully stored receipt --
whose ``finished_at`` and ``dispatch_started_at`` are real ``datetime`` objects after the client
decodes the wire -- raised ``TypeError("cli_result_not_json")`` and exited 70 as
``internal_error``.  Both rendering branches convert before the machine/terminal split, so ``--json``
and ordinary rendering failed alike.

These cases drive the actual command coroutines over receipts decoded by the actual client
decoder, so nothing here can pass on a hand-built value the product never produces.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import datetime
from typing import Any, cast

import pytest
import typer
from tests.builders.privacy_receipts import (
    LOCAL_RECEIPT_ID,
    NETWORK_RECEIPT_ID,
    NOW,
    local_receipt_view,
    network_receipt_view,
)

from yoetz.application.privacy_control import (
    encode_privacy_receipt_page,
    encode_privacy_receipt_view,
)
from yoetz.cli import bootstrap
from yoetz.cli.app import (
    _privacy_receipts_get,  # pyright: ignore[reportPrivateUsage]
    _privacy_receipts_list,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.domain.privacy import ConsentSource, PrivacyOutcome, PrivacyReason, ReceiptCounts
from yoetz.domain.values import JsonObject, freeze_json
from yoetz.ports.control import ControlError
from yoetz.ports.privacy import NetworkEgressReceiptView, PrivacyReceiptPage, PrivacyReceiptView
from yoetz.protocol.canonical import JsonValue
from yoetz.service.client import (
    PrivacyReceiptGetResult,
    _receipt_get_from_wire,  # pyright: ignore[reportPrivateUsage]
    _receipt_page_from_wire,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_EXPECTED_TIMESTAMP = "2026-09-13T12:00:00.000Z"


def _decoded_get(view: PrivacyReceiptView) -> PrivacyReceiptGetResult:
    """Exactly what the CLI holds: the client's decode of the service's encoded receipt."""

    body = JsonObject(
        {
            "schema_version": "1.0.0",
            "outcome": "found",
            "receipt": cast(JsonValue, dict(encode_privacy_receipt_view(view))),
        }
    )
    return _receipt_get_from_wire(cast(JsonObject, freeze_json(body)))


def _decoded_page(*views: PrivacyReceiptView, next_cursor: str | None = None) -> PrivacyReceiptPage:
    page = PrivacyReceiptPage(11, views, next_cursor)
    return _receipt_page_from_wire(cast(JsonObject, freeze_json(encode_privacy_receipt_page(page))))


class _Client:
    def __init__(self, result: object) -> None:
        self._result = result
        self.closed = False

    async def privacy_receipts_get(self, _request: object) -> object:
        return self._result

    async def privacy_receipts_list(self, _request: object) -> object:
        return self._result

    async def close(self) -> None:
        self.closed = True


class _FailingClient(_Client):
    def __init__(self, error: ControlError) -> None:
        super().__init__(None)
        self._error = error

    async def privacy_receipts_get(self, _request: object) -> object:
        raise self._error

    async def privacy_receipts_list(self, _request: object) -> object:
        raise self._error


def _install(monkeypatch: pytest.MonkeyPatch, client: _Client) -> _Client:
    async def build(**_kwargs: object) -> _Client:
        return client

    monkeypatch.setattr("yoetz.cli.app.build_service_client", build)
    return client


def _captured_json(monkeypatch: pytest.MonkeyPatch) -> list[JsonValue]:
    emitted: list[JsonValue] = []
    monkeypatch.setattr("yoetz.cli.app._stdout_json", emitted.append)
    return emitted


class _TtyStdout:
    """A real terminal for the ordinary rendering branch, still captured by pytest."""

    def __init__(self, wrapped: object) -> None:
        self._wrapped = wrapped

    def isatty(self) -> bool:
        return True

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)


def _terminal_lines(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    lines: list[str] = []

    def echo(message: object = "", **_kwargs: object) -> None:
        lines.append(str(message))

    monkeypatch.setattr(sys, "stdout", _TtyStdout(sys.stdout))
    monkeypatch.setattr(typer, "echo", echo)
    return lines


async def test_json_get_renders_a_local_receipt_including_finished_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _install(monkeypatch, _Client(_decoded_get(local_receipt_view())))
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_get(LOCAL_RECEIPT_ID, True) == 0

    payload = cast(dict[str, Any], emitted[0])
    receipt = cast(dict[str, Any], cast(dict[str, Any], payload["receipt"])["receipt"])
    assert payload["outcome"] == "found"
    assert receipt["finished_at"] == _EXPECTED_TIMESTAMP
    assert receipt["purpose"] == "client_result_projection"
    assert client.closed is True


async def test_json_get_renders_a_network_receipt_including_dispatch_started_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _Client(_decoded_get(network_receipt_view())))
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_get(NETWORK_RECEIPT_ID, True) == 0

    receipt = cast(
        dict[str, Any], cast(dict[str, Any], cast(dict[str, Any], emitted[0])["receipt"])["receipt"]
    )
    assert receipt["finished_at"] == _EXPECTED_TIMESTAMP
    assert receipt["dispatch_started_at"] == _EXPECTED_TIMESTAMP
    assert receipt["counts"]["request_body_bytes"] == 1200
    assert receipt["safe_failure_reason"] is None


async def test_json_list_renders_every_timestamp_in_a_mixed_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _decoded_page(network_receipt_view(), local_receipt_view(), next_cursor="AAAA")
    _install(monkeypatch, _Client(page))
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_list(50, None, True) == 0

    payload = cast(dict[str, Any], emitted[0])
    receipts = cast(list[Any], payload["receipts"])
    assert payload["next_cursor"] == "AAAA"
    assert [cast(dict[str, Any], item)["kind"] for item in receipts] == [
        "network_egress",
        "local_disclosure",
    ]
    assert [
        cast(dict[str, Any], cast(dict[str, Any], item)["receipt"])["finished_at"]
        for item in receipts
    ] == [_EXPECTED_TIMESTAMP, _EXPECTED_TIMESTAMP]


async def test_json_list_of_an_empty_page_renders_without_a_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _Client(_decoded_page()))
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_list(50, None, True) == 0

    payload = cast(dict[str, Any], emitted[0])
    assert payload["receipts"] == []
    assert payload["next_cursor"] is None


@pytest.mark.parametrize(
    ("view", "receipt_id"),
    [(local_receipt_view(), LOCAL_RECEIPT_ID), (network_receipt_view(), NETWORK_RECEIPT_ID)],
    ids=["local", "network"],
)
async def test_ordinary_terminal_rendering_shows_the_same_timestamps(
    view: PrivacyReceiptView,
    receipt_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _Client(_decoded_get(view)))
    lines = _terminal_lines(monkeypatch)

    assert await _privacy_receipts_get(receipt_id, False) == 0

    rendered = cast(dict[str, Any], json.loads(lines[0]))
    receipt = cast(dict[str, Any], cast(dict[str, Any], rendered["receipt"])["receipt"])
    assert receipt["finished_at"] == _EXPECTED_TIMESTAMP


async def test_not_found_still_renders_the_bounded_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    not_found = _receipt_get_from_wire(
        cast(
            JsonObject, freeze_json(JsonObject({"schema_version": "1.0.0", "outcome": "not_found"}))
        )
    )
    _install(monkeypatch, _Client(not_found))
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_get(LOCAL_RECEIPT_ID, True) == 0

    assert emitted == [{"schema_version": "1.0.0", "outcome": "not_found"}]


async def test_a_control_refusal_stays_a_bounded_error_not_a_rendering_crash(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install(monkeypatch, _FailingClient(ControlError("vault_locked")))

    assert await _privacy_receipts_get(LOCAL_RECEIPT_ID, True) == 20

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("vault_locked: ")
    assert "Traceback" not in captured.err


async def test_a_list_refusal_stays_a_bounded_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install(monkeypatch, _FailingClient(ControlError("service_unavailable")))

    assert await _privacy_receipts_list(50, None, True) == 20

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("service_unavailable: ")


async def test_the_old_benchmark_error_line_is_gone_for_a_store_side_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue #921: ``invalid_request: the local request could not be completed`` named the
    caller for a request that had nothing wrong with it."""

    correlation_id = "err_70000000-0000-4000-8000-00000000000c"
    _install(
        monkeypatch,
        _FailingClient(ControlError("privacy_audit_unreadable", correlation_id=correlation_id)),
    )
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_list(100, None, True) == 40

    captured = capsys.readouterr()
    assert "invalid_request" not in captured.err
    assert captured.err.startswith(
        "privacy_audit_unreadable: the request was valid, but the local privacy audit holds a "
        f"receipt that could not be read back; correlation_id {correlation_id}\n"
    )
    assert "Continuation: privacy_audit_review" in captured.err
    assert emitted == [
        {
            "ok": False,
            "public_code": "STORAGE_CORRUPT",
            "reason": "privacy_audit_unreadable",
            "retryable": False,
            "correlation_id": correlation_id,
            "recovery": cast(dict[str, Any], emitted[0])["recovery"],
        }
    ]
    assert cast(dict[str, Any], emitted[0])["recovery"]["continuation"] == "privacy_audit_review"


async def test_a_partial_page_prints_every_readable_receipt_and_exits_non_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skipped = "egr_70000000-0000-4000-8000-00000000000d"
    page = _receipt_page_from_wire(
        cast(
            JsonObject,
            freeze_json(
                encode_privacy_receipt_page(
                    PrivacyReceiptPage(
                        11, (network_receipt_view(), local_receipt_view()), None, 2, (skipped,)
                    )
                )
            ),
        )
    )
    _install(monkeypatch, _Client(page))
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_list(100, None, True) == 40

    document = cast(dict[str, Any], emitted[0])
    assert [item["receipt"]["receipt_id"] for item in document["receipts"]] == [
        NETWORK_RECEIPT_ID,
        LOCAL_RECEIPT_ID,
    ]
    assert document["undecodable_count"] == 2
    assert document["undecodable_receipt_ids"] == [skipped]
    captured = capsys.readouterr()
    assert captured.err.startswith(
        "privacy_audit_unreadable: this page is partial; 2 stored receipt(s) could not be read "
        f"back and were skipped: {skipped}\n"
    )


async def test_a_complete_page_still_exits_zero_and_says_nothing_on_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install(monkeypatch, _Client(_decoded_page(network_receipt_view(), local_receipt_view())))
    emitted = _captured_json(monkeypatch)

    assert await _privacy_receipts_list(100, None, True) == 0

    assert cast(dict[str, Any], emitted[0])["undecodable_count"] == 0
    assert capsys.readouterr().err == ""


def test_the_converter_renders_canonical_timestamps_without_a_catch_all() -> None:
    """Bullet 2 of #731: the datetime case is typed; unsupported values still refuse."""

    assert bootstrap.plain_json(NOW) == _EXPECTED_TIMESTAMP

    with pytest.raises(TypeError, match="cli_result_not_json"):
        bootstrap.plain_json(object())


def test_a_non_canonical_timestamp_is_a_typed_refusal_not_an_invented_rendering() -> None:
    from yoetz.protocol.errors import ProtocolValueError

    with pytest.raises(ProtocolValueError):
        bootstrap.plain_json(datetime(2026, 9, 13, 12, 0))


def test_the_menu_shares_the_one_converter() -> None:
    """The byte-identical copy in ``cli/menu.py`` is why #731 had two homes."""

    from yoetz.cli import menu

    assert menu._plain(NOW) == _EXPECTED_TIMESTAMP  # pyright: ignore[reportPrivateUsage]


def _refused_network_view() -> PrivacyReceiptView:
    """A predispatch refusal whose classification still approved a category (#1019)."""

    view = network_receipt_view()
    assert isinstance(view, NetworkEgressReceiptView)
    receipt = replace(
        view.receipt,
        schema_version="1.1.0",
        outcome=PrivacyOutcome.BLOCKED_BY_POLICY,
        consent_source=ConsentSource.NONE,
        counts=ReceiptCounts(4, 0, 4, 4, 0, 900, 0, None, None),
        safe_failure_reason=PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT,
        authorization_id=None,
        dispatch_id=None,
        dispatch_started_at=None,
        request_commitment=None,
    )
    return NetworkEgressReceiptView("network_egress", receipt)


def _terminal_streams(monkeypatch: pytest.MonkeyPatch) -> tuple[list[str], list[str]]:
    out_lines: list[str] = []
    err_lines: list[str] = []

    def echo(message: object = "", *, err: bool = False, **_kwargs: object) -> None:
        (err_lines if err else out_lines).append(str(message))

    monkeypatch.setattr(sys, "stdout", _TtyStdout(sys.stdout))
    monkeypatch.setattr(typer, "echo", echo)
    return out_lines, err_lines


@pytest.mark.parametrize("command", ["get", "list"])
async def test_refused_receipt_labels_classification_approvals_as_not_sent(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    view = _refused_network_view()
    out, err = _terminal_streams(monkeypatch)
    if command == "get":
        _install(monkeypatch, _Client(_decoded_get(view)))
        assert await _privacy_receipts_get(NETWORK_RECEIPT_ID, False) == 0
    else:
        _install(monkeypatch, _Client(_decoded_page(view, local_receipt_view())))
        assert await _privacy_receipts_list(50, None, False) == 0
    assert '"approved_categories":["bounded_structural_metadata"]' in out[0]
    assert err == [
        f"not sent: privacy receipt {NETWORK_RECEIPT_ID} (blocked_by_policy) never reached a "
        "provider; its approved_categories and counts.approved_items are classification "
        "results, not data sent"
    ]


async def test_dispatched_and_json_receipts_carry_no_not_sent_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _out, err = _terminal_streams(monkeypatch)
    _install(monkeypatch, _Client(_decoded_page(network_receipt_view())))
    assert await _privacy_receipts_list(50, None, False) == 0
    _install(monkeypatch, _Client(_decoded_get(_refused_network_view())))
    _captured_json(monkeypatch)
    assert await _privacy_receipts_get(NETWORK_RECEIPT_ID, True) == 0
    assert err == []
