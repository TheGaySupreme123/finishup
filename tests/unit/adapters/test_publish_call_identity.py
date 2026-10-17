"""The host-owned identity of an id-less ``publish_work`` call (issue #1084, ADR-050 decision 2).

Each case pins one rule of the binding record the MCP bridge and the CLI share: what is bound,
what resumes, what is a new call, and what never crosses the file.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.cli.app as cli
from finishup.adapters.integrations.publish_call_identity import (
    PUBLISH_CALLS_DIRECTORY,
    RESUME_WINDOW_MS,
    PublishCallIdentities,
    PublishCallIdentityUnavailable,
    publish_call_commitment,
)
from finishup.protocol.ids import IdKind, is_valid_id
from finishup.protocol.models import PublishWorkRequest

_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"
_OTHER_WRITER = "wri_00000000-0000-4000-8000-000000000002"


def _body(statement: str = "Keep the adapter.", writer: str = _WRITER) -> dict[str, Any]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "session_id": _SESSION,
        "writer_id": writer,
        "event_drafts": [
            {
                "schema": {"name": "decision_recorded", "version": "1.0.0"},
                "payload": {
                    "statement": statement,
                    "rationale": "It covers the case.",
                    "authority": "harness:mcp",
                },
            }
        ],
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _entries(root: Path) -> list[dict[str, Any]]:
    path = root / PUBLISH_CALLS_DIRECTORY / "calls.json"
    if not path.exists():
        return []
    return cast(list[dict[str, Any]], json.loads(path.read_text())["entries"])


def test_only_an_idless_real_call_with_a_valid_route_is_bindable() -> None:
    assert publish_call_commitment(_body()) is not None
    assert publish_call_commitment({**_body(), "request_id": None}) is None
    assert publish_call_commitment({**_body(), "dry_run": True}) is None
    assert publish_call_commitment({**_body(), "session_id": "nope"}) is None
    assert publish_call_commitment([_body()]) is None
    scope, commitment = cast(tuple[str, str], publish_call_commitment(_body()))
    # Key order is not identity; content and route are.
    assert publish_call_commitment(dict(reversed(list(_body().items())))) == (scope, commitment)
    assert publish_call_commitment(_body("Other.")) != (scope, commitment)
    other = cast(tuple[str, str], publish_call_commitment(_body(writer=_OTHER_WRITER)))
    assert other[0] != scope


def test_the_record_holds_commitments_and_ids_only(tmp_path: Path) -> None:
    calls = PublishCallIdentities(state_root=tmp_path)
    binding = calls.bind(_body())
    raw = (tmp_path / PUBLISH_CALLS_DIRECTORY / "calls.json").read_text()
    for secret in (_SESSION, _WRITER, "Keep the adapter.", "harness:mcp"):
        assert secret not in raw
    (entry,) = _entries(tmp_path)
    assert entry["request_id"] == binding.request_id
    assert entry["state"] == "in_flight" and entry["pid"] == os.getpid()
    mode = (tmp_path / PUBLISH_CALLS_DIRECTORY).stat().st_mode & 0o777
    assert mode == 0o700
    assert (tmp_path / PUBLISH_CALLS_DIRECTORY / "calls.json").stat().st_mode & 0o777 == 0o600


def test_an_undelivered_call_resumes_once_and_a_delivered_one_never(tmp_path: Path) -> None:
    calls = PublishCallIdentities(state_root=tmp_path)
    first = calls.bind(_body())
    calls.settle(first, delivered=False)
    resumed = calls.bind(_body())
    assert resumed.resumed and resumed.request_id == first.request_id
    calls.settle(resumed, delivered=True)
    assert _entries(tmp_path) == []
    fresh = calls.bind(_body())
    assert not fresh.resumed and fresh.request_id != first.request_id
    assert is_valid_id(IdKind.REQUEST, fresh.request_id)


def test_a_delivered_call_drops_every_unresolved_call_of_its_writer(tmp_path: Path) -> None:
    """Only the writer's next publish can resume an unknown write; a later one starts fresh."""

    calls = PublishCallIdentities(state_root=tmp_path)
    lost = calls.bind(_body("Lost."))
    calls.settle(lost, delivered=False)
    other_writer = calls.bind(_body("Lost.", writer=_OTHER_WRITER))
    calls.settle(other_writer, delivered=False)
    later = calls.bind(_body("Later."))
    calls.settle(later, delivered=True)
    assert [entry["request_id"] for entry in _entries(tmp_path)] == [other_writer.request_id]
    assert calls.bind(_body("Lost.")).request_id != lost.request_id


def test_a_caller_sent_bound_id_settles_the_binding(tmp_path: Path) -> None:
    calls = PublishCallIdentities(state_root=tmp_path)
    lost = calls.bind(_body())
    calls.settle(lost, delivered=False)
    calls.settle_caller_identity(_body(), lost.request_id)
    assert _entries(tmp_path) == []


def test_an_unresolved_call_expires(tmp_path: Path) -> None:
    now = [10_000_000]
    calls = PublishCallIdentities(state_root=tmp_path, clock_ms=lambda: now[0])
    lost = calls.bind(_body())
    calls.settle(lost, delivered=False)
    now[0] += RESUME_WINDOW_MS + 1
    assert calls.bind(_body()).request_id != lost.request_id


def test_an_unwritable_record_refuses_the_binding(tmp_path: Path) -> None:
    blocked = tmp_path / "state"
    blocked.write_text("not a directory")
    with pytest.raises(PublishCallIdentityUnavailable):
        PublishCallIdentities(state_root=blocked).bind(_body())
    with pytest.raises(PublishCallIdentityUnavailable):
        PublishCallIdentities(state_root=tmp_path).bind({**_body(), "dry_run": True})


def test_the_cli_binds_an_idless_body_like_the_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``finishup publish-work`` keeps the bridge's contract (issue #1084)."""

    import finishup.adapters.integrations.publish_call_identity as identity_module

    monkeypatch.setattr(identity_module, "state_dir", lambda: tmp_path)
    request, binding, calls = cli._publish_work_request(None, json.dumps(_body()))
    assert isinstance(request, PublishWorkRequest)
    assert binding is not None and calls is not None
    assert request.request_id == binding.request_id
    calls.settle(binding, delivered=False)
    again, resumed, _calls = cli._publish_work_request(None, json.dumps(_body()))
    assert resumed is not None and resumed.resumed
    assert cast(PublishWorkRequest, again).request_id == binding.request_id

    preview, unbound, _ = cli._publish_work_request(
        None, json.dumps({**_body("Preview."), "dry_run": True})
    )
    assert unbound is None
    assert is_valid_id(IdKind.REQUEST, cast(PublishWorkRequest, preview).request_id)

    explicit_id = "req_00000000-0000-4000-8000-000000000777"
    explicit, none, _ = cli._publish_work_request(
        None, json.dumps({**_body("Explicit."), "request_id": explicit_id})
    )
    assert none is None and cast(PublishWorkRequest, explicit).request_id == explicit_id
