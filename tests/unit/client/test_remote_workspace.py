"""What the network API's workspace agent claims, runs and delivers (ADR-051, approach C).

``client.remote_workspace`` is the one place approach C asks the shared client side of workspace
remoting for its pieces: the claim under the target's own salt (the same claim a client process
sends, so both bind one handle), the real handler with the target root protected, and the
background delivery of captured observation over one claim-bound client kept between passes.
The connect seam's own claim (``service.client._remote_claim``) is covered here too.
"""

from __future__ import annotations

import base64
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from finishup.client.observation_outbox import ClientDrainSummary
from finishup.client.remote_workspace import (
    CapturedObservationDelivery,
    claim_for_workspace,
    claim_salt,
    handler_for_workspace,
)
from finishup.client.targets import ServerTarget, TargetError
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.client.workspace_claim import workspace_claim
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlError, WorkspaceClaim, WorkspaceLocator
from finishup.service import client as service_client
from finishup.service.client import ClientWorkspaceBinding

_SALT = b"\x07" * 32
_RECORD = ServerTarget(
    "t_0a1b2c3d",
    "lab",
    "https",
    "2026-11-05T00:00:00.000Z",
    base_url="https://api.test",
    claim_salt=base64.b64encode(_SALT).decode("ascii"),
    authorized_at="2026-11-05T00:00:00.000Z",
    disclosure_version=1,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _repository(path: Path) -> WorkspaceLocator:
    path.mkdir(parents=True, mode=0o700)
    subprocess.run(("git", "init", "-q", "-b", "main"), cwd=path, check=True)
    return WorkspaceLocator(str(path.resolve()))


@pytest.mark.anyio
async def test_the_agent_claims_a_workspace_exactly_as_a_client_process_does(
    tmp_path: Path,
) -> None:
    locator = _repository(tmp_path / "repo")
    claim = await claim_for_workspace(_RECORD, locator)
    assert claim == await workspace_claim(locator, _SALT)
    # A nested directory of the same repository claims the same workspace.
    (tmp_path / "repo" / "src").mkdir()
    nested = await claim_for_workspace(_RECORD, WorkspaceLocator(str(tmp_path / "repo" / "src")))
    assert nested == claim


@pytest.mark.anyio
async def test_an_unresolvable_workspace_has_no_claim_and_a_bad_salt_fails_closed(
    tmp_path: Path,
) -> None:
    missing = WorkspaceLocator(str(tmp_path / "missing"))
    assert await claim_for_workspace(_RECORD, missing) is None
    # A record whose salt is unusable never exists: it fails closed where it is read.
    with pytest.raises(TargetError) as raised:
        replace(_RECORD, claim_salt="not base64!")
    assert raised.value.reason == "target_record_invalid"
    assert claim_salt(_RECORD) == _SALT


def test_the_handler_protects_the_target_root(tmp_path: Path) -> None:
    locator = _repository(tmp_path / "repo")
    root = tmp_path / "target"
    handler = handler_for_workspace(locator, root)
    assert type(handler) is WorkspaceAgentHandler
    protected = handler._protected  # pyright: ignore[reportPrivateUsage]
    assert str(root) in protected


class _Client:
    def __init__(self, handle: str | None = "client:0011223344556677") -> None:
        self.workspace_handle = handle
        self.closed = False

    async def observation_ingest(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        raise AssertionError("no row is pending in these tests")

    async def close(self) -> None:
        self.closed = True


class _Drain:
    def __init__(self, *summaries: ClientDrainSummary) -> None:
        self.summaries = list(summaries)
        self.clients: list[object] = []
        self.closed = False

    async def drain(self, client: object) -> ClientDrainSummary:
        self.clients.append(client)
        return self.summaries.pop(0)

    def close(self) -> None:
        self.closed = True


@pytest.mark.anyio
async def test_the_delivery_keeps_one_client_and_reconnects_after_a_control_failure(
    tmp_path: Path,
) -> None:
    claim = WorkspaceClaim("git_common_root", "sha256:" + "a" * 64)
    connected: list[_Client] = []

    async def connect(value: WorkspaceClaim) -> _Client:
        assert value is claim
        client = _Client()
        connected.append(client)
        return client

    delivery = CapturedObservationDelivery(
        _RECORD, tmp_path, WorkspaceLocator(str(tmp_path)), claim, connect=connect
    )
    drain = _Drain(
        ClientDrainSummary(0, None, None),
        ClientDrainSummary(0, None, "service_unavailable"),
        ClientDrainSummary(0, None, None),
    )
    delivery._drain = drain  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage, reportAttributeAccessIssue]
    await delivery.deliver()
    await delivery.deliver()
    # One client served both passes; the failed pass released it.
    assert len(connected) == 1 and connected[0].closed
    await delivery.deliver()
    assert len(connected) == 2 and drain.clients == [connected[0], connected[0], connected[1]]
    await delivery.close()
    assert connected[1].closed and drain.closed


@pytest.mark.anyio
async def test_a_delivery_that_cannot_reach_the_server_leaves_the_rows(tmp_path: Path) -> None:
    claim = WorkspaceClaim("git_common_root", "sha256:" + "b" * 64)

    async def connect(_value: WorkspaceClaim) -> _Client:
        raise ControlError("service_unavailable", retryable=True, phase="remote_unreachable")

    delivery = CapturedObservationDelivery(
        _RECORD, tmp_path, WorkspaceLocator(str(tmp_path)), claim, connect=connect
    )
    assert await delivery.deliver() is None
    await delivery.close()


# --- the connect seam's claim ------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_seam_claims_a_locator_and_never_serves_on_the_call_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claim = WorkspaceClaim("git_common_root", "sha256:" + "c" * 64)
    seen: list[bool] = []

    async def binding_for(
        locator: WorkspaceLocator | None, *, serve_workspace: bool
    ) -> ClientWorkspaceBinding | None:
        del locator
        seen.append(serve_workspace)
        return ClientWorkspaceBinding(claim)

    monkeypatch.setattr("finishup.client.remote_binding.binding_for_active_root", binding_for)
    remote_claim = service_client._remote_claim  # pyright: ignore[reportPrivateUsage]
    assert await remote_claim(WorkspaceLocator("/home/me/repo"), None) is claim
    assert seen == [False]
    # A caller's own binding is used as given; no locator means no claim.
    other = WorkspaceClaim("directory", "sha256:" + "d" * 64)
    assert await remote_claim(None, ClientWorkspaceBinding(other)) is other
    assert await remote_claim(None, None) is None


@pytest.mark.anyio
async def test_the_seam_never_falls_back_to_a_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.adapters.workspace_root import RepositoryIdentityError

    async def unresolvable(
        locator: WorkspaceLocator | None, *, serve_workspace: bool
    ) -> ClientWorkspaceBinding | None:
        del locator, serve_workspace
        raise RepositoryIdentityError("repository_locator_unavailable")

    remote_claim = service_client._remote_claim  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr("finishup.client.remote_binding.binding_for_active_root", unresolvable)
    # No claim, and no path either: the requests name no workspace.
    assert await remote_claim(WorkspaceLocator("/home/me/repo"), None) is None

    async def unreadable(
        locator: WorkspaceLocator | None, *, serve_workspace: bool
    ) -> ClientWorkspaceBinding | None:
        del locator, serve_workspace
        raise TargetError("target_record_invalid")

    monkeypatch.setattr("finishup.client.remote_binding.binding_for_active_root", unreadable)
    with pytest.raises(ControlError) as raised:
        await remote_claim(WorkspaceLocator("/home/me/repo"), None)
    assert (raised.value.reason, raised.value.phase) == (
        "service_unavailable",
        "remote_unreachable",
    )
