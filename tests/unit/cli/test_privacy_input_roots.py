"""``finishup privacy input-roots`` (issue #1082): admitting outside-workspace task inputs.

The way in (a trusted widening), the way out (a tightening that applies at once), the way to see
it, and the policy encoding that keeps every earlier policy's bytes and digest.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import finishup.cli.privacy_setup as setup
from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.application.privacy_policy import privacy_policy_changes
from finishup.cli.app import app
from finishup.domain.privacy import (
    MAX_ADMITTED_INPUT_ROOTS,
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ReviewContextProfile,
    ReviewSelectionPolicy,
    admitted_input_root_valid,
)
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import DataCategory

_INSTALLATION = "ins_10000000-0000-4000-8000-000000000001"
_REPOSITORY = "hmac-sha256:" + "4" * 64
_DIGEST = f"sha256:{'2' * 64}"
_AUTHORITY = f"sha256:{'3' * 64}"
_NOW = datetime(2026, 10, 16, tzinfo=UTC)


def _off(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel, False, (), (), None, (), AuthorizationScopeKind.MACHINE, False, 0, 0, 0
    )


def _policy(
    roots: tuple[str, ...] = (),
    scope: AuthorizationScopeKind = AuthorizationScopeKind.MACHINE,
) -> PrivacyPolicy:
    return PrivacyPolicy(
        "pvy_10000000-0000-4000-8000-000000000004",
        3,
        _DIGEST,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        False,
        AuthorizationScope(scope, _INSTALLATION)
        if scope is AuthorizationScopeKind.MACHINE
        else AuthorizationScope(scope, _INSTALLATION, _REPOSITORY),
        tuple(_off(channel) for channel in sorted(EgressChannel, key=lambda c: c.value)),
        False,
        None,
        (),
        (),
        (DataCategory.FINDING_SUMMARY,),
        (DataClass.ORDINARY_USER_CONTENT,),
        tuple(DataCategory),
        (DataClass.ORDINARY_USER_CONTENT,),
        _NOW,
        admitted_input_roots=roots,
    )


def _snapshot(policy: PrivacyPolicy, grant: str = "granted") -> setup.PrivacySetupSnapshot:
    return setup.PrivacySetupSnapshot(
        policy,
        JsonObject({"kind": "machine", "installation_id": _INSTALLATION}),
        _AUTHORITY,
        grant,  # pyright: ignore[reportArgumentType]
        "not_applicable",
    )


@pytest.fixture
def shared(tmp_path: Path) -> str:
    root = (tmp_path / "shared").resolve()
    root.mkdir()
    return os.fspath(root)


def test_roots_are_validated_sorted_and_bounded() -> None:
    for root in ("/shared", "/data/tasks/legacy_app", "/" + "Users/me/datasets"):
        assert admitted_input_root_valid(root), root
    for root in (
        "/",
        "shared",
        "/etc",
        "/etc/ssl",
        "/proc/1",
        "/dev",
        "/private/etc/hosts",
        "/shared/../etc",
        "/" + "home/me/.ssh",
        "/shared//x",
        "/with space",
    ):
        assert not admitted_input_root_valid(root), root
    policy = _policy(("/zeta", "/alpha"))
    assert policy.admitted_input_roots == ("/alpha", "/zeta")
    with pytest.raises(ValueError):
        _policy(("/a", "/a"))
    with pytest.raises(ValueError):
        _policy(tuple(f"/root{index}" for index in range(MAX_ADMITTED_INPUT_ROOTS + 1)))


def test_an_unset_field_keeps_every_earlier_policy_byte_for_byte() -> None:
    plain = encode_privacy_policy_json(_policy())
    assert "admitted_input_roots" not in plain
    with_roots = encode_privacy_policy_json(_policy(("/shared",)))
    assert with_roots["admitted_input_roots"] == ["/shared"]
    assert with_roots["schema_version"] == "1.2.0"
    decoded = decode_privacy_policy_canonical(canonical_encode(with_roots))
    assert decoded.admitted_input_roots == ("/shared",)
    # An older wire version cannot carry the field.
    older = dict(with_roots, schema_version="1.1.0")
    with pytest.raises(ValueError):
        decode_privacy_policy_canonical(canonical_encode(older))
    # A present but empty list is not canonical.
    empty: dict[str, JsonValue] = dict(with_roots, admitted_input_roots=[])
    with pytest.raises(ValueError):
        decode_privacy_policy_canonical(canonical_encode(empty))


def test_the_repository_grant_decides_the_roots_in_composition() -> None:
    machine = _policy(("/machine",))
    repository = _policy(("/shared",), AuthorizationScopeKind.WORKSPACE)
    assert machine.meet(repository).admitted_input_roots == ("/shared",)
    assert repository.meet(machine).admitted_input_roots == ("/shared",)
    assert _policy().meet(repository).admitted_input_roots == ("/shared",)
    # Any other composition keeps only what both admit.
    assert machine.meet(_policy(("/machine", "/x"))).admitted_input_roots == ("/machine",)
    assert machine.meet(_policy()).admitted_input_roots == ()
    # The composed digest names the roots only when there are some.
    assert (
        machine.meet(repository).policy_digest
        != machine.meet(replace(repository, admitted_input_roots=())).policy_digest
    )


def test_adding_a_root_is_a_widening_and_removing_it_a_tightening() -> None:
    current = _policy()
    added = setup.input_roots_candidate(current, ("/shared",), now=_NOW)
    assert added.version == current.version + 1
    assert added.supersedes_policy_digest == current.policy_digest
    changes = privacy_policy_changes(current, added)
    assert [(change.field, change.widens) for change in changes] == [("admitted_input_roots", True)]
    assert changes[0].after.labels == ("dir:/shared",)
    removed = setup.input_roots_candidate(added, (), now=_NOW)
    assert [(change.field, change.widens) for change in privacy_policy_changes(added, removed)] == [
        ("admitted_input_roots", False)
    ]


def test_a_root_must_be_an_existing_unlinked_directory(shared: str, tmp_path: Path) -> None:
    assert setup.admitted_root_from_path(shared) == shared
    assert setup.admitted_root_from_path(shared + "/") == shared
    (tmp_path / "file.txt").write_text("x\n", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(shared)
    for value in (
        "relative/dir",
        os.fspath(tmp_path / "missing"),
        os.fspath(tmp_path / "file.txt"),
        os.fspath(alias),
        "/etc",
        "/",
    ):
        assert setup.admitted_root_from_path(value) is None, value


def test_add_proposes_and_requires_the_trusted_decision(
    monkeypatch: pytest.MonkeyPatch, shared: str
) -> None:
    proposed: list[PrivacyPolicy] = []
    decided: list[str] = []

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy())

    async def propose(candidate: PrivacyPolicy, digest: str, **_: object) -> str:
        assert digest == _AUTHORITY
        proposed.append(candidate)
        return "ppr_10000000-0000-4000-8000-000000000009"

    async def decide(proposal_id: str) -> object:
        decided.append(proposal_id)
        return SimpleNamespace(status="committed")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", propose)
    monkeypatch.setattr(setup, "_decide", decide)
    report = asyncio.run(setup.run_input_root_change("add", shared))
    assert report.outcome == "configured"
    assert [policy.admitted_input_roots for policy in proposed] == [(shared,)]
    assert decided == ["ppr_10000000-0000-4000-8000-000000000009"]


def test_add_needs_a_terminal_a_grant_and_a_valid_root(
    monkeypatch: pytest.MonkeyPatch, shared: str
) -> None:
    async def granted(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy())

    async def missing(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy(), grant="missing")

    async def never(*_: object, **__: object) -> str:
        raise AssertionError("nothing may be proposed")

    monkeypatch.setattr(setup, "_propose", never)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", granted)
    monkeypatch.setattr(setup, "_interactive_terminal", lambda: False)
    report = asyncio.run(setup.run_input_root_change("add", shared))
    assert (report.outcome, report.reason) == ("failed", "local_terminal_required")
    monkeypatch.setattr(setup, "_interactive_terminal", lambda: True)
    report = asyncio.run(setup.run_input_root_change("add", "/etc"))
    assert (report.outcome, report.reason) == ("failed", "input_root_invalid")
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", missing)
    report = asyncio.run(setup.run_input_root_change("add", shared))
    assert (report.outcome, report.reason) == ("unchanged", "repository_privacy_grant_missing")


def test_remove_tightens_without_a_terminal(monkeypatch: pytest.MonkeyPatch, shared: str) -> None:
    proposed: list[PrivacyPolicy] = []

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy((shared,)))

    async def propose(candidate: PrivacyPolicy, digest: str, **_: object) -> None:
        proposed.append(candidate)
        return None

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: False)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", propose)
    report = asyncio.run(setup.run_input_root_change("remove", shared))
    assert report.outcome == "configured"
    assert [policy.admitted_input_roots for policy in proposed] == [()]
    unchanged = asyncio.run(setup.run_input_root_change("remove", "/never/admitted"))
    assert unchanged.outcome == "unchanged"


def test_cli_commands_add_remove_and_status(monkeypatch: pytest.MonkeyPatch, shared: str) -> None:
    calls: list[tuple[str, str]] = []

    async def change(action: str, value: str, **_: object) -> setup.PrivacySetupReport:
        calls.append((action, value))
        return setup.PrivacySetupReport("configured", "assisted_review", grant_state="granted")

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_policy((shared,)))

    monkeypatch.setattr(setup, "run_input_root_change", change)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    runner = CliRunner()
    added = runner.invoke(app, ["privacy", "input-roots", "add", shared, "--json"])
    removed = runner.invoke(app, ["privacy", "input-roots", "remove", shared, "--json"])
    status = runner.invoke(app, ["privacy", "input-roots", "status"])
    assert added.exit_code == 0 and '"outcome":"configured"' in added.output
    assert removed.exit_code == 0
    assert calls == [("add", shared), ("remove", shared)]
    assert status.exit_code == 0 and shared in status.output
