"""Legacy ``YOETZ_`` environment spellings next to ``FINISHUP_`` (ADR-048).

A legacy name is read only when its FinishUP twin is unset; both set to one value is the same
setting; both set to different values fails closed. The strict loader checks both spellings
against one allowlist and keeps refusing secret-shaped and unknown names under either prefix.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from finishup.config.env import (
    EnvNameConflictError,
    canonical_env_name,
    env_names,
    read_env,
)
from finishup.config.load import (
    environment_config_path,
    load_config,
    parse_minimal_safe_config,
)
from finishup.config.models import ConfigError
from finishup.mcp import server as mcp_server


def test_env_names_pair_the_finishup_and_legacy_spellings() -> None:
    assert env_names("PROFILE") == ("FINISHUP_PROFILE", "YOETZ_PROFILE")
    assert canonical_env_name("FINISHUP_PROFILE") == "FINISHUP_PROFILE"
    assert canonical_env_name("YOETZ_PROFILE") == "FINISHUP_PROFILE"
    assert canonical_env_name("_FINISHUP_TEST_INSTALLATION") is None
    assert canonical_env_name("PATH") is None


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({}, None),
        ({"FINISHUP_PROFILE": "test-fake"}, "test-fake"),
        ({"YOETZ_PROFILE": "test-fake"}, "test-fake"),
        ({"FINISHUP_PROFILE": "test-fake", "YOETZ_PROFILE": "test-fake"}, "test-fake"),
    ],
)
def test_read_env_prefers_finishup_and_falls_back_to_legacy(
    environ: dict[str, str], expected: str | None
) -> None:
    assert read_env("PROFILE", environ) == expected


def test_read_env_refuses_two_spellings_that_disagree() -> None:
    with pytest.raises(EnvNameConflictError) as caught:
        read_env("PROFILE", {"FINISHUP_PROFILE": "test-fake", "YOETZ_PROFILE": "strict-local"})
    assert caught.value.name == "FINISHUP_PROFILE"
    assert "test-fake" not in str(caught.value)
    assert "strict-local" not in str(caught.value)


def test_an_empty_finishup_value_does_not_silently_shadow_a_legacy_one() -> None:
    with pytest.raises(EnvNameConflictError):
        read_env("CONFIG", {"FINISHUP_CONFIG": "", "YOETZ_CONFIG": "/legacy/config.toml"})


def test_load_config_reads_a_legacy_only_variable(tmp_path: Path) -> None:
    config = load_config(
        {},
        {"YOETZ_PROFILE": "test-fake", "YOETZ_LOG_LEVEL": "warning"},
        tmp_path / "config.toml",
    )
    assert config.profile == "test-fake"
    assert config.logging.level == "warning"


def test_load_config_accepts_both_spellings_with_one_value(tmp_path: Path) -> None:
    config = load_config(
        {},
        {"FINISHUP_LOG_LEVEL": "error", "YOETZ_LOG_LEVEL": "error"},
        tmp_path / "config.toml",
    )
    assert config.logging.level == "error"


def test_load_config_refuses_both_spellings_with_different_values(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        load_config(
            {},
            {"FINISHUP_LOG_LEVEL": "error", "YOETZ_LOG_LEVEL": "debug"},
            tmp_path / "config.toml",
        )
    assert caught.value.reason_code == "config_env_conflict"
    assert caught.value.safe_name == "FINISHUP_LOG_LEVEL"


def test_the_finishup_spelling_alone_is_unchanged(tmp_path: Path) -> None:
    config = load_config({}, {"FINISHUP_LOG_LEVEL": "debug"}, tmp_path / "config.toml")
    assert config.logging.level == "debug"


@pytest.mark.parametrize("name", ["YOETZ_PROVIDER_API_KEY", "FINISHUP_PROVIDER_API_KEY"])
def test_secret_shaped_names_are_refused_under_either_prefix(name: str) -> None:
    with pytest.raises(ConfigError) as caught:
        load_config({}, {name: "never-read"}, None)
    assert caught.value.reason_code == "secret_env_forbidden"
    assert caught.value.safe_name == name


@pytest.mark.parametrize("name", ["YOETZ_UNRELATED_SETTING", "FINISHUP_UNRELATED_SETTING"])
def test_unknown_names_are_refused_under_either_prefix(name: str) -> None:
    with pytest.raises(ConfigError) as caught:
        parse_minimal_safe_config({name: "x"}, {})
    assert caught.value.reason_code == "unknown_config_env_var"
    assert caught.value.safe_name == name


def test_minimal_parse_follows_the_legacy_data_dir_and_config(tmp_path: Path) -> None:
    config_path = tmp_path / "legacy.toml"
    config_path.write_text('profile = "test-fake"\n', encoding="utf-8")
    minimal = parse_minimal_safe_config(
        {
            "YOETZ_CONFIG": str(config_path),
            "YOETZ_STORAGE_DATA_DIR": str(tmp_path / "data"),
        },
        {},
    )
    assert minimal.profile == "test-fake"
    assert minimal.data_dir == tmp_path / "data"
    assert minimal.config_path_used == config_path


def test_minimal_parse_refuses_conflicting_storage_roots(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        parse_minimal_safe_config(
            {
                "FINISHUP_STORAGE_DATA_DIR": str(tmp_path / "new"),
                "YOETZ_STORAGE_DATA_DIR": str(tmp_path / "old"),
            },
            {},
        )
    assert caught.value.reason_code == "config_env_conflict"


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({}, None),
        ({"FINISHUP_CONFIG": "/new/config.toml"}, Path("/new/config.toml")),
        ({"YOETZ_CONFIG": "/old/config.toml"}, Path("/old/config.toml")),
        (
            {"FINISHUP_CONFIG": "/one/config.toml", "YOETZ_CONFIG": "/one/config.toml"},
            Path("/one/config.toml"),
        ),
    ],
)
def test_environment_config_path_reads_either_spelling(
    environ: dict[str, str], expected: Path | None
) -> None:
    assert environment_config_path(environ) == expected


def test_environment_config_path_refuses_two_different_files() -> None:
    with pytest.raises(ConfigError) as caught:
        environment_config_path({"FINISHUP_CONFIG": "/new.toml", "YOETZ_CONFIG": "/old.toml"})
    assert caught.value.reason_code == "config_env_conflict"
    assert caught.value.safe_name == "FINISHUP_CONFIG"


def test_every_mcp_deadline_variable_is_known_to_the_strict_loader(tmp_path: Path) -> None:
    tools = sorted(mcp_server._DEFAULT_RPC_DEADLINES_MS)  # pyright: ignore[reportPrivateUsage]
    names = ["MCP_DEADLINE_MS", *(f"MCP_DEADLINE_MS_{tool.upper()}" for tool in tools)]
    for prefix in ("FINISHUP_", "YOETZ_"):
        environ = {prefix + name: "60000" for name in names}
        config = load_config({}, environ, tmp_path / "config.toml")
        assert config.profile == "strict-local"


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({"YOETZ_MCP_DEADLINE_MS_STATUS": "45000"}, 45_000),
        ({"FINISHUP_MCP_DEADLINE_MS_STATUS": "45000"}, 45_000),
        (
            {"FINISHUP_MCP_DEADLINE_MS_STATUS": "45000", "YOETZ_MCP_DEADLINE_MS_STATUS": "45000"},
            45_000,
        ),
    ],
)
def test_mcp_deadlines_read_the_legacy_spelling(
    environ: dict[str, str], expected: int | None
) -> None:
    default = mcp_server._DEFAULT_RPC_DEADLINES_MS["status"]  # pyright: ignore[reportPrivateUsage]
    deadline = mcp_server._rpc_deadline_ms("status", environ)  # pyright: ignore[reportPrivateUsage]
    assert deadline == (default if expected is None else expected)


@pytest.mark.parametrize("global_override", [None, "30000"])
def test_conflicting_deadline_spellings_never_fall_back(global_override: str | None) -> None:
    environ = {
        "FINISHUP_MCP_DEADLINE_MS_STATUS": "45000",
        "YOETZ_MCP_DEADLINE_MS_STATUS": "2000",
    }
    if global_override is not None:
        environ["YOETZ_MCP_DEADLINE_MS"] = global_override
    with pytest.raises(ConfigError) as caught:
        mcp_server._rpc_deadline_ms("status", environ)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason_code == "config_env_conflict"
    assert caught.value.safe_name == "FINISHUP_MCP_DEADLINE_MS_STATUS"


@pytest.mark.parametrize("tool", ["status", "check"])
@pytest.mark.parametrize("per_tool_override", [None, "45000"])
def test_a_per_tool_override_does_not_hide_a_global_deadline_conflict(
    tool: str, per_tool_override: str | None
) -> None:
    environ = {
        "FINISHUP_MCP_DEADLINE_MS": "30000",
        "YOETZ_MCP_DEADLINE_MS": "2000",
    }
    if per_tool_override is not None:
        environ[f"FINISHUP_MCP_DEADLINE_MS_{tool.upper()}"] = per_tool_override
    with pytest.raises(ConfigError):
        mcp_server._rpc_deadline_ms(  # pyright: ignore[reportPrivateUsage]
            tool, environ
        )


@pytest.mark.parametrize("per_tool_override", [None, "45000"])
def test_an_agreed_global_deadline_does_not_control_a_writing_check(
    per_tool_override: str | None,
) -> None:
    environ = {"FINISHUP_MCP_DEADLINE_MS": "2000", "YOETZ_MCP_DEADLINE_MS": "2000"}
    expected = mcp_server._DEFAULT_RPC_DEADLINES_MS["check"]  # pyright: ignore[reportPrivateUsage]
    if per_tool_override is not None:
        environ["FINISHUP_MCP_DEADLINE_MS_CHECK"] = per_tool_override
        expected = int(per_tool_override)
    assert mcp_server._rpc_deadline_ms("check", environ) == expected  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("operation", "mode", "suffix"),
    [
        ("start", None, "MCP_DEADLINE_MS_START"),
        ("start", None, "MCP_DEADLINE_MS"),
        ("status", None, "MCP_DEADLINE_MS_STATUS"),
        ("check", "inspect", "MCP_DEADLINE_MS_STATUS"),
        ("check", "deterministic_only", "MCP_DEADLINE_MS_CHECK"),
        ("check", "deterministic_only", "MCP_DEADLINE_MS"),
        ("closure_prepare", None, "MCP_DEADLINE_MS_STATUS"),
        ("publish_work", None, "MCP_DEADLINE_MS_PUBLISH_WORK"),
    ],
)
async def test_mcp_refuses_deadline_conflicts_before_reaching_a_service(
    monkeypatch: pytest.MonkeyPatch, operation: str, mode: str | None, suffix: str
) -> None:
    monkeypatch.setenv("FINISHUP_" + suffix, "45000")
    monkeypatch.setenv("YOETZ_" + suffix, "2000")
    reached: list[str] = []

    async def invoke(*_args: object, **_kwargs: object) -> object:
        reached.append("service")
        raise AssertionError("must not connect, spawn, or invoke under ambiguous configuration")

    monkeypatch.setattr(mcp_server, "_invoke_with_reconnect", invoke)
    monkeypatch.setattr(mcp_server, "_publish_recovery_from_envelope", invoke)
    arguments: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000048",
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create",
        "task_title": "Environment conflict probe",
        "requested_view": "compact",
    }
    if operation != "start":
        for name in ("mode", "task_title", "requested_view"):
            arguments.pop(name)
        arguments.update(
            session_id="ses_00000000-0000-4000-8000-000000000048",
            writer_id="wri_00000000-0000-4000-8000-000000000048",
        )
    if operation == "status":
        arguments.update(view="compact", limit="10")
    elif operation == "check":
        arguments.update(mode=mode, expected_frontier={"sequence": "0", "head_digest": "genesis"})
    elif operation == "closure_prepare":
        arguments = {name: arguments[name] for name in ("session_id", "writer_id")} | {
            "selection": {"phase": "inventory"}
        }
    elif operation == "publish_work":
        # This otherwise reaches the recovery oracle even though its events fail validation.
        arguments.update(events="invalid", dry_run=False)
    runtime = mcp_server.build_bridge_runtime(host_profile="codex")
    try:
        result = await mcp_server.call_tool(operation, arguments, runtime)
    finally:
        await mcp_server.close_bridge_runtime(runtime)
    assert reached == []
    assert result.isError is True
    body = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], body["error"])
    assert error["code"] == "INVALID_REQUEST"
    assert error["retryable"] is False
    assert cast(dict[str, object], error["safe_details"])["continuation"] == (
        "config_correction_required"
    )
    assert "45000" not in str(result) and "2000" not in str(result)
