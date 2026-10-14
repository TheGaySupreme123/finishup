"""Legacy ``YOETZ_`` environment spellings next to ``FINISHUP_`` (ADR-048).

A legacy name is read only when its FinishUP twin is unset; both set to one value is the same
setting; both set to different values fails closed. The strict loader checks both spellings
against one allowlist and keeps refusing secret-shaped and unknown names under either prefix.
"""

from __future__ import annotations

from pathlib import Path

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
        # Disagreeing spellings are skipped like an unparsable value; the default applies.
        (
            {"FINISHUP_MCP_DEADLINE_MS_STATUS": "45000", "YOETZ_MCP_DEADLINE_MS_STATUS": "2000"},
            None,
        ),
        # A skipped per-tool conflict still falls through to the all-tools override.
        (
            {
                "FINISHUP_MCP_DEADLINE_MS_STATUS": "45000",
                "YOETZ_MCP_DEADLINE_MS_STATUS": "2000",
                "YOETZ_MCP_DEADLINE_MS": "30000",
            },
            30_000,
        ),
    ],
)
def test_mcp_deadlines_read_the_legacy_spelling(
    environ: dict[str, str], expected: int | None
) -> None:
    default = mcp_server._DEFAULT_RPC_DEADLINES_MS["status"]  # pyright: ignore[reportPrivateUsage]
    deadline = mcp_server._rpc_deadline_ms("status", environ)  # pyright: ignore[reportPrivateUsage]
    assert deadline == (default if expected is None else expected)
