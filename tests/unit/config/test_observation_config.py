from __future__ import annotations

import tomllib
from pathlib import Path
from types import TracebackType
from typing import cast

import pytest

from finishup.config.load import load_config
from finishup.config.models import (
    BackgroundAdviceSetting,
    ConfigError,
    FinishUpConfig,
    ObservationConfig,
    VerificationConfig,
    background_advice_setting,
)
from finishup.config.write import (
    render_config_toml,
    write_config_toml,
    write_config_toml_if_unchanged,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance


def test_observation_config_toml_round_trip(tmp_path: Path) -> None:
    config = FinishUpConfig(
        observation=ObservationConfig(
            enabled=False, semantic_advice_enabled=False, semantic_advice_min_interval_seconds=600
        )
    )

    rendered = render_config_toml(config)
    assert "[observation]\nenabled = false\n" in rendered
    assert FinishUpConfig.model_validate(tomllib.loads(rendered), strict=True) == config
    validate_schema_instance("yoetz-config", "1.3.0", cast(JsonValue, tomllib.loads(rendered)))

    path = write_config_toml(config, path=tmp_path / "config.toml")
    assert load_config({}, {}, path) == config


def test_config_compare_and_swap_accepts_exact_preimage(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    disabled = FinishUpConfig(observation=ObservationConfig(enabled=False))
    enabled = FinishUpConfig(observation=ObservationConfig(enabled=True))
    write_config_toml(disabled, path=path)
    expected = path.read_bytes()

    assert write_config_toml_if_unchanged(enabled, expected_bytes=expected, path=path) == path
    assert load_config({}, {}, path) == enabled
    assert (tmp_path / ".config.toml.lock").stat().st_mode & 0o777 == 0o600


def test_config_compare_and_swap_rejects_stale_preimage_without_writing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.toml"
    disabled = FinishUpConfig(observation=ObservationConfig(enabled=False))
    enabled = FinishUpConfig(observation=ObservationConfig(enabled=True))
    write_config_toml(disabled, path=path)
    stale = path.read_bytes()
    concurrent = stale + b"\n# concurrent owner edit\n"
    path.write_bytes(concurrent)

    with pytest.raises(ConfigError) as caught:
        write_config_toml_if_unchanged(enabled, expected_bytes=stale, path=path)

    assert caught.value.reason_code == "config_preimage_mismatch"
    assert path.read_bytes() == concurrent


def test_config_compare_and_swap_distinguishes_absent_from_empty(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    config = FinishUpConfig()

    path.write_bytes(b"")
    with pytest.raises(ConfigError) as caught:
        write_config_toml_if_unchanged(config, expected_bytes=None, path=path)
    assert caught.value.reason_code == "config_preimage_mismatch"
    assert path.read_bytes() == b""

    path.unlink()
    write_config_toml_if_unchanged(config, expected_bytes=None, path=path)
    assert load_config({}, {}, path) == config


def test_all_config_writers_share_the_interprocess_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered: list[Path] = []

    class RecordingLock:
        def __init__(self, target: Path) -> None:
            self.target = target

        def __enter__(self) -> None:
            entered.append(self.target)

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            del exc_type, exc, traceback

    monkeypatch.setattr("finishup.config.write._ConfigWriteLock", RecordingLock)
    first = tmp_path / "first.toml"
    second = tmp_path / "second.toml"

    write_config_toml(FinishUpConfig(), path=first)
    write_config_toml_if_unchanged(FinishUpConfig(), expected_bytes=None, path=second)

    assert entered == [first, second]


def test_config_writer_refuses_preplanted_lock_symlink(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    victim = tmp_path / "victim"
    victim.write_bytes(b"owner content")
    (tmp_path / ".config.toml.lock").symlink_to(victim)

    with pytest.raises(ConfigError) as caught:
        write_config_toml(FinishUpConfig(), path=path)

    assert caught.value.reason_code == "config_value_invalid"
    assert victim.read_bytes() == b"owner content"
    assert not path.exists()


@pytest.mark.parametrize("interval", [0, -1, 86401, True, "180"])
def test_advice_interval_rejects_invalid_values(interval: object) -> None:
    with pytest.raises(ConfigError):
        ObservationConfig.model_validate(
            {"semantic_advice_min_interval_seconds": interval}, strict=True
        )


# --- Background advice default (issue #888, maintainer decision 2026-09-30) -----------------


@pytest.mark.parametrize("semantic", ["required", "optional"])
def test_background_advice_is_on_by_default_where_ai_powered_review_is_configured(
    semantic: str,
) -> None:
    config = FinishUpConfig(verification=VerificationConfig(semantic=semantic))  # type: ignore[arg-type]

    assert config.observation.semantic_advice_enabled is None
    assert background_advice_setting(config) == BackgroundAdviceSetting(True, "default_enabled")


@pytest.mark.parametrize(
    ("chosen", "expected"),
    [
        (True, BackgroundAdviceSetting(True, "owner_enabled")),
        (False, BackgroundAdviceSetting(False, "owner_disabled")),
    ],
)
def test_an_explicit_owner_choice_always_wins(
    chosen: bool, expected: BackgroundAdviceSetting
) -> None:
    config = FinishUpConfig(observation=ObservationConfig(semantic_advice_enabled=chosen))

    assert background_advice_setting(config) == expected


def test_nothing_to_enable_when_review_or_observation_is_off() -> None:
    no_review = FinishUpConfig(
        verification=VerificationConfig(semantic="disabled"),
        observation=ObservationConfig(semantic_advice_enabled=True),
    )
    no_observation = FinishUpConfig(
        observation=ObservationConfig(enabled=False, semantic_advice_enabled=True)
    )

    assert background_advice_setting(no_review) == BackgroundAdviceSetting(
        False, "semantic_review_disabled"
    )
    assert background_advice_setting(no_observation) == BackgroundAdviceSetting(
        False, "observation_disabled"
    )


def test_unset_switch_is_never_persisted_and_turning_it_back_on_round_trips(
    tmp_path: Path,
) -> None:
    """Writing a default config must not freeze today's default as an owner choice."""

    rendered = render_config_toml(FinishUpConfig())
    assert "semantic_advice_enabled" not in rendered
    assert tomllib.loads(rendered)["observation"] == {
        "enabled": True,
        "semantic_advice_min_interval_seconds": 180,
    }
    validate_schema_instance("yoetz-config", "1.3.0", cast(JsonValue, tomllib.loads(rendered)))

    # The reverse state: the owner turns background advice back on, and it stays on.
    enabled = FinishUpConfig(observation=ObservationConfig(semantic_advice_enabled=True))
    path = write_config_toml(enabled, path=tmp_path / "config.toml")
    assert "semantic_advice_enabled = true" in path.read_text(encoding="utf-8")
    loaded = load_config({}, {}, path)
    assert loaded == enabled
    assert background_advice_setting(loaded) == BackgroundAdviceSetting(True, "owner_enabled")


@pytest.mark.parametrize("semantic", ["required", "optional"])
def test_upgraded_config_without_the_switch_keeps_advice_on_and_an_explicit_false_turns_it_off(
    tmp_path: Path, semantic: str
) -> None:
    """Upgrade shape (#888): a stored config that never named the switch resolves to the default.

    Both ``optional`` and ``required`` resolve on (maintainer decision, 2026-09-30), so an
    upgraded installation keeps background advice; an owner's explicit ``false`` turns it off and
    stays off.
    """

    config = FinishUpConfig(verification=VerificationConfig(semantic=semantic))  # type: ignore[arg-type]
    unset = write_config_toml(config, path=tmp_path / "unset.toml")
    assert "semantic_advice_enabled" not in unset.read_text(encoding="utf-8")
    assert background_advice_setting(load_config({}, {}, unset)) == BackgroundAdviceSetting(
        True, "default_enabled"
    )

    off = write_config_toml(
        config.model_copy(update={"observation": ObservationConfig(semantic_advice_enabled=False)}),
        path=tmp_path / "off.toml",
    )
    assert "semantic_advice_enabled = false" in off.read_text(encoding="utf-8")
    assert background_advice_setting(load_config({}, {}, off)) == BackgroundAdviceSetting(
        False, "owner_disabled"
    )
