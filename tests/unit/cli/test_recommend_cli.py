from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import anyio
from typer.testing import CliRunner

import finishup.cli.recommend as recommend_module
from finishup.application.package_update import (
    build_package_update_advisory,
    installed_package_version,
)
from finishup.application.recommendations import (
    RecommendationContext,
    RecommendationState,
    RecommendationStoreError,
    RecommendationTarget,
    load_recommendation_state,
    record_recommendation_decision,
    refresh_pending,
    store_recommendation_state,
)
from finishup.cli.app import app
from finishup.config.models import ConfigError, FinishUpConfig, ObservationConfig
from finishup.config.write import write_config_toml
from finishup.ports.integrations import IntegrationTarget

_RUNNER = CliRunner()


def _activation_target(seed: str = "abcdef") -> RecommendationTarget:
    values = [f"sha256:{character * 64}" for character in seed[:5]]
    fields = {
        "executable_path_digest": values[0],
        "executable_digest": values[1],
        "codex_version": "0.148.0-alpha.6",
        "codex_home_digest": values[2],
        "activation_preview_digest": values[3],
        "plugin_install_digest": values[4],
    }
    target_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
    )
    return RecommendationTarget(
        target_digest=target_digest,
        **fields,
    )


def _patch_state_root(monkeypatch: object, tmp_path: Path) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.application.recommendations.state_dir", lambda: tmp_path
    )


def _patch_pending_context(monkeypatch: object, recommendation_id: str) -> None:
    async def context(**_kwargs: object) -> RecommendationContext:
        if recommendation_id == "observation-enabled":
            return RecommendationContext(observation_enabled=False)
        if recommendation_id == "codex-plugin-activation":
            return RecommendationContext(
                codex_activation_state="installed_not_activated",
                codex_activation_target=_activation_target(),
            )
        return RecommendationContext(
            package_update=build_package_update_advisory(
                installed_version="0.1.0", latest_version="0.2.0", source="cache"
            )
        )

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend._current_context", context
    )


def test_accept_observation_writes_config_and_records_decision(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "observation-enabled")
    config_path = tmp_path / "config.toml"
    write_config_toml(
        FinishUpConfig(observation=ObservationConfig(enabled=False)), path=config_path
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.config_file_path", lambda: config_path
    )

    result = _RUNNER.invoke(app, ["recommend", "accept", "observation-enabled"])

    assert result.exit_code == 0, result.output
    assert "[observation] enabled = true" in result.stdout
    assert "restart the FinishUP service" in result.stdout
    assert tomllib.loads(config_path.read_text(encoding="utf-8"))["observation"] == {
        "enabled": True,
        "semantic_advice_min_interval_seconds": 180,
    }
    state = load_recommendation_state(root=tmp_path)
    assert state.decisions["observation-enabled"].decision == "accepted"


def test_accept_reports_applied_change_when_decision_record_fails(
    tmp_path: Path, monkeypatch: object
) -> None:
    """The applied mutation must stay visible even when recording the decision fails."""

    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "observation-enabled")
    config_path = tmp_path / "config.toml"
    write_config_toml(
        FinishUpConfig(observation=ObservationConfig(enabled=False)), path=config_path
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.config_file_path", lambda: config_path
    )

    def failing_record(*_args: object, **_kwargs: object) -> None:
        raise RecommendationStoreError("recommendation_store_write_failed")

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.record_recommendation_decision", failing_record
    )

    result = _RUNNER.invoke(app, ["recommend", "accept", "observation-enabled"])

    assert result.exit_code == 2
    assert "applied observation-enabled:" in result.stdout
    assert "recommendation_error: recommendation_store_write_failed" in result.output
    assert "the decision could not be recorded" in result.output
    assert tomllib.loads(config_path.read_text(encoding="utf-8"))["observation"] == {
        "enabled": True,
        "semantic_advice_min_interval_seconds": 180,
    }


def test_decline_is_durable_and_removes_cached_pending(tmp_path: Path, monkeypatch: object) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "observation-enabled")
    refresh = RecommendationState(
        last_evaluated_version="0.1.0",
        decisions=MappingProxyType({}),
        pending=("observation-enabled",),
    )
    store_recommendation_state(refresh, root=tmp_path)

    result = _RUNNER.invoke(app, ["recommend", "decline", "observation-enabled"])

    assert result.exit_code == 0, result.output
    assert "will not be shown again" in result.stdout
    state = load_recommendation_state(root=tmp_path)
    assert state.pending == ()
    assert state.decisions["observation-enabled"].decision == "declined"


def test_package_accept_prints_pypi_upgrade_command_only(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "package-update")

    result = _RUNNER.invoke(app, ["recommend", "accept", "package-update"])

    assert result.exit_code == 0, result.output
    assert "finishup upgrade" in result.stdout
    assert "npm" not in result.stdout


def test_list_renders_pending_actions(monkeypatch: object) -> None:
    async def fake_refresh(**_kwargs: object) -> RecommendationState:
        return RecommendationState(
            last_evaluated_version="0.1.0",
            pending=("observation-enabled",),
        )

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend._refresh_for_cli", fake_refresh
    )

    result = _RUNNER.invoke(app, ["recommend", "list"])

    assert result.exit_code == 0, result.output
    assert "Enable local observation" in result.stdout
    assert "finishup recommend accept observation-enabled" in result.stdout
    assert "finishup recommend decline observation-enabled" in result.stdout


def test_list_reoffers_activation_for_another_target_and_same_target_drift(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    first = _activation_target("abcde")
    second = _activation_target("12345")
    drifted = _activation_target("fedcb")
    anyio.run(
        lambda: refresh_pending(
            context=RecommendationContext(
                codex_activation_state="installed_not_activated",
                codex_activation_target=first,
            ),
            root=tmp_path,
            force=True,
        )
    )
    record_recommendation_decision(
        "codex-plugin-activation", "accepted", root=tmp_path, target=first
    )

    selected = second

    async def context(**_kwargs: object) -> RecommendationContext:
        return RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=selected,
        )

    monkeypatch.setattr("finishup.cli.recommend._current_context", context)  # type: ignore[attr-defined]
    other = _RUNNER.invoke(
        app,
        [
            "recommend",
            "list",
            "--codex-path",
            str(tmp_path / "codex"),
            "--codex-home",
            str(tmp_path / "home-b"),
        ],
    )
    assert other.exit_code == 0, other.output
    assert "codex-plugin-activation" in other.stdout
    assert second.target_digest in other.stdout

    selected = drifted
    changed = _RUNNER.invoke(
        app,
        [
            "recommend",
            "list",
            "--codex-path",
            str(tmp_path / "codex"),
            "--codex-home",
            str(tmp_path / "home-a"),
        ],
    )
    assert changed.exit_code == 0, changed.output
    assert "codex-plugin-activation" in changed.stdout
    assert drifted.target_digest in changed.stdout


def test_activation_context_binds_the_exact_preview_target(
    tmp_path: Path, monkeypatch: object
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"codex-binary")
    home = tmp_path / "codex-home"
    home.mkdir()
    preview = SimpleNamespace(
        executable_path=executable,
        executable_digest="sha256:" + ("a" * 64),
        codex_version="0.148.0",
        codex_home=home,
        preview_digest="sha256:" + ("b" * 64),
        plugin_install_digest="sha256:" + ("c" * 64),
    )

    def inspect(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(state=SimpleNamespace(value="installed_not_activated"))

    def preview_target(*_args: object, **_kwargs: object) -> object:
        return preview

    def import_adapter(_name: str) -> object:
        return adapter

    adapter = SimpleNamespace(
        inspect_activation=inspect,
        preview_activation=preview_target,
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.importlib.import_module", import_adapter
    )

    state, target = recommend_module._activation_context(  # pyright: ignore[reportPrivateUsage]
        tmp_path, executable_path=executable, codex_home=home
    )

    assert state == "installed_not_activated"
    assert target is not None
    assert target.executable_digest == preview.executable_digest
    assert target.activation_preview_digest == preview.preview_digest
    assert target.plugin_install_digest == preview.plugin_install_digest
    assert str(executable) not in repr(target)
    assert str(home) not in repr(target)


def test_activation_context_preserves_foreign_state_without_previewing(
    tmp_path: Path, monkeypatch: object
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"codex-binary")
    home = tmp_path / "codex-home"
    home.mkdir()
    preview_calls = 0

    def inspect(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(state=SimpleNamespace(value="foreign"))

    def preview_target(*_args: object, **_kwargs: object) -> object:
        nonlocal preview_calls
        preview_calls += 1
        raise AssertionError("foreign target must not be previewed")

    adapter = SimpleNamespace(
        inspect_activation=inspect,
        preview_activation=preview_target,
    )

    def import_adapter(_name: str) -> object:
        return adapter

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.importlib.import_module", import_adapter
    )

    state, target = recommend_module._activation_context(  # pyright: ignore[reportPrivateUsage]
        tmp_path, executable_path=executable, codex_home=home
    )

    assert state == "foreign"
    assert target is None
    assert preview_calls == 0


def test_activation_preview_failure_clears_cached_actionable_advice(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    config_path = tmp_path / "config.toml"
    monkeypatch.setattr(  # type: ignore[attr-defined]
        recommend_module, "config_file_path", lambda: config_path
    )
    target = _activation_target()
    store_recommendation_state(
        RecommendationState(
            last_evaluated_version=installed_package_version(),
            pending=("codex-plugin-activation",),
            pending_targets=MappingProxyType({"codex-plugin-activation": target}),
        ),
        root=tmp_path,
    )
    executable = tmp_path / "codex"
    executable.write_bytes(b"codex-binary")
    home = tmp_path / "codex-home"
    home.mkdir()

    def inspect(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(state=SimpleNamespace(value="installed_not_activated"))

    def preview_target(*_args: object, **_kwargs: object) -> object:
        raise OSError("preview refused modified target")

    adapter = SimpleNamespace(
        inspect_activation=inspect,
        preview_activation=preview_target,
    )

    def import_adapter(_name: str) -> object:
        return adapter

    monkeypatch.setattr(  # type: ignore[attr-defined]
        recommend_module.importlib, "import_module", import_adapter
    )

    result = _RUNNER.invoke(
        app,
        [
            "recommend",
            "list",
            "--codex-path",
            str(executable),
            "--codex-home",
            str(home),
        ],
    )

    assert result.exit_code == 0, result.output
    state = load_recommendation_state(root=tmp_path)
    assert "codex-plugin-activation" not in state.pending


def test_activation_accept_repreviews_and_applies_exact_digest(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    applied: list[tuple[IntegrationTarget, str]] = []
    executable = tmp_path / "codex-testing-bin"
    executable.write_bytes(b"codex-testing")
    codex_home = tmp_path / "codex-testing"
    preview = SimpleNamespace(
        marketplace_bytes=b'{"plugins":[]}\n',
        config_toml_block='[plugins."finishup@finishup"]\nenabled = true\n',
        preview_digest="sha256:" + "a" * 64,
        codex_home=codex_home,
        plugin_install_path=codex_home / "plugins" / "cache" / "finishup",
        plugin_source_digest="sha256:" + "b" * 64,
        plugin_install_digest="sha256:" + "c" * 64,
        executable_path=executable,
        executable_digest="sha256:" + "d" * 64,
        codex_version="0.148.0-alpha.6",
        probe_command=("--version",),
        inventory_command=("plugin", "list", "--marketplace", "finishup", "--json"),
        install_command=("plugin", "add", "finishup@finishup", "--json"),
        probe_environment="temporary_owner_private_home",
        activation_environment=(
            ("CODEX_HOME", str(codex_home)),
            ("CODEX_TESTING_HOME", str(codex_home)),
        ),
        marketplace_preimage_digest="sha256:" + "e" * 64,
        config_preimage_digest="sha256:" + "f" * 64,
        cache_mutation_planned=True,
        inspection=SimpleNamespace(inventory_verified=False),
    )

    _patch_pending_context(monkeypatch, "codex-plugin-activation")

    expected_home = codex_home.resolve()

    def apply(
        target: IntegrationTarget,
        *,
        approved_digest: str,
        executable_path: str,
        codex_home: Path,
    ) -> None:
        assert executable_path == str(executable)
        assert Path(codex_home).resolve() == expected_home
        state = load_recommendation_state(root=tmp_path)
        assert any(
            row.recommendation_id == "codex-plugin-activation" and row.decision == "accepted"
            for row in state.decisions.values()
        ), "activation decision must commit before host mutation"
        applied.append((target, approved_digest))

    def make_preview(
        _target: IntegrationTarget, *, executable_path: str, codex_home: Path
    ) -> object:
        assert executable_path == str(executable)
        assert Path(codex_home).resolve() == expected_home
        return preview

    def import_adapter(_name: str) -> object:
        return adapter

    adapter = SimpleNamespace(
        preview_activation=make_preview,
        apply_activation=apply,
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.importlib.import_module", import_adapter
    )

    result = _RUNNER.invoke(
        app,
        [
            "recommend",
            "accept",
            "codex-plugin-activation",
            "--codex-path",
            str(executable),
            "--codex-home",
            str(codex_home),
        ],
        input="y\n",
    )

    assert result.exit_code == 0, result.output
    assert preview.preview_digest in result.stdout
    assert '[plugins."finishup@finishup"]' in result.stdout
    assert str(codex_home) in result.stdout
    assert str(executable) in result.stdout
    assert preview.executable_digest in result.stdout
    assert preview.codex_version in result.stdout
    assert preview.plugin_source_digest in result.stdout
    assert preview.plugin_install_digest in result.stdout
    assert preview.marketplace_preimage_digest in result.stdout
    assert preview.config_preimage_digest in result.stdout
    assert f"{executable} --version" in result.stdout
    assert "Probe environment: temporary_owner_private_home" in result.stdout
    assert "Canonical plugin inventory verified before consent: no" in result.stdout
    assert f"{executable} plugin list --marketplace finishup --json" in result.stdout
    assert f"{executable} plugin add finishup@finishup --json" in result.stdout
    assert f"CODEX_HOME={codex_home}" in result.stdout
    assert f"CODEX_TESTING_HOME={codex_home}" in result.stdout
    assert applied and applied[0][1] == preview.preview_digest
    assert "fresh Codex process/session" in result.stdout


def test_activation_store_failure_prevents_host_mutation(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "codex-plugin-activation")
    executable = tmp_path / "codex-testing-bin"
    executable.write_bytes(b"codex-testing")
    codex_home = tmp_path / "codex-testing"
    preview = SimpleNamespace(
        marketplace_bytes=b"{}\n",
        config_toml_block='[plugins."finishup@finishup"]\nenabled = true\n',
        preview_digest="sha256:" + "a" * 64,
        codex_home=codex_home,
        plugin_install_path=codex_home / "plugins" / "cache" / "finishup",
        plugin_source_digest="sha256:" + "b" * 64,
        plugin_install_digest="sha256:" + "c" * 64,
        executable_path=executable,
        executable_digest="sha256:" + "d" * 64,
        codex_version="0.148.0-alpha.6",
        probe_command=("--version",),
        inventory_command=("plugin", "list", "--marketplace", "finishup", "--json"),
        install_command=("plugin", "add", "finishup@finishup", "--json"),
        probe_environment="temporary_owner_private_home",
        activation_environment=(
            ("CODEX_HOME", str(codex_home)),
            ("CODEX_TESTING_HOME", str(codex_home)),
        ),
        marketplace_preimage_digest="sha256:" + "e" * 64,
        config_preimage_digest="sha256:" + "f" * 64,
        cache_mutation_planned=True,
        inspection=SimpleNamespace(inventory_verified=False),
    )
    applied = False

    def make_preview(*_args: object, **_kwargs: object) -> object:
        return preview

    def apply(*_args: object, **_kwargs: object) -> None:
        nonlocal applied
        applied = True

    adapter = SimpleNamespace(preview_activation=make_preview, apply_activation=apply)

    def import_adapter(_name: str) -> object:
        return adapter

    def fail_store(*_args: object, **_kwargs: object) -> RecommendationState:
        raise RecommendationStoreError("recommendation_store_write_failed")

    monkeypatch.setattr(  # type: ignore[attr-defined]
        recommend_module, "record_recommendation_decision", fail_store
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        recommend_module.importlib, "import_module", import_adapter
    )

    result = _RUNNER.invoke(
        app,
        [
            "recommend",
            "accept",
            "codex-plugin-activation",
            "--codex-path",
            str(executable),
            "--codex-home",
            str(codex_home),
        ],
        input="y\n",
    )

    assert result.exit_code == 2
    assert "recommendation_store_write_failed" in result.output
    assert applied is False


def test_unknown_recommendation_is_rejected_without_creating_state(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)

    result = _RUNNER.invoke(app, ["recommend", "accept", "not-real"])

    assert result.exit_code == 2
    assert "recommendation_unknown" in result.output
    assert not (tmp_path / "recommendations.json").exists()


def test_known_but_not_pending_recommendation_is_rejected(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)

    async def satisfied(**_kwargs: object) -> RecommendationContext:
        return RecommendationContext(observation_enabled=True)

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend._current_context", satisfied
    )

    result = _RUNNER.invoke(app, ["recommend", "accept", "observation-enabled"])

    assert result.exit_code == 2
    assert "recommendation_not_pending" in result.output


def test_observation_accept_fails_closed_on_concurrent_config_change(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "observation-enabled")
    config_path = tmp_path / "config.toml"
    write_config_toml(
        FinishUpConfig(observation=ObservationConfig(enabled=False)), path=config_path
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.config_file_path", lambda: config_path
    )

    def stale(*_args: object, **_kwargs: object) -> Path:
        raise ConfigError("config_preimage_mismatch")

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.write_config_toml_if_unchanged", stale
    )

    result = _RUNNER.invoke(app, ["recommend", "accept", "observation-enabled"])

    assert result.exit_code == 2
    assert "config_preview_stale" in result.output
    assert "observation-enabled" not in load_recommendation_state(root=tmp_path).decisions


def test_activation_preview_requires_explicit_post_preview_confirmation(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "codex-plugin-activation")
    applied: list[str] = []
    executable = tmp_path / "codex-testing-bin"
    executable.write_bytes(b"codex-testing")
    codex_home = tmp_path / "codex-testing"
    preview = SimpleNamespace(
        marketplace_bytes=b"{}\n",
        config_toml_block='[plugins."finishup@finishup"]\nenabled = true\n',
        preview_digest="sha256:" + "b" * 64,
        codex_home=codex_home,
        plugin_install_path=codex_home / "plugins" / "cache" / "finishup",
        plugin_source_digest="sha256:" + "c" * 64,
        plugin_install_digest="sha256:" + "d" * 64,
        executable_path=executable,
        executable_digest="sha256:" + "e" * 64,
        codex_version="0.148.0-alpha.6",
        probe_command=("--version",),
        inventory_command=("plugin", "list", "--marketplace", "finishup", "--json"),
        install_command=("plugin", "add", "finishup@finishup", "--json"),
        probe_environment="temporary_owner_private_home",
        activation_environment=(
            ("CODEX_HOME", str(codex_home)),
            ("CODEX_TESTING_HOME", str(codex_home)),
        ),
        marketplace_preimage_digest="sha256:" + "f" * 64,
        config_preimage_digest="sha256:" + "0" * 64,
        cache_mutation_planned=False,
        inspection=SimpleNamespace(inventory_verified=False),
    )

    expected_home = codex_home.resolve()

    def make_preview(
        _target: IntegrationTarget, *, executable_path: str, codex_home: Path
    ) -> object:
        assert executable_path == str(executable)
        assert Path(codex_home).resolve() == expected_home
        return preview

    def apply(
        _target: IntegrationTarget,
        *,
        approved_digest: str,
        executable_path: str,
        codex_home: Path,
    ) -> None:
        assert executable_path == str(executable)
        assert Path(codex_home).resolve() == expected_home
        applied.append(approved_digest)

    adapter = SimpleNamespace(preview_activation=make_preview, apply_activation=apply)

    def import_adapter(_name: str) -> object:
        return adapter

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.importlib.import_module", import_adapter
    )

    result = _RUNNER.invoke(
        app,
        [
            "recommend",
            "accept",
            "codex-plugin-activation",
            "--codex-path",
            str(executable),
            "--codex-home",
            str(codex_home),
        ],
        input="n\n",
    )

    assert result.exit_code == 2
    assert preview.preview_digest in result.stdout
    assert "activation_not_approved" in result.output
    assert applied == []


def test_activation_accept_requires_exact_codex_path(tmp_path: Path, monkeypatch: object) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "codex-plugin-activation")
    result = _RUNNER.invoke(
        app,
        [
            "recommend",
            "accept",
            "codex-plugin-activation",
            "--codex-home",
            str(tmp_path / "codex-testing"),
        ],
    )

    assert result.exit_code == 2
    assert "activation_codex_path_required" in result.output


def test_activation_accept_requires_exact_codex_home(tmp_path: Path, monkeypatch: object) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "codex-plugin-activation")

    result = _RUNNER.invoke(
        app,
        [
            "recommend",
            "accept",
            "codex-plugin-activation",
            "--codex-path",
            str(tmp_path / "codex-testing-bin"),
        ],
    )

    assert result.exit_code == 2
    assert "activation_codex_home_required" in result.output


def _seed_package_update_pending(tmp_path: Path) -> None:
    """Daemon-style refresh: a real performed advisory establishes package-update pending."""

    advisory = build_package_update_advisory(
        installed_version=installed_package_version(),
        latest_version="9999.0.0",
        source="network",
    )
    state = anyio.run(
        lambda: refresh_pending(
            context=RecommendationContext(package_update=advisory), root=tmp_path
        )
    )
    assert "package-update" in state.pending


def _patch_config_path(monkeypatch: object, tmp_path: Path) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.cli.recommend.config_file_path", lambda: tmp_path / "config.toml"
    )


def test_package_update_pending_survives_policyless_list_and_accepts(
    tmp_path: Path, monkeypatch: object
) -> None:
    """Regression: the real policy-less CLI context must not erase daemon-set pending advice."""

    _patch_state_root(monkeypatch, tmp_path)
    _patch_config_path(monkeypatch, tmp_path)
    _seed_package_update_pending(tmp_path)

    listed = _RUNNER.invoke(app, ["recommend", "list"])

    assert listed.exit_code == 0, listed.output
    assert "package-update" in listed.stdout
    assert "package-update" in load_recommendation_state(root=tmp_path).pending

    accepted = _RUNNER.invoke(app, ["recommend", "accept", "package-update"])

    assert accepted.exit_code == 0, accepted.output
    assert "recommendation_not_pending" not in accepted.output
    assert "finishup upgrade" in accepted.stdout
    state = load_recommendation_state(root=tmp_path)
    assert state.decisions["package-update"].decision == "accepted"
    assert "package-update" not in state.pending


def test_package_update_decline_succeeds_after_policyless_list(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_config_path(monkeypatch, tmp_path)
    _seed_package_update_pending(tmp_path)

    listed = _RUNNER.invoke(app, ["recommend", "list"])
    assert listed.exit_code == 0, listed.output

    declined = _RUNNER.invoke(app, ["recommend", "decline", "package-update"])

    assert declined.exit_code == 0, declined.output
    assert "later releases may be recommended" in declined.stdout
    state = load_recommendation_state(root=tmp_path)
    assert "package-update" not in state.pending
    assert state.decisions["package-update"].decision == "declined"


def test_activation_decline_needs_no_codex_authority_and_is_durable(
    tmp_path: Path, monkeypatch: object
) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    target = _activation_target()
    store_recommendation_state(
        RecommendationState(
            last_evaluated_version=installed_package_version(),
            pending=("codex-plugin-activation",),
            pending_targets=MappingProxyType({"codex-plugin-activation": target}),
        ),
        root=tmp_path,
    )

    result = _RUNNER.invoke(app, ["recommend", "decline", "codex-plugin-activation"])

    assert result.exit_code == 0, result.output
    assert "this exact target and activation digest" in result.stdout
    state = load_recommendation_state(root=tmp_path)
    assert state.pending == ()
    assert next(iter(state.decisions.values())).decision == "declined"

    refreshed = anyio.run(
        lambda: refresh_pending(
            context=RecommendationContext(
                codex_activation_state="installed_not_activated",
                codex_activation_target=target,
            ),
            root=tmp_path,
            force=True,
        )
    )

    assert "codex-plugin-activation" not in refreshed.pending
    assert next(iter(refreshed.decisions.values())).decision == "declined"


def test_decline_requires_cached_pending(tmp_path: Path, monkeypatch: object) -> None:
    _patch_state_root(monkeypatch, tmp_path)

    result = _RUNNER.invoke(app, ["recommend", "decline", "codex-plugin-activation"])

    assert result.exit_code == 2
    assert "recommendation_not_pending" in result.output


def test_package_decline_rejects_old_hook_release(tmp_path: Path, monkeypatch: object) -> None:
    _patch_state_root(monkeypatch, tmp_path)
    _patch_pending_context(monkeypatch, "package-update")
    assert _RUNNER.invoke(app, ["recommend", "list"]).exit_code == 0
    declined = _RUNNER.invoke(
        app, ["recommend", "decline", "package-update", "--release-version", "0.1.9"]
    )
    assert declined.exit_code == 2
    assert "recommendation_release_changed" in declined.output
    assert load_recommendation_state(root=tmp_path).pending_package_version == "0.2.0"
    accepted = _RUNNER.invoke(
        app, ["recommend", "accept", "package-update", "--release-version", "0.1.9"]
    )
    assert accepted.exit_code == 2
    assert "uv tool upgrade" not in accepted.output
    assert "package-update" in load_recommendation_state(root=tmp_path).pending
