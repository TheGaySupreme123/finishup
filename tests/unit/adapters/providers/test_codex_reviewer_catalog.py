"""#1118: the reviewer's derived Codex 0.162.1 model catalog, its pins, and its launch gate."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from builders.codex_capability import profile_for, record_for
from finishup.adapters.providers import codex_app_server as module
from finishup.adapters.providers.codex_capability import codex_bundled_model_catalog
from finishup.adapters.providers.codex_reviewer_catalog import (
    REVIEWER_CATALOG_DERIVED_SHA256,
    REVIEWER_CATALOG_MODEL,
    REVIEWER_CATALOG_RESOURCE,
    REVIEWER_CATALOG_RUNTIME_VERSION,
    REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
    bundled_entry_sha256,
    derive_reviewer_catalog,
    packaged_reviewer_catalog_path,
    resolve_reviewer_catalog,
    restore_source_entry,
)
from finishup.protocol.canonical import JsonValue, canonical_encode

_ROOT = Path(__file__).resolve().parents[4]
_SOURCE = _ROOT / REVIEWER_CATALOG_RESOURCE
_MIRROR = _ROOT / "src/finishup/resources" / REVIEWER_CATALOG_RESOURCE


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _bundled_catalog() -> dict[str, JsonValue]:
    """A bundled catalog as ``codex debug models --bundled`` prints it: the source entry plus one."""

    source = dict(restore_source_entry(_SOURCE.read_bytes()))
    other = copy.deepcopy(source)
    other["slug"] = "gpt-6-astra"
    return {"models": [other, source]}


def test_committed_catalog_holds_both_pins_and_its_package_mirror() -> None:
    data = _SOURCE.read_bytes()

    assert _sha256(data) == REVIEWER_CATALOG_DERIVED_SHA256
    assert _MIRROR.read_bytes() == data
    restored = restore_source_entry(data)
    assert _sha256(canonical_encode(dict(restored))) == REVIEWER_CATALOG_SOURCE_ENTRY_SHA256


def test_derivation_removes_exactly_the_three_forced_tool_fields() -> None:
    derived = cast(dict[str, list[dict[str, JsonValue]]], json.loads(_SOURCE.read_bytes()))
    (entry,) = derived["models"]
    source = dict(restore_source_entry(_SOURCE.read_bytes()))

    assert entry["slug"] == REVIEWER_CATALOG_MODEL
    assert "tool_mode" not in entry
    assert entry["experimental_supported_tools"] == []
    assert source["tool_mode"] == "code_mode_only"
    assert source["experimental_supported_tools"] == ["send_user_message_async", "clock"]
    # Every other field, including the window, efforts, truncation and instructions, is unchanged.
    assert set(source) - set(entry) == {"tool_mode"}
    for name in set(entry) - {"experimental_supported_tools"}:
        assert entry[name] == source[name], name
    assert entry["context_window"] == 272000


def test_derivation_from_the_bundled_catalog_reproduces_the_committed_bytes() -> None:
    assert derive_reviewer_catalog(_bundled_catalog()) == _SOURCE.read_bytes()


@pytest.mark.parametrize("change", ["context_window", "experimental_tools", "tool_mode"])
def test_a_changed_source_entry_is_refused(change: str) -> None:
    catalog = _bundled_catalog()
    entry = cast(list[dict[str, JsonValue]], catalog["models"])[1]
    if change == "context_window":
        entry["context_window"] = 500000
    elif change == "experimental_tools":
        entry["experimental_supported_tools"] = ["clock"]
    else:
        del entry["tool_mode"]

    with pytest.raises(ValueError, match="codex_reviewer_catalog_source_changed"):
        derive_reviewer_catalog(catalog)


def test_generator_check_passes_on_the_committed_tree() -> None:
    spec = importlib.util.spec_from_file_location(
        "generate_codex_reviewer_catalog", _ROOT / "scripts/generate_codex_reviewer_catalog.py"
    )
    assert spec is not None and spec.loader is not None
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)

    assert script.check(_ROOT) == []


def test_packaged_path_is_the_installed_regular_file() -> None:
    path = packaged_reviewer_catalog_path()

    assert path is not None
    assert path.is_absolute()
    assert path.read_bytes() == _SOURCE.read_bytes()


@pytest.mark.parametrize(
    ("version", "model", "measured", "catalog", "reason"),
    [
        ("0.162.1", "gpt-6.1-sol", REVIEWER_CATALOG_SOURCE_ENTRY_SHA256, "good", "applied"),
        (
            "0.159.0",
            "gpt-6.1-sol",
            REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
            "good",
            "runtime_release_not_pinned",
        ),
        (
            "0.163.0",
            "gpt-6.1-sol",
            REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
            "good",
            "runtime_release_not_pinned",
        ),
        (
            "0.162.1",
            "gpt-5.6-sol",
            REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
            "good",
            "model_not_pinned",
        ),
        ("0.162.1", "gpt-6.1-sol", None, "good", "bundled_entry_unavailable"),
        ("0.162.1", "gpt-6.1-sol", "sha256:" + "e" * 64, "good", "bundled_entry_changed"),
        (
            "0.162.1",
            "gpt-6.1-sol",
            REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
            None,
            "derived_catalog_unavailable",
        ),
        (
            "0.162.1",
            "gpt-6.1-sol",
            REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
            "missing",
            "derived_catalog_unavailable",
        ),
        (
            "0.162.1",
            "gpt-6.1-sol",
            REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
            "edited",
            "derived_catalog_changed",
        ),
    ],
)
def test_the_catalog_applies_only_when_every_pin_matches(
    tmp_path: Path,
    version: str,
    model: str,
    measured: str | None,
    catalog: str | None,
    reason: str,
) -> None:
    path: Path | None = None
    if catalog is not None:
        path = tmp_path / "catalog.json"
        if catalog == "good":
            path.write_bytes(_SOURCE.read_bytes())
        elif catalog == "edited":
            path.write_bytes(_SOURCE.read_bytes() + b" ")

    decision = resolve_reviewer_catalog(
        runtime_version=version, model=model, measured_entry_sha256=measured, catalog_path=path
    )

    assert decision.reason == reason
    assert (decision.path is not None) is (reason == "applied")


def _overrides(argv: Sequence[str]) -> list[str]:
    assert argv[1:4] == ("app-server", "--stdio", "--strict-config")
    return [value for flag, value in zip(argv[4::2], argv[5::2], strict=True) if flag == "-c"]


def _reviewer_profile(
    *, version: str = REVIEWER_CATALOG_RUNTIME_VERSION, model: str = REVIEWER_CATALOG_MODEL
) -> module.CodexAppServerProfile:
    return profile_for(record_for(b"catalog codex", b"catalog host", version=version), model=model)


def test_launch_passes_the_catalog_through_the_isolated_overrides_when_measured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _reviewer_profile()
    monkeypatch.setattr(module, "_BUNDLED_ENTRY_SHA256", {})
    before = profile.launcher_argv

    # Before the fence measured these bytes, the launch is unchanged.
    assert not any(item.startswith("model_catalog_json=") for item in _overrides(before))

    monkeypatch.setitem(
        module._BUNDLED_ENTRY_SHA256,  # pyright: ignore[reportPrivateUsage]
        profile.executable_sha256,
        REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
    )
    overrides = _overrides(profile.launcher_argv)
    path = packaged_reviewer_catalog_path()

    assert path is not None
    # Alongside, not instead of, the 0.162.1-only keys, as one more ``-c`` after --strict-config.
    assert overrides[-1] == f"model_catalog_json={json.dumps(str(path))}"
    assert overrides[:-1] == _overrides(before)
    assert "agents.enabled=false" in overrides
    assert profile.launcher_sha256 != module.canonical_digest({"argv": list(before), "version": 1})


@pytest.mark.parametrize(
    ("version", "model"), [("0.159.0", REVIEWER_CATALOG_MODEL), ("0.162.1", "gpt-5.6-sol")]
)
def test_other_releases_and_models_never_get_the_catalog(
    monkeypatch: pytest.MonkeyPatch, version: str, model: str
) -> None:
    profile = _reviewer_profile(version=version, model=model)
    monkeypatch.setattr(
        module,
        "_BUNDLED_ENTRY_SHA256",
        {profile.executable_sha256: REVIEWER_CATALOG_SOURCE_ENTRY_SHA256},
    )

    assert not any(
        item.startswith("model_catalog_json=") for item in _overrides(profile.launcher_argv)
    )


def test_measurement_applies_a_matching_runtime_and_records_a_fallback_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = profile_for(
        record_for(b"measured codex", b"measured host", version="0.162.1"),
        home=tmp_path / "home",
        model=REVIEWER_CATALOG_MODEL,
    )
    recorded: list[Mapping[str, str]] = []
    calls: list[Path] = []
    catalogs: list[object] = [_bundled_catalog()]

    def bundled(executable: Path, *, scratch_parent: Path) -> object:
        calls.append(scratch_parent)
        catalog = catalogs[0]
        if isinstance(catalog, Exception):
            raise catalog
        return catalog

    def record(**fields: str) -> str:
        recorded.append(fields)
        return "cor"

    monkeypatch.setattr(module, "_BUNDLED_ENTRY_SHA256", {})
    monkeypatch.setattr(module, "_RECORDED_CATALOG_FALLBACKS", set[tuple[str, str, str]]())
    monkeypatch.setattr(module, "codex_bundled_model_catalog", bundled)
    monkeypatch.setattr(module, "record_bounded_event_without_raising", record)

    assert profile.measure_reviewer_catalog().reason == "applied"
    assert calls == [tmp_path / "home" / "runtime"]
    assert recorded == []

    catalogs[0] = ValueError("codex_bundled_catalog_unavailable")
    for _ in range(2):
        assert profile.measure_reviewer_catalog().reason == "bundled_entry_unavailable"
    assert recorded == [
        {
            "component": "codex_app_server",
            "operation": "codex_reviewer_model_catalog",
            "reason": "bundled_entry_unavailable",
        }
    ]
    assert not any(
        item.startswith("model_catalog_json=") for item in _overrides(profile.launcher_argv)
    )


def test_measurement_is_skipped_for_unpinned_models(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = profile_for(
        record_for(b"other codex", b"other host", version="0.162.1"), home=tmp_path / "home"
    )

    def bundled(executable: Path, *, scratch_parent: Path) -> object:
        raise AssertionError("no measurement for an unpinned model")

    recorded: list[str] = []

    def record(**fields: str) -> str:
        recorded.append(fields["reason"])
        return "cor"

    monkeypatch.setattr(module, "_RECORDED_CATALOG_FALLBACKS", set[tuple[str, str, str]]())
    monkeypatch.setattr(module, "codex_bundled_model_catalog", bundled)
    monkeypatch.setattr(module, "record_bounded_event_without_raising", record)

    assert profile.measure_reviewer_catalog().reason == "model_not_pinned"
    assert recorded == ["model_not_pinned"]


class _Runner:
    def __init__(self, code: int, output: bytes) -> None:
        self.code = code
        self.output = output
        self.calls: list[tuple[tuple[str, ...], Path, Mapping[str, str]]] = []

    def __call__(self, argv: Sequence[str], cwd: Path, env: Mapping[str, str]) -> tuple[int, bytes]:
        self.calls.append((tuple(argv), cwd, dict(env)))
        return self.code, self.output


def test_bundled_catalog_is_read_from_the_candidate_under_a_scratch_home(tmp_path: Path) -> None:
    catalog = _bundled_catalog()
    runner = _Runner(0, json.dumps(catalog).encode())

    parsed = codex_bundled_model_catalog(
        Path("/opt/codex/codex"), scratch_parent=tmp_path, runner=runner
    )

    assert bundled_entry_sha256(parsed) == REVIEWER_CATALOG_SOURCE_ENTRY_SHA256
    ((argv, cwd, env),) = runner.calls
    assert argv == ("/opt/codex/codex", "debug", "models", "--bundled")
    assert env["CODEX_HOME"] == str(cwd / "home")
    assert cwd.parent == tmp_path
    assert not cwd.exists()


@pytest.mark.parametrize(("code", "output"), [(1, b"{}"), (0, b""), (0, b"not json")])
def test_bundled_catalog_failures_are_one_closed_token(
    tmp_path: Path, code: int, output: bytes
) -> None:
    with pytest.raises(ValueError, match="^codex_bundled_catalog_unavailable$"):
        codex_bundled_model_catalog(
            Path("/opt/codex/codex"), scratch_parent=tmp_path, runner=_Runner(code, output)
        )
