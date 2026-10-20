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


@pytest.mark.anyio
@pytest.mark.parametrize("first_applied", [True, False])
async def test_v3_evidence_records_the_argv_its_own_process_launched(
    tmp_path: Path, first_applied: bool
) -> None:
    """#1118 V3: a concurrent launch's catalog measurement must not rewrite this attempt's record.

    A launches (with or without the catalog); while its turn runs, B launches from the same
    executable bytes with the opposite measured outcome, rewriting the shared measurement. Before
    the fix A's evidence was rebuilt from that shared state at completion and recorded B's argv.
    """

    import asyncio
    import tempfile
    from dataclasses import replace
    from datetime import timedelta

    from builders.codex_capability import binding_for, retained_runtime, write_home
    from finishup.ports.semantic import Deadline, SemanticResultSuccess
    from unit.adapters.providers import test_codex_app_server as helpers

    bundled = _bundled_catalog()
    spawned: list[tuple[str, ...]] = []
    tmp_path.chmod(0o700)
    root = Path(tempfile.mkdtemp(dir=tmp_path))
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(module, "verify_private_local_bundle", lambda _path: None)  # pyright: ignore[reportUnknownLambdaType,reportUnknownArgumentType]
        patch.setattr(module, "_BUNDLED_ENTRY_SHA256", {})
        patch.setattr(module, "_RECORDED_CATALOG_FALLBACKS", set[object]())
        patch.setattr(module, "record_bounded_event_without_raising", lambda **_kw: None)  # pyright: ignore[reportUnknownLambdaType,reportUnknownArgumentType]
        executable, record = retained_runtime(root / "bundle", version="0.162.1")
        home_a, home_b = write_home(root / "home-a"), write_home(root / "home-b")
        profile_a = module.CodexAppServerProfile.from_config(
            binding_for(record, executable, home_a, model=REVIEWER_CATALOG_MODEL)
        )
        profile_b = replace(profile_a, codex_home=home_b)

        def catalog(_exe: Path, *, scratch_parent: Path) -> object:
            applies = first_applied if scratch_parent.parent == home_a else not first_applied
            if not applies:
                raise ValueError("codex_bundled_catalog_unavailable")
            return bundled

        patch.setattr(module, "codex_bundled_model_catalog", catalog)

        class FakeProcess:
            stdin = stdout = stderr = None

        async def spawn(*argv: str, **_kwargs: object) -> FakeProcess:
            spawned.append(argv)
            return FakeProcess()

        patch.setattr(asyncio, "create_subprocess_exec", spawn)
        wire = helpers._Runtime(profile_a)  # pyright: ignore[reportPrivateUsage]

        async def request(
            self: module._CodexProcess,  # pyright: ignore[reportPrivateUsage]
            request_id: int,
            method: str,
            params: object,
            timeout: float,
        ) -> object:
            wire.workdir = self.workdir
            result = await wire.request(request_id, method, params, timeout)
            if method == "initialize":
                result["userAgent"] = (
                    "finishup_semantic_evaluator/0.162.1 (Mac OS 26.6.2; arm64) unknown"
                )
            if method == "turn/start":
                await module._launch(profile_b)  # pyright: ignore[reportPrivateUsage]
            return result

        async def read(_self: object, timeout: float) -> object:
            return await wire.read(timeout)

        async def send(_self: object, value: object) -> None:
            await wire.send(cast(dict[str, object], value))

        async def cleanup(_runtime: object) -> str:
            return "terminated"

        patch.setattr(module._CodexProcess, "request", request)  # pyright: ignore[reportPrivateUsage]
        patch.setattr(module._CodexProcess, "read", read)  # pyright: ignore[reportPrivateUsage]
        patch.setattr(module._CodexProcess, "send", send)  # pyright: ignore[reportPrivateUsage]
        patch.setattr(module, "_cleanup", cleanup)
        case = helpers._case()  # pyright: ignore[reportPrivateUsage]
        case = replace(
            case, provider_binding=replace(case.provider_binding, model_id=profile_a.model)
        )
        binding, authority = helpers._attempt(case)  # pyright: ignore[reportPrivateUsage]
        binding = replace(binding, model_id=profile_a.model)
        evaluator = module.CodexAppServerEvaluator(
            profile_a,
            binding,
            authority,
            helpers._Clock(),  # pyright: ignore[reportPrivateUsage]
        )
        deadline = Deadline(helpers._NOW + timedelta(seconds=30), 30.0)  # pyright: ignore[reportPrivateUsage]
        result = await evaluator.evaluate(case, deadline)

    assert isinstance(result, SemanticResultSuccess), result
    assert len(spawned) == 2
    assert ("model_catalog_json=" in " ".join(spawned[0])) is first_applied
    assert ("model_catalog_json=" in " ".join(spawned[1])) is not first_applied
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.launcher_sha256 == module.canonical_digest(
        {"argv": list(spawned[0]), "version": 1}
    )
    assert evidence.launcher_sha256 != module.canonical_digest(
        {"argv": list(spawned[1]), "version": 1}
    )
