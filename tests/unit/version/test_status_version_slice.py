from __future__ import annotations

from types import MappingProxyType

import apsw
import pytest

from finishup.version import (
    PROJECTION_VERSION,
    UNAVAILABLE_RUNTIME_FACT,
    build_status_version_slice_facts,
    build_version_manifest,
)

_ABSENT = MappingProxyType({"status": "absent"})
_HISTORICAL_APSW = "3.51.0.0"
_HISTORICAL_SQLITE = "3.51.0"


def test_status_slice_matches_live_runtime_and_version_manifest() -> None:
    facts = build_status_version_slice_facts()
    manifest = build_version_manifest()

    assert facts.apsw_version == apsw.apsw_version()
    assert facts.sqlite_version == apsw.sqlitelibversion()
    assert facts.sqlite_source_id == apsw.sqlite3_sourceid()
    assert facts.python_version == manifest.python_version
    assert facts.apsw_version == manifest.apsw_version["version"]
    assert facts.sqlite_version == manifest.sqlite_version["version"]
    assert facts.projection_version == PROJECTION_VERSION
    assert facts.apsw_version != _HISTORICAL_APSW
    assert facts.sqlite_version != _HISTORICAL_SQLITE
    assert facts.sqlite_source_id != "runtime-verified-by-connection-gate"


def test_empty_catalog_provider_profiles_are_not_evaluator_proof() -> None:
    facts = build_status_version_slice_facts()
    manifest = build_version_manifest()

    assert facts.provider_profiles == ()
    assert manifest.support_status == "development_unverified"
    assert any(adapter["name"] == "openai" for adapter in manifest.provider_adapters)


def test_status_slice_uses_probed_runtime_not_historical_literals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "finishup.version._runtime_components",
        lambda: (
            MappingProxyType({"status": "present", "version": "9.9.9.9"}),
            MappingProxyType({"status": "present", "version": "9.9.9"}),
            MappingProxyType({"status": "present", "source_id": "probe-sqlite-source-id"}),
            MappingProxyType({"status": "present", "digest": "sha256:" + "ab" * 32}),
        ),
    )
    facts = build_status_version_slice_facts()

    assert facts.apsw_version == "9.9.9.9"
    assert facts.sqlite_version == "9.9.9"
    assert facts.sqlite_source_id == "probe-sqlite-source-id"
    assert facts.apsw_version != _HISTORICAL_APSW
    assert facts.sqlite_version != _HISTORICAL_SQLITE


def test_absent_runtime_components_serialize_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "finishup.version._runtime_components",
        lambda: (_ABSENT, _ABSENT, _ABSENT, _ABSENT),
    )
    facts = build_status_version_slice_facts()

    assert facts.apsw_version == UNAVAILABLE_RUNTIME_FACT
    assert facts.sqlite_version == UNAVAILABLE_RUNTIME_FACT
    assert facts.sqlite_source_id == UNAVAILABLE_RUNTIME_FACT
    assert facts.python_version != UNAVAILABLE_RUNTIME_FACT
