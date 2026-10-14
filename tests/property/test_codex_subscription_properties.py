"""Property checks for the closed Codex subscription child environment."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from hypothesis import given
from hypothesis import strategies as st

from finishup.adapters.providers import codex_app_server as module
from finishup.adapters.providers.codex_app_server import (
    CODEX_APP_SERVER_SCHEMA_SHA256,
    CODEX_EVALUATOR_CAPABILITY_CELL_SHA256,
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    CodexAppServerProfile,
)
from finishup.adapters.providers.data_use_catalog import data_use_record_for_endpoint


def _profile() -> CodexAppServerProfile:
    return CodexAppServerProfile(
        provider_id="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        endpoint_profile_version="1.0.0",
        executable_path=Path("/opt/codex/0.157.1/codex"),
        executable_sha256="sha256:27ceb5f9b957b43a519efe4eaa3816a0bffb0a531a2c89af18840c0a3c016a7d",
        runtime_version="0.157.1",
        source_identity="openai-codex-npm-darwin-arm64-0.157.1",
        app_server_schema_sha256=CODEX_APP_SERVER_SCHEMA_SHA256,
        capability_cell_sha256=CODEX_EVALUATOR_CAPABILITY_CELL_SHA256,
        capability_profile=CODEX_EVALUATOR_CAPABILITY_PROFILE,
        capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        codex_home=Path("/var/lib/finishup/codex-0.150.1"),
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        model="gpt-5.6-sol",
        reasoning_effort="high",
        timeout_seconds=30,
        data_use_profile=data_use_record_for_endpoint("codex-chatgpt-subscription").profile,
    )


_ENVIRONMENT = st.dictionaries(
    keys=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_", min_size=1, max_size=24),
    values=st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=80),
    max_size=20,
)


@given(_ENVIRONMENT)
def test_ambient_environment_cannot_change_the_child_authority(
    ambient: dict[str, str],
) -> None:
    profile = _profile()
    expected = {
        "CODEX_HOME": str(profile.codex_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "RUST_LOG": "error",
    }

    with patch.dict(os.environ, ambient, clear=True):
        assert module._process_environment(profile) == expected  # pyright: ignore[reportPrivateUsage]
