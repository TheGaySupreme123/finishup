"""Property checks for the closed Codex subscription child environment."""

from __future__ import annotations

import os
from unittest.mock import patch

from hypothesis import given
from hypothesis import strategies as st

from builders.codex_capability import profile_for
from finishup.adapters.providers import codex_app_server as module
from finishup.adapters.providers.codex_app_server import CodexAppServerProfile


def _profile() -> CodexAppServerProfile:
    return profile_for()


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
