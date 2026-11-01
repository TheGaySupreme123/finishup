"""Snapshot support for the terminal-UI renderers.

Snapshots are plain text files under ``snapshots/``. They exist so that the
exact wording of a safety-relevant screen — an integration preview, a privacy
disclosure, a readiness summary — cannot drift without a reviewer seeing the
diff. Regenerate deliberately with ``FINISHUP_UPDATE_SNAPSHOTS=1``; never as a
reflex when a test fails, because that is precisely the failure these lock.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

_SNAPSHOTS = Path(__file__).parent / "snapshots"


@pytest.fixture
def assert_snapshot() -> Callable[[str, Sequence[str]], None]:
    def check(name: str, lines: Sequence[str]) -> None:
        path = _SNAPSHOTS / f"{name}.txt"
        rendered = "\n".join(lines) + "\n"
        if os.environ.get("FINISHUP_UPDATE_SNAPSHOTS") == "1":
            if os.environ.get("CI"):
                pytest.fail("snapshot regeneration is disabled in CI")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered, encoding="utf-8")
            return
        assert path.is_file(), (
            f"missing snapshot {path.name}; regenerate with FINISHUP_UPDATE_SNAPSHOTS=1"
        )
        assert rendered == path.read_text(encoding="utf-8"), f"snapshot drift in {path.name}"

    return check
