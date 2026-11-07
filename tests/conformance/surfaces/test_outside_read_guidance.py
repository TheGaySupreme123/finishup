"""Shipped guidance tells an agent what to do when review could not read a file outside the work.

Refusal-guide review (ADR-051 decision 5): a check can report `task_input_outside_not_admitted`
(the service's policy admits no root for the file) or `outside_reads_not_listed` (a remote
server's owner kept the file from that server in listed mode). Copying either file into the
workspace would send it to review against the owner's choice, so the guidance forbids it, names
the owner's command with its full arguments, says on which computer it runs, and never asks the
agent to run it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_GUIDANCE: Final = _REPO_ROOT / "guidance"


def _collapsed(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_review_guidance_forbids_copying_a_file_review_could_not_read() -> None:
    review = _collapsed(_GUIDANCE / "review.md")

    assert (
        "If a check reports `task_input_outside_not_admitted` or `outside_reads_not_listed`, do"
        " not copy, move or restate those files into the workspace" in review
    )
    assert "(receipt.md#final-prose)" in review


def test_final_prose_names_each_owner_step_and_where_it_runs() -> None:
    receipt = _collapsed(_GUIDANCE / "receipt.md")
    final = receipt[receipt.index("## Final prose") :]

    assert "never take it yourself" in final
    assert "`finishup privacy input-roots add <folder>`" in final
    # A remote server's own folders are listed on the client (ADR-051 decision 5, 2026-11-07).
    assert (
        "for a remote server, `finishup server folders add NAME FOLDER`, run on the computer that"
        " holds the project" in final
    )
    assert "`finishup server folders add NAME FOLDER` for a file outside the project" in final
    assert "`finishup server folders mode NAME local`" in final
    assert "the only step for a test in the project that Git ignores" in final
    assert "on the computer that holds the project" in final
