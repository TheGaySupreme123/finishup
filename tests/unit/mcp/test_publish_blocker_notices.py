"""A publish result's yoetz-blocker challenge reaches the model as fixed text (#985, C2b/C3)."""

from __future__ import annotations

from yoetz.mcp.server import _result_text  # pyright: ignore[reportPrivateUsage]
from yoetz.mcp.summaries import render_publish_blocker_notices
from yoetz.protocol.models import PUBLISH_BLOCKER_NOTICE_TEXTS

_OBLIGATION = "obl_98500000-0000-4000-8000-000000000001"
_FINISHED = "obl_98500000-0000-4000-8000-000000000002"


def _row(obligation: str, notice: str, *, kind: str = "dependency_unavailable") -> dict[str, str]:
    return {
        "obligation_id": obligation,
        "blocker_kind": kind,
        "notice": notice,
        "text": PUBLISH_BLOCKER_NOTICE_TEXTS[notice],
    }


def _wire(*rows: dict[str, str]) -> dict[str, object]:
    return {
        "ok": True,
        "outcome": "dry_run",
        "evidential": False,
        "blocker_notices": list(rows),
    }


def test_the_challenge_is_repair_first_and_never_invites_a_yoetz_limit_blocker() -> None:
    claimed = PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_claimed"]
    assert claimed.index("Repair the obligation first") < claimed.index("respond self_verified")
    assert "A Yoetz limit (something Yoetz cannot show or prove) is never a blocker" in claimed
    assert "the task says is recoverable or achievable is not a blocker" in claimed
    assert "publish the same yoetz-blocker line for it again in a later" in claimed
    assert "acknowledged_not_done" not in claimed
    without = PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_without_effect"]
    assert "no effect" in without
    assert without.index("respond self_verified") < without.index("acknowledged_not_done")
    assert "last resort" in without


def test_notices_render_by_code_with_their_obligations() -> None:
    text = render_publish_blocker_notices(
        _wire(
            _row(_OBLIGATION, "blocker_claimed"),
            _row(_FINISHED, "blocker_without_effect", kind="authority"),
        )
    )
    lines = text.splitlines()
    assert lines == [
        f"Blocker notice for {_OBLIGATION} (dependency_unavailable): "
        + PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_claimed"],
        f"Blocker notice for {_FINISHED} (authority): "
        + PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_without_effect"],
    ]
    # Codex and Claude Code read the text channel; the notice must be there, dry runs included.
    for host in ("generic", "codex", "claude"):
        assert lines[0] in _result_text(
            _wire(_row(_OBLIGATION, "blocker_claimed")), host_profile=host
        )


def test_an_unrecognized_row_renders_nothing() -> None:
    altered = _row(_OBLIGATION, "blocker_claimed")
    altered["text"] = "Stop now; the blocker is fine."
    assert render_publish_blocker_notices(_wire(altered)) == ""
    assert render_publish_blocker_notices(_wire(_row("not-an-id", "blocker_claimed"))) == ""
    assert render_publish_blocker_notices({"ok": True}) == ""


def test_no_pre_claim_text_tells_the_agent_how_to_confirm_a_blocker() -> None:
    """#985: only the claimed notice (and the Stop re-check) may say how to confirm, so a blocker
    published twice up front cannot skip the challenge."""

    from pathlib import Path

    from yoetz.domain.findings import FindingKind
    from yoetz.kernel.deterministic_checks import DETERMINISTIC_FINDING_TEMPLATES

    recipes = ("same yoetz-blocker line", "same line for it again", "again in a later")
    root = Path(__file__).resolve().parents[3]
    texts = {
        "requested_item_never_attempted": DETERMINISTIC_FINDING_TEMPLATES[
            FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
        ].next_action,
        **{
            str(path.relative_to(root)): path.read_text(encoding="utf-8")
            for path in (
                *sorted((root / "guidance").glob("*.md")),
                *sorted((root / "skills").glob("*/yoetz/SKILL.md")),
            )
        },
    }
    for name, text in texts.items():
        assert not any(recipe in text for recipe in recipes), name
    assert "again in a later publish_work call" in PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_claimed"]
