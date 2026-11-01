"""Structural setup consent keeps other hosts' native content arms (issue #835)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import pytest

import finishup.adapters.integrations.observation_local as observation_local
import finishup.cli.observe as observe_cli
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import setup
from finishup.domain.observation import ObservationRevokeCommand
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.protocol.canonical import JsonValue
from finishup.tui.models import LayerState
from finishup.tui.runtime import FinishUpRuntime

_CLAUDE = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
_CURSOR = CURSOR_ORDINARY_OBSERVATION_PROFILE_ID


def _isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[LocalObservationStore, Path, str]:
    """Point the default store root (the one setup opens) at a disposable directory."""

    state = tmp_path / "state"
    monkeypatch.setattr(observation_local, "state_dir", lambda: state)
    workspace = tmp_path / "project"
    workspace.mkdir()
    store = LocalObservationStore()
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.set_runtime_enabled(True)
    return store, workspace, commitment


def test_codex_setup_consent_keeps_an_approved_claude_arm_and_its_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact reproduction from the issue, asserted the other way round."""

    store, workspace, commitment = _isolated(tmp_path, monkeypatch)
    store.grant_consent(commitment, content_capture_profiles=(_CLAUDE,))
    before = store.content_capture_authority(commitment)
    assert before is not None and before.active and before.profiles == (_CLAUDE,)

    report = setup._grant_observation_consent(workspace)  # pyright: ignore[reportPrivateUsage]

    assert report == {
        "outcome": "granted",
        "transition": "unchanged",
        "workspace_commitment": commitment,
        "content_capture_profiles": [_CLAUDE],
    }
    reopened = LocalObservationStore()
    after = reopened.content_capture_authority(commitment)
    assert after == before
    assert reopened.content_capture_authority_is_current(
        commitment, before.generation, before.profiles
    )


def test_codex_setup_consent_keeps_a_pending_selection_preview_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A selection preview binds the consent fence; routine setup must not stale it."""

    store, workspace, commitment = _isolated(tmp_path, monkeypatch)
    store.grant_consent(commitment, content_capture_profiles=(_CLAUDE,))
    preview_authority = observe_cli._selection_authority_digest(  # pyright: ignore[reportPrivateUsage]
        store, commitment
    )

    setup._grant_observation_consent(workspace)  # pyright: ignore[reportPrivateUsage]

    assert (
        observe_cli._selection_authority_digest(  # pyright: ignore[reportPrivateUsage]
            LocalObservationStore(), commitment
        )
        == preview_authority
    )


def test_codex_setup_consent_on_a_fresh_workspace_grants_no_content_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, workspace, commitment = _isolated(tmp_path, monkeypatch)

    report = setup._grant_observation_consent(workspace)  # pyright: ignore[reportPrivateUsage]

    assert report == {
        "outcome": "granted",
        "transition": "granted",
        "workspace_commitment": commitment,
        "content_capture_profiles": [],
    }
    assert store.content_capture_profiles(commitment) == ()


def test_codex_setup_consent_after_revocation_does_not_restore_the_revoked_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, workspace, commitment = _isolated(tmp_path, monkeypatch)
    store.grant_consent(commitment, content_capture_profiles=(_CLAUDE,))
    revoked = store.content_capture_authority(commitment)
    assert revoked is not None
    store.revoke(ObservationRevokeCommand(commitment))
    pending = store.pending_consent_revocation(commitment)
    assert pending is not None

    blocked = setup._grant_observation_consent(workspace)  # pyright: ignore[reportPrivateUsage]
    assert blocked["outcome"] == "failed"
    assert store.content_capture_profiles(commitment) == ()

    store.mark_consent_revocation_fenced(commitment, pending[0])
    report = setup._grant_observation_consent(workspace)  # pyright: ignore[reportPrivateUsage]

    assert report["transition"] == "granted"
    assert report["content_capture_profiles"] == []
    assert not store.content_capture_authority_is_current(
        commitment, revoked.generation, revoked.profiles
    )


def test_observe_grant_reports_the_arms_it_kept(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = str(tmp_path)
    assert observe_cli.grant_observation(workspace=workspace, _state=tmp_path) == 0
    first = capsys.readouterr().out
    assert "observation_content_capture_kept" not in first

    for profile in (_CURSOR, _CLAUDE):
        assert (
            observe_cli.enable_observation_content(
                profile=profile, workspace=workspace, _state=tmp_path
            )
            == 0
        )
    capsys.readouterr()
    assert observe_cli.grant_observation(workspace=workspace, _state=tmp_path) == 0

    out = capsys.readouterr().out
    assert "observation_consent_granted:hmac-sha256:" in out
    assert f"observation_content_capture_kept:{_CLAUDE},{_CURSOR}" in out
    assert workspace not in out
    store = LocalObservationStore(_state=tmp_path)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    assert store.content_capture_profiles(commitment) == (_CLAUDE, _CURSOR)


def test_setup_summary_names_the_content_arms_consent_kept(
    capsys: pytest.CaptureFixture[str],
) -> None:
    setup._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        {
            "registration": {
                "outcome": "already_registered",
                "observation_consent": {
                    "outcome": "granted",
                    "transition": "unchanged",
                    "workspace_commitment": "hmac-sha256:" + "a" * 64,
                    "content_capture_profiles": [_CLAUDE],
                },
            },
            "service": {"reachable": True, "state": "ready"},
            "provider": {},
            "integration": {},
            "next_steps": [],
        }
    )

    out = capsys.readouterr().out
    assert "Observation consent: granted" in out
    assert f"Native content profiles kept: {_CLAUDE}" in out


def test_terminal_interface_consent_layer_names_the_kept_arms(tmp_path: Path) -> None:
    runtime = FinishUpRuntime(cwd=tmp_path)

    def consent_layer(profiles: list[str]) -> tuple[LayerState, str]:
        outcome = runtime._integration_outcome(  # pyright: ignore[reportPrivateUsage]
            {
                "outcome": "already_registered",
                "state": "yoetz_owned",
                "observation_consent": {
                    "outcome": "granted",
                    "transition": "unchanged",
                    "content_capture_profiles": profiles,
                },
            }
        )
        layer = next(item for item in outcome.layers if item.key == "project_consent")
        return layer.state, layer.detail

    assert consent_layer([_CLAUDE]) == (
        LayerState.VERIFIED,
        f"native content profiles kept: {_CLAUDE}",
    )
    assert consent_layer([]) == (LayerState.VERIFIED, "")


def test_setup_summary_explains_background_advice_off_in_fixed_words(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue #888: a ready provider with background advice turned off by the owner names why."""

    setup._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        {
            "registration": {},
            "service": {"reachable": True, "state": "ready"},
            "provider": {},
            "integration": {},
            "readiness": {
                "observation_ready": True,
                "semantic_advice_ready": False,
                "semantic_advice_note": "background_advice_off:owner_disabled",
            },
            "next_steps": [],
        }
    )

    out = capsys.readouterr().out
    assert "AI-powered advice readiness: off (set to false" in out
    # The way back is named only where the owner turned it off.
    assert "set it to true" in out
    assert "background_advice_off:" not in out


@pytest.mark.parametrize(
    "note",
    [
        "background_advice_off:semantic_review_disabled",
        "background_advice_off:observation_disabled",
        "semantic_configuration_incomplete",
        "deterministic_only_until_provider_ready",
        "background_advice_unreadable",
    ],
)
def test_setup_summary_names_the_turn_on_hint_only_for_an_owner_false(
    capsys: pytest.CaptureFixture[str], note: str
) -> None:
    """Issue #888: advice is on by default, so no other note tells the owner to set ``true``."""

    setup._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        {
            "registration": {},
            "service": {"reachable": True, "state": "ready"},
            "provider": {},
            "integration": {},
            "readiness": {
                "observation_ready": True,
                "semantic_advice_ready": False,
                "semantic_advice_note": note,
            },
            "next_steps": [],
        }
    )

    out = capsys.readouterr().out
    assert "= true" not in out
    assert "set it to true" not in out


@pytest.mark.parametrize(
    "note",
    [
        "background_advice_off:unknown",
        "background_advice_off:a_reason_this_client_does_not_know",
        "background_advice_off:",
    ],
)
def test_setup_summary_never_renders_an_unreadable_background_advice_token(
    capsys: pytest.CaptureFixture[str], note: str
) -> None:
    """Issue #888: an absent or unrecognized advice reason renders fixed words, not the token."""

    setup._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        {
            "registration": {},
            "service": {"reachable": True, "state": "ready"},
            "provider": {},
            "integration": {},
            "readiness": {
                "observation_ready": True,
                "semantic_advice_ready": False,
                "semantic_advice_note": note,
            },
            "next_steps": [],
        }
    )

    out = capsys.readouterr().out
    assert "background_advice_off" not in out
    assert "a_reason_this_client_does_not_know" not in out
    assert "AI-powered advice readiness: not demonstrated" in out
    assert "background-advice setting could not be read" in out


@pytest.mark.parametrize(
    "advice",
    [
        None,
        "on",
        {},
        {"enabled": False},
        {"enabled": False, "reason": 7},
        {"enabled": False, "reason": "a_reason_this_client_does_not_know"},
        # A reason that contradicts ``enabled`` is unreadable, never rendered as its own text.
        {"enabled": False, "reason": "owner_enabled"},
        {"enabled": True, "reason": "owner_disabled"},
        {"enabled": True, "reason": "semantic_review_disabled"},
        {"enabled": False, "reason": "default_enabled"},
        {"enabled": True},
    ],
)
def test_setup_readiness_marks_absent_or_malformed_background_advice_unreadable(
    advice: object,
) -> None:
    """Issue #888: a status without a known advice fact is unreadable, never a raw reason."""

    status: dict[str, object] = {"semantic_ready": True}
    if advice is not None:
        status["background_advice"] = advice

    ready, note = setup._semantic_advice_readiness(status)  # pyright: ignore[reportPrivateUsage]

    assert ready is False
    assert note == "background_advice_unreadable"


def test_setup_readiness_keeps_known_background_advice_reasons() -> None:
    status = {
        "semantic_ready": True,
        "background_advice": {"enabled": False, "reason": "owner_disabled"},
    }

    assert setup._semantic_advice_readiness(status) == (  # pyright: ignore[reportPrivateUsage]
        False,
        "background_advice_off:owner_disabled",
    )
    # Issue #888: an unset switch is on by default where AI-powered review is configured.
    assert setup._semantic_advice_readiness(  # pyright: ignore[reportPrivateUsage]
        {
            "semantic_ready": True,
            "background_advice": {"enabled": True, "reason": "default_enabled"},
        }
    ) == (True, "configured_and_composed; live_provider_dispatch_not_tested")
    assert setup._semantic_advice_readiness(  # pyright: ignore[reportPrivateUsage]
        {"semantic_ready": True, "background_advice": {"enabled": True, "reason": "owner_enabled"}}
    ) == (True, "configured_and_composed; live_provider_dispatch_not_tested")
    assert setup._semantic_advice_readiness(  # pyright: ignore[reportPrivateUsage]
        {"semantic_ready": False}
    ) == (False, "semantic_configuration_incomplete")


_INTERNAL_TOKEN = re.compile(r"[a-z]+_[a-z_]+")


@pytest.mark.parametrize(
    ("note", "reason_words"),
    [
        ("semantic_configuration_incomplete", "AI-powered review provider is not ready"),
        (
            "deterministic_only_until_provider_ready",
            "local checks only until an AI-powered review provider is ready",
        ),
        ("configured_and_composed; live_provider_dispatch_not_tested", None),
        ("background_advice_unreadable", "background-advice setting could not be read"),
        ("background_advice_off:owner_enabled", "background-advice setting could not be read"),
        ("a_note_this_client_does_not_know", None),
        (None, None),
        (7, None),
    ],
)
def test_setup_summary_advice_line_never_renders_an_internal_token(
    capsys: pytest.CaptureFixture[str], note: object, reason_words: str | None
) -> None:
    """Issue #888: every advice note renders fixed words; no ``_``-joined token reaches people."""

    readiness: dict[str, object] = {"observation_ready": True, "semantic_advice_ready": False}
    if note is not None:
        readiness["semantic_advice_note"] = note
    setup._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        cast(
            dict[str, JsonValue],
            {
                "registration": {},
                "service": {"reachable": True, "state": "ready"},
                "provider": {},
                "integration": {},
                "readiness": readiness,
                "next_steps": [],
            },
        )
    )

    line = next(
        row for row in capsys.readouterr().out.splitlines() if "AI-powered advice readiness:" in row
    )
    assert _INTERNAL_TOKEN.search(line) is None, line
    assert line.strip().startswith("AI-powered advice readiness: not demonstrated")
    if reason_words is None:
        assert line.strip() == "AI-powered advice readiness: not demonstrated"
    else:
        assert reason_words in line
