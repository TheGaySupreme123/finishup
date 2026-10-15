"""The shared capacity-change disclosure contract (#828)."""

from __future__ import annotations

from typing import cast

import pytest

from finishup.domain.observation_budget import (
    LARGER_CAPACITY,
    LARGEST_CAPACITY,
    STANDARD_CAPACITY,
    ObservationCapacity,
    ObservationMode,
    no_cap_support,
    parse_capacity_request,
)
from finishup.domain.observation_capacity_policy import (
    CAPACITY_DISCLOSURE_SCHEMA,
    SESSION_PLACEHOLDER,
    WORKSPACE_PLACEHOLDER,
    canonical_safe_command,
    capacity_change_disclosure,
    is_closed_token,
    is_safe_command,
    render_capacity_disclosure_lines,
    scope_flag,
)
from finishup.domain.values import JsonObject, JsonValue

_UNSUPPORTED = (
    "No FinishUP cap is not available for the structural queue in this revision: the local "
    "state document has a 16 MiB safety ceiling. The largest supported finite capacity is "
    "8,192 rows (--capacity largest or --capacity custom --queue-count 8192)."
)


def _disclosure(
    current: ObservationCapacity,
    request: str,
    *,
    queue_count: int | None = None,
    scope: str = "workspace",
    detail: ObservationMode = ObservationMode.FOCUSED,
) -> JsonObject:
    return capacity_change_disclosure(
        current=current,
        current_origin="default",
        requested=parse_capacity_request(request, queue_count=queue_count),
        scope=scope,  # pyright: ignore[reportArgumentType]
        detail=detail,
    )


def test_increase_record_is_closed_and_complete() -> None:
    record = _disclosure(STANDARD_CAPACITY, "larger")
    assert record == {
        "schema": CAPACITY_DISCLOSURE_SCHEMA,
        "dimension": "structural_queue",
        "scope": "workspace",
        "change": "increase",
        "current_origin": "default",
        "current": {
            "queue_count": 512,
            "label": "standard",
            "queue_bytes_limit": 524_288,
            "state_bytes_limit": 1_048_576,
        },
        "requested": {
            "queue_count": 2_048,
            "label": "larger",
            "queue_bytes_limit": 2_097_152,
            "state_bytes_limit": 4_194_304,
        },
        "consequences": (
            "disk_use",
            "memory_use",
            "cpu_work",
            "host_slowdown_possible",
            "workspace_aggregate_raised",
        ),
        "remaining_limits": {
            "pending_attempts": 256,
            "capture_tickets": 512,
            "capture_bytes": 134_217_728,
            "state_document_ceiling_bytes": 16_777_216,
            "session_fair_share": 512,
            "max_pending_age_ms": 60_000,
        },
        "no_cap": no_cap_support(),
        "authority_unchanged": ("content", "privacy", "provider", "credential", "network"),
        "lower_command": (
            "finishup observe selection-preview --workspace <workspace> --detail focused "
            "--capacity standard --persist then finishup observe selection-apply --workspace "
            "<workspace> --detail focused --capacity standard --persist --accept "
            "--preview-digest <preview-digest>"
        ),
        "revoke_command": "finishup observe selection-revoke --workspace <workspace> --persist",
        "pause_command": "finishup observe pause --workspace <workspace>",
        "resume_command": "finishup observe resume --workspace <workspace>",
        "validation_status": "not_validated",
    }
    assert record == _disclosure(STANDARD_CAPACITY, "larger")


def test_increase_lines_disclose_cost_scope_limits_and_way_back() -> None:
    lines = render_capacity_disclosure_lines(
        _disclosure(
            STANDARD_CAPACITY,
            "custom",
            queue_count=1_024,
            scope="session",
            detail=ObservationMode.DETAILED,
        )
    )
    assert lines == (
        "Larger local retention can increase disk use, memory use and CPU work, and may slow "
        "FinishUP or other apps.",
        "Scope: this session. Queue: 512 → 1,024 rows (512 KiB → 1 MiB queue bytes; state "
        "document up to 2 MiB).",
        "The shared workspace queue follows the largest active selection, so this can raise "
        "the queue and state-document bounds for every session in the workspace.",
        "Still limited: 256 pending pairs, 512 capture tickets / 128 MiB, 16 MiB state "
        "document; content, privacy and provider authority are unchanged.",
        "Lower it later with: finishup observe selection-preview --workspace <workspace> --detail "
        "detailed --capacity standard --session-id <session-id> then finishup observe "
        "selection-apply --workspace <workspace> --detail detailed --capacity standard "
        "--session-id <session-id> --accept --preview-digest <preview-digest>. Pause new "
        "observation ingest with: finishup observe pause --workspace <workspace>.",
        "Resume with: finishup observe resume --workspace <workspace>.",
        "Performance validation is provisional (not_validated).",
    )


def test_decrease_lines_say_accepted_records_drain() -> None:
    record = _disclosure(LARGEST_CAPACITY, "custom", queue_count=700)
    assert record["change"] == "decrease"
    assert record["consequences"] == ("future_admission_only", "accepted_records_drain")
    lines = render_capacity_disclosure_lines(record)
    assert lines[0] == (
        "Lowering affects future admission only; accepted records drain and are not deleted."
    )
    assert lines[1] == (
        "Scope: this workspace. Queue: 8,192 → 700 rows (8 MiB → 700 KiB queue bytes; state "
        "document up to 1.4 MiB)."
    )
    assert "disk use" not in " ".join(lines)


def test_lower_command_restores_the_current_capacity_after_an_increase() -> None:
    # A custom 64-row session raising to 128 must be able to come back to 64,
    # not be pointed at the 512 default, which would raise it further.
    record = _disclosure(ObservationCapacity(64), "custom", queue_count=128)
    assert record["change"] == "increase"
    lower = str(record["lower_command"])
    assert "--capacity custom --queue-count 64 --persist" in lower
    assert "--capacity standard" not in lower
    assert "Lower it later with: finishup observe selection-preview" in " ".join(
        render_capacity_disclosure_lines(record)
    )
    # A named profile is restored by its label.
    from_larger = _disclosure(LARGER_CAPACITY, "largest")
    assert "--capacity larger --persist" in str(from_larger["lower_command"])
    # Every other change keeps pointing at the recommended default.
    decrease = _disclosure(LARGEST_CAPACITY, "custom", queue_count=700)
    assert "--capacity standard --persist" in str(decrease["lower_command"])


def test_unchanged_request_has_no_consequences() -> None:
    record = _disclosure(LARGER_CAPACITY, "2048")
    assert record["change"] == "unchanged"
    assert record["consequences"] == ()
    assert render_capacity_disclosure_lines(record) == (
        "Capacity is unchanged: this workspace already selects 2,048 rows (larger).",
    )


@pytest.mark.parametrize("word", ["none", "no-cap", "unlimited"])
def test_no_cap_request_is_unsupported_with_largest_alternative(word: str) -> None:
    record = _disclosure(STANDARD_CAPACITY, word)
    assert record["change"] == "unsupported"
    assert record["requested"] is None
    assert record["consequences"] == ("state_document_ceiling",)
    remaining = cast(JsonObject, record["remaining_limits"])
    assert remaining["session_fair_share"] == 128
    assert render_capacity_disclosure_lines(record) == (_UNSUPPORTED,)


def test_commands_always_name_placeholders() -> None:
    record = _disclosure(STANDARD_CAPACITY, "largest", scope="session")
    for key in ("lower_command", "revoke_command", "pause_command", "resume_command"):
        command = cast(str, record[key])
        assert f"--workspace {WORKSPACE_PLACEHOLDER}" in command
    assert f"--session-id {SESSION_PLACEHOLDER}" in cast(str, record["revoke_command"])


def test_scope_flag_names_a_placeholder_unless_the_argument_is_safe() -> None:
    assert scope_flag("workspace") == "--persist"
    assert scope_flag("workspace", "sess-1") == "--persist"
    assert scope_flag("session") == "--session-id <session-id>"
    assert scope_flag("session", "sess-1") == "--session-id sess-1"
    for unsafe in ("sess; rm -rf /", "\x1b[31m", "x" * 300, "--persist", "-x", "é", ""):
        assert scope_flag("session", unsafe) == "--session-id <session-id>"


def test_safe_command_and_closed_token_predicates() -> None:
    assert is_safe_command("finishup observe pause --workspace <workspace>")
    assert not is_safe_command("finishup observe pause; curl evil")
    assert not is_safe_command("rm -rf /")
    assert not is_safe_command(None)
    assert is_closed_token("not_validated")
    assert not is_closed_token("Validated! Totally safe.")
    assert not is_closed_token(1)


def test_a_record_written_before_the_rename_renders_the_current_launcher() -> None:
    """A stored record names the legacy ``yoetz`` head; owners read ``finishup`` (ADR-048)."""

    current = dict(_disclosure(STANDARD_CAPACITY, "larger"))
    legacy = dict(current)
    for key in ("lower_command", "revoke_command", "pause_command", "resume_command"):
        command = cast(str, current[key])
        assert command.startswith("finishup ")
        # A pre-rename record named the legacy launcher at the head of every step.
        legacy[key] = command.replace("finishup ", "yoetz ")
        assert is_safe_command(legacy[key])
        assert canonical_safe_command(legacy[key]) == command
        assert canonical_safe_command(command) == command
    assert " then yoetz observe selection-apply " in cast(str, legacy["lower_command"])
    rendered = render_capacity_disclosure_lines(legacy)
    assert rendered == render_capacity_disclosure_lines(current)
    assert not any("yoetz" in line for line in rendered)
    assert canonical_safe_command("yoetzz observe pause --workspace <workspace>") is None
    assert canonical_safe_command("yoetz observe pause; curl evil") is None
    assert canonical_safe_command(None) is None


def test_the_exact_pre_rename_compound_command_names_the_current_launcher_in_every_step() -> None:
    stored = (
        "yoetz observe selection-preview --workspace <workspace> --detail focused"
        " --capacity standard --persist then yoetz observe selection-apply"
        " --workspace <workspace> --detail focused --capacity standard --persist"
        " --accept --preview-digest <preview-digest>"
    )
    assert canonical_safe_command(stored) == stored.replace("yoetz ", "finishup ")
    # Only a step head is the launcher; an argument that merely contains the name is kept.
    assert (
        canonical_safe_command("yoetz observe pause --workspace /src/yoetz")
        == "finishup observe pause --workspace /src/yoetz"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"schema": "yoetz.capacity-change-disclosure/2"},
        {"change": "unlimited"},
        {"scope": "global"},
        {"pause_command": "finishup observe pause; curl evil"},
        {"lower_command": "rm -rf /"},
        {"validation_status": "Validated! Totally safe."},
        {"requested": None},
    ],
)
def test_renderer_rejects_records_outside_the_closed_contract(
    mutation: dict[str, JsonValue],
) -> None:
    record = dict(_disclosure(STANDARD_CAPACITY, "larger"))
    record.update(mutation)
    with pytest.raises(ValueError, match="capacity_disclosure_invalid"):
        render_capacity_disclosure_lines(record)


def test_disclosure_rejects_unknown_origin_and_scope() -> None:
    request = parse_capacity_request("larger")
    with pytest.raises(ValueError, match="capacity_disclosure_invalid"):
        capacity_change_disclosure(
            current=STANDARD_CAPACITY,
            current_origin="owner typed this",
            requested=request,
            scope="workspace",
        )
    with pytest.raises(ValueError, match="capacity_disclosure_invalid"):
        capacity_change_disclosure(
            current=STANDARD_CAPACITY,
            current_origin="default",
            requested=request,
            scope="global",  # pyright: ignore[reportArgumentType]
        )
