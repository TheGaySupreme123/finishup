"""Slash-command catalog, ranking, and resolution."""

from __future__ import annotations

from finishup.tui.commands import SLASH_COMMANDS, command_named, filter_commands


def test_the_documented_commands_are_all_present_with_descriptions() -> None:
    names = {command.name for command in SLASH_COMMANDS}
    assert {
        "status",
        "work",
        "lineage",
        "project",
        "findings",
        "check",
        "receipt",
        "connect",
        "privacy",
        "provider",
        "service",
        "doctor",
        "help",
        "quit",
    } <= names
    assert all(command.summary and command.summary[0].islower() for command in SLASH_COMMANDS)
    assert all(command.token.startswith("/") for command in SLASH_COMMANDS)
    work = next(command for command in SLASH_COMMANDS if command.name == "work")
    assert "by session ID" in work.summary
    assert "browse" not in work.summary


def test_an_empty_query_lists_everything_in_catalog_order() -> None:
    assert filter_commands("/") == SLASH_COMMANDS
    assert filter_commands("") == SLASH_COMMANDS


def test_exact_and_prefix_matches_outrank_substring_matches() -> None:
    # '/s' must not put '/status' behind '/service' or a description hit.
    assert filter_commands("/st")[0].name == "status"
    assert filter_commands("/status")[0].name == "status"
    ranked = [command.name for command in filter_commands("/c")]
    assert ranked[:2] == ["check", "connect"]


def test_a_description_only_hit_ranks_last_but_still_appears() -> None:
    matches = [command.name for command in filter_commands("/protected")]
    assert matches == ["service"]
    assert filter_commands("/receipt")[0].name == "receipt"


def test_unknown_queries_return_nothing_rather_than_a_wrong_guess() -> None:
    assert filter_commands("/zzzz") == ()
    assert command_named("/zzzz") is None


def test_command_named_accepts_a_bare_name_and_ignores_arguments() -> None:
    assert command_named("status") is not None
    assert command_named("/status").name == "status"  # pyright: ignore[reportOptionalMemberAccess]
    assert command_named("/receipt markdown").name == "receipt"  # pyright: ignore[reportOptionalMemberAccess]
    assert command_named("") is None
