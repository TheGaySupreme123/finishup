"""Selection, approval, and entry view logic, without a terminal.

The rules asserted here are safety rules, not cosmetics: a disabled row must be
unreachable by every path that can select, an approval must not be reachable by
accident, and a searchable picker must not steal digits from the query.
"""

from __future__ import annotations

from finishup.tui.widgets.views import ApprovalView, Option, SelectionView, TextEntryView

ROWS = (
    Option("a", "Alpha"),
    Option("b", "Bravo", disabled=True, disabled_reason="not available"),
    Option("c", "Charlie"),
    Option("d", "Delta", disabled=True),
    Option("e", "Echo"),
)


def picker(**overrides: object) -> SelectionView:
    options = overrides.pop("options", ROWS)
    return SelectionView(name="test", options=options, **overrides)  # type: ignore[arg-type]


def test_the_cursor_starts_on_the_first_enabled_row() -> None:
    view = picker(options=(Option("x", "X", disabled=True), Option("y", "Y")))
    assert view.cursor == 1
    assert view.selected is not None
    assert view.selected.key == "y"


def test_arrow_navigation_skips_every_disabled_row() -> None:
    view = picker()
    assert view.selected.key == "a"  # pyright: ignore[reportOptionalMemberAccess]
    view.move(1)
    assert view.selected.key == "c"  # pyright: ignore[reportOptionalMemberAccess]
    view.move(1)
    assert view.selected.key == "e"  # pyright: ignore[reportOptionalMemberAccess]
    view.move(-1)
    assert view.selected.key == "c"  # pyright: ignore[reportOptionalMemberAccess]


def test_navigation_stops_at_the_ends_rather_than_wrapping_onto_a_disabled_row() -> None:
    view = picker()
    view.move(-10)
    assert view.selected.key == "a"  # pyright: ignore[reportOptionalMemberAccess]
    view.move(10)
    assert view.selected.key == "e"  # pyright: ignore[reportOptionalMemberAccess]


def test_home_and_end_land_on_enabled_rows() -> None:
    view = picker()
    view.jump(end=True)
    assert view.selected.key == "e"  # pyright: ignore[reportOptionalMemberAccess]
    view.jump(end=False)
    assert view.selected.key == "a"  # pyright: ignore[reportOptionalMemberAccess]


def test_a_number_shortcut_cannot_choose_a_disabled_row() -> None:
    view = picker()
    assert view.choose_number(2) is False  # Bravo is disabled
    assert view.choose_number(4) is False  # Delta is disabled
    assert view.cursor == 0


def test_a_number_beyond_the_list_selects_nothing() -> None:
    view = picker()
    assert view.choose_number(9) is False


def test_a_searchable_picker_does_not_interpret_printable_shortcuts() -> None:
    assert picker(searchable=True).accepts_printable_shortcuts is False
    assert picker(searchable=False).accepts_printable_shortcuts is True


def test_a_text_entry_never_interprets_printable_shortcuts() -> None:
    entry = TextEntryView(name="t", title="T", label="L")
    assert entry.accepts_printable_shortcuts is False


def test_filtering_ranks_exact_then_prefix_then_substring() -> None:
    view = picker(
        options=(
            Option("1", "Anthropic"),
            Option("2", "OpenAI"),
            Option("3", "OpenRouter"),
            Option("4", "Vercel AI Gateway", "openai compatible"),
        ),
        searchable=True,
    )
    view.filter("open")
    assert [option.label for option in view.options][:2] == ["OpenAI", "OpenRouter"]
    view.filter("openai")
    assert view.options[0].label == "OpenAI"


def test_filtering_to_nothing_leaves_no_selectable_option() -> None:
    view = picker(searchable=True)
    view.filter("zzzz")
    assert view.options == ()
    assert view.selected is None


def test_clearing_the_filter_restores_every_option() -> None:
    view = picker(searchable=True)
    view.filter("alpha")
    assert len(view.options) == 1
    view.filter("")
    assert view.options == ROWS


def test_a_view_dismisses_only_once() -> None:
    view = picker()
    posted: list[object] = []
    view.post_message = posted.append  # type: ignore[method-assign,assignment]
    view.dismiss("a")
    view.dismiss("a")
    assert len(posted) == 1


def test_an_approval_offers_the_decline_option_and_can_default_to_it() -> None:
    approval = ApprovalView(
        name="widen",
        title="Widen privacy?",
        body=("exact disclosure",),
        approve_label="Yes",
        decline_label="No",
        default_to_safe=True,
    )
    assert [option.label for option in approval.options] == ["Yes", "No"]
    # A privacy-widening approval never starts with the cursor on "yes".
    assert approval.selected is not None
    assert approval.selected.key == "decline"


def test_an_ordinary_approval_starts_on_the_affirmative_option() -> None:
    approval = ApprovalView(
        name="ok",
        title="Connect?",
        body=(),
        approve_label="Yes",
        decline_label="No",
    )
    assert approval.selected is not None
    assert approval.selected.key == "approve"
