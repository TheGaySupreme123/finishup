"""The bounded-text composer (tb4n3 RC-2, #1025): required kept, optional shrinks, never raises."""

from __future__ import annotations

import pytest

from yoetz.domain.bounded_text import (
    DEFAULT_CUT_MARKER,
    Part,
    ascii_safe,
    clip_to_limit,
    compose_bounded,
    compose_bounded_detail,
    compose_parts,
    list_variants,
)


def test_everything_fits_keeps_order_required_optional_tail() -> None:
    text = compose_bounded(["head"], [["opt-a"], ["opt-b"]], 100, tail=["frontier: 1."])
    assert text == "head opt-a opt-b frontier: 1."


def test_optional_takes_the_longest_variant_that_fits() -> None:
    long_variant = "x" * 30
    short_variant = "y" * 10
    text = compose_bounded(["head"], [[long_variant, short_variant]], 20)
    assert text == f"head {short_variant}"
    detail = compose_bounded_detail(["head"], [[long_variant, short_variant]], 20)
    assert detail.shortened == (0,) and detail.kept == (0,) and detail.dropped == ()


def test_optional_item_with_no_fitting_variant_is_dropped_and_reported() -> None:
    detail = compose_bounded_detail(["head"], [["x" * 50, "y" * 40]], 20)
    assert detail.text == "head"
    assert detail.dropped == (0,)


def test_earlier_optional_has_priority_and_a_later_small_one_still_fills_leftover() -> None:
    text = compose_bounded(["head"], [["A" * 12], ["B" * 12], ["c" * 3]], 24)
    assert text == "head " + "A" * 12 + " ccc"


def test_required_is_never_dropped_to_make_room_for_optional() -> None:
    text = compose_bounded(["verdict: ok"], [["z" * 200]], 40, tail=["frontier: 7."])
    assert text == "verdict: ok frontier: 7."


def test_required_over_budget_is_cut_with_a_visible_marker() -> None:
    detail = compose_bounded_detail(["a" * 100, "frontier: 7."], [["opt"]], 60)
    assert len(detail.text) <= 60
    assert detail.cut_required is True
    assert DEFAULT_CUT_MARKER in detail.text
    assert "frontier: 7." in detail.text
    assert detail.dropped == (0,)


def test_hard_cut_when_every_part_is_already_tiny() -> None:
    text = compose_bounded(["a", "b", "c", "d", "e", "f"], [], 5)
    assert len(text) <= 5
    assert text.endswith(DEFAULT_CUT_MARKER)


@pytest.mark.parametrize("limit", [0, -1, 1, 2, 3])
def test_degenerate_limits_never_raise(limit: int) -> None:
    text = compose_bounded(["required text"], [["optional"]], limit)
    assert len(text) <= max(limit, 0)


def test_a_bare_string_is_one_part_not_a_sequence_of_characters() -> None:
    assert compose_bounded("abc", ["def"], 50, tail="ghi") == "abc def ghi"


def test_parts_are_trimmed_and_empty_parts_skipped() -> None:
    assert compose_bounded(["a; ", ""], [["  ", "b; "]], 50, tail=["c."]) == "a; b; c."


def test_non_ascii_never_raises_and_is_folded_or_replaced() -> None:
    text = compose_bounded(["café — done …"], [["\U0001f600"]], 100)
    assert text.isascii()
    assert "?" in text and " - done ..." in text


def test_lone_surrogate_does_not_raise() -> None:
    text = compose_bounded(["bad \ud800 text"], [], 50)
    assert text.isascii()


def test_control_characters_become_question_marks() -> None:
    assert ascii_safe("a\x00b\x07c\nd") == "a?b?c\nd"


def test_ascii_only_false_counts_characters_and_keeps_text() -> None:
    text = compose_bounded(["café"], [["— more"]], 20, ascii_only=False)
    assert text == "café — more"


def test_clip_to_limit_marks_the_cut() -> None:
    assert clip_to_limit("abcdefghij", 8) == "abcde..."
    assert clip_to_limit("abc", 8) == "abc"
    assert clip_to_limit("abc", 0) == ""
    assert clip_to_limit("abcdef", 2) == ".."


def test_compose_parts_renders_in_list_order_but_grants_room_by_priority() -> None:
    parts = [
        Part(("lead",), required=True),
        Part(("low-priority-clause",), priority=9),
        Part(("high-priority-clause",), priority=1),
        Part(("frontier: 5.",), required=True),
    ]
    roomy = compose_parts(parts, 200)
    assert roomy.text == "lead low-priority-clause high-priority-clause frontier: 5."
    tight = compose_parts(parts, 40)
    assert tight.text == "lead high-priority-clause frontier: 5."
    assert tight.dropped == (1,)


def test_a_required_part_keeps_its_shortest_variant_until_room_upgrades_it() -> None:
    parts = [
        Part(("a very long explanatory lead " * 3, "short lead"), required=True),
        Part(("frontier: 5.",), required=True),
    ]
    assert compose_parts(parts, 40).text == "short lead frontier: 5."
    assert compose_parts(parts, 40).shortened == (0,)
    assert compose_parts(parts, 400).text.startswith("a very long explanatory lead")


def test_required_upgrade_outranks_every_optional_part() -> None:
    parts = [
        Part(("L" * 30, "l" * 5), required=True),
        Part(("o" * 20,)),
    ]
    assert compose_parts(parts, 40).text == "L" * 30
    assert compose_parts(parts, 40).dropped == (1,)
    assert compose_parts(parts, 60).text == "L" * 30 + " " + "o" * 20


def test_list_variants_shrinks_one_value_at_a_time_and_counts_the_rest() -> None:
    variants = list_variants("ids: ", ["a", "b", "c"], suffix=";")
    assert variants == ("ids: a, b, c;", "ids: a, b; +1 more;", "ids: a; +2 more;")
    assert list_variants("ids: ", []) == ()
    thinned = list(list_variants("ids: ", [f"v{n}" for n in range(500)], max_variants=16))
    assert 2 <= len(thinned) <= 17
    assert thinned[0].endswith("v499") and thinned[-1].startswith("ids: v0; +499 more")


def test_list_variants_pick_the_most_values_that_fit() -> None:
    values = [f"fnd_{n:04d}" for n in range(30)]
    text = compose_bounded(["head"], [list_variants("ids: ", values)], 100)
    assert len(text) <= 100
    assert "+" in text and "more" in text
    shown = text.split("ids: ")[1].split(";")[0].split(", ")
    assert shown == values[: len(shown)] and len(shown) > 3
