"""Property tests for the bounded-text composer (tb4n3 RC-2, #1025)."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from finishup.domain.bounded_text import compose_bounded, compose_bounded_detail

# Arbitrary Unicode, including lone surrogates, control characters and astral planes.
_TEXT = st.text(alphabet=st.characters(codec=None), min_size=0, max_size=120)
_ITEM = st.one_of(_TEXT, st.lists(_TEXT, max_size=4))
_LIMITS = st.integers(min_value=-5, max_value=600)


@settings(max_examples=300, deadline=None)
@given(
    required=st.lists(_TEXT, max_size=6),
    optional=st.lists(_ITEM, max_size=8),
    tail=st.lists(_TEXT, max_size=3),
    limit=_LIMITS,
    sep=st.sampled_from([" ", "; ", "\n", ""]),
)
def test_never_raises_ascii_and_within_limit(
    required: list[str],
    optional: list[str | list[str]],
    tail: list[str],
    limit: int,
    sep: str,
) -> None:
    text = compose_bounded(required, optional, limit, sep=sep, tail=tail)
    assert text.isascii()
    assert len(text.encode("ascii")) <= max(limit, 0)


@settings(max_examples=300, deadline=None)
@given(
    required=st.lists(st.text(alphabet="abcdef ;:", min_size=1, max_size=40), max_size=4),
    optional=st.lists(
        st.lists(st.text(alphabet="xyz", min_size=1, max_size=40), max_size=3), max_size=6
    ),
    limit=st.integers(min_value=0, max_value=400),
)
def test_required_survives_whenever_it_fits(
    required: list[str], optional: list[list[str]], limit: int
) -> None:
    cleaned = [part.strip() for part in required if part.strip()]
    fixed = " ".join(cleaned)
    text = compose_bounded(cleaned, optional, limit)
    if len(fixed) <= limit:
        assert text.startswith(fixed)
    else:
        detail = compose_bounded_detail(cleaned, optional, limit)
        assert detail.cut_required
