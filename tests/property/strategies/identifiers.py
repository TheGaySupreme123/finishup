"""Property strategies for the public identifier boundary."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from string import ascii_letters, digits
from typing import Final

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

__all__ = [
    "strategy_invalid_ids",
    "strategy_request_id_dicts",
    "strategy_valid_ids",
]

_VALID_REQUEST_ID: Final[str] = "req_00000000-0000-4000-8000-000000000001"
_ACTOR_ALPHABET: Final[str] = ascii_letters + digits + "._:-"
_NON_ACTOR_KINDS: Final[tuple[IdKind, ...]] = tuple(
    kind for kind in IdKind if kind is not IdKind.ACTOR
)


class _RaisingGetMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 0

    def get(self, key: str, default: object = None, /) -> object:
        raise RuntimeError(f"request_id lookup failed for {key!r}")


class _SpoofedMapping:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[dict[str, object]]:
        return dict

    def get(self, key: object, default: object = None, /) -> object:
        raise AssertionError("spoofed mapping should not have been queried")


class _CoercibleRequestId:
    def __str__(self) -> str:
        raise AssertionError("coercion was attempted")


def _canonical_uuid_texts() -> SearchStrategy[str]:
    return st.uuids(version=4).map(str)


def _valid_actor_ids() -> SearchStrategy[str]:
    return st.text(alphabet=_ACTOR_ALPHABET, min_size=1, max_size=128)


def _valid_value_for_kind(kind: IdKind) -> SearchStrategy[str]:
    if kind is IdKind.ACTOR:
        return _valid_actor_ids()
    return _canonical_uuid_texts().map(
        lambda suffix, prefix=PREFIX_BY_KIND[kind]: prefix + suffix,
    )


strategy_valid_ids: SearchStrategy[tuple[IdKind, str]] = st.sampled_from(tuple(IdKind)).flatmap(
    lambda kind: st.tuples(st.just(kind), _valid_value_for_kind(kind)),
)


@st.composite
def _invalid_ids(draw: st.DrawFn) -> tuple[IdKind, object, str]:
    case = draw(
        st.sampled_from(
            (
                "wrong-prefix",
                "wrong-length",
                "wrong-case",
                "nil-uuid",
                "wrong-version",
                "wrong-variant",
                "non-ascii",
                "actor-format",
            ),
        ),
    )
    if case == "wrong-prefix":
        kind = draw(st.sampled_from(_NON_ACTOR_KINDS))
        other_kind = draw(st.sampled_from(tuple(k for k in _NON_ACTOR_KINDS if k is not kind)))
        return (
            kind,
            PREFIX_BY_KIND[other_kind] + draw(_canonical_uuid_texts()),
            "id_wrong_prefix",
        )
    if case == "wrong-length":
        kind = draw(st.sampled_from(_NON_ACTOR_KINDS))
        uuid_text = draw(_canonical_uuid_texts())
        return kind, PREFIX_BY_KIND[kind] + uuid_text[:-1], "id_wrong_length"
    if case == "wrong-case":
        kind = draw(st.sampled_from(_NON_ACTOR_KINDS))
        uuid_text = draw(_canonical_uuid_texts())
        return kind, PREFIX_BY_KIND[kind] + uuid_text.upper(), "id_malformed_uuid"
    if case == "nil-uuid":
        kind = draw(st.sampled_from(_NON_ACTOR_KINDS))
        return (
            kind,
            PREFIX_BY_KIND[kind] + "00000000-0000-0000-0000-000000000000",
            "id_uuid_not_version_4",
        )
    if case == "wrong-version":
        kind = draw(st.sampled_from(_NON_ACTOR_KINDS))
        return (
            kind,
            PREFIX_BY_KIND[kind] + "00000000-0000-5000-8000-000000000001",
            "id_uuid_not_version_4",
        )
    if case == "wrong-variant":
        kind = draw(st.sampled_from(_NON_ACTOR_KINDS))
        return (
            kind,
            PREFIX_BY_KIND[kind] + "00000000-0000-4000-7000-000000000001",
            "id_uuid_wrong_variant",
        )
    if case == "non-ascii":
        kind = draw(st.sampled_from(_NON_ACTOR_KINDS))
        uuid_text = draw(_canonical_uuid_texts())
        return kind, PREFIX_BY_KIND[kind] + uuid_text[:-1] + "é", "id_not_ascii"
    return draw(
        st.sampled_from(
            (
                (IdKind.ACTOR, "", "actor_id_malformed"),
                (IdKind.ACTOR, "actor has spaces", "actor_id_malformed"),
                (IdKind.ACTOR, "agt!bad", "actor_id_malformed"),
                (IdKind.ACTOR, "x" * 129, "id_wrong_length"),
            ),
        ),
    )


strategy_invalid_ids: SearchStrategy[tuple[IdKind, object, str]] = _invalid_ids()


strategy_request_id_dicts: SearchStrategy[object] = st.one_of(
    st.just({"request_id": _VALID_REQUEST_ID}),
    st.just({}),
    st.just(None),
    st.just([]),
    st.just("not-a-mapping"),
    st.dictionaries(
        keys=st.text(min_size=1, max_size=8),
        values=st.one_of(
            st.integers(),
            st.text(min_size=0, max_size=16),
            st.binary(min_size=0, max_size=16),
            st.none(),
        ),
        max_size=4,
    ),
    st.fixed_dictionaries({"request_id": st.one_of(st.integers(), st.text(), st.none())}),
    st.fixed_dictionaries({"request_id": st.just(_CoercibleRequestId())}),
    st.fixed_dictionaries({"request_id": st.just(_VALID_REQUEST_ID + "0")}),
    st.fixed_dictionaries(
        {"request_id": st.text(alphabet=_ACTOR_ALPHABET, min_size=1, max_size=16)}
    ),
    st.builds(_RaisingGetMapping),
    st.builds(_SpoofedMapping),
)
