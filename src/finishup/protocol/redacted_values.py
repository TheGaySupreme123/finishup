"""Structural locations of credential-like values withheld from the external reviewer (#982).

Owner-approved PL2-1: the agent may see which case items lost values on their way to the external
reviewer, and on which lines, but never a value, a byte offset, or a path.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast

from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import OPAQUE_ITEM_ID_PATTERN

__all__ = [
    "MAX_SEMANTIC_REDACTED_VALUE_ITEMS",
    "MAX_SEMANTIC_REDACTED_VALUE_LINE",
    "MAX_SEMANTIC_REDACTED_VALUE_LINES",
    "SEMANTIC_REDACTED_VALUE_DISPOSITIONS",
    "SemanticRedactedValue",
    "semantic_redacted_values_from_wire",
    "validate_semantic_redacted_values",
]

_OPAQUE_ITEM_PATTERN: Final[re.Pattern[str]] = re.compile(OPAQUE_ITEM_ID_PATTERN, re.ASCII)

# Owner-approved PL2-1 (issue #982): where the external reviewer's copy of the work differed from
# what local checks saw. Structural only: the opaque case item id, the item's catalogued ledger
# reference when it is itself an opaque token, and the 1-based line numbers in the item's own text
# where a credential-like value was replaced or matched. Never a value, a byte offset, or a path.
MAX_SEMANTIC_REDACTED_VALUE_ITEMS: Final = 64
MAX_SEMANTIC_REDACTED_VALUE_LINES: Final = 32
MAX_SEMANTIC_REDACTED_VALUE_LINE: Final = 2_147_483_647
SEMANTIC_REDACTED_VALUE_DISPOSITIONS: Final = ("item_withheld", "value_replaced")


@dataclass(frozen=True, slots=True)
class SemanticRedactedValue:
    """One case item whose external-review copy lost credential-like values (PL2-1)."""

    item_id: str
    disposition: Literal["item_withheld", "value_replaced"]
    lines: tuple[int, ...] = ()
    source_ref: str | None = None

    def __post_init__(self) -> None:
        invalid = "semantic_redacted_values_invalid"
        if type(self.item_id) is not str or _OPAQUE_ITEM_PATTERN.fullmatch(self.item_id) is None:
            raise ProtocolValueError(invalid)
        if self.disposition not in SEMANTIC_REDACTED_VALUE_DISPOSITIONS:
            raise ProtocolValueError(invalid)
        lines = cast(tuple[object, ...], self.lines)
        if (
            type(lines) is not tuple
            or len(lines) > MAX_SEMANTIC_REDACTED_VALUE_LINES
            or any(
                type(line) is not int or not 1 <= line <= MAX_SEMANTIC_REDACTED_VALUE_LINE
                for line in lines
            )
            or lines != tuple(sorted(set(cast(tuple[int, ...], lines))))
        ):
            raise ProtocolValueError(invalid)
        if self.source_ref is not None and (
            type(self.source_ref) is not str
            or _OPAQUE_ITEM_PATTERN.fullmatch(self.source_ref) is None
        ):
            raise ProtocolValueError(invalid)

    def as_wire(self) -> dict[str, object]:
        """Canonical JSON object; ``source_ref`` is omitted when unknown."""

        wire: dict[str, object] = {
            "disposition": self.disposition,
            "item_id": self.item_id,
            "lines": list(self.lines),
        }
        if self.source_ref is not None:
            wire["source_ref"] = self.source_ref
        return wire

    @classmethod
    def from_wire(cls, value: object) -> SemanticRedactedValue:
        invalid = "semantic_redacted_values_invalid"
        if not isinstance(value, Mapping):
            raise ProtocolValueError(invalid)
        source = cast(Mapping[object, object], value)
        if not set(source) <= {"disposition", "item_id", "lines", "source_ref"} or not {
            "disposition",
            "item_id",
            "lines",
        } <= set(source):
            raise ProtocolValueError(invalid)
        lines = source["lines"]
        if type(lines) not in {list, tuple}:
            raise ProtocolValueError(invalid)
        return cls(
            cast(str, source["item_id"]),
            cast(Literal["item_withheld", "value_replaced"], source["disposition"]),
            tuple(cast(list[int], lines)),
            cast(str | None, source.get("source_ref")),
        )


def validate_semantic_redacted_values(value: object) -> tuple[SemanticRedactedValue, ...]:
    """Validate the bounded, item-id-sorted, unique tuple carried on every surface."""

    invalid = "semantic_redacted_values_invalid"
    if type(value) is not tuple:
        raise ProtocolValueError(invalid)
    values = cast(tuple[object, ...], value)
    if len(values) > MAX_SEMANTIC_REDACTED_VALUE_ITEMS or any(
        type(item) is not SemanticRedactedValue for item in values
    ):
        raise ProtocolValueError(invalid)
    typed = cast(tuple[SemanticRedactedValue, ...], values)
    item_ids = tuple(item.item_id for item in typed)
    if item_ids != tuple(sorted(set(item_ids), key=str.encode)):
        raise ProtocolValueError(invalid)
    return typed


def semantic_redacted_values_from_wire(value: object) -> tuple[SemanticRedactedValue, ...]:
    """Decode the JSON array form; raises ``ProtocolValueError`` on any deviation."""

    if type(value) not in {list, tuple}:
        raise ProtocolValueError("semantic_redacted_values_invalid")
    return validate_semantic_redacted_values(
        tuple(SemanticRedactedValue.from_wire(item) for item in cast(list[object], value))
    )
