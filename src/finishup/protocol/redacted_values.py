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
    "AGENT_REVISABLE_ITEM_PREFIXES",
    "MAX_SEMANTIC_REDACTED_VALUE_ITEMS",
    "MAX_SEMANTIC_REDACTED_VALUE_LINE",
    "MAX_SEMANTIC_REDACTED_VALUE_LINES",
    "SEMANTIC_REDACTED_VALUE_DISPOSITIONS",
    "SEMANTIC_REVIEW_BLOCK_MATCH_CLASSES",
    "SEMANTIC_REVIEW_BLOCK_STAGES",
    "SemanticRedactedValue",
    "SemanticRedactedValueDisposition",
    "SemanticReviewBlockMatchClass",
    "SemanticReviewBlockStage",
    "review_block_agent_revisable",
    "review_blocked_recorded",
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
# ``review_blocked`` (#1138): a credential-like match in this item stopped the whole AI-powered
# review and the refused content was not sent (an earlier exchange of the same conversation may
# have been); it names the privacy scan ``stage`` that refused and the match's confidence
# ``match_class``. The ``review-packet`` item stands for a match no single item explains
# (FinishUP's own packet structure, or content spanning items).
SEMANTIC_REDACTED_VALUE_DISPOSITIONS: Final = ("item_withheld", "review_blocked", "value_replaced")
SEMANTIC_REVIEW_BLOCK_STAGES: Final = ("candidate", "prepared_case", "reviewer_exchange")
SEMANTIC_REVIEW_BLOCK_MATCH_CLASSES: Final = ("heuristic", "high_confidence")
type SemanticRedactedValueDisposition = Literal["item_withheld", "review_blocked", "value_replaced"]
type SemanticReviewBlockStage = Literal["candidate", "prepared_case", "reviewer_exchange"]
type SemanticReviewBlockMatchClass = Literal["heuristic", "high_confidence"]


@dataclass(frozen=True, slots=True)
class SemanticRedactedValue:
    """One case item whose external-review copy lost credential-like values (PL2-1).

    A ``review_blocked`` entry (#1138) names an item whose match stopped the whole review, with
    the refusing ``stage`` and the match's ``match_class``; the other dispositions carry neither.
    """

    item_id: str
    disposition: SemanticRedactedValueDisposition
    lines: tuple[int, ...] = ()
    source_ref: str | None = None
    stage: SemanticReviewBlockStage | None = None
    match_class: SemanticReviewBlockMatchClass | None = None

    def __post_init__(self) -> None:
        invalid = "semantic_redacted_values_invalid"
        if type(self.item_id) is not str or _OPAQUE_ITEM_PATTERN.fullmatch(self.item_id) is None:
            raise ProtocolValueError(invalid)
        if self.disposition not in SEMANTIC_REDACTED_VALUE_DISPOSITIONS:
            raise ProtocolValueError(invalid)
        if self.disposition == "review_blocked":
            if (
                self.stage not in SEMANTIC_REVIEW_BLOCK_STAGES
                or self.match_class not in SEMANTIC_REVIEW_BLOCK_MATCH_CLASSES
            ):
                raise ProtocolValueError(invalid)
        elif self.stage is not None or self.match_class is not None:
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
        if self.stage is not None:
            wire["stage"] = self.stage
        if self.match_class is not None:
            wire["match_class"] = self.match_class
        return wire

    @classmethod
    def from_wire(cls, value: object) -> SemanticRedactedValue:
        invalid = "semantic_redacted_values_invalid"
        if not isinstance(value, Mapping):
            raise ProtocolValueError(invalid)
        source = cast(Mapping[object, object], value)
        if not set(source) <= {
            "disposition",
            "item_id",
            "lines",
            "source_ref",
            "stage",
            "match_class",
        } or not {
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
            cast(SemanticRedactedValueDisposition, source["disposition"]),
            tuple(cast(list[int], lines)),
            cast(str | None, source.get("source_ref")),
            cast(SemanticReviewBlockStage | None, source.get("stage")),
            cast(SemanticReviewBlockMatchClass | None, source.get("match_class")),
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


def review_blocked_recorded(values: tuple[SemanticRedactedValue, ...]) -> bool:
    """Whether any entry is ``review_blocked`` (#1138); only the newest record versions carry it."""

    return any(item.disposition == "review_blocked" for item in values)


# #966: review items whose text the agent itself published (a claim, obligation, plan goal,
# decision, its own disclosures or finding answers). A revision without the value is new
# content the next check composes; every other item (a task input, the check-time change,
# captured output or published evidence, the task statement, FinishUP's own rows, the packet
# structure) stays in the case as it is, so no agent action clears a block it caused.
AGENT_REVISABLE_ITEM_PREFIXES: Final = (
    "agent-disclosures",
    "claim-",
    "decision-",
    "goal-",
    "local-finding-answer-",
    "obligation-",
)


def review_block_agent_revisable(values: tuple[SemanticRedactedValue, ...]) -> bool | None:
    """Whether every ``review_blocked`` item is agent-published text; ``None`` with none named."""

    blocked = tuple(item for item in values if item.disposition == "review_blocked")
    if not blocked:
        return None
    return all(item.item_id.startswith(AGENT_REVISABLE_ITEM_PREFIXES) for item in blocked)
