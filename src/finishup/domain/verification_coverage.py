"""Bounded, agent-declared verification facts; never a correctness certificate."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, cast

from finishup.domain.values import ActionId, ResultId, action_id, result_id
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import ProtocolValueError

MAX_COVERAGE_CRITERIA: Final = 24
MAX_CRITERION_WITNESSES: Final = 3
# A quote must name something beyond punctuation, articles, modals and quantifiers, or it
# would match every stated criterion at once (#1170 review). Numbers such as 1.06 count.
MIN_CRITERION_CONTENT_CHARACTERS: Final = 3
_QUOTE_TOKEN: Final = re.compile(r"\w+(?:[.,']\w+)*")
_QUOTE_STOPWORDS: Final = frozenset(
    {
        "a",
        "all",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "been",
        "being",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "each",
        "every",
        "for",
        "from",
        "had",
        "has",
        "have",
        "if",
        "in",
        "is",
        "it",
        "its",
        "least",
        "less",
        "may",
        "might",
        "more",
        "most",
        "must",
        "no",
        "none",
        "not",
        "of",
        "on",
        "or",
        "shall",
        "should",
        "some",
        "than",
        "that",
        "the",
        "then",
        "these",
        "this",
        "those",
        "to",
        "was",
        "were",
        "when",
        "which",
        "will",
        "with",
        "would",
    }
)
CoverageFlag = Literal[
    "no_test",
    "failing_cases",
    "own_or_tuned_only",
    "public_only",
    "stale",
    "repeated_run",
    "redundant_tests",
]
CriterionSource = Literal["task_statement", "obligation", "manifest_quote"]
VERIFICATION_COVERAGE_FLAGS: Final = (
    "no_test",
    "failing_cases",
    "own_or_tuned_only",
    "public_only",
    "stale",
    "repeated_run",
    "redundant_tests",
)
VERIFICATION_DATA_SOURCES: Final = (
    "task_public",
    "own_generated",
    "independent",
    "held_out",
    "stated_environment",
    "unknown",
)
# Human labels. Data scope and tuning are independent axes: public cases the agent tuned on
# carry both ``public_only`` and ``own_or_tuned_only``, and the labels say so plainly.
_FLAG_LABELS: Final[Mapping[str, str]] = {
    "no_test": "no test",
    "failing_cases": "failing cases",
    "own_or_tuned_only": "only own-generated or tuned-on cases",
    "public_only": "only task-public cases",
    "stale": "stale",
    "repeated_run": "candidate repeat on same recorded work",
    "redundant_tests": "candidate redundant tests",
}


def criterion_quote_is_specific(quote: str) -> bool:
    """Whether ``quote`` names more than punctuation and common function words."""

    return (
        sum(
            len(re.sub(r"\W", "", token))
            for token in _QUOTE_TOKEN.findall(quote)
            if token.casefold() not in _QUOTE_STOPWORDS
        )
        >= MIN_CRITERION_CONTENT_CHARACTERS
    )


def criterion_quote_pattern(quote: str) -> re.Pattern[str] | None:
    """The whole-word occurrence pattern of a specific ``quote``, or ``None`` if it is generic."""

    if not quote or not criterion_quote_is_specific(quote):
        return None
    start = r"(?<!\w)(?<!\d[.,])" if re.match(r"\w", quote[0]) else ""
    end = r"(?!\w)(?![.,]\d)" if re.match(r"\w", quote[-1]) else ""
    return re.compile(start + re.escape(quote) + end)


def criterion_quote_in_text(quote: str, text: str) -> bool:
    """Whether a specific ``quote`` occurs verbatim in ``text`` at word boundaries.

    ``1`` inside ``1.06`` or ``atio`` inside ``ratio`` is not an occurrence. This is the
    admission rule and the only way a witness quote can map a longer candidate criterion.
    """

    pattern = criterion_quote_pattern(quote)
    return pattern is not None and pattern.search(text) is not None


def criterion_quote_position(quote: str, text: str) -> int:
    """The offset of the first whole-word occurrence of ``quote`` in ``text``, or ``-1``."""

    pattern = criterion_quote_pattern(quote)
    match = None if pattern is None else pattern.search(text)
    return -1 if match is None else match.start()


def coverage_flag_label(flag: str) -> str:
    return _FLAG_LABELS.get(flag, flag.replace("_", " "))


@dataclass(frozen=True, slots=True)
class VerificationWitness:
    result_id: ResultId
    action_id: ActionId
    data_source: str
    cases: int
    failing: int
    tuned_on_these_cases: bool | None = None
    worst: str | None = None
    stale: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "result_id", result_id(self.result_id))
        object.__setattr__(self, "action_id", action_id(self.action_id))
        if (
            self.data_source not in VERIFICATION_DATA_SOURCES
            or type(self.cases) is not int
            or not 0 <= self.cases <= 2**53 - 1
            or type(self.failing) is not int
            or not 0 <= self.failing <= self.cases
            or (
                self.tuned_on_these_cases is not None
                and type(self.tuned_on_these_cases) is not bool
            )
            or (
                self.worst is not None
                and (type(self.worst) is not str or not 1 <= len(self.worst) <= 64)
            )
            or type(self.stale) is not bool
        ):
            raise ProtocolValueError("invalid_event_value_type")


@dataclass(frozen=True, slots=True)
class VerificationCriterion:
    criterion_quote: str
    source: CriterionSource
    flags: tuple[CoverageFlag, ...] = ()
    witnesses: tuple[VerificationWitness, ...] = ()
    unresolved_failing_runs: int = 0
    repeated_runs: int = 0
    redundant_tests: int = 0
    omitted_witnesses: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.criterion_quote) is not str
            or not 1 <= len(self.criterion_quote) <= 240
            or self.source not in {"task_statement", "obligation", "manifest_quote"}
            or type(self.flags) is not tuple
            or any(value not in VERIFICATION_COVERAGE_FLAGS for value in self.flags)
            or len(set(self.flags)) != len(self.flags)
            or type(self.witnesses) is not tuple
            or len(self.witnesses) > MAX_CRITERION_WITNESSES
            or any(type(value) is not VerificationWitness for value in self.witnesses)
            or any(
                type(value) is not int or not 0 <= value <= 2**53 - 1
                for value in (
                    self.unresolved_failing_runs,
                    self.repeated_runs,
                    self.redundant_tests,
                    self.omitted_witnesses,
                )
            )
        ):
            raise ProtocolValueError("invalid_event_value_type")


@dataclass(frozen=True, slots=True)
class VerificationCoverage:
    criteria: tuple[VerificationCriterion, ...] = ()
    omitted_criteria: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.criteria) is not tuple
            or len(self.criteria) > MAX_COVERAGE_CRITERIA
            or any(type(value) is not VerificationCriterion for value in self.criteria)
            or type(self.omitted_criteria) is not int
            or not 0 <= self.omitted_criteria <= 2**53 - 1
        ):
            raise ProtocolValueError("invalid_event_value_type")


def verification_coverage_to_json(value: VerificationCoverage) -> dict[str, JsonValue]:
    return {
        "label": "agent-declared",
        "advisory": True,
        "omitted_criteria": value.omitted_criteria,
        "criteria": [
            {
                (
                    "obligation_criterion_quote"
                    if row.source == "obligation"
                    else "task_criterion_quote"
                ): row.criterion_quote,
                "source": row.source,
                "flags": list(row.flags),
                "unresolved_failing_runs": row.unresolved_failing_runs,
                "repeated_runs": row.repeated_runs,
                "redundant_tests": row.redundant_tests,
                "omitted_witnesses": row.omitted_witnesses,
                "witnesses": [
                    {
                        "result_id": witness.result_id,
                        "action_id": witness.action_id,
                        "data_source": witness.data_source,
                        "cases": witness.cases,
                        "failing": witness.failing,
                        "stale": witness.stale,
                        **(
                            {}
                            if witness.tuned_on_these_cases is None
                            else {"tuned_on_these_cases": witness.tuned_on_these_cases}
                        ),
                        **({} if witness.worst is None else {"worst": witness.worst}),
                    }
                    for witness in row.witnesses
                ],
            }
            for row in value.criteria
        ],
    }


def verification_coverage_from_json(value: object) -> VerificationCoverage:
    """Decode the closed local receipt member (projected omissions are rendered separately)."""

    invalid = "invalid_event_value_type"
    if not isinstance(value, Mapping):
        raise ProtocolValueError(invalid)
    source = cast(Mapping[str, object], value)
    if (
        set(source) != {"label", "advisory", "criteria", "omitted_criteria"}
        or source["label"] != "agent-declared"
        or source["advisory"] is not True
    ):
        raise ProtocolValueError(invalid)
    if type(source["criteria"]) not in {list, tuple}:
        raise ProtocolValueError(invalid)
    rows: list[VerificationCriterion] = []
    for item in cast(list[object], source["criteria"]):
        if not isinstance(item, Mapping):
            raise ProtocolValueError(invalid)
        row = cast(Mapping[str, object], item)
        quote_key = (
            "obligation_criterion_quote"
            if row.get("source") == "obligation"
            else "task_criterion_quote"
        )
        if (
            set(row)
            != {
                quote_key,
                "source",
                "flags",
                "witnesses",
                "unresolved_failing_runs",
                "repeated_runs",
                "redundant_tests",
                "omitted_witnesses",
            }
            or type(row["witnesses"]) not in {list, tuple}
            or type(row["flags"]) not in {list, tuple}
        ):
            raise ProtocolValueError(invalid)
        witnesses: list[VerificationWitness] = []
        for raw in cast(list[object], row["witnesses"]):
            if not isinstance(raw, Mapping):
                raise ProtocolValueError(invalid)
            witness = cast(Mapping[str, object], raw)
            required = {"result_id", "action_id", "data_source", "cases", "failing", "stale"}
            if not required <= set(witness) or set(witness) - required - {
                "worst",
                "tuned_on_these_cases",
            }:
                raise ProtocolValueError(invalid)
            witnesses.append(
                VerificationWitness(
                    result_id=cast(ResultId, witness["result_id"]),
                    action_id=cast(ActionId, witness["action_id"]),
                    data_source=cast(str, witness["data_source"]),
                    cases=cast(int, witness["cases"]),
                    failing=cast(int, witness["failing"]),
                    stale=cast(bool, witness["stale"]),
                    worst=cast(str | None, witness.get("worst")),
                    tuned_on_these_cases=cast(bool | None, witness.get("tuned_on_these_cases")),
                )
            )
        rows.append(
            VerificationCriterion(
                criterion_quote=cast(str, row[quote_key]),
                source=cast(CriterionSource, row["source"]),
                flags=cast(tuple[CoverageFlag, ...], tuple(cast(list[object], row["flags"]))),
                witnesses=tuple(witnesses),
                unresolved_failing_runs=cast(int, row["unresolved_failing_runs"]),
                repeated_runs=cast(int, row["repeated_runs"]),
                redundant_tests=cast(int, row["redundant_tests"]),
                omitted_witnesses=cast(int, row["omitted_witnesses"]),
            )
        )
    return VerificationCoverage(tuple(rows), cast(int, source["omitted_criteria"]))


def verification_coverage_lines(
    value: VerificationCoverage, *, include_content: bool = True
) -> tuple[str, ...]:
    """Plain prose shared by local receipt and terminal renderers; no success badge."""

    lines = ["Advisory; declarations and candidate gaps do not establish correctness."]
    for index, row in enumerate(value.criteria, 1):
        quote = (
            " ".join(row.criterion_quote.split())
            if include_content
            else f"Criterion {index}; text omitted from this rendering"
        )
        flags = ", ".join(coverage_flag_label(flag) for flag in row.flags) or "witness recorded"
        lines.append(f'Criterion: "{quote}" ({row.source.replace("_", " ")}); {flags}.')
        for witness in row.witnesses:
            detail = f"{witness.result_id}: {witness.data_source}; {witness.failing}/{witness.cases} failing"
            if witness.worst is not None and include_content:
                detail += "; worst=" + " ".join(witness.worst.split())
            if witness.tuned_on_these_cases is True:
                detail += "; tuned on these cases"
            elif witness.tuned_on_these_cases is None:
                detail += "; tuning not declared"
            if witness.stale:
                detail += "; predates a material edit"
            lines.append(detail + ".")
        if row.omitted_witnesses:
            lines.append(
                f"{row.omitted_witnesses} other check witnesses omitted; {row.unresolved_failing_runs} check(s) retain failing cases."
            )
    if not value.criteria:
        lines.append("No criterion witnesses or candidate criteria recorded.")
    if value.omitted_criteria:
        lines.append(f"{value.omitted_criteria} candidate criteria omitted by the display bound.")
    return tuple(lines)


def verification_coverage_wire_lines(value: Mapping[str, object]) -> tuple[str, ...]:
    """Render a privacy-projected member without recovering withheld quote or metric text."""

    lines = ["Advisory; agent-declared witnesses and candidate gaps do not establish correctness."]
    raw_rows = value.get("criteria", ())
    if not isinstance(raw_rows, (list, tuple)):
        return tuple(lines)
    for raw in cast(Sequence[object], raw_rows)[:MAX_COVERAGE_CRITERIA]:
        if not isinstance(raw, Mapping):
            continue
        row = cast(Mapping[str, object], raw)
        text = row.get("obligation_criterion_quote", row.get("task_criterion_quote"))
        quote = " ".join(text.split()) if isinstance(text, str) else "criterion text withheld"
        flags = row.get("flags", ())
        labels = (
            ", ".join(
                coverage_flag_label(flag)
                for flag in cast(Sequence[object], flags)
                if isinstance(flag, str) and flag in VERIFICATION_COVERAGE_FLAGS
            )
            if isinstance(flags, (tuple, list))
            else ""
        )
        lines.append(f'Criterion: "{quote}"; {labels or "witness recorded"}.')
        witnesses = row.get("witnesses", ())
        if isinstance(witnesses, (list, tuple)):
            for raw_witness in cast(Sequence[object], witnesses)[:MAX_CRITERION_WITNESSES]:
                if not isinstance(raw_witness, Mapping):
                    continue
                witness = cast(Mapping[str, object], raw_witness)
                detail = f"{witness.get('result_id')}: {witness.get('data_source')}; {witness.get('failing')}/{witness.get('cases')} failing"
                worst = witness.get("worst")
                if isinstance(worst, str):
                    detail += "; worst=" + " ".join(worst.split())
                elif worst is not None:
                    detail += "; worst value withheld"
                if witness.get("tuned_on_these_cases") is True:
                    detail += "; tuned on these cases"
                if witness.get("stale") is True:
                    detail += "; predates a material edit"
                lines.append(detail + ".")
        if row.get("omitted_witnesses"):
            lines.append(
                f"{row['omitted_witnesses']} other check witnesses omitted; {row.get('unresolved_failing_runs', 0)} check(s) retain failing cases."
            )
    if value.get("omitted_criteria"):
        lines.append(
            f"{value['omitted_criteria']} candidate criteria omitted by the display bound."
        )
    return tuple(lines)
