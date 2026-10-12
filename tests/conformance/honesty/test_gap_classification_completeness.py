"""Build-time completeness of the closure-readiness gap classification (issue #913, ADR-032).

``ready_with_limitations`` is only reachable if every gap code the product emits is classified:
a real code that falls through to the conservative ``unclassified_gap:<code>`` default keeps
readiness actionable forever. This test therefore enumerates every gap-code producer and fails
when one emits a code the closed table in ``yoetz.kernel.closure_readiness`` does not classify.

Producers are enumerated two ways:

* by value, where the vocabulary is typed: ``ObservationGapCode``, ``CoordinationGapCode``, every
  ``semantic_coverage_gap_code`` output, the publication-channel baselines, and the lineage
  manifest read-gap template;
* by source, where codes are string literals: a syntax-tree scan of ``src/yoetz`` collects the
  literals that reach a gap sink — ``*_GAP``/``*_GAPS`` constants, ``gaps.add(...)``-style
  accumulators, ``CaseGap``/``LineageGap``/``ImportGap`` constructors, ``known_gaps=`` and
  ``gap_codes=`` keywords, set unions with a gap collection, lineage blocker accumulators, and
  import reason codes. Formatted markers must use a known template whose base code is classified.

A new gap code therefore cannot ship unless its author classifies it in the same change.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path
from typing import Final

import pytest

import yoetz
from yoetz.domain.coordination import CoordinationGapCode
from yoetz.domain.observation import ObservationGapCode
from yoetz.domain.receipts import (
    CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
    semantic_coverage_gap_code,
)
from yoetz.kernel.closure_readiness import (
    GAP_CLASSIFICATION,
    GAP_CLASSIFICATION_VERSION,
    READINESS_CHECK_CONDITIONS,
    UNCLASSIFIED_GAP_PREFIX,
    GapClass,
    classify_gap,
    gap_base_code,
    split_gaps,
)
from yoetz.kernel.lineage import (
    _READ_GAP_REASONS,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.protocol.coverage import COVERAGE_DEFAULTS_BY_CHANNEL
from yoetz.protocol.models import VALID_SEMANTIC_REASONS

_SRC: Final = Path(yoetz.__file__).resolve().parent
_CODE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_GAP_KEYWORDS: Final = frozenset({"known_gaps", "gap_codes", "gaps", "coverage_gaps", "gap_code"})
_SINK_CALLS: Final = frozenset(
    {"CaseGap", "ImportGap", "LineageGap", "_add_gap", "note_blocker", "note_coverage_gap"}
)
_GAP_TARGET: Final = re.compile(r"(^|_)(gap|gaps|gap_code|gap_codes)$", re.IGNORECASE)
# Lineage child blockers become parent readiness gaps without passing through a gap-named value.
_LINEAGE_BLOCKER_FILES: Final = frozenset({"kernel/lineage.py", "application/task_views.py"})
_IMPORT_REASON_NAMES: Final = frozenset({"reason", "reasons", "admission_reason"})
_IMPORT_REASON_FUNCTIONS: Final = frozenset({"_validate_wrapper"})

# Literals the scan reaches that are not gap codes, each with the reason it is not one.
_NOT_GAP_CODES: Final = {
    # Wire field names read out of a gap-bearing envelope.
    "gap_codes": "field name of an observation envelope",
    "known_gaps": "field name of a coverage object",
    # A lineage read-gap *reason*; it is emitted only as lineage_manifest_<reason>.
    "unreadable": "lineage read-gap reason, emitted as lineage_manifest_unreadable",
    # Check-time change unavailability reasons (ADR-031); emitted only as
    # check_time_change_unavailable_<reason>, which the typed producers enumerate.
    "no_linked_subject": "check-time change reason, emitted with its check_time_change prefix",
    "no_packet_room": "check-time change reason, emitted with its check_time_change prefix",
}

# Formatted gap markers: literal prefix -> base code the marker classifies by (None when the
# prefix is itself the classified form, or when the base is a separately enumerated template).
_KNOWN_TEMPLATES: Final[dict[str, str | None]] = {
    ":": None,  # f"{code}:{event}" completion-scope and case markers; code is a classified literal
    "check_coverage:": None,  # wraps a check's own known_gaps
    "check_payload_unavailable:": "check_payload_unavailable",
    "lineage_manifest_": None,  # expanded over the lineage read-gap reasons below
    "missing_ref::": "missing_ref",
    "redacted_event:": "redacted_event",
    "redacted_object:": "redacted_object",
    "retained_finding_coverage:": None,  # wraps a retained finding's known_gaps
    "semantic_outcome:": None,  # wraps a semantic_coverage_gap_code output
    "unavailable_captured_object::": None,  # marker for captured_object_unavailable
    "unavailable_event:": None,  # marker for event_payload_unavailable
    "unknown_event::@": "unknown_event",
}

# The 20 codes observed in the DeepSWE v2 evidence and the group #913 assigns each (for
# semantic_review_not_requested: on a local-only route).
_OBSERVED_V2: Final = {
    "unpaired_event": GapClass.STANDING_LIMITATION,
    "host_outcome_unavailable": GapClass.STANDING_LIMITATION,
    "observation_qualified_partial": GapClass.STANDING_LIMITATION,
    "advice_semantic_pending": GapClass.STANDING_LIMITATION,
    "check_current_as_of_earlier_frontier": GapClass.STANDING_LIMITATION,
    "content_unselected": GapClass.STANDING_LIMITATION,
    "semantic_review_not_requested": GapClass.STANDING_LIMITATION,
    "evidence_content_digest_only": GapClass.STANDING_LIMITATION,
    "semantic_reference_scope_reduced": GapClass.STANDING_LIMITATION,
    "semantic_case_content_over_item_limit": GapClass.STANDING_LIMITATION,
    "semantic_packet_insufficient": GapClass.STANDING_LIMITATION,
    "truncated_payload": GapClass.STANDING_LIMITATION,
    "content_capture_unavailable": GapClass.STANDING_LIMITATION,
    "completion_plan_not_claimed": GapClass.AGENT_ACTIONABLE,
    "content_redacted": GapClass.STANDING_LIMITATION,
    "command_attempt_uncorroborated": GapClass.STANDING_LIMITATION,
    "semantic_challenges_rejected": GapClass.STANDING_LIMITATION,
    "semantic_relevance_review_not_run": GapClass.STANDING_LIMITATION,
    "pending_attempt_expired": GapClass.STANDING_LIMITATION,
    "unsupported_event": GapClass.STANDING_LIMITATION,
}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    return ""


class _GapLiteralScan(ast.NodeVisitor):
    """Collect string literals that reach a gap sink in one source file."""

    def __init__(self, relative: str) -> None:
        self.relative = relative
        self.codes: dict[str, set[str]] = defaultdict(set)
        self.templates: dict[str, set[str]] = defaultdict(set)
        self._functions: list[str] = []
        self._enum_depth = 0
        self._lineage = relative in _LINEAGE_BLOCKER_FILES
        self._importer = relative.startswith("adapters/importers/")

    def _values(self, node: ast.AST, where: str, *, shallow: bool = False) -> None:
        if isinstance(node, ast.Subscript):
            self._values(node.value, where, shallow=shallow)
            return
        if isinstance(node, ast.Compare | ast.Lambda):
            return  # a comparison consumes codes; it does not emit them
        if isinstance(node, ast.Dict):
            for value in node.values:
                self._values(value, where, shallow=shallow)
            return
        if isinstance(node, ast.JoinedStr):
            prefix = "".join(
                part.value
                for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            self.templates[prefix].add(where)
            return
        if isinstance(node, ast.Call):
            if shallow:
                return
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {
                "encode",
                "get",
                "join",
                "pop",
                "removeprefix",
                "split",
                "startswith",
            }:
                self._values(func.value, where)
                return
            if isinstance(func, ast.Name) and func.id in {
                "_case_json_array",
                "_case_json_object",
                "_field",
                "getattr",
            }:
                return
            for argument in node.args:
                self._values(argument, where)
            for keyword in node.keywords:
                if keyword.arg not in {"detail", "key"}:
                    self._values(keyword.value, where)
            return
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and _CODE.fullmatch(node.value):
                self.codes[node.value].add(where)
            return
        for child in ast.iter_child_nodes(node):
            self._values(child, where, shallow=shallow)

    def _where(self, node: ast.stmt | ast.expr) -> str:
        return f"{self.relative}:{node.lineno}"

    def _sink_target(self, name: str) -> bool:
        return bool(name) and (
            _GAP_TARGET.search(name) is not None
            or (self._lineage and name in {"blocking", "blockers"})
            or (self._importer and name in _IMPORT_REASON_NAMES)
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        enum = any("Enum" in ast.unparse(base) for base in node.bases)
        self._enum_depth += enum
        self.generic_visit(node)
        self._enum_depth -= enum

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._functions.append(node.name)
        self.generic_visit(node)
        self._functions.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._functions.append(node.name)
        self.generic_visit(node)
        self._functions.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        # Enum members named *_GAP (``LedgerFreshness.REDACTED_GAP``) are states, not gap codes.
        if not self._enum_depth and any(self._sink_target(_name(t)) for t in node.targets):
            self._values(node.value, self._where(node))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if (
            not self._enum_depth
            and node.value is not None
            and self._sink_target(_name(node.target))
        ):
            self._values(node.value, self._where(node))
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        function = self._functions[-1] if self._functions else ""
        if node.value is not None and re.search(r"gap(s|_codes?)$", function):
            self._values(node.value, self._where(node), shallow=True)
        elif (
            self._importer
            and function in _IMPORT_REASON_FUNCTIONS
            and isinstance(node.value, ast.Tuple)
            and node.value.elts
        ):
            self._values(node.value.elts[-1], self._where(node), shallow=True)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"add", "append", "extend", "update"}:
            receiver = _name(func.value)
            if self._sink_target(receiver) or "gap" in receiver.lower():
                for argument in node.args:
                    self._values(argument, self._where(node))
        if _name(func) in _SINK_CALLS:
            for argument in node.args[:2]:
                self._values(argument, self._where(node))
            for keyword in node.keywords:
                if keyword.arg in {"code", "marker"}:
                    self._values(keyword.value, self._where(node))
        for keyword in node.keywords:
            if keyword.arg in _GAP_KEYWORDS:
                self._values(keyword.value, self._where(node))
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.BitOr) and any(
            "gap" in _name(side).lower() for side in (node.left, node.right)
        ):
            self._values(node, self._where(node))
        self.generic_visit(node)

    def _starred(self, node: ast.Set | ast.Tuple | ast.List) -> None:
        if any(
            isinstance(element, ast.Starred) and "gap" in _name(element.value).lower()
            for element in node.elts
        ):
            self._values(node, self._where(node))
        self.generic_visit(node)

    def visit_Set(self, node: ast.Set) -> None:
        self._starred(node)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        self._starred(node)

    def visit_List(self, node: ast.List) -> None:
        self._starred(node)


def _scan_sources() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    codes: dict[str, set[str]] = defaultdict(set)
    templates: dict[str, set[str]] = defaultdict(set)
    for path in sorted(_SRC.rglob("*.py")):
        relative = path.relative_to(_SRC).as_posix()
        if relative.startswith("resources/"):
            continue
        scan = _GapLiteralScan(relative)
        scan.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        for code, sites in scan.codes.items():
            codes[code].update(sites)
        for prefix, sites in scan.templates.items():
            templates[prefix].update(sites)
    return codes, templates


def _typed_producers() -> dict[str, str]:
    produced: dict[str, str] = {}
    for member in ObservationGapCode:
        produced[member.value] = "ObservationGapCode"
    for member in CoordinationGapCode:
        produced[member.value] = "CoordinationGapCode"
    for status, reasons in VALID_SEMANTIC_REASONS.items():
        for reason in reasons:
            code = semantic_coverage_gap_code(status, reason)
            if code is not None:
                produced[code] = "semantic_coverage_gap_code"
    for coverage in COVERAGE_DEFAULTS_BY_CHANNEL.values():
        for code in coverage.known_gaps:
            produced[code] = "COVERAGE_DEFAULTS_BY_CHANNEL"
    for reason in _READ_GAP_REASONS:
        produced[f"lineage_manifest_{reason}"] = "lineage manifest read-gap template"
    for code in CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS:
        produced[code] = "check_time_change_unavailable_reason_gap"
    return produced


@pytest.fixture(scope="module")
def scanned() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    return _scan_sources()


def test_every_emitted_gap_code_is_classified(
    scanned: tuple[dict[str, set[str]], dict[str, set[str]]],
) -> None:
    literal_codes, _ = scanned
    emitted = {code: sorted(sites)[0] for code, sites in literal_codes.items()}
    emitted.update(_typed_producers())
    for token in _NOT_GAP_CODES:
        emitted.pop(token, None)
    unclassified = {code: site for code, site in emitted.items() if code not in GAP_CLASSIFICATION}
    assert not unclassified, (
        "Classify these gap codes in yoetz.kernel.closure_readiness.GAP_CLASSIFICATION "
        f"(agent-actionable or standing) in the same change that emits them: {unclassified}"
    )


def test_formatted_gap_markers_use_known_templates(
    scanned: tuple[dict[str, set[str]], dict[str, set[str]]],
) -> None:
    _, templates = scanned
    unknown = {prefix: sorted(sites)[0] for prefix, sites in templates.items()}
    for prefix in _KNOWN_TEMPLATES:
        unknown.pop(prefix, None)
    assert not unknown, (
        "A formatted gap marker has no known base-code template; add it to _KNOWN_TEMPLATES "
        f"and classify its base code: {unknown}"
    )
    for prefix, base in _KNOWN_TEMPLATES.items():
        if base is not None:
            assert base in GAP_CLASSIFICATION, prefix
            assert gap_base_code(prefix + "x") in {base, prefix.split(":")[0]}


def test_the_table_names_only_emitted_codes(
    scanned: tuple[dict[str, set[str]], dict[str, set[str]]],
) -> None:
    """A closed table stays honest in both directions: no entry for a code nothing emits."""

    literal_codes, _ = scanned
    # Readiness derives its check conditions itself; they are classified like any gap code.
    emitted = set(literal_codes) | set(_typed_producers()) | set(READINESS_CHECK_CONDITIONS)
    assert set(GAP_CLASSIFICATION) <= emitted, sorted(set(GAP_CLASSIFICATION) - emitted)


def test_not_gap_code_exclusions_are_still_needed(
    scanned: tuple[dict[str, set[str]], dict[str, set[str]]],
) -> None:
    literal_codes, _ = scanned
    assert set(_NOT_GAP_CODES) <= set(literal_codes)
    assert not set(_NOT_GAP_CODES) & set(GAP_CLASSIFICATION)


def test_observed_v2_codes_have_their_owner_approved_group() -> None:
    for code, expected in _OBSERVED_V2.items():
        assert (
            classify_gap(code, semantic_review_required=False, semantic_review_current=False)
            is expected
        ), code
    assert len(_OBSERVED_V2) == 20
    # completion_plan_not_claimed is the only unconditionally actionable observed code.
    assert [code for code, group in _OBSERVED_V2.items() if group is GapClass.AGENT_ACTIONABLE] == [
        "completion_plan_not_claimed"
    ]


@pytest.mark.parametrize(
    ("required", "current", "expected"),
    (
        (False, False, GapClass.STANDING_LIMITATION),
        (False, True, GapClass.STANDING_LIMITATION),
        (True, True, GapClass.STANDING_LIMITATION),
        (True, False, GapClass.AGENT_ACTIONABLE),
    ),
)
def test_semantic_review_not_requested_follows_the_route_rule(
    required: bool, current: bool, expected: GapClass
) -> None:
    assert (
        classify_gap(
            "semantic_review_not_requested",
            semantic_review_required=required,
            semantic_review_current=current,
        )
        is expected
    )
    # The route flags never move any other code.
    for code, group in GAP_CLASSIFICATION.items():
        if code != "semantic_review_not_requested":
            assert (
                classify_gap(
                    code, semantic_review_required=required, semantic_review_current=current
                )
                is group
            )


@pytest.mark.parametrize(
    ("marker", "base"),
    (
        ("coverage:content_unselected", "content_unselected"),
        ("check_coverage:host_outcome_unavailable", "host_outcome_unavailable"),
        ("retained_finding_coverage:unpaired_event", "unpaired_event"),
        ("semantic_outcome:semantic_review_not_requested", "semantic_review_not_requested"),
        (
            "lineage:lineage_child_open:tsk_00000000-0000-4000-8000-000000000001",
            "lineage_child_open",
        ),
        ("unknown_event:evt_00000000-0000-4000-8000-000000000001:future@9.0.0", "unknown_event"),
        (
            "completion_scope_undeclared:evt_00000000-0000-4000-8000-000000000001",
            "completion_scope_undeclared",
        ),
        ("host_outcome_unavailable", "host_outcome_unavailable"),
    ),
)
def test_prefixed_forms_classify_by_base_code(marker: str, base: str) -> None:
    assert gap_base_code(marker) == base
    assert classify_gap(
        marker, semantic_review_required=False, semantic_review_current=False
    ) is classify_gap(base, semantic_review_required=False, semantic_review_current=False)


def test_runtime_unknown_code_is_named_and_stays_actionable() -> None:
    split = split_gaps(
        (
            "host_outcome_unavailable",
            "coverage:gap_from_a_newer_build",
            "completion_plan_not_claimed",
            "Not A Code",
        ),
        semantic_review_required=False,
        semantic_review_current=False,
    )
    assert split.standing_limitations == ("host_outcome_unavailable",)
    assert split.agent_actionable == (
        "completion_plan_not_claimed",
        UNCLASSIFIED_GAP_PREFIX + "gap_from_a_newer_build",
        UNCLASSIFIED_GAP_PREFIX + "unreadable_gap_code",
    )
    assert GAP_CLASSIFICATION_VERSION == "7"
