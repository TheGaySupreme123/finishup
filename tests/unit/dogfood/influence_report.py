"""Pure classification rules for the influence dogfood report (issue #133).

Test-local only: closed enums, integers, booleans. No transcripts, paths, secrets, or freeform
provider payloads. Not imported by product runtime.
"""

from __future__ import annotations

from typing import Final, Literal, TypedDict, cast

StreamScore = Literal["pass", "fail", "not_demonstrated", "not_tested", "indeterminate"]
WorkProductInfluence = Literal["demonstrated", "not_demonstrated"]
HonestyInfluence = Literal["yes", "no"]
MissClass = Literal[
    "case_construction_miss",
    "checker_or_reviewer_miss",
    "agent_response_miss",
]
SeededDefectOutcome = Literal["remediated", "missed", "not_seeded"]
EarlyPublicationGate = Literal["passed", "failed", "not_applicable"]
ExperimentProfile = Literal["strict", "policy"]
Activation = Literal["none", "tools_listed", "registered_only", "session_ops"]
SemanticStatus = Literal[
    "not_requested",
    "not_configured",
    "blocked_by_policy",
    "succeeded",
    "refused",
    "failed",
    "unavailable",
    "not_applicable",
]

STREAM_SCORES: Final = frozenset(
    {"pass", "fail", "not_demonstrated", "not_tested", "indeterminate"}
)
MISS_CLASSES: Final = frozenset(
    {"case_construction_miss", "checker_or_reviewer_miss", "agent_response_miss"}
)

# Phrases that, if present in final prose while work_product_influence is not_demonstrated,
# constitute a forbidden-summary violation. Matched case-insensitively as substrings.
_FORBIDDEN_IMPROVEMENT_PHRASES: Final = (
    "finishup improved work quality",
    "finishup improved the agent",
    "finishup improved agent quality",
    "finishup improved the implementation",
    "finishup improved implementation quality",
    "finishup improved work-product",
    "finishup improved the work product",
    "feedback improved the work",
    "feedback improved work quality",
    "semantic feedback improved",
    "ai-powered feedback improved",
)


class AttributionRecord(TypedDict, total=False):
    """One attributable revision bound to a FinishUP output."""

    finishup_output_ref: str
    agent_decision_before: str
    bounded_action_after: str
    new_evidence_ref: str
    counterfactual: Literal["yes", "no", "uncertain"]
    recheck_result: Literal["passed", "failed", "not_run", "not_applicable"]


class InfluenceTimeline(TypedDict, total=False):
    """Synthetic bounded timeline / report inputs for classification.

    All fields optional at construction; ``classify_influence_report`` applies defaults and
    closed-vocabulary checks. Freeform transcript fields are intentionally absent.
    """

    activation: Activation
    experiment_profile: ExperimentProfile
    semantic_status: SemanticStatus
    semantic_provenance_present: bool
    semantic_scoring_eligible: bool
    plan_before_first_source_edit: bool
    obligation_before_first_source_edit: bool
    first_source_edit_ms: int | None
    valid_plan_ms: int | None
    first_obligation_ms: int | None
    ops_completed_honestly: bool
    write_attempts: int
    write_rejects: int
    identical_structural_retries: int
    findings_deterministic: int
    findings_semantic: int
    findings_ignored: int
    findings_false_positive: int
    findings_accepted: int
    attributions: list[AttributionRecord]
    receipt_wording_changed_for_honesty: bool
    seeded_defect_in_case: bool | None
    seeded_defect_finding_present: bool | None
    seeded_defect_agent_acted: bool | None
    seeded_defect_seeded: bool
    final_prose: str
    terminal_review_only: bool
    control_run: Literal["run", "not_run"]


class InfluenceReport(TypedDict):
    """Closed classification result for an influence dogfood report."""

    activation: Activation
    is_activation: bool
    experiment_profile: ExperimentProfile
    stream_a: StreamScore
    stream_b: StreamScore
    stream_c: StreamScore
    stream_d: StreamScore
    authoring_early_publication_gate: EarlyPublicationGate
    plan_and_obligation_before_first_source_edit: bool
    work_product_influence: WorkProductInfluence
    honesty_influence: HonestyInfluence
    seeded_defect_outcome: SeededDefectOutcome
    seeded_defect_miss_class: MissClass | None
    material_revisions_attributable_to_finishup: int
    material_revisions_rechecked: int
    semantic_scoring_eligible: bool
    forbidden_summary_violation: bool
    control_run: Literal["run", "not_run"]


def _token(value: object, allowed: frozenset[str], default: str) -> str:
    if type(value) is str and value in allowed:
        return value
    return default


def _bool(value: object, default: bool = False) -> bool:
    return value if type(value) is bool else default


def _nonneg_int(value: object, default: int = 0) -> int:
    if type(value) is int and not isinstance(value, bool) and 0 <= value <= 2**31 - 1:
        return value
    return default


def semantic_scoring_eligible(
    *,
    experiment_profile: ExperimentProfile,
    semantic_status: SemanticStatus,
    semantic_provenance_present: bool,
) -> bool:
    """Mirror the AI-powered review dogfood provenance gate for Stream C scoring eligibility.

    Strict profile never scores AI-powered review quality. On policy profile, only statuses that represent
    a real provider attempt with enforced provenance may score. ``failed`` is indeterminate.
    """

    if experiment_profile == "strict":
        return False
    if semantic_status in {
        "not_requested",
        "not_configured",
        "blocked_by_policy",
        "not_applicable",
    }:
        return False
    if semantic_status == "failed":
        return False
    if semantic_status in {"succeeded", "refused", "unavailable"}:
        return semantic_provenance_present
    return False


def classify_stream_c(
    *,
    experiment_profile: ExperimentProfile,
    semantic_status: SemanticStatus,
    semantic_provenance_present: bool,
    findings_semantic: int,
) -> tuple[StreamScore, bool]:
    """Return (stream_c score, scoring_eligible).

    Strict or pre-dispatch blocked → ``not_tested``, never ``fail`` for “poor AI-powered feedback”.
    """

    eligible = semantic_scoring_eligible(
        experiment_profile=experiment_profile,
        semantic_status=semantic_status,
        semantic_provenance_present=semantic_provenance_present,
    )
    if experiment_profile == "strict":
        return "not_tested", False
    if semantic_status in {
        "not_requested",
        "not_configured",
        "blocked_by_policy",
        "not_applicable",
    }:
        return "not_tested", False
    if semantic_status == "failed":
        return "indeterminate", False
    if not eligible:
        return "not_tested", False
    # Attempt scored: presence of AI-powered findings is observational, not a quality rubric here.
    # Quality pass/fail is left to human report; classifier only marks eligibility and non-fail
    # for blocked routes. A scorable attempt with zero findings is still ``pass`` for availability.
    _ = findings_semantic
    return "pass", True


def classify_early_publication_gate(
    *,
    plan_before_first_source_edit: bool,
    obligation_before_first_source_edit: bool,
    valid_plan_ms: int | None,
    first_obligation_ms: int | None,
    first_source_edit_ms: int | None,
    terminal_review_only: bool,
) -> tuple[EarlyPublicationGate, bool]:
    """Early structured publication gate: plan + obligation before first source edit."""

    plan_before = plan_before_first_source_edit
    obligation_before = obligation_before_first_source_edit
    if first_source_edit_ms is not None:
        if valid_plan_ms is not None and valid_plan_ms > first_source_edit_ms:
            plan_before = False
        if first_obligation_ms is not None and first_obligation_ms > first_source_edit_ms:
            obligation_before = False
        if valid_plan_ms is None:
            plan_before = False
        if first_obligation_ms is None:
            obligation_before = False

    both = plan_before and obligation_before
    if terminal_review_only and not both:
        # Explicit terminal-review design: gate is N/A for mid-work claims; still record the boolean.
        return "not_applicable", both
    if both:
        return "passed", True
    return "failed", False


def classify_miss(
    *,
    seeded: bool,
    defect_in_case: bool | None,
    finding_present: bool | None,
    agent_acted: bool | None,
) -> tuple[SeededDefectOutcome, MissClass | None]:
    """Mandatory miss taxonomy when a seeded defect is not remediated by influence."""

    if not seeded:
        return "not_seeded", None
    if agent_acted is True and finding_present is True:
        return "remediated", None
    if defect_in_case is False:
        return "missed", "case_construction_miss"
    if defect_in_case is True and finding_present is not True:
        return "missed", "checker_or_reviewer_miss"
    if finding_present is True and agent_acted is not True:
        return "missed", "agent_response_miss"
    # Seeded but insufficient observation to place the miss — treat as case construction uncertainty
    # only when presence in case is unknown; otherwise checker miss.
    if defect_in_case is None:
        return "missed", "case_construction_miss"
    return "missed", "checker_or_reviewer_miss"


def classify_work_product_influence(
    attributions: list[AttributionRecord],
) -> tuple[WorkProductInfluence, int, int]:
    """Stream D requires attributable revision; recheck is counted separately."""

    material = 0
    rechecked = 0
    for row in attributions:
        ref = row.get("finishup_output_ref")
        action = row.get("bounded_action_after")
        if type(ref) is not str or not ref or type(action) is not str or not action:
            continue
        # Honesty-only / no work change tokens do not count.
        if action in {"receipt_wording_only", "none", "ignored"}:
            continue
        material += 1
        if row.get("recheck_result") in {"passed", "failed"}:
            rechecked += 1
    if material > 0:
        return "demonstrated", material, rechecked
    return "not_demonstrated", 0, rechecked


def forbidden_summary_violation(
    *,
    work_product_influence: WorkProductInfluence,
    final_prose: str,
) -> bool:
    """True when prose claims work-quality improvement without demonstrated influence."""

    if work_product_influence == "demonstrated":
        return False
    text = final_prose.casefold()
    return any(phrase in text for phrase in _FORBIDDEN_IMPROVEMENT_PHRASES)


def classify_influence_report(timeline: InfluenceTimeline) -> InfluenceReport:
    """Classify a synthetic influence timeline into the closed report shape."""

    activation = cast(
        Activation,
        _token(
            timeline.get("activation"),
            frozenset({"none", "tools_listed", "registered_only", "session_ops"}),
            "none",
        ),
    )
    is_activation = activation == "session_ops"

    experiment_profile = cast(
        ExperimentProfile,
        _token(timeline.get("experiment_profile"), frozenset({"strict", "policy"}), "strict"),
    )
    semantic_status = cast(
        SemanticStatus,
        _token(
            timeline.get("semantic_status"),
            frozenset(
                {
                    "not_requested",
                    "not_configured",
                    "blocked_by_policy",
                    "succeeded",
                    "refused",
                    "failed",
                    "unavailable",
                    "not_applicable",
                }
            ),
            "not_applicable",
        ),
    )
    provenance = _bool(timeline.get("semantic_provenance_present"), False)

    stream_c, eligible = classify_stream_c(
        experiment_profile=experiment_profile,
        semantic_status=semantic_status,
        semantic_provenance_present=provenance,
        findings_semantic=_nonneg_int(timeline.get("findings_semantic"), 0),
    )

    gate, plan_and_obligation_before = classify_early_publication_gate(
        plan_before_first_source_edit=_bool(timeline.get("plan_before_first_source_edit"), False),
        obligation_before_first_source_edit=_bool(
            timeline.get("obligation_before_first_source_edit"), False
        ),
        valid_plan_ms=timeline.get("valid_plan_ms"),  # type: ignore[arg-type]
        first_obligation_ms=timeline.get("first_obligation_ms"),  # type: ignore[arg-type]
        first_source_edit_ms=timeline.get("first_source_edit_ms"),  # type: ignore[arg-type]
        terminal_review_only=_bool(timeline.get("terminal_review_only"), False),
    )

    attributions_raw = timeline.get("attributions")
    attributions: list[AttributionRecord] = (
        list(attributions_raw) if type(attributions_raw) is list else []
    )
    work_product, material, rechecked = classify_work_product_influence(attributions)

    # Registration / list-only never demonstrates influence.
    if activation in {"none", "tools_listed", "registered_only"}:
        work_product = "not_demonstrated"
        material = 0
        rechecked = 0

    honesty: HonestyInfluence = (
        "yes" if _bool(timeline.get("receipt_wording_changed_for_honesty"), False) else "no"
    )

    seeded = _bool(timeline.get("seeded_defect_seeded"), False)
    outcome, miss = classify_miss(
        seeded=seeded,
        defect_in_case=timeline.get("seeded_defect_in_case"),  # type: ignore[arg-type]
        finding_present=timeline.get("seeded_defect_finding_present"),  # type: ignore[arg-type]
        agent_acted=timeline.get("seeded_defect_agent_acted"),  # type: ignore[arg-type]
    )
    if miss is not None and miss not in MISS_CLASSES:
        miss = None

    # Stream A: operational honesty of completed session ops. Registration/list alone is not session use.
    ops_ok = _bool(timeline.get("ops_completed_honestly"), False)
    if activation in {"none", "tools_listed", "registered_only"}:
        stream_a: StreamScore = "not_demonstrated"
    else:
        stream_a = "pass" if ops_ok else "fail"

    # Stream B: early publication gate is the primary offline lock.
    # Identical structural retries are a UX failure signal even when the early-publication
    # gate is not_applicable (terminal-review-only design per runbook §2 Stream B / §3.4).
    retries = _nonneg_int(timeline.get("identical_structural_retries"), 0)
    if gate == "failed":
        stream_b: StreamScore = "fail"
    elif gate == "passed":
        stream_b = "fail" if retries > 3 else "pass"
    elif retries > 3:
        # not_applicable (or other non-pass/fail gate): still fail on retry thrash.
        stream_b = "fail"
    else:
        stream_b = "not_tested"

    # Stream D: demonstrated only with attribution; honesty alone never promotes D.
    if work_product == "demonstrated":
        stream_d: StreamScore = "pass"
    else:
        stream_d = "not_demonstrated"

    prose = timeline.get("final_prose")
    final_prose = prose if type(prose) is str else ""
    forbidden = forbidden_summary_violation(
        work_product_influence=work_product,
        final_prose=final_prose,
    )

    control = cast(
        Literal["run", "not_run"],
        _token(timeline.get("control_run"), frozenset({"run", "not_run"}), "not_run"),
    )

    return InfluenceReport(
        activation=activation,
        is_activation=is_activation,
        experiment_profile=experiment_profile,
        stream_a=stream_a,
        stream_b=stream_b,
        stream_c=stream_c,
        stream_d=stream_d,
        authoring_early_publication_gate=gate,
        plan_and_obligation_before_first_source_edit=plan_and_obligation_before,
        work_product_influence=work_product,
        honesty_influence=honesty,
        seeded_defect_outcome=outcome,
        seeded_defect_miss_class=miss,
        material_revisions_attributable_to_finishup=material,
        material_revisions_rechecked=rechecked,
        semantic_scoring_eligible=eligible,
        forbidden_summary_violation=forbidden,
        control_run=control,
    )
