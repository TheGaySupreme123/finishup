"""Stable guidance URI catalog, including bounded section topics.

The heading entries intentionally live in a closed source catalog: runtime admission must reject
invented anchors even though the advertised JSON Schema uses a compact pattern.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from finishup.legacy_names import GUIDANCE_SCHEME, LEGACY_GUIDANCE_SCHEME

__all__ = [
    "ALL_GUIDANCE_URIS",
    "FOCUSED_GUIDANCE_URIS",
    "GUIDANCE_DOCUMENT_URIS",
    "GUIDANCE_TOPIC_URIS",
    "GUIDANCE_URI_PREFIX",
    "LEGACY_ALL_GUIDANCE_URIS",
    "LEGACY_GUIDANCE_ANCHORS",
    "LEGACY_GUIDANCE_URI_PREFIX",
    "REGISTERED_GUIDANCE_URIS",
    "canonical_guidance_uri",
    "guidance_uri_in_scheme_of",
    "is_legacy_guidance_uri",
    "legacy_guidance_uri",
]

GUIDANCE_URI_PREFIX: Final = f"{GUIDANCE_SCHEME}://guidance/"

GUIDANCE_DOCUMENT_URIS: Final[tuple[str, ...]] = (
    "finishup://guidance/agent-instructions.md",
    "finishup://guidance/workflow.md",
    "finishup://guidance/publication-policy.md",
    "finishup://guidance/coverage-and-receipts.md",
    "finishup://guidance/request-templates.md",
)

FOCUSED_GUIDANCE_URIS: Final[tuple[str, ...]] = (
    "finishup://guidance/startup.md",
    "finishup://guidance/recovery.md",
    "finishup://guidance/publication.md",
    "finishup://guidance/review.md",
    "finishup://guidance/receipt.md",
    "finishup://guidance/delegation.md",
    "finishup://guidance/consent.md",
    "finishup://guidance/page-delivery.md",
)

GUIDANCE_TOPIC_URIS: Final[tuple[str, ...]] = (
    "finishup://guidance/startup.md",
    "finishup://guidance/recovery.md",
    "finishup://guidance/publication.md",
    "finishup://guidance/review.md",
    "finishup://guidance/receipt.md",
    "finishup://guidance/delegation.md",
    "finishup://guidance/consent.md",
    "finishup://guidance/page-delivery.md",
    "finishup://guidance/agent-instructions.md#when-to-use-finishup",
    "finishup://guidance/agent-instructions.md#guidance-catalog",
    "finishup://guidance/agent-instructions.md#essential-boundaries",
    "finishup://guidance/agent-instructions.md#start-contract",
    "finishup://guidance/agent-instructions.md#review-and-closure",
    "finishup://guidance/agent-instructions.md#multi-agent-work",
    "finishup://guidance/agent-instructions.md#read-more",
    "finishup://guidance/coverage-and-receipts.md#coverage-and-receipts",
    "finishup://guidance/coverage-and-receipts.md#coverage-is-a-vector",
    "finishup://guidance/coverage-and-receipts.md#evidence-and-provenance",
    "finishup://guidance/coverage-and-receipts.md#freshness-redaction-and-unknown-input",
    "finishup://guidance/coverage-and-receipts.md#findings-and-responses",
    "finishup://guidance/coverage-and-receipts.md#coverage-attribution",
    "finishup://guidance/coverage-and-receipts.md#repair-then-finish",
    "finishup://guidance/coverage-and-receipts.md#closure-readiness-actionable-standing-acknowledged",
    "finishup://guidance/coverage-and-receipts.md#state-examples",
    "finishup://guidance/coverage-and-receipts.md#child-dependencies-and-project-advice",
    "finishup://guidance/coverage-and-receipts.md#candidate-findings-are-not-a-check",
    "finishup://guidance/coverage-and-receipts.md#effective-claims-and-limitations",
    "finishup://guidance/coverage-and-receipts.md#check-mode-and-ai-powered-review-coverage",
    "finishup://guidance/coverage-and-receipts.md#complete-specification-preflight-and-provider-bound-input-coverage",
    "finishup://guidance/coverage-and-receipts.md#prose-the-reviewer-will-not-see-whole",
    "finishup://guidance/coverage-and-receipts.md#check-scope",
    "finishup://guidance/coverage-and-receipts.md#receipt-format",
    "finishup://guidance/coverage-and-receipts.md#receipt-fields-and-wording",
    "finishup://guidance/coverage-and-receipts.md#discover-evidence-before-authoring-replacements",
    "finishup://guidance/coverage-and-receipts.md#ai-powered-review-authority-who-already-decided-what",
    "finishup://guidance/coverage-and-receipts.md#when-host-auto-review-blocks-an-ai-powered-check-before-finishup-runs",
    "finishup://guidance/coverage-and-receipts.md#when-a-check-is-waiting-on-a-local-decision",
    "finishup://guidance/coverage-and-receipts.md#when-the-current-repository-grant-is-missing",
    "finishup://guidance/coverage-and-receipts.md#recovery",
    "finishup://guidance/coverage-and-receipts.md#bounded-recovery-and-fresh-verification",
    "finishup://guidance/coverage-and-receipts.md#degraded-and-unavailable-behavior",
    "finishup://guidance/coverage-and-receipts.md#startup-failure-precedence",
    "finishup://guidance/coverage-and-receipts.md#inherited-unavailability-and-delegation",
    "finishup://guidance/coverage-and-receipts.md#unrelated-command-gaps-and-action-result-repairs",
    "finishup://guidance/coverage-and-receipts.md#missing-review-content-and-concrete-repair-attempts",
    "finishup://guidance/publication-policy.md#publication-policy",
    "finishup://guidance/publication-policy.md#materiality-checklist",
    "finishup://guidance/publication-policy.md#cadence",
    "finishup://guidance/publication-policy.md#the-sixteen-event-families",
    "finishup://guidance/publication-policy.md#obligations-evidence-and-claims",
    "finishup://guidance/publication-policy.md#digest-subjects-and-provenance",
    "finishup://guidance/publication-policy.md#discover-evidence-before-authoring-replacements",
    "finishup://guidance/publication-policy.md#making-a-change-reviewable",
    "finishup://guidance/publication-policy.md#claim-correction-and-limitation-linkage",
    "finishup://guidance/publication-policy.md#repair-then-finish",
    "finishup://guidance/publication-policy.md#operation-specific-recovery-and-templates",
    "finishup://guidance/publication-policy.md#declare-completion-scope-in-the-plan",
    "finishup://guidance/publication-policy.md#obligation-resolution",
    "finishup://guidance/publication-policy.md#requested-items-and-attempt-accounting",
    "finishup://guidance/publication-policy.md#subject-state-and-freshness",
    "finishup://guidance/publication-policy.md#batching-sequencing-and-retry",
    "finishup://guidance/publication-policy.md#service-filled-values",
    "finishup://guidance/publication-policy.md#event-draft-skeleton",
    "finishup://guidance/publication-policy.md#set-valued-reference-lists",
    "finishup://guidance/publication-policy.md#reference-mirrors",
    "finishup://guidance/publication-policy.md#event-time-claims",
    "finishup://guidance/publication-policy.md#multi-agent-work",
    "finishup://guidance/publication-policy.md#forbidden-content",
    "finishup://guidance/publication-policy.md#mini-flows",
    "finishup://guidance/publication-policy.md#code-change",
    "finishup://guidance/publication-policy.md#research",
    "finishup://guidance/publication-policy.md#plan-revision",
    "finishup://guidance/publication-policy.md#large-generated-inventory",
    "finishup://guidance/publication-policy.md#check-completion-scope-before-append",
    "finishup://guidance/request-templates.md#finishup-request-templates-and-exceptional-operations",
    "finishup://guidance/request-templates.md#replace-the-illustrative-values-first",
    "finishup://guidance/request-templates.md#initial-shape-matrix-and-bounded-guidance-reads",
    "finishup://guidance/request-templates.md#reconstruct-a-bounded-guidance-document",
    "finishup://guidance/request-templates.md#publication-templates",
    "finishup://guidance/request-templates.md#publish-shapes",
    "finishup://guidance/request-templates.md#start",
    "finishup://guidance/request-templates.md#publish-work-revise-the-task-statement",
    "finishup://guidance/request-templates.md#publish-work-plan-plus-obligation",
    "finishup://guidance/request-templates.md#alternate-plan-published-explicitly-no-obligations",
    "finishup://guidance/request-templates.md#publish-work-assignment",
    "finishup://guidance/request-templates.md#publish-work-decision",
    "finishup://guidance/request-templates.md#publish-work-action",
    "finishup://guidance/request-templates.md#publish-work-result",
    "finishup://guidance/request-templates.md#publish-work-evidence",
    "finishup://guidance/request-templates.md#publish-work-claim",
    "finishup://guidance/request-templates.md#canonical-completion-claim-repair",
    "finishup://guidance/request-templates.md#publish-work-revised-plan",
    "finishup://guidance/request-templates.md#status",
    "finishup://guidance/request-templates.md#status-resolution-history-after-a-repair-check",
    "finishup://guidance/request-templates.md#check-whole-case",
    "finishup://guidance/request-templates.md#check-complete-task-specification",
    "finishup://guidance/request-templates.md#check-scoped",
    "finishup://guidance/request-templates.md#respond",
    "finishup://guidance/request-templates.md#receipt",
    "finishup://guidance/request-templates.md#start-delegate-child-attach-and-self-registration",
    "finishup://guidance/request-templates.md#publish-work-child-and-work-lifecycle",
    "finishup://guidance/request-templates.md#child-accepted",
    "finishup://guidance/request-templates.md#child-rejected",
    "finishup://guidance/request-templates.md#child-written-off",
    "finishup://guidance/request-templates.md#delegation-cancelled",
    "finishup://guidance/request-templates.md#work-closed",
    "finishup://guidance/request-templates.md#work-cancelled",
    "finishup://guidance/request-templates.md#work-written-off",
    "finishup://guidance/request-templates.md#publish-work-declare-coordination-responsibility",
    "finishup://guidance/request-templates.md#publish-work-coordination-disposition",
    "finishup://guidance/request-templates.md#guided-closure-and-recovery",
    "finishup://guidance/request-templates.md#mcp-closure-prepare",
    "finishup://guidance/request-templates.md#setup-and-consent",
    "finishup://guidance/request-templates.md#recommendations",
    "finishup://guidance/workflow.md#finishup-cooperative-workflow",
    "finishup://guidance/workflow.md#start-and-resume",
    "finishup://guidance/workflow.md#recovery-decision-table-02",
    "finishup://guidance/workflow.md#upgrade-and-schema-continuity",
    "finishup://guidance/workflow.md#owner-selected-required-startup",
    "finishup://guidance/workflow.md#material-work",
    "finishup://guidance/workflow.md#cadence",
    "finishup://guidance/workflow.md#completion",
    "finishup://guidance/workflow.md#errors-and-continuations",
    "finishup://guidance/workflow.md#consumer-and-maintainer-scope",
    "finishup://guidance/workflow.md#evidence-first-closure",
    "finishup://guidance/workflow.md#delegation-and-project-coordination",
    "finishup://guidance/workflow.md#child-assignment-and-child-closure",
    "finishup://guidance/workflow.md#project-coordination",
    "finishup://guidance/workflow.md#protect-an-evidence-sensitive-read",
    "finishup://guidance/workflow.md#start-selectors-and-findings",
    "finishup://guidance/workflow.md#findings-and-recheck",
    "finishup://guidance/workflow.md#degraded-and-unavailable-behavior",
    "finishup://guidance/workflow.md#inherited-unavailability-and-delegation",
    "finishup://guidance/workflow.md#safety-and-privacy",
    "finishup://guidance/workflow.md#promote-a-buffered-read",
    "finishup://guidance/workflow.md#change-local-retention-capacity",
    "finishup://guidance/workflow.md#first-start-contention-recovery",
    "finishup://guidance/workflow.md#missing-review-content-and-concrete-repair-attempts",
)

ALL_GUIDANCE_URIS: Final[tuple[str, ...]] = (
    "finishup://guidance/agent-instructions.md",
    "finishup://guidance/workflow.md",
    "finishup://guidance/publication-policy.md",
    "finishup://guidance/coverage-and-receipts.md",
    "finishup://guidance/request-templates.md",
    "finishup://guidance/startup.md",
    "finishup://guidance/recovery.md",
    "finishup://guidance/publication.md",
    "finishup://guidance/review.md",
    "finishup://guidance/receipt.md",
    "finishup://guidance/delegation.md",
    "finishup://guidance/consent.md",
    "finishup://guidance/page-delivery.md",
    "finishup://guidance/agent-instructions.md#when-to-use-finishup",
    "finishup://guidance/agent-instructions.md#guidance-catalog",
    "finishup://guidance/agent-instructions.md#essential-boundaries",
    "finishup://guidance/agent-instructions.md#start-contract",
    "finishup://guidance/agent-instructions.md#review-and-closure",
    "finishup://guidance/agent-instructions.md#multi-agent-work",
    "finishup://guidance/agent-instructions.md#read-more",
    "finishup://guidance/coverage-and-receipts.md#coverage-and-receipts",
    "finishup://guidance/coverage-and-receipts.md#coverage-is-a-vector",
    "finishup://guidance/coverage-and-receipts.md#evidence-and-provenance",
    "finishup://guidance/coverage-and-receipts.md#freshness-redaction-and-unknown-input",
    "finishup://guidance/coverage-and-receipts.md#findings-and-responses",
    "finishup://guidance/coverage-and-receipts.md#coverage-attribution",
    "finishup://guidance/coverage-and-receipts.md#repair-then-finish",
    "finishup://guidance/coverage-and-receipts.md#closure-readiness-actionable-standing-acknowledged",
    "finishup://guidance/coverage-and-receipts.md#state-examples",
    "finishup://guidance/coverage-and-receipts.md#child-dependencies-and-project-advice",
    "finishup://guidance/coverage-and-receipts.md#candidate-findings-are-not-a-check",
    "finishup://guidance/coverage-and-receipts.md#effective-claims-and-limitations",
    "finishup://guidance/coverage-and-receipts.md#check-mode-and-ai-powered-review-coverage",
    "finishup://guidance/coverage-and-receipts.md#complete-specification-preflight-and-provider-bound-input-coverage",
    "finishup://guidance/coverage-and-receipts.md#prose-the-reviewer-will-not-see-whole",
    "finishup://guidance/coverage-and-receipts.md#check-scope",
    "finishup://guidance/coverage-and-receipts.md#receipt-format",
    "finishup://guidance/coverage-and-receipts.md#receipt-fields-and-wording",
    "finishup://guidance/coverage-and-receipts.md#discover-evidence-before-authoring-replacements",
    "finishup://guidance/coverage-and-receipts.md#ai-powered-review-authority-who-already-decided-what",
    "finishup://guidance/coverage-and-receipts.md#when-host-auto-review-blocks-an-ai-powered-check-before-finishup-runs",
    "finishup://guidance/coverage-and-receipts.md#when-a-check-is-waiting-on-a-local-decision",
    "finishup://guidance/coverage-and-receipts.md#when-the-current-repository-grant-is-missing",
    "finishup://guidance/coverage-and-receipts.md#recovery",
    "finishup://guidance/coverage-and-receipts.md#bounded-recovery-and-fresh-verification",
    "finishup://guidance/coverage-and-receipts.md#degraded-and-unavailable-behavior",
    "finishup://guidance/coverage-and-receipts.md#startup-failure-precedence",
    "finishup://guidance/coverage-and-receipts.md#inherited-unavailability-and-delegation",
    "finishup://guidance/coverage-and-receipts.md#unrelated-command-gaps-and-action-result-repairs",
    "finishup://guidance/coverage-and-receipts.md#missing-review-content-and-concrete-repair-attempts",
    "finishup://guidance/publication-policy.md#publication-policy",
    "finishup://guidance/publication-policy.md#materiality-checklist",
    "finishup://guidance/publication-policy.md#cadence",
    "finishup://guidance/publication-policy.md#the-sixteen-event-families",
    "finishup://guidance/publication-policy.md#obligations-evidence-and-claims",
    "finishup://guidance/publication-policy.md#digest-subjects-and-provenance",
    "finishup://guidance/publication-policy.md#discover-evidence-before-authoring-replacements",
    "finishup://guidance/publication-policy.md#making-a-change-reviewable",
    "finishup://guidance/publication-policy.md#claim-correction-and-limitation-linkage",
    "finishup://guidance/publication-policy.md#repair-then-finish",
    "finishup://guidance/publication-policy.md#operation-specific-recovery-and-templates",
    "finishup://guidance/publication-policy.md#declare-completion-scope-in-the-plan",
    "finishup://guidance/publication-policy.md#obligation-resolution",
    "finishup://guidance/publication-policy.md#requested-items-and-attempt-accounting",
    "finishup://guidance/publication-policy.md#subject-state-and-freshness",
    "finishup://guidance/publication-policy.md#batching-sequencing-and-retry",
    "finishup://guidance/publication-policy.md#service-filled-values",
    "finishup://guidance/publication-policy.md#event-draft-skeleton",
    "finishup://guidance/publication-policy.md#set-valued-reference-lists",
    "finishup://guidance/publication-policy.md#reference-mirrors",
    "finishup://guidance/publication-policy.md#event-time-claims",
    "finishup://guidance/publication-policy.md#multi-agent-work",
    "finishup://guidance/publication-policy.md#forbidden-content",
    "finishup://guidance/publication-policy.md#mini-flows",
    "finishup://guidance/publication-policy.md#code-change",
    "finishup://guidance/publication-policy.md#research",
    "finishup://guidance/publication-policy.md#plan-revision",
    "finishup://guidance/publication-policy.md#large-generated-inventory",
    "finishup://guidance/publication-policy.md#check-completion-scope-before-append",
    "finishup://guidance/request-templates.md#finishup-request-templates-and-exceptional-operations",
    "finishup://guidance/request-templates.md#replace-the-illustrative-values-first",
    "finishup://guidance/request-templates.md#initial-shape-matrix-and-bounded-guidance-reads",
    "finishup://guidance/request-templates.md#reconstruct-a-bounded-guidance-document",
    "finishup://guidance/request-templates.md#publication-templates",
    "finishup://guidance/request-templates.md#publish-shapes",
    "finishup://guidance/request-templates.md#start",
    "finishup://guidance/request-templates.md#publish-work-revise-the-task-statement",
    "finishup://guidance/request-templates.md#publish-work-plan-plus-obligation",
    "finishup://guidance/request-templates.md#alternate-plan-published-explicitly-no-obligations",
    "finishup://guidance/request-templates.md#publish-work-assignment",
    "finishup://guidance/request-templates.md#publish-work-decision",
    "finishup://guidance/request-templates.md#publish-work-action",
    "finishup://guidance/request-templates.md#publish-work-result",
    "finishup://guidance/request-templates.md#publish-work-evidence",
    "finishup://guidance/request-templates.md#publish-work-claim",
    "finishup://guidance/request-templates.md#canonical-completion-claim-repair",
    "finishup://guidance/request-templates.md#publish-work-revised-plan",
    "finishup://guidance/request-templates.md#status",
    "finishup://guidance/request-templates.md#status-resolution-history-after-a-repair-check",
    "finishup://guidance/request-templates.md#check-whole-case",
    "finishup://guidance/request-templates.md#check-complete-task-specification",
    "finishup://guidance/request-templates.md#check-scoped",
    "finishup://guidance/request-templates.md#respond",
    "finishup://guidance/request-templates.md#receipt",
    "finishup://guidance/request-templates.md#start-delegate-child-attach-and-self-registration",
    "finishup://guidance/request-templates.md#publish-work-child-and-work-lifecycle",
    "finishup://guidance/request-templates.md#child-accepted",
    "finishup://guidance/request-templates.md#child-rejected",
    "finishup://guidance/request-templates.md#child-written-off",
    "finishup://guidance/request-templates.md#delegation-cancelled",
    "finishup://guidance/request-templates.md#work-closed",
    "finishup://guidance/request-templates.md#work-cancelled",
    "finishup://guidance/request-templates.md#work-written-off",
    "finishup://guidance/request-templates.md#publish-work-declare-coordination-responsibility",
    "finishup://guidance/request-templates.md#publish-work-coordination-disposition",
    "finishup://guidance/request-templates.md#guided-closure-and-recovery",
    "finishup://guidance/request-templates.md#mcp-closure-prepare",
    "finishup://guidance/request-templates.md#setup-and-consent",
    "finishup://guidance/request-templates.md#recommendations",
    "finishup://guidance/workflow.md#finishup-cooperative-workflow",
    "finishup://guidance/workflow.md#start-and-resume",
    "finishup://guidance/workflow.md#recovery-decision-table-02",
    "finishup://guidance/workflow.md#upgrade-and-schema-continuity",
    "finishup://guidance/workflow.md#owner-selected-required-startup",
    "finishup://guidance/workflow.md#material-work",
    "finishup://guidance/workflow.md#cadence",
    "finishup://guidance/workflow.md#completion",
    "finishup://guidance/workflow.md#errors-and-continuations",
    "finishup://guidance/workflow.md#consumer-and-maintainer-scope",
    "finishup://guidance/workflow.md#evidence-first-closure",
    "finishup://guidance/workflow.md#delegation-and-project-coordination",
    "finishup://guidance/workflow.md#child-assignment-and-child-closure",
    "finishup://guidance/workflow.md#project-coordination",
    "finishup://guidance/workflow.md#protect-an-evidence-sensitive-read",
    "finishup://guidance/workflow.md#start-selectors-and-findings",
    "finishup://guidance/workflow.md#findings-and-recheck",
    "finishup://guidance/workflow.md#degraded-and-unavailable-behavior",
    "finishup://guidance/workflow.md#inherited-unavailability-and-delegation",
    "finishup://guidance/workflow.md#safety-and-privacy",
    "finishup://guidance/workflow.md#promote-a-buffered-read",
    "finishup://guidance/workflow.md#change-local-retention-capacity",
    "finishup://guidance/workflow.md#first-start-contention-recovery",
    "finishup://guidance/workflow.md#missing-review-content-and-concrete-repair-attempts",
)

# Legacy document enumeration remains stable for resources/list; topic URIs use the exact catalog above.
REGISTERED_GUIDANCE_URIS: Final[tuple[str, ...]] = GUIDANCE_DOCUMENT_URIS

# Installed 0.1-0.3 guidance, skills, host artifacts and the released read-guidance 1.0.0 contract
# name ``yoetz://guidance/...`` (ADR-048). A legacy URI is recognized only as the exact legacy
# spelling of a catalogued entry: the scheme, plus the four title anchors whose heading carried the
# product name. It is never resolved by pattern, so the closed catalog stays the admission rule.
LEGACY_GUIDANCE_URI_PREFIX: Final = f"{LEGACY_GUIDANCE_SCHEME}://guidance/"
# Frozen legacy identifier (ADR-048): heading anchors as the pre-rename guidance spelled them.
LEGACY_GUIDANCE_ANCHORS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "agent-instructions.md#when-to-use-yoetz": "agent-instructions.md#when-to-use-finishup",
        "coverage-and-receipts.md#when-host-auto-review-blocks-an-ai-powered-check-before-yoetz-runs": (
            "coverage-and-receipts.md"
            "#when-host-auto-review-blocks-an-ai-powered-check-before-finishup-runs"
        ),
        "request-templates.md#yoetz-request-templates-and-exceptional-operations": (
            "request-templates.md#finishup-request-templates-and-exceptional-operations"
        ),
        "workflow.md#yoetz-cooperative-workflow": "workflow.md#finishup-cooperative-workflow",
    }
)
_CURRENT_TO_LEGACY_ANCHOR: Final[Mapping[str, str]] = MappingProxyType(
    {current: legacy for legacy, current in LEGACY_GUIDANCE_ANCHORS.items()}
)
_ALL_GUIDANCE_URI_SET: Final = frozenset(ALL_GUIDANCE_URIS)


def legacy_guidance_uri(uri: str) -> str:
    """Spell one catalogued guidance URI the way pre-rename guidance named it (ADR-048)."""

    if uri not in _ALL_GUIDANCE_URI_SET:
        raise ValueError("guidance_resource_uri_unregistered")
    relative = uri.removeprefix(GUIDANCE_URI_PREFIX)
    return LEGACY_GUIDANCE_URI_PREFIX + _CURRENT_TO_LEGACY_ANCHOR.get(relative, relative)


LEGACY_ALL_GUIDANCE_URIS: Final[tuple[str, ...]] = tuple(
    legacy_guidance_uri(uri) for uri in ALL_GUIDANCE_URIS
)
_LEGACY_TO_CURRENT: Final[Mapping[str, str]] = MappingProxyType(
    dict(zip(LEGACY_ALL_GUIDANCE_URIS, ALL_GUIDANCE_URIS, strict=True))
)


def is_legacy_guidance_uri(uri: object) -> bool:
    """Whether ``uri`` is the exact legacy spelling of a catalogued entry (ADR-048)."""

    return type(uri) is str and uri in _LEGACY_TO_CURRENT


def canonical_guidance_uri(uri: object) -> str | None:
    """The catalogued ``finishup://`` URI that ``uri`` names in either spelling, else ``None``.

    A current catalog entry is returned unchanged; an exact legacy spelling maps to its entry
    (ADR-048). Anything else, including an uncatalogued anchor, returns ``None``.
    """

    if type(uri) is not str:
        return None
    if uri in _ALL_GUIDANCE_URI_SET:
        return uri
    return _LEGACY_TO_CURRENT.get(uri)


def guidance_uri_in_scheme_of(uri: str, caller_uri: str) -> str:
    """Render catalogued ``uri`` in the scheme ``caller_uri`` used (ADR-048).

    A caller that asked in the legacy scheme reads its answer, page continuations included, in
    that scheme, as the released read-guidance 1.0.0 result requires; every other caller reads the
    current spelling.
    """

    if caller_uri.startswith(LEGACY_GUIDANCE_URI_PREFIX):
        return legacy_guidance_uri(uri)
    return uri
