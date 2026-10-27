"""Local privacy classification, minimization, and exact-byte scan."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Final, Protocol, cast

from finishup.application.semantic_case import (
    REVIEW_PACKET_ITEM_ID,
    assemble_filtered_review_packet,
)
from finishup.domain.privacy import (
    OBSERVATION_ADVICE_PACKET_ITEM_ID,
    CandidateContext,
    CandidateContextItem,
    ClassifiedContext,
    ClassifiedContextItem,
    CredentialHeuristic,
    DataClass,
    DisclosureProvenance,
    EgressChannel,
    ForbiddenDataKind,
    LocalDisclosureSink,
    PrivacyDecision,
    ProjectionProvenanceContext,
    external_review_credential_heuristic,
)
from finishup.observability.privacy import (
    heuristic_value_lines,
    redact_encoded_heuristic_spans,
    redact_heuristic_spans,
    scan_finding_is_heuristic,
    scan_for_sensitive_content,
)
from finishup.ports.privacy import EffectivePrivacyPolicy, MinimizedDisclosure
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import OPAQUE_ITEM_ID_PATTERN
from finishup.protocol.models import DataCategory
from finishup.protocol.redacted_values import (
    MAX_SEMANTIC_REDACTED_VALUE_ITEMS,
    MAX_SEMANTIC_REDACTED_VALUE_LINES,
    SemanticRedactedValue,
)

__all__ = [
    "EGRESS_BYTES_PER_TOKEN_ESTIMATE",
    "ClassificationRuleset",
    "LocalPrivacyEnforcer",
    "MinimizationRuleset",
    "ProvenanceRuleset",
    "ReviewSelectionRuleset",
    "SecretScanRuleset",
    "SensitiveScan",
    "TrustedProvenanceResolver",
    "clean_item_data_class",
    "estimated_token_count",
    "scan_exact_bytes",
    "scan_exact_bytes_with_confidence",
]

# The whole-case token ceiling in ChannelPolicy is compared against this estimate, so anything
# that publishes a token budget has to derive it the same way or the two ceilings silently
# disagree. Four bytes per token is the usual rough estimate for this content.
EGRESS_BYTES_PER_TOKEN_ESTIMATE: Final = 4


def estimated_token_count(byte_count: int) -> int:
    """Estimate the token count a channel ``max_tokens`` ceiling is compared against."""

    if type(byte_count) is not int or byte_count < 0:
        raise ValueError("egress_byte_count_invalid")
    return (byte_count + EGRESS_BYTES_PER_TOKEN_ESTIMATE - 1) // EGRESS_BYTES_PER_TOKEN_ESTIMATE


# The bounded Python source proof and minimum-span transform are a new scanner profile. Keep the
# profile identity distinct so proposals and receipts cannot present the previous whole-item policy
# as though it had used the new semantics.
_SCANNER_REGISTRY_VERSION = "observability-sensitive-content-v3"
_SCANNER_PROFILE_DIGEST = "sha256:70957e0aac5cefb3d012c21715049718ec1cd2c51a8c4b4489d4bc5eacfb5726"
_STRUCTURAL_CATEGORIES = frozenset(
    {DataCategory.BOUNDED_STRUCTURAL_METADATA, DataCategory.DECLARED_FILE_TYPE}
)


def clean_item_data_class(category: DataCategory) -> DataClass:
    """The data class an item of ``category`` receives when no forbidden data is found in it.

    The review-case planner uses this to measure only what a channel will release, so it must
    stay the classifier's own rule (issue #907 Phase 1b).
    """

    return (
        DataClass.PUBLIC_STRUCTURAL
        if category in _STRUCTURAL_CATEGORIES
        else DataClass.ORDINARY_USER_CONTENT
    )


_FORBIDDEN_SOURCE_PREFIXES: tuple[tuple[str, ForbiddenDataKind], ...] = (
    ("credential:", ForbiddenDataKind.CREDENTIAL_FILE),
    ("environment:", ForbiddenDataKind.UNRELATED_ENVIRONMENT),
    ("keyring:", ForbiddenDataKind.KEYRING_CONTENT),
    ("out_of_scope:", ForbiddenDataKind.OUT_OF_SCOPE_FILE),
    ("raw_database:", ForbiddenDataKind.RAW_DATABASE),
    ("raw_log:", ForbiddenDataKind.UNRESTRICTED_LOG),
    ("raw_stderr:", ForbiddenDataKind.RAW_STDERR),
    ("transcript:", ForbiddenDataKind.COMPLETE_TRANSCRIPT),
    ("vault:", ForbiddenDataKind.HIDDEN_AUTH_CONFIGURATION),
)


@dataclass(frozen=True, slots=True)
class ClassificationRuleset:
    version: str = "privacy-classification-v1"


@dataclass(frozen=True, slots=True)
class ProvenanceRuleset:
    version: str = "privacy-provenance-v1"


@dataclass(frozen=True, slots=True)
class ReviewSelectionRuleset:
    version: str = "privacy-review-selection-v1"


@dataclass(frozen=True, slots=True)
class MinimizationRuleset:
    version: str = "privacy-minimization-v1"


@dataclass(frozen=True, slots=True)
class SecretScanRuleset:
    version: str = _SCANNER_REGISTRY_VERSION
    profile_digest: str = _SCANNER_PROFILE_DIGEST


class TrustedProvenanceResolver(Protocol):
    """Resolve a frozen-frontier ledger fact; ``None`` means ambiguous and denies widening."""

    def resolve(
        self,
        context: ProjectionProvenanceContext,
        candidate: CandidateContext,
        item: CandidateContextItem,
    ) -> DisclosureProvenance | None: ...


@dataclass(frozen=True, slots=True)
class SensitiveScan:
    """Closed scanner classes used by egress without retaining matched bytes."""

    high_confidence: tuple[ForbiddenDataKind, ...]
    heuristic: tuple[ForbiddenDataKind, ...]
    saturated: bool = False

    def __post_init__(self) -> None:
        for values in (self.high_confidence, self.heuristic):
            if type(values) is not tuple or any(
                type(value) is not ForbiddenDataKind for value in values
            ):
                raise ValueError("sensitive_scan_kinds_invalid")
            if values != tuple(sorted(set(values), key=lambda value: value.value.encode())):
                raise ValueError("sensitive_scan_kinds_not_canonical")
        if set(self.high_confidence) & set(self.heuristic):
            raise ValueError("sensitive_scan_kind_class_overlap")
        if type(self.saturated) is not bool:
            raise ValueError("sensitive_scan_saturation_invalid")

    @property
    def all_findings(self) -> tuple[ForbiddenDataKind, ...]:
        return tuple(
            sorted(
                set(self.high_confidence) | set(self.heuristic),
                key=lambda value: value.value.encode(),
            )
        )


def scan_exact_bytes_with_confidence(data: bytes) -> SensitiveScan:
    """Map scanner findings while preserving high-confidence versus heuristic classes."""

    findings = scan_for_sensitive_content(data)
    high: set[ForbiddenDataKind] = set()
    heuristic: set[ForbiddenDataKind] = set()
    for finding in findings:
        kind = (
            ForbiddenDataKind.PRIVATE_CERTIFICATE
            if finding.kind == "private_key_marker"
            else ForbiddenDataKind.API_CREDENTIAL
        )
        if scan_finding_is_heuristic(finding):
            heuristic.add(kind)
        else:
            high.add(kind)
    # The shared scanner deliberately caps findings. A saturated result cannot prove that no
    # later high-confidence credential exists, so egress must fail closed rather than treating a
    # crowded heuristic-only result as safe.
    saturated = len(findings) >= 128
    if saturated:
        high.add(ForbiddenDataKind.API_CREDENTIAL)
    # If two detector classes overlap, the high-confidence class wins. This keeps a concrete
    # credential from ever being downgraded merely because a heuristic also matched its span.
    heuristic.difference_update(high)
    return SensitiveScan(
        tuple(sorted(high, key=lambda value: value.value.encode())),
        tuple(sorted(heuristic, key=lambda value: value.value.encode())),
        saturated,
    )


def scan_exact_bytes(
    data: bytes, *, credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED
) -> tuple[ForbiddenDataKind, ...]:
    """Map the shared scanner to the closed never-send vocabulary.

    This public backstop deliberately includes heuristic findings. The semantic minimizer uses
    ``scan_exact_bytes_with_confidence`` to omit a heuristic-only item; a heuristic that survives
    into a final rendered body still fails closed here.

    ``credential_heuristic=DISABLED`` is the owner opt-out (issue #982): only the high-confidence
    class is reported. Known credential shapes, private-key markers, URI passwords, canaries and
    scanner saturation are in that class, so they still fail closed.
    """

    scan = scan_exact_bytes_with_confidence(data)
    if credential_heuristic is CredentialHeuristic.ENFORCED:
        return scan.all_findings
    if credential_heuristic is not CredentialHeuristic.DISABLED:
        raise ValueError("credential_heuristic_invalid")
    return scan.high_confidence


_SEMANTIC_PACKET_SCHEMA = "yoetz.review-packet-case/2"


def _assemble_semantic_review_payload(
    classified: ClassifiedContext,
    included: tuple[ClassifiedContextItem, ...],
    *,
    withheld_item_ids: tuple[str, ...] = (),
    transformed_content: dict[str, bytes] | None = None,
    unselected_item_ids: tuple[str, ...] = (),
) -> bytes:
    """Assemble the versioned review-packet document from privacy-approved case items.

    The pre-egress builder supplies one structural ``review-packet`` envelope (with item catalog
    and packet metadata) plus separate categorized content items. Projection reuses the shared
    builder filter so section/source_kind/subject_ref are never reverse-engineered from origin_ref.
    """

    del classified  # catalog on the envelope is the authority; classified only supplied included.
    included_by_id = {item.candidate.item_id: item for item in included}
    envelope_item = included_by_id.get(REVIEW_PACKET_ITEM_ID)
    if envelope_item is None:
        # Structural envelope withheld or missing: fail closed to empty authorized payload shape
        # recognized by the coordinator as insufficient approved context when ids are empty.
        return canonical_encode(
            cast(
                JsonValue,
                {
                    "items": [],
                    "omissions": [],
                    "schema": _SEMANTIC_PACKET_SCHEMA,
                },
            )
        )
    try:
        envelope_bytes = (
            transformed_content.get(REVIEW_PACKET_ITEM_ID, envelope_item.candidate.plaintext)
            if transformed_content is not None
            else envelope_item.candidate.plaintext
        )
        envelope = strict_json_parse(envelope_bytes)
    except Exception:
        return canonical_encode(
            cast(
                JsonValue,
                {
                    "items": [],
                    "omissions": [],
                    "schema": _SEMANTIC_PACKET_SCHEMA,
                },
            )
        )
    if not (
        isinstance(envelope, dict)
        and envelope.get("schema") == _SEMANTIC_PACKET_SCHEMA
        and isinstance(envelope.get("review_packet"), dict)
        and isinstance(envelope.get("item_catalog"), list)
    ):
        return canonical_encode(
            cast(JsonValue, {"items": [], "omissions": [], "schema": _SEMANTIC_PACKET_SCHEMA})
        )
    content_by_id = {
        item_id: (
            transformed_content.get(item_id, item.candidate.plaintext)
            if transformed_content is not None
            else item.candidate.plaintext
        )
        for item_id, item in included_by_id.items()
        if item_id != REVIEW_PACKET_ITEM_ID
    }
    return assemble_filtered_review_packet(
        cast(dict[str, object], envelope),
        content_by_id=content_by_id,
        included_item_ids=set(included_by_id),
        withheld_item_ids=set(withheld_item_ids),
        redacted_item_ids=set(transformed_content or ()),
        unselected_item_ids=set(unselected_item_ids),
        # The bytes each item had before redaction: a row cut at disclosure (#1230) then reads
        # its own size, not the composed one.
        before_bytes_by_id={
            item_id: len(item.candidate.plaintext) for item_id, item in included_by_id.items()
        },
    )


# One round normally suffices; the bound keeps a pathological packet from looping.
_MAX_PARTIAL_WITHHOLD_ROUNDS: Final = 3


def _items_carrying_heuristic(
    included: tuple[ClassifiedContextItem, ...],
    transformed_content: dict[str, bytes],
) -> frozenset[str]:
    """Ids of included items whose own content, as JSON-encoded in the packet, scans heuristic.

    The prepared packet embeds each item's text as a JSON string, so each item is scanned both as
    sent bytes and in that encoding. Only the item id is returned; no scanned bytes are retained.
    """

    offending: set[str] = set()
    for item in included:
        content = transformed_content.get(item.candidate.item_id, item.candidate.plaintext)
        forms = [content]
        try:
            forms.append(canonical_encode(content.decode("utf-8")))
        except UnicodeDecodeError:
            pass
        if any(scan_exact_bytes_with_confidence(form).all_findings for form in forms):
            offending.add(item.candidate.item_id)
    return frozenset(offending)


def _redact_encoded_heuristic_spans(content: bytes) -> tuple[bytes, int] | None:
    """The shared encoded-form pass, with this minimizer's own value pass (#1230)."""

    return redact_encoded_heuristic_spans(content, redact=redact_heuristic_spans)


_OPAQUE_SOURCE_REF: Final = re.compile(OPAQUE_ITEM_ID_PATTERN, re.ASCII)


def _catalog_source_refs(classified: ClassifiedContext) -> dict[str, str]:
    """Map case item ids to their catalogued ledger refs from the structural envelope.

    Only refs that are themselves opaque tokens (``evd_...``, ``evt_...``, ``lineage``) are kept;
    anything else, such as a path, is left out. Nothing here reads item content.
    """

    envelope = next(
        (
            item.candidate.plaintext
            for item in classified.items
            if item.candidate.item_id == REVIEW_PACKET_ITEM_ID
        ),
        None,
    )
    if envelope is None:
        return {}
    try:
        parsed = strict_json_parse(envelope)
    except (TypeError, ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    catalog = parsed.get("item_catalog")
    refs: dict[str, str] = {}
    if type(catalog) is not list:
        return refs
    for row in catalog:
        if not isinstance(row, dict):
            continue
        item_id = row.get("item_id")
        source_ref = row.get("source_ref")
        if (
            type(item_id) is str
            and type(source_ref) is str
            and _OPAQUE_SOURCE_REF.fullmatch(source_ref) is not None
        ):
            refs[item_id] = source_ref
    return refs


def _heuristic_lines_of(content: bytes) -> set[int]:
    """Lines where the heuristic matches ``content`` raw or in its JSON-string encoding."""

    lines = set(heuristic_value_lines(content))
    try:
        encoded = canonical_encode(content.decode("utf-8"))
    except UnicodeDecodeError:
        return lines
    lines.update(heuristic_value_lines(encoded, json_string=True))
    return lines


def _semantic_redacted_values(
    replaced_lines: dict[str, set[int]],
    included_ids: set[str],
    withheld_item_ids: tuple[str, ...],
    withheld_lines: dict[str, set[int]],
    source_refs: dict[str, str],
) -> tuple[SemanticRedactedValue, ...]:
    """Bounded PL2-1 projection: item ids, catalogued refs and line numbers, never values."""

    entries: list[SemanticRedactedValue] = []
    withheld = set(withheld_item_ids)
    for item_id in sorted({*replaced_lines, *withheld}, key=str.encode):
        if item_id in withheld:
            disposition = "item_withheld"
            lines = withheld_lines.get(item_id, set())
        elif item_id in included_ids:
            disposition = "value_replaced"
            lines = replaced_lines[item_id]
        else:
            continue
        entries.append(
            SemanticRedactedValue(
                item_id,
                disposition,
                tuple(sorted(lines))[:MAX_SEMANTIC_REDACTED_VALUE_LINES],
                source_refs.get(item_id),
            )
        )
        if len(entries) >= MAX_SEMANTIC_REDACTED_VALUE_ITEMS:
            break
    return tuple(entries)


class LocalPrivacyEnforcer:
    """Provider-free implementation of the local privacy classifier port."""

    __slots__ = (
        "_classification",
        "_minimization",
        "_provenance",
        "_provenance_resolver",
        "_review_selection",
        "_scanner",
    )

    def __init__(
        self,
        *,
        provenance_resolver: TrustedProvenanceResolver | None = None,
        classification: ClassificationRuleset = ClassificationRuleset(),
        provenance: ProvenanceRuleset = ProvenanceRuleset(),
        review_selection: ReviewSelectionRuleset = ReviewSelectionRuleset(),
        minimization: MinimizationRuleset = MinimizationRuleset(),
        scanner: SecretScanRuleset = SecretScanRuleset(),
    ) -> None:
        self._provenance_resolver = provenance_resolver
        self._classification = classification
        self._provenance = provenance
        self._review_selection = review_selection
        self._minimization = minimization
        self._scanner = scanner

    def classify(
        self, candidate: CandidateContext, policy: EffectivePrivacyPolicy
    ) -> ClassifiedContext:
        if type(candidate) is not CandidateContext or type(policy) is not EffectivePrivacyPolicy:
            raise TypeError("privacy_classification_input_invalid")
        # The owner policy decides whether the low-confidence assignment heuristic participates
        # at all (issue #982). The setting travels on the classified context, so minimization
        # and every later scan of these bytes apply the same value.
        # Only external AI-reviewer egress honours the opt-out; local sinks always enforce.
        credential_heuristic = (
            external_review_credential_heuristic(
                policy.policy, candidate.provider_binding, local_sink=candidate.local_sink
            )
            if candidate.channel is EgressChannel.LLM_INFERENCE
            else CredentialHeuristic.ENFORCED
        )
        heuristic_enforced = credential_heuristic is CredentialHeuristic.ENFORCED
        classified: list[ClassifiedContextItem] = []
        for item in candidate.items:
            source_findings = {
                kind
                for prefix, kind in _FORBIDDEN_SOURCE_PREFIXES
                if item.origin_ref.startswith(prefix)
            }
            scan = scan_exact_bytes_with_confidence(item.plaintext)
            source_findings.update(scan.high_confidence)
            heuristic_findings: set[ForbiddenDataKind] = (
                set(scan.heuristic) if heuristic_enforced else set()
            )
            scope_valid = item.source_disclosure_permitted and candidate.scope.contains(
                item.source_scope
            )
            data_class = (
                DataClass.SECRET_OR_CRYPTOGRAPHIC
                if source_findings
                else clean_item_data_class(item.category)
            )
            resolved_provenance: DisclosureProvenance | None = None
            if candidate.local_sink is LocalDisclosureSink.AGENT_CONTEXT and not source_findings:
                resolver = self._provenance_resolver
                if resolver is not None and candidate.provenance_context is not None:
                    context = candidate.provenance_context
                    assert context is not None
                    resolved = resolver.resolve(context, candidate, item)
                    if resolved is not None and type(resolved) is not DisclosureProvenance:
                        raise ValueError("privacy_provenance_invalid")
                    resolved_provenance = resolved
            classified.append(
                ClassifiedContextItem(
                    candidate=item,
                    data_class=data_class,
                    forbidden_findings=tuple(
                        sorted(source_findings, key=lambda value: value.value.encode())
                    ),
                    scope_valid=scope_valid,
                    classifier_ruleset_version=self._classification.version,
                    provenance=resolved_provenance,
                    heuristic_findings=tuple(
                        sorted(heuristic_findings, key=lambda value: value.value.encode())
                    ),
                )
            )
        return ClassifiedContext(candidate, tuple(classified), credential_heuristic)

    def minimize_and_scan(
        self, classified: ClassifiedContext, decision: PrivacyDecision
    ) -> MinimizedDisclosure:
        if type(classified) is not ClassifiedContext or type(decision) is not PrivacyDecision:
            raise TypeError("privacy_minimization_input_invalid")
        approved = set(decision.approved_item_ids)
        heuristic_enforced = classified.credential_heuristic is CredentialHeuristic.ENFORCED
        included: tuple[ClassifiedContextItem, ...] = tuple(
            item
            for item in classified.items
            if item.candidate.item_id in approved
            and item.scope_valid
            and not item.forbidden_findings
            and item.data_class is not DataClass.SECRET_OR_CRYPTOGRAPHIC
        )
        included_id_set = {entry.candidate.item_id for entry in included}
        withheld_item_ids = tuple(
            sorted(
                {
                    item.candidate.item_id
                    for item in classified.items
                    if item.scope_valid
                    and item.heuristic_findings
                    and item.candidate.item_id not in included_id_set
                    # Left out for room (#1230), not withheld for its value.
                    and item.candidate.item_id not in decision.unselected_item_ids
                },
                key=str.encode,
            )
        )
        transformed_content: dict[str, bytes] = {}
        redacted_span_count = 0
        # PL2-1: the 1-based lines of each item where a value was replaced. Lines only; the
        # values and their offsets are never kept.
        replaced_lines: dict[str, set[int]] = {}
        for item in included:
            if not item.heuristic_findings:
                continue
            sanitized, span_count = redact_heuristic_spans(item.candidate.plaintext)
            transformed_content[item.candidate.item_id] = sanitized
            redacted_span_count += span_count
            if span_count:
                replaced_lines.setdefault(item.candidate.item_id, set()).update(
                    heuristic_value_lines(item.candidate.plaintext)
                )
        if classified.candidate.purpose == "semantic-review":
            prepared = _assemble_semantic_review_payload(
                classified,
                included,
                withheld_item_ids=withheld_item_ids,
                transformed_content=transformed_content,
                unselected_item_ids=decision.unselected_item_ids,
            )
            # Partial withholding (issue #976): a low-confidence heuristic that survives into the
            # prepared bytes is replaced in place inside the item(s) whose own encoded content
            # carries it, or, failing that, withholds only those items, and the packet is
            # re-assembled, in bounded rounds. A high-confidence finding, a
            # heuristic in the structural envelope, or one no single item explains leaves the
            # prepared bytes as they are, and egress still fails the whole case closed.
            encoded_redacted_ids: set[str] = set()
            # With the owner opt-out (issue #982) heuristic matches are not findings at all, so
            # there is nothing to replace or withhold here.
            for _round in range(_MAX_PARTIAL_WITHHOLD_ROUNDS if heuristic_enforced else 0):
                surviving = scan_exact_bytes_with_confidence(prepared)
                if not surviving.heuristic or surviving.high_confidence:
                    break
                offending = _items_carrying_heuristic(included, transformed_content)
                if not offending or REVIEW_PACKET_ITEM_ID in offending:
                    break
                # Redact the value, not the item (issue #982, owner decision B2): first replace
                # only the suspicious values as they appear in the packet's JSON encoding, so the
                # reviewer keeps the rest of the line, item and file. An item is withheld only
                # when that in-place replacement cannot make it scan clean, or already failed.
                to_withhold: set[str] = set()
                for item in included:
                    item_id = item.candidate.item_id
                    if item_id not in offending:
                        continue
                    current = transformed_content.get(item_id, item.candidate.plaintext)
                    replaced = (
                        None
                        if item_id in encoded_redacted_ids
                        else _redact_encoded_heuristic_spans(current)
                    )
                    if replaced is None:
                        to_withhold.add(item_id)
                        continue
                    sanitized, span_count = replaced
                    try:
                        encoded_current = canonical_encode(current.decode("utf-8"))
                    except UnicodeDecodeError:
                        encoded_current = b""
                    replaced_lines.setdefault(item_id, set()).update(
                        heuristic_value_lines(encoded_current, json_string=True)
                    )
                    transformed_content[item_id] = sanitized
                    redacted_span_count += span_count
                    encoded_redacted_ids.add(item_id)
                if to_withhold:
                    included = tuple(
                        item for item in included if item.candidate.item_id not in to_withhold
                    )
                    for item_id in to_withhold:
                        transformed_content.pop(item_id, None)
                    withheld_item_ids = tuple(
                        sorted({*withheld_item_ids, *to_withhold}, key=str.encode)
                    )
                prepared = _assemble_semantic_review_payload(
                    classified,
                    included,
                    withheld_item_ids=withheld_item_ids,
                    transformed_content=transformed_content,
                    unselected_item_ids=decision.unselected_item_ids,
                )
            # The assembly helper fails closed to a structural empty fallback when the approved
            # envelope is missing or malformed.  That fallback is useful as a bounded diagnostic,
            # but it is not a provider-bound review packet.  Clear the approved ids so the
            # coordinator returns INSUFFICIENT_APPROVED_CONTEXT instead of dispatching a successful
            # contentless semantic request.
            try:
                semantic_packet = strict_json_parse(prepared)
            except (TypeError, ValueError, UnicodeDecodeError):
                included = ()
            else:
                if not (
                    isinstance(semantic_packet, dict)
                    and semantic_packet.get("schema") == _SEMANTIC_PACKET_SCHEMA
                    and isinstance(semantic_packet.get("review_packet"), dict)
                ):
                    included = ()
                elif any(
                    item.candidate.item_id == OBSERVATION_ADVICE_PACKET_ITEM_ID
                    for item in classified.items
                ):
                    # Advice without its actual structural content is not a usable advice
                    # packet, even when the generic envelope alone remains approved.
                    rows = semantic_packet.get("items")
                    if not isinstance(rows, list) or not any(
                        isinstance(row, dict)
                        and row.get("item_id") == OBSERVATION_ADVICE_PACKET_ITEM_ID
                        for row in rows
                    ):
                        included = ()
        else:
            rows = [
                {
                    "category": item.candidate.category.value,
                    "content_base64": base64.b64encode(
                        transformed_content.get(item.candidate.item_id, item.candidate.plaintext)
                    ).decode("ascii"),
                    "item_id": item.candidate.item_id,
                }
                for item in included
            ]
            prepared = canonical_encode(
                cast(JsonValue, {"items": rows, "schema": "yoetz.minimized-disclosure/1"})
            )
        prepared_scan = scan_exact_bytes_with_confidence(prepared)
        source_digests = tuple(
            sorted(
                {
                    f"sha256:{hashlib.sha256(item.candidate.plaintext).hexdigest()}"
                    for item in included
                },
                key=str.encode,
            )
        )
        included_ids = tuple(sorted((item.candidate.item_id for item in included), key=str.encode))
        approved_categories = tuple(
            sorted({item.candidate.category for item in included}, key=lambda value: value.value)
        )
        removed = len(classified.items) - len(included)
        items_by_id = {item.candidate.item_id: item for item in classified.items}
        redacted_values = _semantic_redacted_values(
            replaced_lines,
            set(included_ids),
            withheld_item_ids,
            {
                item_id: _heuristic_lines_of(items_by_id[item_id].candidate.plaintext)
                for item_id in withheld_item_ids
                if item_id in items_by_id
            },
            _catalog_source_refs(classified)
            if classified.candidate.purpose == "semantic-review"
            else {},
        )
        return MinimizedDisclosure(
            prepared_bytes=prepared,
            included_item_ids=included_ids,
            source_item_digests=source_digests,
            approved_categories=approved_categories,
            blocked_categories=decision.blocked_categories,
            transformation_summary=tuple(
                sorted(
                    {
                        ("minimized_items", removed),
                        ("redacted_spans", redacted_span_count),
                    },
                    key=lambda item: item[0].encode(),
                )
            ),
            byte_count=len(prepared),
            token_count=estimated_token_count(len(prepared)),
            case_digest=f"sha256:{hashlib.sha256(prepared).hexdigest()}",
            scanner_registry_version=self._scanner.version,
            scanner_profile_digest=self._scanner.profile_digest,
            forbidden_findings=prepared_scan.high_confidence,
            withheld_item_ids=withheld_item_ids,
            heuristic_findings=prepared_scan.heuristic if heuristic_enforced else (),
            redacted_span_count=redacted_span_count,
            redacted_values=redacted_values,
        )

    def scan_exact_bytes(
        self,
        data: bytes,
        *,
        credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED,
    ) -> tuple[ForbiddenDataKind, ...]:
        return scan_exact_bytes(data, credential_heuristic=credential_heuristic)

    def scanner_identity(self) -> tuple[str, str]:
        """Return the registry/profile pair that guards prepared and rendered bytes."""

        return self._scanner.version, self._scanner.profile_digest
