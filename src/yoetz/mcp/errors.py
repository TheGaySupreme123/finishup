"""Bounded structured error mappings for the MCP transport surface."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Final, cast

from pydantic import ValidationError

from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import (
    REASON_CODE_CONTINUATIONS,
    SAFE_DETAIL_KEYS,
    PublicErrorCode,
    PublicOperationError,
)
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import FRONTIER_LEAVES, OperationFailureModel

# One definition of the admission shapes the protocol validator already enforces on the way out.
# Declaring them a second time here let this projector admit a token the validator never emits, or
# reject one it does, with nothing to catch the drift.
from yoetz.protocol.schemas import (
    EVENT_FAMILY_NAME_PATTERN,
    MAX_UNKNOWN_PROPERTY_COUNT,
    SCHEMA_VERSION_PATTERN,
)

__all__ = [
    "VALIDATION_REASON_TOKENS",
    "authoring_hint",
    "build_last_resort_internal_error_result",
    "build_public_error_result",
    "safe_validation_locations",
    "sanitize_unknown_tool_name",
    "tool_error_envelope",
]

# Every name here is a frozen presentation-schema property name, never a caller-controlled key, so
# naming one leaks nothing the caller did not already send. The import-time gate at the bottom of
# this module keeps the set complete over every declared name: one that is missing from here
# projects to its allowlisted parent, so the caller is told the parent is `missing` when it is
# present and valid, or that a whole payload is wrong when one key inside it is.
_SAFE_LOCATION_SEGMENTS: Final = frozenset(
    {
        # obligation_published 1.1.0 (#1002).
        "acknowledged_not_done_reason",
        "context_digest",
        "detection_id",
        "membership_generation",
        "recipient_task_id",
        "acceptance_criteria",
        "attach_handle",
        "child_task_id",
        "correlation_id",
        "expires_at",
        "handle",
        "parent_session_id",
        "parent_tool_call_id",
        "project_id",
        "reason_code",
        "selection",
        "phase",
        "observed_event_ids",
        "requested_item_indexes",
        "result_ids",
        "subagent_id",
        "actor",
        "actor_id",
        "actor_type",
        "approval_commitment",
        "approved_check_result_digest",
        # Frozen payload field names. Without them a nested enum failure (action_kind) projects
        # only to /event_drafts/N and the hint cannot name admitted members.
        "action_id",
        "action_kind",
        "affected_obligation_ids",
        "after_sequence",
        "alternatives",
        "artifact_refs",
        "asserted_by",
        "assignee_actor_id",
        "at_frontier",
        "attempted_items",
        # Evidence filter selector (status ``filter.author``, issue #914).
        "author",
        "authority",
        "byte_count",
        "captured_object_id",
        "causal_parents",
        "change",
        "claim_id",
        "claim_ids",
        "claim_kind",
        "client",
        "command",
        "content_availability",
        "content_digest",
        "cursor",
        "described_state",
        "description",
        "diff_digest",
        "digest_binding",
        "display_name",
        "disposition",
        "disputes_refs",
        "dry_run",
        # Issue #996: the earlier finding a respond duplicate_of answer links to.
        "duplicate_of_finding_id",
        "event_drafts",
        "event_id",
        "evidence_expectation",
        "evidence_id",
        "evidence_kind",
        "evidence_refs",
        "exit_status",
        "expected_frontier",
        "external_ref",
        "filter",
        "finding_frontier",
        "finding_id",
        "format",
        "freshness",
        "handoff_of",
        # Frontier leaves. Without them a wrong key inside expected_frontier/at_frontier projects
        # to the parent object and the caller learns only that "something" there is wrong.
        "head_digest",
        "include",
        "include_resolved",
        "include_unavailable",
        "integration",
        "item_kind",
        "kind",
        "limit",
        "limitation_refs",
        "max_findings",
        "final_review",
        "await_observations",
        "mode",
        "name",
        "no_obligations_reason",
        "obligation_changes",
        "obligation_id",
        "obligation_ids",
        "obligation_refs",
        "observed_at",
        "occurred_at",
        "operation_request_id",
        "origin",
        "outcome",
        "payload",
        "page_size",
        "plan_version",
        "policy_packs",
        "priority",
        "protocol_version",
        "publication_channel",
        "provenance",
        "rationale",
        "reason",
        "redaction_profile",
        "reference",
        "replacement_obligation_ids",
        "request_id",
        "requested_items",
        "requested_view",
        "resolution_evidence_refs",
        "result_id",
        # obligation_published 1.1.0 requested-item role (#1002).
        "role",
        "schema",
        "schema_name",
        "schema_version",
        "semantic_conclusion",
        "semantic_included_refs",
        "scope",
        "scope_description",
        "scope_exclusions",
        "sequence",
        "session_id",
        "source_refs",
        "statement",
        "status",
        "strength",
        "subject",
        "subject_state",
        "summary",
        "supersedes_event_id",
        "supersedes_claim_refs",
        "supersedes_plan_version",
        "supporting_refs",
        "task_id",
        "task_statement",
        "task_title",
        "tree_digest",
        "value",
        "version",
        "view",
        "waiver_expiry",
        "waiver_scope",
        "workspace_ref",
        "write_policy",
        "writer_id",
    }
)
# The reviewed escape hatch for the gate below. Empty today: no frozen `required` name has been
# judged unsafe to name. Adding one is an explicit review decision, not silent drift.
_DELIBERATELY_UNLOCATABLE: Final[frozenset[str]] = frozenset()
# The same escape hatch for merely *declared* names. Empty today: every frozen presentation-schema
# property is a name the caller already sent, so locating one leaks nothing.
_DELIBERATELY_UNLOCATABLE_DECLARED: Final[frozenset[str]] = frozenset()
_SAFE_VALIDATION_REASONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "missing": "missing",
        "extra_forbidden": "extra_forbidden",
        "literal_error": "invalid_value",
        "enum": "invalid_value",
        "bool_type": "invalid_type",
        "dict_type": "invalid_type",
        "int_type": "invalid_type",
        "list_type": "invalid_type",
        "string_type": "invalid_type",
        "tuple_type": "invalid_type",
        # Closed object-rule tokens projected from schema-side dependentRequired / if-then.
        "paired_field_required": "paired_field_required",
        "conditional_field_required": "conditional_field_required",
    }
)
# ValueError ctx tokens from `_validate_model_against_schema` projection: root-level object rules,
# and the closed instance reason a nested schema failure carries. Only these may replace the
# generic value_error reason; never trust free-form exception text.
_SAFE_VALUE_ERROR_REASON_TOKENS: Final = frozenset(
    {
        "paired_field_required",
        "conditional_field_required",
        "extra_forbidden",
        "guidance_page_size_invalid",
        "guidance_page_invalid",
        "guidance_revision_digest_mismatch",
    }
)
_EXTRA_FORBIDDEN_REASON: Final = "extra_forbidden"
# Every ``reasons`` member a validation location can carry. The text projector re-gates against
# this closed set before naming one, so the list on the wire and the token in the summary can
# never disagree, and nothing outside it -- however it got onto an envelope -- is ever rendered.
VALIDATION_REASON_TOKENS: Final[frozenset[str]] = frozenset(
    {*_SAFE_VALIDATION_REASONS.values(), *_SAFE_VALUE_ERROR_REASON_TOKENS, "invalid_type_or_value"}
)
_CONDITIONAL_FIELD_REQUIRED_REASON: Final = "conditional_field_required"
_EVENT_DRAFT_PAYLOAD_FIELD_POINTER: Final = re.compile(
    r"/event_drafts/[0-9]{1,3}/payload/[a-z][a-z0-9_]{0,63}", re.ASCII
)
# Payload pointers the unknown-key hint answers. Deeper pointers name their own admitted values.
_EVENT_DRAFT_PAYLOAD_POINTER: Final = re.compile(r"/event_drafts/[0-9]{1,3}/payload", re.ASCII)
# tb4n2 R3 (issue #1023): where a 1.1.0-only obligation feature lands when the draft says 1.0.0.
_OBLIGATION_V1_1_FEATURE_POINTER: Final = re.compile(
    r"/event_drafts/[0-9]{1,3}/payload(?:/status|/requested_items/[0-9]{1,2}(?:/item_kind)?)?",
    re.ASCII,
)
_OBLIGATION_ITEM_POINTER: Final = re.compile(
    r"/event_drafts/[0-9]{1,3}/payload/requested_items/[0-9]{1,2}", re.ASCII
)
_OBLIGATION_ITEM_KEYS_HINT: Final = (
    "a requested item admits only item_kind, value and role, and role only on"
    " obligation_published 1.1.0 (on file and directory items)"
)
_OBLIGATION_VERSION_HINT: Final = (
    "obligation_published 1.0.0 admits no item role, no directory item and no"
    " acknowledged_not_done status: publish such an obligation as obligation_published 1.1.0,"
    " which also accepts a plain obligation"
)
_EVENT_DRAFT_NESTED_PAYLOAD_POINTER: Final = re.compile(
    r"/event_drafts/[0-9]{1,3}/payload/[a-z]", re.ASCII
)
# ``/event_drafts/N/payload/<array>/<index>/<field>``: a member rule of a payload array item.
_EVENT_DRAFT_PAYLOAD_ITEM_FIELD_POINTER: Final = re.compile(
    r"/event_drafts/[0-9]{1,3}/payload/([a-z][a-z0-9_]{0,63})/[0-9]{1,3}/([a-z][a-z0-9_]{0,63})",
    re.ASCII,
)
_REASON_CODE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
# A closed registry of checked-in corrective sentences for facts that are true of the contract but
# are not expressible as a JSON Schema keyword, so no hint built from the schema alone can state
# them. Keys are `(tool, pointer, reason)`; nothing here is derived from a caller value, and the
# import-time gate below checks every field name each sentence mentions against that tool's frozen
# presentation schema so the registry cannot drift away from the contract it describes.
_CHECK_SCOPE_CORRECTION: Final = (
    "omit scope for the whole case, or send both claim_ids and obligation_ids as arrays of "
    "unique ids, where two empty arrays also mean the whole case"
)
_STATUS_FILTER_CORRECTION: Final = (
    "filter is admitted only with view assignment, candidate_findings, evidence, findings, "
    "history, obligations, or operation; omit filter for advice, compact, lineage, project, "
    "results, and versions"
)
_CORRECTIVE_HINTS: Final[Mapping[tuple[str, str, str], tuple[str, tuple[str, ...]]]] = (
    MappingProxyType(
        {
            # `scope` is optional, so a partial scope object reports its own required members as
            # missing and never says that dropping the whole object is the third admitted repair.
            ("check", "/scope", "missing"): (
                _CHECK_SCOPE_CORRECTION,
                ("scope", "claim_ids", "obligation_ids"),
            ),
            ("check", "/scope/claim_ids", "missing"): (
                _CHECK_SCOPE_CORRECTION,
                ("scope", "claim_ids", "obligation_ids"),
            ),
            ("check", "/scope/obligation_ids", "missing"): (
                _CHECK_SCOPE_CORRECTION,
                ("scope", "claim_ids", "obligation_ids"),
            ),
            # tb4n1: six status calls sent limit "200"; the pattern alone reads as a regex puzzle.
            ("status", "/limit", "invalid_type_or_value"): (
                'limit is a decimal string from "1" to "100"; read further pages with cursor',
                ("limit", "cursor"),
            ),
            # tb4n1: three status calls sent ``filter`` beside ``view`` results and got only the
            # template pointer. ``_STATUS_FILTER_BY_VIEW`` in the protocol models is the source;
            # a unit test keeps this sentence equal to it.
            ("status", "/filter", "extra_forbidden"): (
                _STATUS_FILTER_CORRECTION,
                ("filter", "view"),
            ),
            # tb4n1: a ``sequence:head_digest`` frontier was sent where only the sequence goes.
            ("status", "/at_frontier", "invalid_type_or_value"): (
                'at_frontier is a ledger sequence alone as a decimal string such as "42", '
                "without the head digest; omit at_frontier to read the current frontier",
                ("at_frontier",),
            ),
        }
    )
)
# Checked-in sentences for payload reference lists whose admitted id kind is a contract fact the
# id pattern states only as a regex. Keyed by ``(family, field)``; the import-time gate below
# checks that each named family declares every field its sentence mentions. tb4n1: 14 rejections
# put evidence ids in ``limitation_refs`` or result ids in a result's ``evidence_refs``.
_REFERENCE_LIST_CORRECTIONS: Final[Mapping[tuple[str, str], tuple[str, tuple[str, ...]]]] = (
    MappingProxyType(
        {
            ("claim_recorded", "limitation_refs"): (
                "limitation_refs names only non-success result ids (res_); cite evidence ids "
                "(evd_) in supporting_refs",
                ("limitation_refs", "supporting_refs"),
            ),
            ("result_recorded", "evidence_refs"): (
                "a result's evidence_refs names only evidence ids (evd_); cite result ids (res_) "
                "from a claim's supporting_refs or limitation_refs instead",
                ("evidence_refs",),
            ),
            ("claim_recorded", "disputes_refs"): (
                "disputes_refs names claim ids (clm_) or event ids (evt_); answer a finding "
                "(fnd_) with the respond tool instead",
                ("disputes_refs",),
            ),
        }
    )
)
_EVENT_DRAFT_PAYLOAD_MEMBER_POINTER: Final = re.compile(
    r"/event_drafts/[0-9]{1,3}/payload/([a-z][a-z0-9_]{0,63})/[0-9]{1,3}", re.ASCII
)
_MAX_VALIDATION_LOCATIONS: Final = 8
# Bounded so the hint stays a hint: a long enum dump would bury the field locations it explains.
_MAX_HINT_FIELDS: Final = 3
_MAX_HINT_ENUM_MEMBERS: Final = 16
# Schema-name unions (ordinary publish families) are larger than payload enums; keep a separate
# bound so `/event_drafts/N` can name admitted families without dumping unbounded oneOf lists.
_MAX_HINT_SCHEMA_NAMES: Final = 18
_MAX_HINT_PATTERN_CHARS: Final = 96
_MAX_HINT_REF_HOPS: Final = 8
_MAX_HINT_POINTER_SEGMENTS: Final = 8
_LOCAL_DEFS_PREFIX: Final = "#/$defs/"


def _pointer_for_location(
    location: object, *, project_parent_on_unsafe_leaf: bool = False
) -> str | None:
    if not isinstance(location, Sequence) or isinstance(location, str | bytes | bytearray):
        return None
    segments: list[str] = []
    for item in cast(Sequence[str | int], location):
        if type(item) is str:
            if item not in _SAFE_LOCATION_SEGMENTS:
                # Forbidden extras often name an untrusted key (e.g. client.id). Prefer the
                # allowlisted parent path over dropping the whole location or allowlisting "id".
                if project_parent_on_unsafe_leaf and segments:
                    break
                return None
            segments.append(item)
        elif type(item) is int and 0 <= item <= 100:
            # An index communicates shape, not a rejected value. Keep it bounded.
            segments.append(str(item))
        else:
            return None
        if len(segments) > 8:
            return None
    if not segments:
        return ""
    return "/" + "/".join(segments)


def _reason_from_validation_item(item: Mapping[str, object]) -> str:
    """Map one Pydantic error item to a closed safe reason token."""

    raw_reason = item.get("type")
    if type(raw_reason) is not str:
        return "invalid_type_or_value"
    if raw_reason == "value_error":
        # Object-rule projections stash a closed token on ValueError; do not trust other messages.
        ctx = item.get("ctx")
        if isinstance(ctx, Mapping):
            error = cast(Mapping[object, object], ctx).get("error")
            if isinstance(error, BaseException):
                token = str(error)
                if token in _SAFE_VALUE_ERROR_REASON_TOKENS:
                    return token
        return "invalid_type_or_value"
    return _SAFE_VALIDATION_REASONS.get(raw_reason, "invalid_type_or_value")


def _family_from_validation_item(item: Mapping[str, object]) -> str | None:
    """Return the frozen event family the validator named, or None.

    Admission is doubly closed: the token must look like a family name and must be one this bridge
    publishes, so nothing caller-controlled can arrive under the key.
    """

    from yoetz.mcp.descriptors import ORDINARY_MCP_PUBLISH_EVENT_FAMILIES

    ctx = item.get("ctx")
    if not isinstance(ctx, Mapping):
        return None
    family = cast(Mapping[object, object], ctx).get("schema_name")
    if type(family) is not str or EVENT_FAMILY_NAME_PATTERN.fullmatch(family) is None:
        return None
    return family if family in ORDINARY_MCP_PUBLISH_EVENT_FAMILIES else None


def _family_version_from_validation_item(item: Mapping[str, object]) -> str | None:
    """Return the frozen schema version of the family the validator named, or None.

    The validator reads it from the catalogue entry the failing schema's ``$id`` names, so it is
    frozen schema content and never the ``schema.version`` the caller sent. Admission is closed by
    the same version pattern the protocol validator enforces.
    """

    ctx = item.get("ctx")
    if not isinstance(ctx, Mapping):
        return None
    version = cast(Mapping[object, object], ctx).get("schema_version")
    if type(version) is not str or SCHEMA_VERSION_PATTERN.fullmatch(version) is None:
        return None
    return version


def _unknown_count_from_validation_item(item: Mapping[str, object]) -> int:
    """Return the bounded count of unadmitted properties, or 0 when the validator named none."""

    ctx = item.get("ctx")
    if not isinstance(ctx, Mapping):
        return 0
    count = cast(Mapping[object, object], ctx).get("count")
    if type(count) is not int or not 1 <= count <= MAX_UNKNOWN_PROPERTY_COUNT + 1:
        return 0
    return count


def _misplaced_field_from_validation_item(item: Mapping[str, object]) -> str | None:
    """Return the frozen-vocabulary field name the validator flagged as misplaced, or None.

    Admission is doubly closed, mirroring `_family_from_validation_item`: the token must look
    like a payload field name and must be a name this module's frozen allowlist already trusts,
    so nothing caller-controlled can arrive under the key (issue #266).
    """

    ctx = item.get("ctx")
    if not isinstance(ctx, Mapping):
        return None
    field = cast(Mapping[object, object], ctx).get("misplaced_field")
    if type(field) is not str or EVENT_FAMILY_NAME_PATTERN.fullmatch(field) is None:
        return None
    return field if field in _SAFE_LOCATION_SEGMENTS else None


def _missing_fields_from_validation_item(item: Mapping[str, object]) -> tuple[str, ...]:
    """Return the schema-listed required names the validator found absent, allowlist-gated."""

    ctx = item.get("ctx")
    if not isinstance(ctx, Mapping):
        return ()
    names = cast(Mapping[object, object], ctx).get("missing_fields")
    if type(names) is not tuple:
        return ()
    admitted: list[str] = []
    for name in cast(tuple[object, ...], names):
        if type(name) is not str or name not in _SAFE_LOCATION_SEGMENTS or name in admitted:
            return ()
        admitted.append(name)
    return tuple(admitted[:_MAX_VALIDATION_LOCATIONS])


def _conditional_requirement_from_validation_item(
    item: Mapping[str, object],
) -> tuple[str, str] | None:
    """Return a frozen const discriminator only when its bounded shape is safe to carry."""

    ctx = item.get("ctx")
    if not isinstance(ctx, Mapping):
        return None
    source = cast(Mapping[object, object], ctx)
    field = source.get("condition_field")
    value = source.get("condition_value")
    if (
        type(field) is not str
        or field not in _SAFE_LOCATION_SEGMENTS
        or EVENT_FAMILY_NAME_PATTERN.fullmatch(field) is None
        or type(value) is not str
        or not value.isascii()
        or not 1 <= len(value) <= 64
    ):
        return None
    return (field, value)


def safe_validation_locations(exc: object) -> tuple[dict[str, str], ...]:
    """Project Pydantic failures to allowlisted locations and bounded reason tokens.

    ``family``, ``family_version``, ``misplaced_field``, ``count``, and selected-oneOf condition
    facts ride along only for the hint builders in this module.
    ``build_public_error_result`` projects only ``field`` and ``reason`` to the wire — plus the
    bounded ``repair_*`` fact when ownership is unambiguous (issue #266) — so none of the
    ride-along keys reaches a caller directly.
    """

    if not isinstance(exc, ValidationError):
        return ()
    projected: list[dict[str, str]] = []
    try:
        # Context is required to recover closed object-rule reason tokens; inputs stay excluded.
        errors = exc.errors(include_url=False, include_context=True, include_input=False)
    except BaseException:
        return ()
    for item in errors:
        pointer = _pointer_for_location(
            item.get("loc"),
            # Project to the nearest allowlisted parent so untrusted leaf keys (payload fields,
            # extras) never appear, while still naming a useful location such as /event_drafts/0.
            project_parent_on_unsafe_leaf=True,
        )
        # Empty pointers (model-level failures with no path) are not actionable; omit them.
        if pointer is None or pointer == "":
            continue
        source = cast(Mapping[str, object], item)
        reason = _reason_from_validation_item(source)
        entry = {"field": pointer, "reason": reason}
        if reason == _EXTRA_FORBIDDEN_REASON:
            family = _family_from_validation_item(source)
            if family is not None:
                entry["family"] = family
                # Only meaningful beside a family, and a family with several admitted versions is
                # answered with the wrong key list without it (issue #239).
                family_version = _family_version_from_validation_item(source)
                if family_version is not None:
                    entry["family_version"] = family_version
                # Only meaningful beside a family: ownership is a fact about where else the field
                # is legal, and without the selected family there is no "else" (issue #266).
                misplaced_field = _misplaced_field_from_validation_item(source)
                if misplaced_field is not None:
                    entry["misplaced_field"] = misplaced_field
            count = _unknown_count_from_validation_item(source)
            if count:
                entry["count"] = str(count)
        elif (
            reason == "invalid_type_or_value"
            and _EVENT_DRAFT_PAYLOAD_POINTER.fullmatch(pointer) is not None
        ):
            # A payload missing a required key: the validator named the frozen family whose
            # branch the caller's discriminator selected, so the hint can state its contract.
            family = _family_from_validation_item(source)
            family_version = _family_version_from_validation_item(source)
            if family is not None and family_version is not None:
                entry["family"] = family
                entry["family_version"] = family_version
                missing_fields = _missing_fields_from_validation_item(source)
                if missing_fields:
                    entry["missing_fields"] = ",".join(missing_fields)
        elif (
            reason == "invalid_type_or_value"
            and _EVENT_DRAFT_NESTED_PAYLOAD_POINTER.match(pointer) is not None
        ):
            # A value inside a payload (an id pattern in ``limitation_refs``): the family lets the
            # hint walk the selected branch where several families share the field name with
            # different admitted shapes (tb4n1: result_recorded ``evidence_refs``).
            family = _family_from_validation_item(source)
            family_version = _family_version_from_validation_item(source)
            if family is not None and family_version is not None:
                entry["family"] = family
                entry["family_version"] = family_version
        elif reason == _CONDITIONAL_FIELD_REQUIRED_REASON:
            family = _family_from_validation_item(source)
            family_version = _family_version_from_validation_item(source)
            if family is not None and family_version is not None:
                entry["family"] = family
                entry["family_version"] = family_version
            condition = _conditional_requirement_from_validation_item(source)
            if condition is not None:
                entry["condition_field"] = condition[0]
                entry["condition_value"] = condition[1]
        projected.append(entry)
        if len(projected) == _MAX_VALIDATION_LOCATIONS:
            break
    return tuple(projected)


def authoring_hint(
    schema: object, locations: Sequence[Mapping[str, str]], *, tool: str | None = None
) -> str:
    """Name the admitted values for rejected fields, from the frozen presentation schema.

    An agent that cannot author `start` cannot use the product at all, and the 2026-07-27 dogfood
    burned two calls plus a source-reading detour on exactly that: an empty object, then a guessed
    request-id shape and a mode that is not an admitted value. Field locations alone did not close
    the gap because they say where, not what. Nested `/event_drafts/N` failures need the same:
    walk local ``$defs`` so payload enums such as `action_kind` are named. The 2026-08-03 dogfood
    then showed that naming the admitted event families is still not enough to author a draft,
    because nothing said which key carries the family or what else the envelope requires.

    Root-level object rules (``dependentRequired``, attach ``if/then``) name the required peer or
    safe alternative from schema metadata only — never from submitted values.

    ``tool`` selects the closed corrective registry in this module, which supplies checked-in
    sentences for contract facts no JSON Schema keyword can express. It is optional so a caller
    holding only a schema still gets every schema-derived part.

    Every character comes from the checked-in presentation schema — enum members, consts, bounded
    patterns, pairing maps, required lists, and the worked example's own keys — or from the closed
    corrective registry in this module, so no caller-controlled text can reach the message.
    """

    if not isinstance(schema, Mapping):
        return ""
    document = cast(Mapping[str, JsonValue], schema)
    parts: list[str] = []
    seen: set[tuple[str, str]] = set()
    example_families: list[str] = []
    try:
        if not isinstance(document.get("properties"), Mapping):
            return ""
        # Fixed order, least specific last, so truncation at _MAX_HINT_FIELDS always keeps the
        # part that names the most about how to author the next request.
        keyed_parts: list[tuple[str, tuple[str, str]]] = [
            *((text, (text, "")) for text in _obligation_version_hint_parts(locations)),
            *_family_payload_contract_hint_parts(document, locations),
            *_unknown_payload_key_hint_parts(document, locations),
            *_conditional_requirement_hint_parts(document, locations),
            *((text, (text, "")) for text in _object_rule_hint_parts(document, locations)),
            *_event_draft_hint_parts(document, locations),
            *((text, (text, "")) for text in _corrective_hint_parts(tool, locations)),
            *((text, (text, "")) for text in _reference_list_hint_parts(locations)),
            *((text, (text, "")) for text in _required_peer_hint_parts(document, locations)),
        ]
        for text, key in keyed_parts:
            if key in seen:
                continue
            seen.add(key)
            parts.append(text)
            if len(parts) == _MAX_HINT_FIELDS:
                break
        if len(parts) < _MAX_HINT_FIELDS:
            for location in locations:
                pointer = location.get("field", "")
                reason = location.get("reason", "")
                if type(pointer) is not str or not pointer.startswith("/"):
                    continue
                # Object-rule and unknown-property locations already contributed their own
                # schema-derived text above; the union node itself admits no values to name.
                if reason in _SAFE_VALUE_ERROR_REASON_TOKENS:
                    continue
                label, admitted, family = _hint_for_pointer(
                    document,
                    pointer,
                    preferred=_location_identity(location),
                )
                key = (label, admitted)
                if not admitted or key in seen:
                    continue
                seen.add(key)
                parts.append(f"{label} admits {admitted}")
                if family is not None and family not in example_families:
                    example_families.append(family)
                if len(parts) == _MAX_HINT_FIELDS:
                    break
        if _has_example(document):
            if example_families:
                named = ", ".join(example_families[:_MAX_HINT_FIELDS])
                parts.append(
                    f"see yoetz://guidance/request-templates.md for a complete {named} request"
                )
            else:
                parts.append("see yoetz://guidance/request-templates.md for a complete request")
    except Exception:
        # A hint must never turn a clear validation error into an internal error — including when
        # even the example probe fails. Prefer the checked-in fallback text over silence or raise.
        try:
            has_example = _has_example(document)
        except Exception:
            has_example = True
        return (
            " Hint: see yoetz://guidance/request-templates.md for a complete request."
            if has_example
            else ""
        )
    if not parts:
        return ""
    return " Hint: " + "; ".join(parts) + "."


def _object_rule_hint_parts(
    document: Mapping[str, JsonValue], locations: Sequence[Mapping[str, str]]
) -> list[str]:
    """Build pairing / conditional hints from schema metadata for object-rule locations."""

    paired_fields: list[str] = []
    conditional_fields: list[str] = []
    for location in locations:
        pointer = location.get("field", "")
        reason = location.get("reason", "")
        if type(pointer) is not str or not pointer.startswith("/"):
            continue
        segments = pointer.removeprefix("/").split("/")
        if len(segments) != 1 or not segments[0]:
            continue
        field = segments[0]
        if field not in _SAFE_LOCATION_SEGMENTS:
            continue
        if reason == "paired_field_required":
            if field not in paired_fields:
                paired_fields.append(field)
        elif reason == "conditional_field_required":
            if field not in conditional_fields:
                conditional_fields.append(field)
    parts: list[str] = []
    if paired_fields:
        parts.extend(_paired_field_hint_parts(document, paired_fields))
    if conditional_fields:
        parts.extend(_conditional_field_hint_parts(document, conditional_fields))
    return parts


def _event_draft_hint_parts(
    document: Mapping[str, JsonValue], locations: Sequence[Mapping[str, str]]
) -> list[tuple[str, tuple[str, str]]]:
    """Name the draft envelope keys and the key that carries the family, for `/event_drafts/<int>`.

    The 2026-08-03 dogfood agent already knew the admitted family values and still guessed four
    different top-level keys for the discriminator, because nothing named `schema.name` or said
    what else an envelope must carry. Both facts are read from the frozen presentation schema.

    Each part carries the dedupe key the generic pointer loop would use, so the union's admitted
    families are stated once under the label that says where they go.
    """

    if not any(_recital_applies(location) for location in locations):
        return []
    node = _event_draft_items(document)
    if node is None:
        return []
    item_properties = node.get("properties")
    if not isinstance(item_properties, Mapping):
        return []
    parts: list[tuple[str, tuple[str, str]]] = []
    required = _format_required_list(
        node.get("required"), cast(Mapping[str, JsonValue], item_properties)
    )
    if required:
        text = f"each event_drafts entry requires {required}"
        parts.append((text, (text, "")))
    admitted = _union_schema_names(document, node)
    if admitted:
        parts.append((f"schema.name admits {admitted}", ("schema.name", admitted)))
    return parts


def _event_draft_items(document: Mapping[str, JsonValue]) -> Mapping[str, JsonValue] | None:
    """Resolve the frozen `event_drafts` item node, or None when this schema has none."""

    properties = document.get("properties")
    if not isinstance(properties, Mapping):
        return None
    drafts = _resolve_local(document, cast(Mapping[str, JsonValue], properties).get("event_drafts"))
    if not isinstance(drafts, Mapping):
        return None
    items = _resolve_local(document, cast(Mapping[str, JsonValue], drafts).get("items"))
    if not isinstance(items, Mapping):
        return None
    return cast(Mapping[str, JsonValue], items)


def _unknown_payload_key_hint_parts(
    document: Mapping[str, JsonValue], locations: Sequence[Mapping[str, str]]
) -> list[tuple[str, tuple[str, str]]]:
    """Name the admitted payload keys for a family whose payload carried unknown properties.

    Admitted key names are frozen presentation-schema content — the same class of fact this module
    already speaks for enum members and required lists. The rejected key names are
    caller-controlled and are never echoed; only the closed reason token, the pointer, and a
    bounded integer count travel out of the validator (issue #240).
    """

    parts: list[tuple[str, tuple[str, str]]] = []
    for location in locations:
        if location.get("reason", "") != _EXTRA_FORBIDDEN_REASON:
            continue
        pointer = location.get("field", "")
        if type(pointer) is not str or _EVENT_DRAFT_PAYLOAD_POINTER.fullmatch(pointer) is None:
            continue
        family = location.get("family")
        family = family if type(family) is str else None
        family_version = location.get("family_version")
        family_version = family_version if type(family_version) is str else None
        admitted = _payload_property_names(document, family, family_version)
        subject = f"the {family} schema" if family is not None and admitted else "the event schema"
        measure = _unknown_property_measure(location.get("count", ""))
        text = f"the payload carries {measure} {subject} does not admit"
        if admitted:
            text = f"{text}; admitted keys are {admitted}"
        parts.append((text, (text, "")))
        # One bounded ownership sentence when the rejected key is a known field with exactly one
        # legal owning family. Both names are frozen registry content; the field name matched the
        # frozen schema vocabulary before it could travel here (issue #266).
        misplaced = location.get("misplaced_field")
        if type(misplaced) is str and family is not None:
            owner = _FIELD_OWNERSHIP.get(misplaced)
            if owner is not None and owner != family:
                ownership = f"{misplaced} is admitted only by the {owner} payload, not {family}"
                parts.append((ownership, (ownership, "")))
        if not admitted:
            # Without the family the caller still needs the contract; the recital is gated off.
            names = _union_schema_names(document, cast(JsonValue, _event_draft_items(document)))
            if names:
                parts.append((f"schema.name admits {names}", ("schema.name", names)))
        if len(parts) >= _MAX_HINT_FIELDS:
            break
    return parts


def _family_payload_contract_hint_parts(
    document: Mapping[str, JsonValue], locations: Sequence[Mapping[str, str]]
) -> list[tuple[str, tuple[str, str]]]:
    """State the selected family's required and admitted payload keys for a malformed payload.

    Benchmark full3 agents wrote ``plan_revised`` drafts with ``plan_published`` keys (no
    ``supersedes_plan_version``, ``reason``, or ``obligation_changes``) and got only the generic
    envelope recital, which their drafts already satisfied. The family and version arrive from the
    validator's catalogue lookup, and every name below is read from the frozen presentation schema;
    nothing the caller sent is echoed.
    """

    parts: list[tuple[str, tuple[str, str]]] = []
    for location in locations:
        if location.get("reason", "") != "invalid_type_or_value":
            continue
        pointer = location.get("field", "")
        if type(pointer) is not str or _EVENT_DRAFT_PAYLOAD_POINTER.fullmatch(pointer) is None:
            continue
        family = location.get("family")
        family_version = location.get("family_version")
        payload = _payload_schema(
            document,
            family if type(family) is str else None,
            family_version if type(family_version) is str else None,
        )
        if payload is None:
            continue
        properties = payload.get("properties")
        if not isinstance(properties, Mapping):
            continue
        prop_names = cast(Mapping[str, JsonValue], properties)
        required = _format_required_list(payload.get("required"), prop_names)
        admitted = _payload_property_names(
            document,
            cast(str, family),
            cast(str, family_version),
        )
        if not required or not admitted:
            continue
        raw_missing = location.get("missing_fields")
        missing = (
            _format_required_list(cast(JsonValue, raw_missing.split(",")), prop_names)
            if type(raw_missing) is str and raw_missing
            else ""
        )
        # Name the absent keys first: the whole required list alone left tb4n1 agents diffing
        # it against a draft that already carried all but one of them.
        subject = f"the {family} {family_version} payload"
        lead = f"{subject} is missing {missing}; it requires" if missing else f"{subject} requires"
        text = f"{lead} {required}; admitted keys are {admitted}"
        parts.append((text, (text, "")))
        if len(parts) >= _MAX_HINT_FIELDS:
            break
    return parts


def _payload_property_names(
    document: Mapping[str, JsonValue], family: str | None, family_version: str | None
) -> str:
    """Return the admitted payload keys of one family version, or "" when they cannot be named.

    Both consts must match. A family may carry several admitted versions — ``evidence_recorded``
    has 1.0.0 and 1.1.0 — and the presentation schema preserves each versioned branch. Selecting
    on the name alone would answer a 1.1.0 failure with the 1.0.0 key list and so tell the caller
    to delete ``digest_binding``, a key 1.1.0 requires (issue #239). When no branch matches both,
    the caller gets the family-free wording, which still states the count and names ``schema.name``.

    Both the name and the version come from frozen schema content on either side: the presentation
    branch's own consts, and the version the validator read from the catalogue. Neither is ever
    taken from the instance.
    """

    payload = _payload_schema(document, family, family_version)
    if payload is None:
        return ""
    payload_properties = payload.get("properties")
    if not isinstance(payload_properties, Mapping):
        return ""
    names = sorted(
        key for key in cast(Mapping[object, object], payload_properties) if type(key) is str
    )
    # A partial list would read as complete and send the caller after the wrong key.
    if not names or len(names) > _MAX_HINT_SCHEMA_NAMES:
        return ""
    if any(name not in _SAFE_LOCATION_SEGMENTS for name in names):
        return ""
    return _format_required_list(
        cast(JsonValue, names), cast(Mapping[str, JsonValue], payload_properties)
    )


def _payload_schema(
    document: Mapping[str, JsonValue], family: str | None, family_version: str | None
) -> Mapping[str, JsonValue] | None:
    """Return the exact frozen payload schema for a family and version."""

    if family is None or family_version is None:
        return None
    items = _event_draft_items(document)
    if items is None:
        return None
    options = items.get("oneOf")
    if not isinstance(options, list):
        options = items.get("anyOf")
    if not isinstance(options, list):
        return None
    for branch in cast(list[JsonValue], options):
        resolved = _resolve_local(document, branch)
        if not isinstance(resolved, Mapping):
            continue
        if _schema_name_const(document, resolved) != family:
            continue
        if _schema_version_const(document, resolved) != family_version:
            continue
        branch_properties = cast(Mapping[str, JsonValue], resolved).get("properties")
        if not isinstance(branch_properties, Mapping):
            return None
        payload = _resolve_local(
            document, cast(Mapping[str, JsonValue], branch_properties).get("payload")
        )
        if not isinstance(payload, Mapping):
            return None
        return cast(Mapping[str, JsonValue], payload)
    return None


def _conditional_requirement_hint_parts(
    document: Mapping[str, JsonValue], locations: Sequence[Mapping[str, str]]
) -> list[tuple[str, tuple[str, str]]]:
    """Render selected-oneOf, anyOf-of-required, and allOf peer repairs from frozen schema metadata."""

    parts: list[tuple[str, tuple[str, str]]] = []
    seen: set[str] = set()
    for location in locations:
        if location.get("reason") != _CONDITIONAL_FIELD_REQUIRED_REASON:
            continue
        pointer = location.get("field")
        if type(pointer) is not str:
            continue
        item_match = _EVENT_DRAFT_PAYLOAD_ITEM_FIELD_POINTER.fullmatch(pointer)
        if item_match is not None:
            text = _array_item_conditional_text(
                document,
                location.get("family"),
                location.get("family_version"),
                item_match.group(1),
                item_match.group(2),
            )
            if text is not None and text not in seen:
                seen.add(text)
                parts.append((text, (text, "")))
                if len(parts) == _MAX_HINT_FIELDS:
                    break
            continue
        if _EVENT_DRAFT_PAYLOAD_FIELD_POINTER.fullmatch(pointer) is None:
            continue
        required = pointer.rsplit("/", 1)[-1]
        payload = _payload_schema(
            document,
            location.get("family"),
            location.get("family_version"),
        )
        if payload is None:
            continue
        properties = payload.get("properties")
        if not isinstance(properties, Mapping) or required not in properties:
            continue
        prop_names = cast(Mapping[str, JsonValue], properties)
        text = _selected_branch_requirement_text(
            payload,
            prop_names,
            location.get("condition_field"),
            location.get("condition_value"),
            required,
        )
        if text is None:
            text = _allof_required_peer_text(payload, prop_names, required)
        if text is None or text in seen:
            continue
        seen.add(text)
        parts.append((text, (text, "")))
        if len(parts) == _MAX_HINT_FIELDS:
            break
    return parts


def _array_item_conditional_text(
    document: Mapping[str, JsonValue],
    family: object,
    family_version: object,
    array: str,
    missing: str,
) -> str | None:
    """State which const values of a payload array item require ``missing``.

    tb4n1: 19 ``plan_revised`` rejections at ``obligation_changes/<n>/reason`` were answered with
    only the template URI, because the peer rule lives in the item's own ``allOf`` and not on the
    payload. Every name and value here is read from that frozen item schema.
    """

    if type(family) is not str or type(family_version) is not str:
        return None
    if array not in _SAFE_LOCATION_SEGMENTS or missing not in _SAFE_LOCATION_SEGMENTS:
        return None
    payload = _payload_schema(document, family, family_version)
    if payload is None:
        return None
    properties = payload.get("properties")
    if not isinstance(properties, Mapping):
        return None
    array_node = _resolve_local(document, cast(Mapping[str, JsonValue], properties).get(array))
    if not isinstance(array_node, Mapping):
        return None
    item = _resolve_local(document, cast(Mapping[str, JsonValue], array_node).get("items"))
    if not isinstance(item, Mapping):
        return None
    item_node = cast(Mapping[str, JsonValue], item)
    item_properties = item_node.get("properties")
    all_of = item_node.get("allOf")
    if not isinstance(item_properties, Mapping) or not isinstance(all_of, list):
        return None
    prop_names = cast(Mapping[str, JsonValue], item_properties)
    if missing not in prop_names:
        return None
    condition_field: str | None = None
    values: list[str] = []
    for rule in cast(list[JsonValue], all_of):
        if not isinstance(rule, Mapping):
            continue
        if_node = cast(Mapping[str, JsonValue], rule).get("if")
        then_node = cast(Mapping[str, JsonValue], rule).get("then")
        if not isinstance(if_node, Mapping) or not isinstance(then_node, Mapping):
            continue
        then_required = cast(Mapping[str, JsonValue], then_node).get("required")
        if not isinstance(then_required, list) or missing not in cast(list[object], then_required):
            continue
        condition = _if_const_condition(cast(Mapping[str, JsonValue], if_node), prop_names)
        if condition is None:
            continue
        field, _, value = condition.partition(" ")
        if condition_field is not None and field != condition_field:
            return None
        condition_field = field
        if value not in values:
            values.append(value)
    if condition_field is None or not values:
        return None
    return f"each {array} entry with {condition_field} {' or '.join(values)} requires {missing}"


def _selected_branch_requirement_text(
    payload: Mapping[str, JsonValue],
    prop_names: Mapping[str, JsonValue],
    condition_field: object,
    condition_value: object,
    required: str,
) -> str | None:
    """Return the selected const-branch repair, including anyOf required alternatives."""

    options = payload.get("oneOf")
    if (
        type(condition_field) is not str
        or type(condition_value) is not str
        or condition_field not in prop_names
        or not isinstance(options, list)
    ):
        return None
    for branch in cast(list[JsonValue], options):
        if not isinstance(branch, Mapping):
            continue
        source = cast(Mapping[str, JsonValue], branch)
        branch_properties = source.get("properties")
        if not isinstance(branch_properties, Mapping):
            continue
        condition = cast(Mapping[str, JsonValue], branch_properties).get(condition_field)
        if not isinstance(condition, Mapping):
            continue
        if cast(Mapping[str, JsonValue], condition).get("const") != condition_value:
            continue
        branch_required = source.get("required")
        if isinstance(branch_required, list) and required in cast(list[object], branch_required):
            required_names = _format_required_list(branch_required, prop_names)
            if required_names:
                return f"{condition_field} {condition_value} requires {required_names}"
        alternatives = source.get("anyOf")
        if not isinstance(alternatives, list):
            continue
        matched = False
        names: list[str] = []
        for alternative in cast(list[JsonValue], alternatives):
            if not isinstance(alternative, Mapping):
                continue
            required_list = cast(Mapping[str, JsonValue], alternative).get("required")
            text = _format_required_list(required_list, prop_names)
            if not text:
                continue
            if text not in names:
                names.append(text)
            if isinstance(required_list, list) and required in cast(list[object], required_list):
                matched = True
        if matched and names:
            return f"{condition_field} {condition_value} requires {' or '.join(names)}"
    return None


def _allof_required_peer_text(
    payload: Mapping[str, JsonValue],
    prop_names: Mapping[str, JsonValue],
    missing: str,
) -> str | None:
    """Return a single-condition ``if``/``then`` allOf peer for the missing field, or None.

    Both frozen shapes are rendered: ``if required X then required Y`` (``content_digest requires
    digest_binding``) and the single-property ``if properties.X const V then required Y``
    (``action_kind command requires command``).
    """

    all_of = payload.get("allOf")
    if not isinstance(all_of, list):
        return None
    for item in cast(list[JsonValue], all_of):
        if not isinstance(item, Mapping):
            continue
        source = cast(Mapping[str, JsonValue], item)
        if_node = source.get("if")
        then_node = source.get("then")
        if not isinstance(if_node, Mapping) or not isinstance(then_node, Mapping):
            continue
        then_required = cast(Mapping[str, JsonValue], then_node).get("required")
        if (
            not isinstance(then_required, list)
            or missing not in cast(list[object], then_required)
            or _format_required_list(then_required, prop_names) != missing
        ):
            continue
        present = _allof_peer_condition_text(cast(Mapping[str, JsonValue], if_node), prop_names)
        if present is None:
            continue
        return f"{present} requires {missing}"
    return None


def _allof_peer_condition_text(
    if_node: Mapping[str, JsonValue], prop_names: Mapping[str, JsonValue]
) -> str | None:
    """Name an allOf peer condition: a const-valued property, else a single required key."""

    if isinstance(if_node.get("properties"), Mapping):
        return _if_const_condition(if_node, prop_names)
    if_required = if_node.get("required")
    if not isinstance(if_required, list) or len(cast(list[object], if_required)) != 1:
        return None
    return _format_required_list(if_required, prop_names) or None


def _unknown_property_measure(count: object) -> str:
    """Render the bounded cardinality of unadmitted keys, never a key name."""

    if type(count) is not str or not count.isdigit():
        return "properties"
    value = int(count)
    if value == 1:
        return "1 property"
    if value == MAX_UNKNOWN_PROPERTY_COUNT + 1:
        return f"at least {MAX_UNKNOWN_PROPERTY_COUNT} properties"
    if 2 <= value <= MAX_UNKNOWN_PROPERTY_COUNT:
        return f"{value} properties"
    return "properties"


def _recital_applies(location: Mapping[str, str]) -> bool:
    """Whether the draft-envelope recital answers this location.

    The recital answers "this entry is not a draft". An unknown key *inside* a payload proves the
    entry already is one and that its family was admitted, so the recital would assert facts the
    request already satisfies (issue #240). An unknown key on the draft object itself is still an
    envelope defect, and the recital is exactly right for it.
    """

    if not _is_event_draft_index_pointer(location):
        return False
    if location.get("reason", "") != _EXTRA_FORBIDDEN_REASON:
        # A payload whose family the validator named is already a well-formed draft; its own
        # contract hint answers it, and the envelope recital would only restate what it satisfies.
        return not (
            location.get("field", "").endswith("/payload") and type(location.get("family")) is str
        )
    return not location.get("field", "").endswith("/payload")


def _is_event_draft_index_pointer(location: Mapping[str, str]) -> bool:
    """Match a whole rejected draft, or the payload the family discriminator selects.

    `/event_drafts/N/payload` is included because the generic pointer loop can name nothing there:
    the payload node is a union of family shapes with no enum, const, or pattern of its own, so
    that pointer reaches the caller today as a bare template fallback. Deeper payload pointers
    (`/event_drafts/N/payload/<enum>`) already name their admitted members and are left alone.
    """

    pointer = location.get("field", "")
    if type(pointer) is not str or not pointer.startswith("/"):
        return False
    segments = pointer.removeprefix("/").split("/")
    if not segments or segments[0] != "event_drafts":
        return False
    if len(segments) == 2 and segments[1].isdigit():
        return True
    return len(segments) == 3 and segments[1].isdigit() and segments[2] == "payload"


def _obligation_version_hint_parts(locations: Sequence[Mapping[str, str]]) -> list[str]:
    """The one obligation version sentence for a 1.1.0-only feature sent on 1.0.0 (issue #1023).

    It fires for a 1.0.0 ``obligation_published`` location at the payload, its ``status`` or a
    requested item's ``item_kind``, and for an unknown key on a requested item (``role`` is the
    only key a requested item gains in 1.1.0; requested items exist only on obligations). The
    sentence is checked-in text, never caller content.
    """

    for location in locations:
        pointer = location.get("field", "")
        if type(pointer) is not str:
            continue
        reason = location.get("reason", "")
        on_v1_0 = (
            location.get("family") == "obligation_published"
            and location.get("family_version") == "1.0.0"
            and _OBLIGATION_V1_1_FEATURE_POINTER.fullmatch(pointer) is not None
            and "missing_fields" not in location
        )
        unknown_item_key = (
            reason == _EXTRA_FORBIDDEN_REASON
            and _OBLIGATION_ITEM_POINTER.fullmatch(pointer) is not None
        )
        if on_v1_0:
            return [_OBLIGATION_VERSION_HINT]
        if unknown_item_key:
            # The validator does not say which key or version, so state the item contract that
            # is true for both: an unknown key is wrong everywhere, a role needs 1.1.0.
            return [_OBLIGATION_ITEM_KEYS_HINT]
    return []


def _corrective_hint_parts(tool: str | None, locations: Sequence[Mapping[str, str]]) -> list[str]:
    """Return checked-in corrective sentences registered for this tool's rejected locations."""

    if type(tool) is not str:
        return []
    parts: list[str] = []
    for location in locations:
        pointer = location.get("field", "")
        reason = location.get("reason", "")
        if type(pointer) is not str or type(reason) is not str:
            continue
        entry = _CORRECTIVE_HINTS.get((tool, pointer, reason))
        if entry is None:
            continue
        text = entry[0]
        if text not in parts:
            parts.append(text)
        if len(parts) == _MAX_HINT_FIELDS:
            break
    return parts


def _reference_list_hint_parts(locations: Sequence[Mapping[str, str]]) -> list[str]:
    """Return the checked-in id-kind sentence for a rejected payload reference-list member."""

    parts: list[str] = []
    for location in locations:
        if location.get("reason") != "invalid_type_or_value":
            continue
        pointer = location.get("field", "")
        match = (
            _EVENT_DRAFT_PAYLOAD_MEMBER_POINTER.fullmatch(pointer) if type(pointer) is str else None
        )
        family = location.get("family")
        if match is None or type(family) is not str:
            continue
        entry = _REFERENCE_LIST_CORRECTIONS.get((family, match.group(1)))
        if entry is None or entry[0] in parts:
            continue
        parts.append(entry[0])
        if len(parts) == _MAX_HINT_FIELDS:
            break
    return parts


def _required_peer_hint_parts(
    document: Mapping[str, JsonValue], locations: Sequence[Mapping[str, str]]
) -> list[str]:
    """Name every required member of an object one of whose members is reported ``missing``.

    A nested `missing` names one absent member and says nothing about the rest, so an agent that
    sends half of a required pair learns only half the repair. Names come from the parent object's
    own ``required`` list, and only when it declares two or more, so the part adds something the
    location itself did not already say.
    """

    parts: list[str] = []
    for location in locations:
        pointer = location.get("field", "")
        if location.get("reason", "") != "missing":
            continue
        if type(pointer) is not str or not pointer.startswith("/"):
            continue
        segments = pointer.removeprefix("/").split("/")
        if len(segments) != 2 or segments[1].isdigit():
            continue
        parent = segments[0]
        if parent not in _SAFE_LOCATION_SEGMENTS:
            continue
        properties = document.get("properties")
        if not isinstance(properties, Mapping):
            continue
        node = _resolve_local(document, cast(Mapping[str, JsonValue], properties).get(parent))
        if not isinstance(node, Mapping):
            continue
        parent_node = cast(Mapping[str, JsonValue], node)
        parent_properties = parent_node.get("properties")
        if not isinstance(parent_properties, Mapping):
            continue
        required = parent_node.get("required")
        if not isinstance(required, list) or len(cast(list[object], required)) < 2:
            continue
        names = _format_required_list(required, cast(Mapping[str, JsonValue], parent_properties))
        if not names:
            continue
        text = f"{parent} requires {names}"
        if text not in parts:
            parts.append(text)
        if len(parts) == _MAX_HINT_FIELDS:
            break
    return parts


def _paired_field_hint_parts(document: Mapping[str, JsonValue], fields: Sequence[str]) -> list[str]:
    """Name required peers from schema ``dependentRequired`` only."""

    deps = document.get("dependentRequired")
    if not isinstance(deps, Mapping):
        return []
    properties = document.get("properties")
    if not isinstance(properties, Mapping):
        return []
    prop_names = cast(Mapping[str, JsonValue], properties)
    field_set = set(fields)
    parts: list[str] = []
    seen: set[str] = set()
    for key, peers in cast(Mapping[object, object], deps).items():
        if type(key) is not str or key not in prop_names:
            continue
        if key not in field_set and not (
            isinstance(peers, list)
            and any(type(p) is str and p in field_set for p in cast(list[object], peers))
        ):
            continue
        if not isinstance(peers, list):
            continue
        peer_names = [
            peer for peer in cast(list[object], peers) if type(peer) is str and peer in prop_names
        ]
        if not peer_names:
            continue
        text = f"{key} requires {', '.join(peer_names)}"
        if text in seen:
            continue
        seen.add(text)
        parts.append(text)
        if len(parts) == _MAX_HINT_FIELDS:
            break
    return parts


def _conditional_field_hint_parts(
    document: Mapping[str, JsonValue], fields: Sequence[str]
) -> list[str]:
    """Name safe required alternatives from conditions or a bounded property description."""

    del fields  # Field list confirms a conditional failure; alternatives come from the schema.
    properties = document.get("properties")
    if not isinstance(properties, Mapping):
        return []
    prop_names = cast(Mapping[str, JsonValue], properties)
    all_of = document.get("allOf")
    if not isinstance(all_of, list):
        mode = prop_names.get("mode")
        if not isinstance(mode, Mapping):
            return []
        description = cast(Mapping[str, JsonValue], mode).get("description")
        if (
            type(description) is str
            and description.isascii()
            and 1 <= len(description) <= 256
            and description.startswith("mode attach requires ")
        ):
            return [description]
        return []
    for branch in cast(list[JsonValue], all_of):
        if not isinstance(branch, Mapping):
            continue
        source = cast(Mapping[str, JsonValue], branch)
        if_node = source.get("if")
        then_node = source.get("then")
        if not isinstance(if_node, Mapping) or not isinstance(then_node, Mapping):
            continue
        condition = _if_const_condition(cast(Mapping[str, JsonValue], if_node), prop_names)
        alternatives = _required_alternatives(cast(Mapping[str, JsonValue], then_node), prop_names)
        if not alternatives:
            continue
        alt_text = " or ".join(alternatives)
        if condition is not None:
            return [f"{condition} requires {alt_text}"]
        return [f"requires {alt_text}"]
    return []


def _if_const_condition(
    if_node: Mapping[str, JsonValue], prop_names: Mapping[str, JsonValue]
) -> str | None:
    """Return ``field value`` for a simple ``if.properties.X.const`` condition, else None."""

    required = if_node.get("required")
    props = if_node.get("properties")
    if not isinstance(props, Mapping):
        return None
    if isinstance(required, list):
        keys = [item for item in cast(list[object], required) if type(item) is str]
    else:
        keys = [key for key in cast(Mapping[object, object], props) if type(key) is str]
    if len(keys) != 1:
        return None
    field = keys[0]
    if field not in prop_names or field not in _SAFE_LOCATION_SEGMENTS:
        return None
    field_schema = cast(Mapping[str, JsonValue], props).get(field)
    if not isinstance(field_schema, Mapping):
        return None
    const = cast(Mapping[str, JsonValue], field_schema).get("const")
    if type(const) is not str or not const.isascii() or len(const) > 64:
        return None
    return f"{field} {const}"


def _required_alternatives(
    then_node: Mapping[str, JsonValue], prop_names: Mapping[str, JsonValue]
) -> list[str]:
    """Return human-readable required alternatives under then.anyOf|oneOf|required."""

    options = then_node.get("anyOf")
    if not isinstance(options, list):
        options = then_node.get("oneOf")
    if isinstance(options, list):
        alts: list[str] = []
        for branch in cast(list[JsonValue], options):
            if not isinstance(branch, Mapping):
                continue
            required = cast(Mapping[str, JsonValue], branch).get("required")
            text = _format_required_list(required, prop_names)
            if text and text not in alts:
                alts.append(text)
            if len(alts) == _MAX_HINT_FIELDS:
                break
        return alts
    return (
        [_format_required_list(then_node.get("required"), prop_names)]
        if then_node.get("required") is not None
        else []
    )


def _format_required_list(required: object, prop_names: Mapping[str, JsonValue]) -> str:
    if not isinstance(required, list):
        return ""
    names = [
        item
        for item in cast(list[object], required)
        if type(item) is str and item in prop_names and item in _SAFE_LOCATION_SEGMENTS
    ]
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"


def _location_identity(location: Mapping[str, str]) -> tuple[str, str] | None:
    """Return the validator-named ``(family, version)`` riding on one location, or None."""

    family = location.get("family")
    version = location.get("family_version")
    if type(family) is not str or type(version) is not str:
        return None
    return (family, version)


def _hint_for_pointer(
    document: Mapping[str, JsonValue],
    pointer: str,
    *,
    preferred: tuple[str, str] | None = None,
) -> tuple[str, str, str | None]:
    """Return ``(label, admitted_values, example_family_or_none)`` for one pointer.

    ``preferred`` is the family and version the validator named for this location. It settles a
    draft union whose branches all carry the field with different admitted shapes, so the hint
    states the selected family's contract instead of nothing.
    """

    raw_segments = pointer.removeprefix("/").split("/")
    if not raw_segments or raw_segments == [""]:
        return "", "", None
    if len(raw_segments) > _MAX_HINT_POINTER_SEGMENTS:
        return "", "", None
    segments: list[str | int] = []
    for item in raw_segments:
        if item.isdigit():
            segments.append(int(item))
        else:
            segments.append(item)
    node: JsonValue = cast(JsonValue, document)
    family: str | None = None
    for index, segment in enumerate(segments):
        node = _resolve_local(document, node)
        if type(segment) is int:
            if not isinstance(node, Mapping):
                return "", "", None
            items = cast(Mapping[str, JsonValue], node).get("items")
            if items is None:
                return "", "", None
            node = items
            continue
        # At a discriminated union, prefer the branch that can continue the remaining path.
        remaining = segments[index:]
        selected = _select_union_branch(document, node, remaining, preferred=preferred)
        if selected is not None:
            branch_node, branch_family = selected
            if branch_family is not None:
                family = branch_family
            node = branch_node
        elif _is_schema_discriminator_path(remaining):
            # Ambiguous oneOf (every branch has schema/name): name admitted families instead of
            # walking the shared base pattern that does not say which schemas are publishable.
            admitted = _union_schema_names(document, node)
            if admitted:
                return "schema.name", admitted, family
        node = _resolve_local(document, node)
        if not isinstance(node, Mapping):
            return "", "", None
        source = cast(Mapping[str, JsonValue], node)
        props = source.get("properties")
        if not isinstance(props, Mapping):
            # Discriminator failures land on schema/name; admit consts from the enclosing oneOf.
            if segment == "name":
                admitted = _union_schema_names(document, node)
                if admitted:
                    return "schema.name", admitted, family
            return "", "", None
        fields = cast(Mapping[str, JsonValue], props)
        if type(segment) is not str or segment not in fields:
            return "", "", None
        node = fields[segment]
    node = _resolve_local(document, node)
    leaf = raw_segments[-1]
    # An array-item pointer (/event_drafts/N) names the admitted families under the key that
    # carries them; the label is the missing information, so it must not read as a bare "family".
    if leaf.isdigit():
        admitted = _union_schema_names(document, node)
        if admitted:
            return "schema.name", admitted, family
        # An array member (``limitation_refs/0``) names the member shape under the array's own
        # label: tb4n1 agents put evidence ids where only result ids are admitted and got nothing.
        parent = raw_segments[-2] if len(raw_segments) >= 2 else ""
        if not parent or parent.isdigit() or parent not in _SAFE_LOCATION_SEGMENTS:
            return "", "", None
        member = _admitted_values(node) or _plain_string_member(node)
        if not member:
            return "", "", None
        return f"each {parent} entry", member, family
    admitted = _admitted_values(node)
    if not admitted and isinstance(node, Mapping):
        admitted = _union_schema_names(document, node)
        if admitted and leaf in {"schema", "name"}:
            return "schema.name" if leaf == "name" else "schema", admitted, family
    if not admitted:
        return "", "", None
    return leaf, admitted, family


def _select_union_branch(
    document: Mapping[str, JsonValue],
    node: JsonValue,
    remaining: Sequence[str | int],
    *,
    preferred: tuple[str, str] | None = None,
) -> tuple[JsonValue, str | None] | None:
    """Pick the oneOf/anyOf branch that can resolve the remaining pointer, if unique enough."""

    if not isinstance(node, Mapping) or not remaining:
        return None
    source = cast(Mapping[str, JsonValue], node)
    options = source.get("oneOf")
    if not isinstance(options, list):
        options = source.get("anyOf")
    if not isinstance(options, list) or not options:
        return None
    matches: list[tuple[JsonValue, str | None]] = []
    for branch in cast(list[JsonValue], options):
        resolved = _resolve_local(document, branch)
        family = _schema_name_const(document, resolved)
        if _branch_covers_path(document, resolved, remaining):
            matches.append((resolved, family))
    if not matches:
        return None
    # Prefer a branch whose family const is known when several cover the path.
    if len(matches) == 1:
        return matches[0]
    if preferred is not None:
        for branch, family in matches:
            if family == preferred[0] and _schema_version_const(document, branch) == preferred[1]:
                return branch, family
    with_family = [item for item in matches if item[1] is not None]
    if len(with_family) == 1:
        return with_family[0]
    families = {family for _, family in with_family}
    admitted = {
        _branch_leaf_admitted_values(document, branch, remaining) for branch, _ in with_family
    }
    if len(families) == 1 and len(admitted) == 1 and "" not in admitted:
        return with_family[0]
    if len(families) == 1 and "" not in admitted:
        # One family whose versions admit different values here (obligation_published 1.0.0 and
        # 1.1.0 ``status``, #1002): name the newest version's contract, which a new draft uses.
        def version_key(item: tuple[JsonValue, str | None]) -> tuple[int, ...]:
            version = _schema_version_const(document, item[0]) or ""
            parts = version.split(".")
            return tuple(int(part) for part in parts) if all(p.isdigit() for p in parts) else ()

        return max(with_family, key=version_key)
    # Ambiguous: stay on the union node so callers can name admitted schema names.
    return None


def _branch_leaf_admitted_values(
    document: Mapping[str, JsonValue], branch: JsonValue, remaining: Sequence[str | int]
) -> str:
    """Return a branch leaf's values when a path crosses no nested union."""

    node = branch
    for segment in remaining:
        node = _resolve_local(document, node)
        if type(segment) is int:
            if not isinstance(node, Mapping):
                return ""
            node = cast(Mapping[str, JsonValue], node).get("items")
            if node is None:
                return ""
            continue
        if not isinstance(node, Mapping):
            return ""
        properties = cast(Mapping[str, JsonValue], node).get("properties")
        if not isinstance(properties, Mapping):
            return ""
        fields = cast(Mapping[str, JsonValue], properties)
        if type(segment) is not str or segment not in fields:
            return ""
        node = fields[segment]
    return _admitted_values(_resolve_local(document, node))


def _branch_covers_path(
    document: Mapping[str, JsonValue],
    branch: JsonValue,
    remaining: Sequence[str | int],
) -> bool:
    node: JsonValue = branch
    for index, segment in enumerate(remaining):
        node = _resolve_local(document, node)
        if type(segment) is int:
            if not isinstance(node, Mapping):
                return False
            items = cast(Mapping[str, JsonValue], node).get("items")
            if items is None:
                return False
            node = items
            continue
        nested = _select_union_branch(document, node, remaining[index:])
        if nested is not None:
            node = nested[0]
        node = _resolve_local(document, node)
        if not isinstance(node, Mapping):
            return False
        props = cast(Mapping[str, JsonValue], node).get("properties")
        if not isinstance(props, Mapping):
            return False
        fields = cast(Mapping[str, JsonValue], props)
        if type(segment) is not str or segment not in fields:
            return False
        node = fields[segment]
    return True


def _schema_identity_const(
    document: Mapping[str, JsonValue], branch: JsonValue, member: str
) -> str | None:
    """Read one frozen ``schema.<member>`` const off a draft-union branch."""

    node = _resolve_local(document, branch)
    if not isinstance(node, Mapping):
        return None
    props = cast(Mapping[str, JsonValue], node).get("properties")
    if not isinstance(props, Mapping):
        return None
    schema_node = cast(Mapping[str, JsonValue], props).get("schema")
    schema_node = _resolve_local(document, schema_node) if schema_node is not None else None
    if not isinstance(schema_node, Mapping):
        return None
    schema_props = cast(Mapping[str, JsonValue], schema_node).get("properties")
    if not isinstance(schema_props, Mapping):
        return None
    member_node = cast(Mapping[str, JsonValue], schema_props).get(member)
    member_node = _resolve_local(document, member_node) if member_node is not None else None
    if not isinstance(member_node, Mapping):
        return None
    const_value = cast(Mapping[str, JsonValue], member_node).get("const")
    return const_value if type(const_value) is str else None


def _schema_name_const(document: Mapping[str, JsonValue], branch: JsonValue) -> str | None:
    return _schema_identity_const(document, branch, "name")


def _schema_version_const(document: Mapping[str, JsonValue], branch: JsonValue) -> str | None:
    return _schema_identity_const(document, branch, "version")


def _is_schema_discriminator_path(remaining: Sequence[str | int]) -> bool:
    if not remaining:
        return False
    if remaining == ["schema"] or remaining == ["name"]:
        return True
    return list(remaining) == ["schema", "name"]


def _union_schema_names(document: Mapping[str, JsonValue], node: JsonValue) -> str:
    resolved = _resolve_local(document, node)
    if not isinstance(resolved, Mapping):
        return ""
    source = cast(Mapping[str, JsonValue], resolved)
    options = source.get("oneOf")
    if not isinstance(options, list):
        options = source.get("anyOf")
    if not isinstance(options, list):
        return ""
    names: list[str] = []
    for branch in cast(list[JsonValue], options):
        family = _schema_name_const(document, branch)
        if family is not None and family not in names:
            names.append(family)
        if len(names) > _MAX_HINT_SCHEMA_NAMES:
            return ""
    if not names or len(names) > _MAX_HINT_SCHEMA_NAMES:
        return ""
    return ", ".join(sorted(names))


def _resolve_local(document: Mapping[str, JsonValue], field: JsonValue) -> JsonValue:
    """Follow local ``#/$defs/`` references only, bounded against cycles and chains."""

    current = field
    seen: set[str] = set()
    for _ in range(_MAX_HINT_REF_HOPS):
        if not isinstance(current, Mapping):
            return current
        reference = cast(Mapping[str, JsonValue], current).get("$ref")
        if type(reference) is not str or not reference.startswith(_LOCAL_DEFS_PREFIX):
            return current
        if reference in seen:
            return field
        seen.add(reference)
        definitions = document.get("$defs")
        if not isinstance(definitions, Mapping):
            return field
        key = reference.removeprefix(_LOCAL_DEFS_PREFIX)
        nxt = cast(Mapping[str, JsonValue], definitions).get(key)
        if nxt is None:
            return field
        current = nxt
    return field


def _admitted_values(field: JsonValue) -> str:
    if not isinstance(field, Mapping):
        return ""
    source = cast(Mapping[str, JsonValue], field)
    raw_enum = source.get("enum")
    if isinstance(raw_enum, list):
        members = [str(item) for item in cast(list[JsonValue], raw_enum) if type(item) is str]
        if members and len(members) <= _MAX_HINT_ENUM_MEMBERS:
            return ", ".join(sorted(members))
    raw_const = source.get("const")
    if type(raw_const) is str:
        return raw_const
    # A bounded pattern is the only way to state an identifier's shape. The dogfood agent invented
    # a free-form request id because nothing named the required one.
    raw_pattern = source.get("pattern")
    if type(raw_pattern) is str and len(raw_pattern) <= _MAX_HINT_PATTERN_CHARS:
        return f"values matching {raw_pattern}"
    return ""


def _plain_string_member(field: JsonValue) -> str:
    """Name a bounded plain-string array member, which has no enum, const, or pattern."""

    if not isinstance(field, Mapping):
        return ""
    source = cast(Mapping[str, JsonValue], field)
    if source.get("type") != "string":
        return ""
    bound = source.get("maxLength")
    if type(bound) is int and bound > 0:
        return f"a plain string of at most {bound} characters"
    return "a plain string"


def _has_example(document: Mapping[str, JsonValue]) -> bool:
    examples = document.get("examples")
    return isinstance(examples, list) and bool(cast(list[JsonValue], examples))


def sanitize_unknown_tool_name(name: object) -> str:
    """Return one caller-independent message for an unregistered tools/call name."""

    del name
    return "The requested tool is not registered."


def _validated_failure(
    public_error: Mapping[str, object], request_id: str | None
) -> dict[str, JsonValue]:
    candidate: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "ok": False,
        "error": dict(public_error),
    }
    if request_id is not None:
        candidate["request_id"] = request_id
    validated = OperationFailureModel.model_validate(candidate)
    return cast(
        dict[str, JsonValue],
        validated.model_dump(mode="json", by_alias=True, exclude_unset=True),
    )


_FIELD_OWNERSHIP_REPAIR_KIND: Final = "field_ownership"
_FIELD_OWNERSHIP_TEMPLATE_URI: Final = "yoetz://guidance/request-templates.md"
# The continuation for a body the schema validator rejected before any write (ADR-030). It is the
# same rejection whatever field failed, so it is classified once here, at the only producer of
# location-shaped ``safe_details``, rather than per reason token: the field pointer and authoring
# hint already say *what* to fix, and the directive says that fixing it is a correction under a
# new request identity, not a retry of a terminal error.
_INPUT_CORRECTION_CONTINUATION: Final = "input_correction_new_identity"
_FIELD_OWNERSHIP_CONTINUATION: Final = "field_ownership_repair"


def _field_ownership_repair(locations: Sequence[Mapping[str, str]]) -> dict[str, str] | None:
    """Return the bounded repair fact for the first misplaced uniquely-owned payload field.

    The request stays rejected; this fact only names where the rejected field is legal, so a
    caller repairs by moving the field instead of deleting it and silently losing the record it
    carried (issue #266). Every value is frozen content: the field name matched the frozen schema
    vocabulary inside the validator, both family names come from the import-gated ownership
    registry beside the frozen presentation schema, and the template URI is a checked-in constant.
    When ownership is ambiguous or unknown there is no entry in the registry and no fact travels.
    """

    for location in locations:
        if location.get("reason") != _EXTRA_FORBIDDEN_REASON:
            continue
        family = location.get("family")
        field = location.get("misplaced_field")
        if type(family) is not str or type(field) is not str:
            continue
        owner = _FIELD_OWNERSHIP.get(field)
        if owner is None or owner == family:
            continue
        return {
            "repair_field": field,
            "repair_kind": _FIELD_OWNERSHIP_REPAIR_KIND,
            "repair_owning_family": owner,
            "repair_selected_family": family,
            "repair_template_uri": _FIELD_OWNERSHIP_TEMPLATE_URI,
        }
    return None


def tool_error_envelope(
    error: PublicOperationError, *, request_id: str | None = None
) -> dict[str, JsonValue]:
    """Map one bound public application error to the common operation-failure shape."""

    if type(error) is not PublicOperationError:
        raise TypeError("public_operation_error_wrong_type")
    return _validated_failure(error.as_public_dict(), request_id)


def build_public_error_result(
    code: PublicErrorCode,
    message: str,
    retryable: bool,
    correlation_id: str,
    *,
    request_id: str | None = None,
    safe_details: object | None = None,
    details_reason_code: str | None = None,
) -> dict[str, JsonValue]:
    """Build and schema-check one exact public operation-failure result.

    ``details_reason_code`` carries a second machine-readable fact beside field locations, so a
    caller never has to choose between knowing what to fix and knowing what else happened.
    """

    if type(safe_details) is tuple:
        locations = cast(tuple[Mapping[str, str], ...], safe_details)
        details: dict[str, object] = {
            "fields": tuple(location["field"] for location in locations),
            "reasons": tuple(location["reason"] for location in locations),
        }
        if type(details_reason_code) is str and _REASON_CODE.fullmatch(details_reason_code):
            details["reason_code"] = details_reason_code
        repair = _field_ownership_repair(locations)
        if repair is not None:
            details.update(repair)
        # A location-shaped rejection is always caller input the validator refused. The reason
        # code rides beside the locations only when a boundary knows something the locations do
        # not (the recovery oracle was unreachable), and that fact decides the directive; otherwise
        # the ownership repair, when one applies, is the more specific instruction.
        reason_continuation = (
            REASON_CODE_CONTINUATIONS.get(details_reason_code)
            if type(details_reason_code) is str
            else None
        )
        if reason_continuation is not None:
            details["continuation"] = reason_continuation
        elif repair is not None:
            details["continuation"] = _FIELD_OWNERSHIP_CONTINUATION
        else:
            details["continuation"] = _INPUT_CORRECTION_CONTINUATION
        public_error: dict[str, object] = {
            "code": code.value,
            "message": message,
            "retryable": retryable,
            "correlation_id": correlation_id,
            # `safe_details` keys are ASCII-ordered on the wire (docs/INTERFACES.md). Literal
            # insertion order put `reason_code` last, which is neither the documented order nor
            # the one every other producer of this map emits.
            "safe_details": dict(sorted(details.items())),
        }
        return _validated_failure(public_error, request_id)
    error = PublicOperationError(
        code,
        message,
        retryable,
        correlation_id=correlation_id,
        safe_details=safe_details,
    )
    return tool_error_envelope(error, request_id=request_id)


_LAST_RESORT_CORRELATION_ID: Final = new_id(IdKind.CORRELATION)
_LAST_RESORT_MESSAGE: Final = "An internal error occurred."


def build_last_resort_internal_error_result() -> dict[str, JsonValue]:
    """Return a helper-free, request-independent failure admitted by every tool schema."""

    # Deliberately do not call constructors, validators, serializers, ID generators, or summary
    # helpers here. The shared values were admitted when this module initialized.
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "ok": False,
        "error": {
            "code": "INTERNAL_ERROR",
            "message": _LAST_RESORT_MESSAGE,
            "retryable": False,
            "correlation_id": _LAST_RESORT_CORRELATION_ID,
        },
    }


# Fail startup if the supposedly universal literal branch ever leaves the shared schema contract.
OperationFailureModel.model_validate(build_last_resort_internal_error_result())

# Frontier leaves are hand-authored on every state-sensitive publish, and getting one wrong is the
# single most common routine payload mistake. They are frozen schema names already trusted as
# SAFE_DETAIL_KEYS, so failing to locate one is a diagnostic gap, not a safety property.
if not set(FRONTIER_LEAVES) <= _SAFE_LOCATION_SEGMENTS:
    raise RuntimeError("safe_location_segments_missing_frontier_leaf")
if not set(FRONTIER_LEAVES) <= set(SAFE_DETAIL_KEYS):
    raise RuntimeError("safe_detail_keys_missing_frontier_leaf")


def _schema_names(node: JsonValue, required: set[str], declared: set[str]) -> None:
    """Collect every ``required`` name and every declared property name, walking ``$defs`` too."""

    if isinstance(node, Mapping):
        source = cast(Mapping[str, JsonValue], node)
        names = source.get("required")
        if isinstance(names, list):
            required.update(item for item in cast(list[object], names) if type(item) is str)
        properties = source.get("properties")
        if isinstance(properties, Mapping):
            declared.update(
                key for key in cast(Mapping[object, object], properties) if type(key) is str
            )
        for value in source.values():
            _schema_names(value, required, declared)
    elif isinstance(node, list):
        for value in cast(list[JsonValue], node):
            _schema_names(value, required, declared)


def _check_locatable_required_names() -> None:
    """Fail startup if a frozen required property name cannot be located in a public error.

    A `required` name absent from the allowlist does not merely lose detail: the location projects
    to its allowlisted parent, so the caller is told the parent is `missing` when the parent was
    sent and only an interior member was wrong. That is worse than silence, and the 2026-08-03
    dogfood spent four guesses against exactly that shape of report.

    The same pass keeps the corrective registry honest: every field name a checked-in sentence
    mentions must still be declared by that tool's presentation schema.

    Declared-but-not-required names are held to the same rule. A payload key such as `source_refs`
    that is absent from the allowlist collapses its failure to `/event_drafts/N/payload`, which is
    what the 2026-08-13 dogfood was answered with, and the hint then recites envelope requirements
    the request already satisfied (issue #240).
    """

    from yoetz.mcp.descriptors import descriptor_for

    for tool in (
        "start",
        "publish_work",
        "check",
        "respond",
        "status",
        "receipt",
        "closure_prepare",
    ):
        required: set[str] = set()
        declared: set[str] = set()
        _schema_names(cast(JsonValue, descriptor_for(tool).input_schema), required, declared)
        if required - _SAFE_LOCATION_SEGMENTS - _DELIBERATELY_UNLOCATABLE:
            raise RuntimeError("safe_location_segments_missing_required_field")
        if declared - _SAFE_LOCATION_SEGMENTS - _DELIBERATELY_UNLOCATABLE_DECLARED:
            raise RuntimeError("safe_location_segments_missing_declared_field")
        for (registered_tool, _, _), (_, fields) in _CORRECTIVE_HINTS.items():
            if registered_tool == tool and not set(fields) <= declared:
                raise RuntimeError("corrective_hint_names_unknown_field")
    publish_schema = cast(JsonValue, descriptor_for("publish_work").input_schema)
    for (family, field), (_, fields) in _REFERENCE_LIST_CORRECTIONS.items():
        versions = [
            version
            for version in ("1.0.0", "1.1.0", "1.2.0")
            if _payload_schema(cast(Mapping[str, JsonValue], publish_schema), family, version)
        ]
        declared_by_family: set[str] = set()
        for version in versions:
            payload = _payload_schema(
                cast(Mapping[str, JsonValue], publish_schema), family, version
            )
            payload_properties = payload.get("properties") if payload is not None else None
            if isinstance(payload_properties, Mapping):
                declared_by_family.update(
                    key
                    for key in cast(Mapping[object, object], payload_properties)
                    if type(key) is str
                )
        if field not in declared_by_family or not set(fields) <= _SAFE_LOCATION_SEGMENTS:
            raise RuntimeError("reference_list_correction_names_unknown_field")
    registered_tools = {tool for tool, _, _ in _CORRECTIVE_HINTS}
    if not registered_tools <= {"start", "publish_work", "check", "respond", "status", "receipt"}:
        raise RuntimeError("corrective_hint_names_unknown_tool")


_check_locatable_required_names()


def _build_field_ownership() -> Mapping[str, str]:
    """Map each payload field to its sole owning ordinary publish family, or omit it.

    Derived at import from the frozen publish_work presentation schema — the exact surface
    callers author against — so the registry cannot drift from the contract it corrects (issue
    #266). A field is entered only when ownership is unambiguous: fields declared by more than
    one ordinary family are excluded, as is anything the presentation draft branches declare
    beside the payload. Keys the wire draft envelope itself admits (``evidence_refs``,
    ``artifact_refs``) never arrive here because the validator's ``misplaced_field`` projection
    skips them: those are misplaced across levels, not families. Every key is a declared
    presentation property, which the gate above already holds inside ``_SAFE_LOCATION_SEGMENTS``.
    """

    from yoetz.mcp.descriptors import ORDINARY_MCP_PUBLISH_EVENT_FAMILIES, descriptor_for

    document = descriptor_for("publish_work").input_schema
    items = _event_draft_items(document)
    if items is None:
        raise RuntimeError("field_ownership_event_drafts_missing")
    options = items.get("oneOf")
    if not isinstance(options, list):
        options = items.get("anyOf")
    if not isinstance(options, list):
        raise RuntimeError("field_ownership_event_drafts_missing")
    owners: dict[str, set[str]] = {}
    envelope_keys: set[str] = set()
    for branch in cast(list[JsonValue], options):
        resolved = _resolve_local(document, branch)
        if not isinstance(resolved, Mapping):
            continue
        family = _schema_name_const(document, resolved)
        if family is None or family not in ORDINARY_MCP_PUBLISH_EVENT_FAMILIES:
            continue
        branch_properties = cast(Mapping[str, JsonValue], resolved).get("properties")
        if not isinstance(branch_properties, Mapping):
            continue
        typed_branch_properties = cast(Mapping[str, JsonValue], branch_properties)
        envelope_keys.update(key for key in typed_branch_properties if type(key) is str)
        payload = _resolve_local(document, typed_branch_properties.get("payload"))
        if not isinstance(payload, Mapping):
            continue
        payload_properties = cast(Mapping[str, JsonValue], payload).get("properties")
        if not isinstance(payload_properties, Mapping):
            continue
        for key in cast(Mapping[object, object], payload_properties):
            if type(key) is str:
                owners.setdefault(key, set()).add(family)
    ownership = {
        field: next(iter(families))
        for field, families in owners.items()
        if len(families) == 1 and field not in envelope_keys and field in _SAFE_LOCATION_SEGMENTS
    }
    # The registry is generated, but the fact issue #266 exists to state is pinned here: losing it
    # to a schema or projection change must fail startup, not silently drop the repair.
    if ownership.get("attempted_items") != "action_recorded":
        raise RuntimeError("field_ownership_registry_drifted")
    return MappingProxyType(dict(sorted(ownership.items())))


_FIELD_OWNERSHIP: Final[Mapping[str, str]] = _build_field_ownership()
