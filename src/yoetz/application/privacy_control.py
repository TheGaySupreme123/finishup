"""Ordinary-control support handlers for privacy policy show/propose/tighten and receipt reads."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timedelta
from typing import Final, cast

from yoetz.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from yoetz.application.privacy_policy import (
    GetPrivacyEffectiveRequest,
    GetPrivacyReceiptRequest,
    GetPrivacySetupRequest,
    ListPrivacyReceiptsRequest,
    PolicyDecisionRequired,
    PrivacyPolicyApplication,
    PrivacyPolicyResult,
    ProposePrivacyPolicyRequest,
    TightenPrivacyPolicyRequest,
    privacy_get_effective,
    privacy_get_setup,
    privacy_pending_list,
    privacy_propose_policy,
    privacy_receipts_get,
    privacy_receipts_list,
    privacy_tighten_policy,
)
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    EgressChannel,
    LocalDisclosureSink,
    PrivacyOutcome,
    PrivacyPolicy,
    ProviderBinding,
    ReviewSelectionPolicy,
)
from yoetz.domain.values import (
    JsonObject,
    format_rfc3339_millis,
    freeze_json,
    parse_rfc3339_millis,
)
from yoetz.ports.control import ControlError, ControlMethod, RepositoryPrivacyContext
from yoetz.ports.privacy import (
    EffectivePrivacyPolicy,
    NetworkEgressReceiptView,
    PrivacyAuditUnreadable,
    PrivacyReceiptCursorInvalid,
    PrivacyReceiptPage,
    PrivacyReceiptQuery,
    PrivacyReceiptView,
    ProviderReconciliation,
)
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_encode,
    parse_canonical_integer_string,
)
from yoetz.protocol.errors import ProtocolValueError

__all__ = [
    "build_privacy_support_handlers",
    "encode_effective_privacy_policy",
    "encode_privacy_policy_result",
    "encode_privacy_receipt_page",
    "encode_privacy_receipt_view",
]

_RECEIPT_WIRE_SCHEMA_VERSION: Final = "1.0.0"
_RECEIPT_LIST_KEYS: Final = frozenset({"schema_version", "filters", "page_size", "cursor"})
_RECEIPT_FILTER_KEYS: Final = frozenset(
    {
        "outcome",
        "channel",
        "sink",
        "provider_id",
        "endpoint_profile_id",
        "policy_version",
        "scope_kind",
        "finished_from",
        "finished_through",
    }
)
_RECEIPT_GET_KEYS: Final = frozenset({"schema_version", "receipt_id"})

type _SupportHandler = Callable[..., Awaitable[JsonObject]]


def _repository_scope(
    app: PrivacyPolicyApplication, context: RepositoryPrivacyContext | None
) -> AuthorizationScope:
    if context is None:
        raise ControlError("invalid_request")
    return AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE,
        app.setup_scope.installation_id,
        context.commitment,
    )


def _as_json_object(request: object) -> JsonObject:
    try:
        normalized = freeze_json(request)
    except ProtocolValueError as exc:
        raise ControlError("invalid_request") from exc
    if type(normalized) is not JsonObject:
        raise ControlError("invalid_request")
    return normalized


def _provider_reconciliation_to_wire(value: ProviderReconciliation) -> dict[str, JsonValue]:
    """Encode reconciliation as the frozen control-result shape.

    The domain type is deliberately wider than the wire contract: it names the generation
    ``policy_generation`` and pairs each unavailable binding digest with an internal reason.
    The reviewed schema carries a decimal-string ``policy_version`` and digests only, so this
    is written out by hand rather than reflected off the dataclass.
    """

    digests: list[JsonValue] = []
    for digest, _reason in value.unavailable_bindings:
        if digest not in digests:
            digests.append(digest)
    return {
        "policy_version": str(value.policy_generation),
        "activated_count": value.activated_count,
        "deactivated_count": value.deactivated_count,
        "unavailable_binding_digests": digests,
    }


def _review_selection_to_wire(value: object) -> JsonValue:
    if type(value) is not ReviewSelectionPolicy:
        raise TypeError("review_selection_invalid")
    return cast(
        JsonValue,
        {
            "sections": list(value.sections),
            "excerpt_kinds": list(value.excerpt_kinds),
            "relevance": value.relevance,
            "include_finding_prose": value.include_finding_prose,
            "include_exact_command_text": value.include_exact_command_text,
            "max_timeline_items": value.max_timeline_items,
            "max_assessments": value.max_assessments,
            "max_change_observations": value.max_change_observations,
            "max_excerpts": value.max_excerpts,
            "max_omissions": value.max_omissions,
            "max_excerpt_bytes": value.max_excerpt_bytes,
            "max_total_excerpt_bytes": value.max_total_excerpt_bytes,
        },
    )


def encode_effective_privacy_policy(effective: EffectivePrivacyPolicy) -> JsonObject:
    return JsonObject(
        {
            "schema_version": "1.0.0",
            "policy": encode_privacy_policy_json(effective.policy),
        }
    )


def encode_privacy_policy_result(
    result: PrivacyPolicyResult, *, schema_version: str = "1.0.0"
) -> JsonObject:
    return JsonObject(
        {
            "schema_version": schema_version,
            "outcome": "tightening_applied",
            "policy": encode_privacy_policy_json(result.policy),
            "revoked_authorization_count": result.revoked_authorization_count,
            "closed_session_count": result.closed_session_count,
            "provider_reconciliation": _provider_reconciliation_to_wire(
                result.provider_reconciliation
            ),
        }
    )


def _encode_decision_required(
    required: PolicyDecisionRequired,
    *,
    expected_policy_version: int,
    schema_version: str = "1.0.0",
) -> JsonObject:
    proposal = required.prepared.proposal
    return JsonObject(
        {
            "schema_version": schema_version,
            "outcome": "decision_required",
            "proposal_id": required.privacy_proposal_id,
            "proposal_digest": proposal.proposal_digest,
            "candidate_policy_digest": proposal.proposed_policy.policy_digest,
            "expected_policy_version": str(expected_policy_version),
            "expires_at": format_rfc3339_millis(proposal.expires_at),
        }
    )


def _scope_from_body(body: JsonObject, default: AuthorizationScope) -> AuthorizationScope:
    raw = body.get("scope")
    if raw is None:
        return default
    if type(raw) is not JsonObject:
        raise ControlError("invalid_request")
    if len(raw) == 0:
        return default
    try:
        return AuthorizationScope(
            AuthorizationScopeKind(cast(str, raw["kind"])),
            cast(str, raw["installation_id"]),
            cast(str | None, raw.get("workspace_ref_commitment")),
            cast(str | None, raw.get("task_id")),
            cast(str | None, raw.get("request_id")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlError("invalid_request") from exc


def _candidate_from_body(body: JsonObject) -> PrivacyPolicy:
    raw = body.get("candidate_policy")
    if raw is None:
        raise ControlError("invalid_request")
    try:
        return decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, raw)))
    except (TypeError, ValueError, ProtocolValueError) as exc:
        raise ControlError("invalid_request") from exc


def _scope_to_wire(scope: AuthorizationScope) -> dict[str, JsonValue]:
    values: dict[str, JsonValue] = {
        "kind": scope.kind.value,
        "installation_id": scope.installation_id,
    }
    for name in ("workspace_ref_commitment", "task_id", "request_id"):
        value = cast(str | None, getattr(scope, name))
        if value is not None:
            values[name] = value
    return values


def encode_privacy_receipt_view(view: PrivacyReceiptView) -> JsonObject:
    """Encode one receipt view as the schema-native wire shape the service client decodes.

    Every counter travels as a decimal string (the ``uint53_decimal`` vocabulary of the receipt
    schema) and every optional field is absent rather than ``null``, so the body validates
    against ``privacy/egress-receipt-1.0.0`` and round-trips through the client unchanged.
    """

    receipt = view.receipt
    counts: dict[str, JsonValue] = {
        "candidate_items": str(receipt.counts.candidate_items),
        "included_items": str(receipt.counts.included_items),
        "removed_items": str(receipt.counts.removed_items),
        "approved_items": str(receipt.counts.approved_items),
        "blocked_items": str(receipt.counts.blocked_items),
        "candidate_bytes": str(receipt.counts.candidate_bytes),
        "final_bytes": str(receipt.counts.final_bytes),
    }
    if receipt.counts.estimated_input_tokens is not None:
        counts["estimated_input_tokens"] = str(receipt.counts.estimated_input_tokens)
    if receipt.counts.request_body_bytes is not None:
        counts["request_body_bytes"] = str(receipt.counts.request_body_bytes)
    # v1.0 is a released wire shape with ``additionalProperties=false``.  New scan-stage and
    # withheld-item fields are additive in v1.1, so an old receipt view must retain its exact
    # historical shape rather than emitting fields that a v1.0 consumer rejects.
    secret_scan: dict[str, JsonValue] = {
        "registry_version": receipt.secret_scan.registry_version,
        "scanner_profile_digest": receipt.secret_scan.scanner_profile_digest,
        "match_count": str(receipt.secret_scan.match_count),
        "passed": receipt.secret_scan.passed,
    }
    if receipt.schema_version != "1.0.0":
        secret_scan["stage"] = receipt.secret_scan.stage.value
        if receipt.secret_scan.not_run_reason is not None:
            secret_scan["not_run_reason"] = receipt.secret_scan.not_run_reason.value
        if receipt.secret_scan.credential_heuristic.value != "enforced":
            # The owner had the low-confidence credential heuristic off for this disclosure.
            secret_scan["credential_heuristic"] = receipt.secret_scan.credential_heuristic.value
    body: dict[str, JsonValue] = {
        "schema_version": receipt.schema_version,
        "receipt_id": receipt.receipt_id,
        "request_id": receipt.request_id,
        "privacy_proposal_id": receipt.privacy_proposal_id,
        "outcome": receipt.outcome.value,
        "finished_at": format_rfc3339_millis(receipt.finished_at),
        "scope": _scope_to_wire(receipt.scope),
        "purpose": receipt.purpose,
        "policy": {
            "policy_id": receipt.policy.policy_id,
            "version": str(receipt.policy.version),
            "policy_digest": receipt.policy.policy_digest,
            "authorization_scope_digest": receipt.policy.authorization_scope_digest,
        },
        "consent_source": receipt.consent_source.value,
        "approved_categories": [item.value for item in receipt.approved_categories],
        "blocked_categories": [item.value for item in receipt.blocked_categories],
        "counts": counts,
        "transformations": {
            "minimized_items": str(receipt.transformations.minimized_items),
            "redacted_spans": str(receipt.transformations.redacted_spans),
            "blocked_items": str(receipt.transformations.blocked_items),
        },
        "secret_scan": secret_scan,
        "audit_store_version": receipt.audit_store_version,
    }
    if receipt.withheld_item_ids and receipt.schema_version != "1.0.0":
        # Item identities are bounded opaque references.  The matched bytes and source prose
        # never cross this receipt surface.
        body["withheld_item_ids"] = list(receipt.withheld_item_ids)
        body["withheld_item_reason"] = receipt.withheld_item_reason
    if receipt.safe_failure_reason is not None:
        body["safe_failure_reason"] = receipt.safe_failure_reason.value
    if isinstance(view, NetworkEgressReceiptView):
        network = view.receipt
        body["channel"] = network.channel.value
        destination = network.destination
        if isinstance(destination, ProviderBinding):
            body["destination"] = {
                "provider_id": destination.provider_id,
                "model_id": destination.model_id,
                "endpoint_profile_id": destination.endpoint_profile_id,
                "endpoint_profile_version": destination.endpoint_profile_version,
                "transport": destination.transport,
            }
        else:
            body["destination"] = {
                "kind": destination.kind.value,
                "profile_id": destination.profile_id,
                "profile_version": destination.profile_version,
            }
        if network.authorization_id is not None:
            body["authorization_id"] = network.authorization_id
        if network.dispatch_id is not None:
            body["dispatch_id"] = network.dispatch_id
        if network.dispatch_started_at is not None:
            body["dispatch_started_at"] = format_rfc3339_millis(network.dispatch_started_at)
        if network.request_commitment is not None:
            body["request_commitment"] = {
                "algorithm": network.request_commitment.algorithm,
                "commitment": network.request_commitment.commitment,
            }
        return JsonObject({"kind": "network_egress", "receipt": body})
    body["sink"] = view.receipt.sink.value
    return JsonObject({"kind": "local_disclosure", "receipt": body})


def encode_privacy_receipt_page(page: PrivacyReceiptPage) -> JsonObject:
    values: dict[str, JsonValue] = {
        "schema_version": _RECEIPT_WIRE_SCHEMA_VERSION,
        "snapshot_generation": str(page.snapshot_generation),
        "receipts": [
            cast(JsonValue, dict(encode_privacy_receipt_view(view))) for view in page.receipts
        ],
    }
    if page.next_cursor is not None:
        values["next_cursor"] = page.next_cursor
    if page.undecodable_count:
        # Present only on a partial page, so a complete page keeps its exact prior bytes. The ids
        # are structural receipt ids; nothing a skipped row stored is echoed (issue #921).
        values["undecodable_count"] = str(page.undecodable_count)
        values["undecodable_receipt_ids"] = list(page.undecodable_receipt_ids)
    return JsonObject(values)


def _optional_text(body: JsonObject, name: str) -> str | None:
    value = body.get(name)
    if value is None:
        return None
    if type(value) is not str or not value:
        raise ControlError("invalid_request")
    return value


def _optional_time(body: JsonObject, name: str) -> datetime | None:
    value = body.get(name)
    if value is None:
        return None
    try:
        return parse_rfc3339_millis(value)
    except (TypeError, ValueError) as exc:
        raise ControlError("invalid_request") from exc


def _receipt_query_from_body(body: JsonObject) -> PrivacyReceiptQuery:
    """Decode the client's ``ListPrivacyReceiptsRequest`` wire body into one bounded query.

    Unknown keys are rejected rather than ignored: a misspelled filter that silently widened the
    listing would hand back receipts the caller asked to exclude.
    """

    if body.get("schema_version") != _RECEIPT_WIRE_SCHEMA_VERSION:
        raise ControlError("invalid_request")
    if not set(body).issubset(_RECEIPT_LIST_KEYS):
        raise ControlError("invalid_request")
    raw_filters = body.get("filters", JsonObject({}))
    if type(raw_filters) is not JsonObject or not set(raw_filters).issubset(_RECEIPT_FILTER_KEYS):
        raise ControlError("invalid_request")
    page_size = body.get("page_size", 50)
    if type(page_size) is not int or not 1 <= page_size <= 100:
        raise ControlError("invalid_request")
    cursor = _optional_text(body, "cursor")
    policy_version: int | None = None
    raw_version = raw_filters.get("policy_version")
    if raw_version is not None:
        if type(raw_version) is not str:
            raise ControlError("invalid_request")
        try:
            policy_version = parse_canonical_integer_string(raw_version)
        except (TypeError, ValueError) as exc:
            raise ControlError("invalid_request") from exc
        if policy_version <= 0:
            raise ControlError("invalid_request")
    try:
        outcome = _optional_text(raw_filters, "outcome")
        channel = _optional_text(raw_filters, "channel")
        sink = _optional_text(raw_filters, "sink")
        scope_kind = _optional_text(raw_filters, "scope_kind")
        return PrivacyReceiptQuery(
            receipt_id=None,
            outcome=None if outcome is None else PrivacyOutcome(outcome),
            channel=None if channel is None else EgressChannel(channel),
            local_sink=None if sink is None else LocalDisclosureSink(sink),
            provider_id=_optional_text(raw_filters, "provider_id"),
            endpoint_profile_id=_optional_text(raw_filters, "endpoint_profile_id"),
            policy_version=policy_version,
            scope_kind=None if scope_kind is None else AuthorizationScopeKind(scope_kind),
            finished_at_from=_optional_time(raw_filters, "finished_from"),
            finished_at_through=_optional_time(raw_filters, "finished_through"),
            limit=page_size,
            cursor=cursor,
        )
    except (TypeError, ValueError) as exc:
        raise ControlError("invalid_request") from exc


def _audit_unreadable(exc: PrivacyAuditUnreadable, operation: str) -> ControlError:
    """Name a store-side receipt failure once, record it, and never call it the caller's.

    The request reached the audit store, so it was well formed: reporting ``invalid_request`` here
    told the operator to fix a command that had nothing wrong with it and left no diagnostic
    behind (issue #921). The closed store reason goes to the owner-only diagnostic sink under the
    correlation id the caller receives; no receipt content travels with either.
    """

    from yoetz.observability.logging import record_public_error_without_raising

    correlation_id = record_public_error_without_raising(
        component="privacy_audit",
        operation=operation,
        reason=exc.reason,
    )
    return ControlError("privacy_audit_unreadable", retryable=False, correlation_id=correlation_id)


def _policy_rejection() -> ControlError:
    """Every policy-layer rejection is a caller-fixable, non-retryable request error.

    The application raises bounded reason tokens (``privacy_policy_stale``,
    ``privacy_authority_required``, …) but the control envelope carries no free-form detail,
    so they collapse to one closed reason rather than leaking the internal token.
    """

    return ControlError("invalid_request", retryable=False)


def build_privacy_support_handlers(
    app: PrivacyPolicyApplication,
) -> Mapping[ControlMethod, _SupportHandler]:
    """Bind privacy_* ordinary-control methods to one PrivacyPolicyApplication."""

    async def get_setup(
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        body = _as_json_object(request)
        if body.get("schema_version") != "2.0.0":
            raise ControlError("invalid_request")
        scope = _repository_scope(app, repository_privacy_context)
        now = app.clock.now_utc()
        try:
            view = await privacy_get_setup(
                app,
                GetPrivacySetupRequest(
                    "repository_setup",
                    "begin",
                    0,
                    now + timedelta(seconds=app.proposal_ttl_seconds),
                    True,
                    repository_scope=scope,
                ),
            )
        except (TypeError, ValueError) as exc:
            raise _policy_rejection() from exc
        authority = view.authority
        if authority is None:
            raise _policy_rejection()
        return JsonObject(
            {
                "schema_version": "2.0.0",
                "composed_policy": encode_privacy_policy_json(view.effective.policy),
                "bound_scope": cast(
                    JsonValue,
                    {
                        "kind": scope.kind.value,
                        "installation_id": scope.installation_id,
                        "workspace_ref_commitment": scope.workspace_ref_commitment,
                    },
                ),
                "authority_digest": authority.authority_digest,
                "grant_state": authority.grant_state,
                "migration_state": authority.migration_state,
                "channel_choices": cast(
                    JsonValue,
                    [
                        {
                            "channel": choice.channel.value,
                            "enabled": choice.enabled,
                            "capability_state": choice.capability_state,
                        }
                        for choice in view.channel_choices
                    ],
                ),
                "allowed_blocked_examples": cast(
                    JsonValue,
                    [
                        {"code": item.code, "allowed": item.allowed}
                        for item in view.allowed_blocked_examples
                    ],
                ),
                "recipes": cast(
                    JsonValue,
                    [
                        {
                            "recipe": recipe.recipe,
                            "privacy_profile": recipe.privacy_profile.value,
                            "review_context_profile": recipe.review_context_profile.value,
                            "review_selection": _review_selection_to_wire(recipe.review_selection),
                        }
                        for recipe in view.recipes
                    ],
                ),
                "never_send_editable": False,
            }
        )

    async def get_effective(
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        body = _as_json_object(request)
        try:
            is_v2 = body.get("schema_version") == "2.0.0"
            if is_v2:
                scope = _repository_scope(app, repository_privacy_context)
                authority = await app.policy_store.repository_authority(scope)
                effective = authority.effective
            else:
                scope = _scope_from_body(body, app.setup_scope)
                effective = await privacy_get_effective(app, GetPrivacyEffectiveRequest(scope))
        except ControlError:
            raise
        except (TypeError, ValueError) as exc:
            raise _policy_rejection() from exc
        return encode_effective_privacy_policy(effective)

    async def propose_policy(
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        body = _as_json_object(request)
        try:
            is_v2 = body.get("schema_version") == "2.0.0"
            if is_v2:
                scope = _repository_scope(app, repository_privacy_context)
                digest = body["authority_digest"]
                if type(digest) is not str:
                    raise ControlError("invalid_request")
                authority = await app.policy_store.repository_authority(scope)
                expected_policy_digest = authority.effective.effective_digest
            else:
                scope = None
                digest = body["expected_policy_digest"]
                if type(digest) is not str:
                    raise ControlError("invalid_request")
                expected_policy_digest = digest
            if type(digest) is not str:
                raise ControlError("invalid_request")
            candidate = _candidate_from_body(body)
            if not is_v2 and candidate.effective_scope.kind is not AuthorizationScopeKind.MACHINE:
                raise ControlError("invalid_request")
            result = await privacy_propose_policy(
                app,
                ProposePrivacyPolicyRequest(
                    expected_policy_digest,
                    candidate,
                    digest if scope is not None else None,
                    scope,
                ),
            )
            if type(result) is PolicyDecisionRequired:
                proposal = result.prepared.proposal
                current = await app.policy_store.effective_policy(proposal.scope)
                # This is a second read; a concurrent commit in between would otherwise report
                # a version belonging to a different policy than the one just prepared. The
                # proposal pins the generation it was prepared against, so disagreement means
                # the proposal is already stale and the caller must re-read and retry.
                if current.generation != proposal.expected_generation or (
                    proposal.expected_policy_digest is not None
                    and current.effective_digest != proposal.expected_policy_digest
                ):
                    raise _policy_rejection()
                return _encode_decision_required(
                    result,
                    expected_policy_version=current.policy.version,
                    schema_version="2.0.0" if is_v2 else "1.0.0",
                )
            if type(result) is PrivacyPolicyResult:
                return encode_privacy_policy_result(
                    result, schema_version="2.0.0" if is_v2 else "1.0.0"
                )
            raise ControlError("invalid_request")
        except ControlError:
            raise
        except KeyError as exc:
            raise ControlError("invalid_request") from exc
        except (TypeError, ValueError) as exc:
            raise _policy_rejection() from exc

    async def tighten_policy(request: object) -> JsonObject:
        body = _as_json_object(request)
        try:
            digest = body["expected_policy_digest"]
            if type(digest) is not str:
                raise ControlError("invalid_request")
            candidate = _candidate_from_body(body)
            if candidate.effective_scope.kind is not AuthorizationScopeKind.MACHINE:
                raise ControlError("invalid_request")
            result = await privacy_tighten_policy(
                app, TightenPrivacyPolicyRequest(digest, candidate)
            )
        except ControlError:
            raise
        except KeyError as exc:
            raise ControlError("invalid_request") from exc
        except (TypeError, ValueError) as exc:
            raise _policy_rejection() from exc
        return encode_privacy_policy_result(result)

    async def pending_list(request: object) -> JsonObject:
        # Takes no parameters: a pending decision is open or it is not. Any body is accepted and
        # ignored rather than rejected, so a future caller adding a field cannot be told its
        # request was invalid when nothing about the answer would have changed.
        del request
        try:
            page = await privacy_pending_list(app)
        except ControlError:
            raise
        except (TypeError, ValueError) as exc:
            raise _policy_rejection() from exc
        return JsonObject(
            {
                "schema": "yoetz.privacy-pending-page/1",
                "snapshot_generation": page.snapshot_generation,
                "pending": [
                    {
                        "pending_id": entry.pending_id,
                        "task_id": entry.task_id,
                        "expires_at": format_rfc3339_millis(entry.expires_at),
                    }
                    for entry in page.pending
                ],
            }
        )

    async def receipts_list(request: object) -> JsonObject:
        query = _receipt_query_from_body(_as_json_object(request))
        try:
            page = await privacy_receipts_list(app, ListPrivacyReceiptsRequest(query))
        except ControlError:
            raise
        except PrivacyReceiptCursorInvalid as exc:
            # A cursor from a different query or a corrupt one is the caller's to fix; the
            # bounded envelope carries no detail, so it collapses to one closed reason.
            raise _policy_rejection() from exc
        except PrivacyAuditUnreadable as exc:
            raise _audit_unreadable(exc, "privacy_receipts_list") from exc
        # Anything else is unexpected, not a caller error: it reaches the daemon's recorded
        # ``read_projection_failed`` path instead of being folded into ``invalid_request``.
        return encode_privacy_receipt_page(page)

    async def receipts_get(request: object) -> JsonObject:
        body = _as_json_object(request)
        if body.get("schema_version") != _RECEIPT_WIRE_SCHEMA_VERSION or not set(body).issubset(
            _RECEIPT_GET_KEYS
        ):
            raise ControlError("invalid_request")
        receipt_id = body.get("receipt_id")
        if type(receipt_id) is not str:
            raise ControlError("invalid_request")
        try:
            lookup = GetPrivacyReceiptRequest(receipt_id)
        except (TypeError, ValueError) as exc:
            raise ControlError("invalid_request") from exc
        try:
            view = await privacy_receipts_get(app, lookup)
        except ControlError:
            raise
        except PrivacyAuditUnreadable as exc:
            raise _audit_unreadable(exc, "privacy_receipts_get") from exc
        if view is None:
            return JsonObject(
                {"schema_version": _RECEIPT_WIRE_SCHEMA_VERSION, "outcome": "not_found"}
            )
        return JsonObject(
            {
                "schema_version": _RECEIPT_WIRE_SCHEMA_VERSION,
                "outcome": "found",
                "receipt": cast(JsonValue, dict(encode_privacy_receipt_view(view))),
            }
        )

    return {
        ControlMethod.PRIVACY_GET_EFFECTIVE: get_effective,
        ControlMethod.PRIVACY_GET_SETUP: get_setup,
        ControlMethod.PRIVACY_PENDING_LIST: pending_list,
        ControlMethod.PRIVACY_PROPOSE_POLICY: propose_policy,
        ControlMethod.PRIVACY_RECEIPTS_GET: receipts_get,
        ControlMethod.PRIVACY_RECEIPTS_LIST: receipts_list,
        ControlMethod.PRIVACY_TIGHTEN_POLICY: tighten_policy,
    }
