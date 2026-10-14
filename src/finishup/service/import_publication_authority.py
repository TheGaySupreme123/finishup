"""Exact one-use authority for publishing one prepared Codex JSONL import plan."""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.adapters.importers.codex_jsonl import (
    CODEX_JSONL_MAPPING_VERSION,
    profile_for_codex_version,
)
from finishup.domain.events import MAX_TEXT_BYTES
from finishup.ports.importer import ImportAllocation
from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.consent import ImportPublicationPreviewModel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    MAX_EVENTS_PER_BATCH,
    ActorType,
    ClientKind,
    IntegrationKind,
    PublishWorkRequestModel,
)
from finishup.service.elevated_bootstrap import (
    ElevatedBootstrapError,
    ImportPublicationAuthorization,
    consume_import_publication_authorization,
    load_import_publication_authorization,
    load_pending,
    prepare_pending,
)

__all__ = ["ImportPublicationAuthority"]

_MAX_SOURCE_BYTES: Final = 4_194_304
_MAX_LINE_BYTES: Final = 1_048_576
_MAX_LINES: Final = 20_000
_MAX_BATCHES: Final = 1_024


@dataclass(slots=True)
class _ActiveImport:
    target_digest: str
    session_id: str
    writer_id: str
    request_id: str | None = None
    event_ids: tuple[str, ...] = ()
    admission_used: bool = False


@dataclass(frozen=True, slots=True)
class _Activation:
    authorization: ImportPublicationAuthorization
    active: _ActiveImport
    context_token: Token[_ActiveImport | None]


class ImportPublicationAuthority:
    """Consent-backed callable used by the publish-work admission gate."""

    def __init__(self, *, state_path: Path | None = None) -> None:
        self._state_path = state_path
        self._active: ContextVar[_ActiveImport | None] = ContextVar(
            "finishup_import_publication_authority", default=None
        )

    def _preview(self, allocation: ImportAllocation) -> dict[str, JsonValue]:
        captured = allocation.captured_source
        if allocation.plan_digest is None:
            raise PublicOperationError(
                PublicErrorCode.STORAGE_CORRUPT,
                "The prepared import plan is incomplete.",
                False,
            )
        try:
            profile = profile_for_codex_version(captured.codex_version)
        except ValueError as exc:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The Codex capability profile is unsupported.",
                False,
            ) from exc
        if profile.profile_id != captured.codex_capability_profile_id:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "The Codex capability profile does not match its version.",
                False,
            )
        target_body: dict[str, JsonValue] = {
            "schema": "yoetz.import-publication-target/1",
            "source_identity_digest": allocation.source_identity.identity_digest,
            "capture_manifest_commitment": captured.capture_metadata_object.commitment,
            "publication_plan_digest": allocation.plan_digest,
            "task_id": allocation.source_identity.task_id,
            "session_id": allocation.session_id,
            "writer_id": allocation.publishing_writer_id,
            "codex_capability_profile_id": captured.codex_capability_profile_id,
            "codex_capability_profile_digest": profile.contract_digest,
            "codex_version": captured.codex_version,
            "mapping_version": allocation.source_identity.mapping_version,
            "source_byte_count": captured.byte_count,
            "source_line_count": captured.line_count,
            "candidate_count_upper_bound": min(captured.line_count * 2, 102_400),
            "gap_count_upper_bound": captured.line_count,
            "batch_count": allocation.batch_count,
            "publication_count": allocation.batch_count + 1,
            "max_source_bytes": _MAX_SOURCE_BYTES,
            "max_line_bytes": _MAX_LINE_BYTES,
            "max_lines": _MAX_LINES,
            "max_excerpt_bytes": MAX_TEXT_BYTES,
            "max_events_per_batch": MAX_EVENTS_PER_BATCH,
            "max_batches": _MAX_BATCHES,
            "complete_transcript_included": False,
            "reasoning_items_included": False,
            "reviewer_egress_changed": False,
        }
        model = ImportPublicationPreviewModel.model_validate(
            {
                **target_body,
                "schema": "yoetz.import-publication-preview/1",
                "authorization_target_digest": canonical_digest(target_body),
            }
        )
        return cast(dict[str, JsonValue], model.model_dump(mode="json", by_alias=True))

    def activate(self, allocation: ImportAllocation) -> object:
        preview = self._preview(allocation)
        target_digest = cast(str, preview["authorization_target_digest"])
        authorization = load_import_publication_authorization(
            target_digest, _state=self._state_path
        )
        if authorization is None:
            pending = load_pending(_state=self._state_path)
            if pending is None:
                try:
                    prepare_pending(
                        "import_publication",
                        target_digest=target_digest,
                        import_publication_preview=preview,
                        _state=self._state_path,
                    )
                except ElevatedBootstrapError as exc:
                    if exc.reason == "import_publication_authorization_active":
                        raise PublicOperationError(
                            PublicErrorCode.OPERATION_PENDING,
                            "Another authorized import must finish before this plan can be authorized.",
                            True,
                            safe_details={
                                "operation": "import_publication",
                                "state": "pending",
                            },
                        ) from exc
                    if exc.reason != "pending_already_active":
                        raise
            elif (
                pending.operation != "import_publication" or pending.target_digest != target_digest
            ):
                # The single pending slot remains authoritative. The prepared import is durable and
                # can be retried after the unrelated consent is completed or expires.
                pass
            raise PublicOperationError(
                PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
                "This exact import plan requires user authorization.",
                False,
                safe_details={
                    "operation": "import_publication",
                    "reason_code": "import_publication_authority_required",
                    "state": "pending",
                },
            )
        active = _ActiveImport(
            target_digest,
            allocation.session_id,
            allocation.publishing_writer_id,
        )
        return _Activation(authorization, active, self._active.set(active))

    def bind(
        self,
        token: object,
        *,
        request_id: str,
        event_ids: tuple[str, ...],
    ) -> None:
        """Bind the active grant to the next exact persisted plan publication."""

        if type(token) is not _Activation or self._active.get() is not token.active:
            raise TypeError("import_publication_activation_invalid")
        if (
            type(request_id) is not str
            or type(event_ids) is not tuple
            or not 1 <= len(event_ids) <= MAX_EVENTS_PER_BATCH
            or any(type(value) is not str for value in event_ids)
        ):
            raise TypeError("import_publication_binding_invalid")
        token.active.request_id = request_id
        token.active.event_ids = event_ids
        token.active.admission_used = False

    def deactivate(self, token: object, *, completed: bool) -> None:
        if type(token) is not _Activation:
            raise TypeError("import_publication_activation_invalid")
        activation = token
        self._active.reset(activation.context_token)
        if completed:
            try:
                consume_import_publication_authorization(
                    activation.authorization, _state=self._state_path
                )
            except ElevatedBootstrapError:
                # The import is already terminal. Preserve the truthful success response; replaying
                # the same import reconciles an interrupted owner-only cleanup.
                pass

    def reconcile_completed(self, allocation: ImportAllocation) -> None:
        preview = self._preview(allocation)
        target_digest = cast(str, preview["authorization_target_digest"])
        authorization = load_import_publication_authorization(
            target_digest, _state=self._state_path
        )
        if authorization is None:
            return
        try:
            consume_import_publication_authorization(authorization, _state=self._state_path)
        except ElevatedBootstrapError:
            pass

    def __call__(self, request: object) -> bool:
        active = self._active.get()
        if (
            active is None
            or active.request_id is None
            or active.admission_used
            or type(request) is not PublishWorkRequestModel
            or request.request_id != active.request_id
            or request.session_id != active.session_id
            or request.writer_id != active.writer_id
            or request.dry_run is not None
            or request.actor.actor_id != "importer"
            or request.actor.actor_type is not ActorType.IMPORTER
            or request.client.kind is not ClientKind.IMPORTER
            or request.client.version != CODEX_JSONL_MAPPING_VERSION
            or request.client.integration is not IntegrationKind.CODEX_JSONL_IMPORT
        ):
            return False
        event_ids: list[str] = []
        for value in request.event_drafts:
            if not isinstance(value, Mapping):
                return False
            event_id = value.get("event_id")
            if type(event_id) is not str:
                return False
            event_ids.append(event_id)
        if tuple(event_ids) != active.event_ids:
            return False
        active.admission_used = True
        return True
