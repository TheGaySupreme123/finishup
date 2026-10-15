"""Typed identities and admission rules for project coordination.

Project coordination deliberately lives beside the privacy domain without adding a ``project``
member to :class:`~finishup.domain.privacy.AuthorizationScope`.  A project is an amendable graph,
whereas an authorization scope is a frozen containment value.  This module contains the small,
pure value objects shared by the catalog, detector, and CLI application layers; it does not read a
catalog or an object store.

User supplied project text is represented by :class:`ProjectTextRef`.  The plaintext itself never
appears in any value's structural representation.  A service may resolve the reference through an
encrypted object store when the selected disclosure sink permits it.
"""

from __future__ import annotations

import posixpath
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Final, Literal, Protocol, cast

from finishup.domain.values import (
    JsonObject,
    JsonValue,
    ObligationId,
    format_rfc3339_millis,
    object_id,
    obligation_id,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "COORDINATION_DETAIL_FORMAT",
    "CoordinationAdmission",
    "CoordinationCoverage",
    "CoordinationDetection",
    "CoordinationDisposition",
    "CoordinationError",
    "CoordinationErrorCode",
    "CoordinationGapCode",
    "CoordinationGrant",
    "CoordinationObligationState",
    "GrantState",
    "LineageAcceptance",
    "LineageOrigin",
    "MemberKind",
    "OverlapKind",
    "ProjectDescriptor",
    "ProjectKind",
    "ProjectMembership",
    "ProjectTextRef",
    "ProjectTextStore",
    "SessionHealth",
    "WorkState",
    "canonical_resource_identity",
    "classify_resource_overlap",
    "coordination_detection_identity",
    "coordination_generation_is_current",
    "overlap_resource_commitments",
    "overlap_resource_identities",
    "project_id",
    "relative_resource_identity",
]


_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_RESOURCE_BYTES: Final = 4_096
_MAX_RESOURCES: Final = 256
_TOKEN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_PROJECT_ID_RE: Final = re.compile(
    r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
_POSIX_RESOURCE_RE: Final = re.compile(r"^[^\x00\r\n]+$", re.UNICODE)

COORDINATION_DETAIL_FORMAT: Final = "yoetz.coordination-details/1"


class ProjectKind(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    """The two project objects supported in v1."""

    REPOSITORY = "repository"
    GENERAL = "general"


class MemberKind(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    """A project membership identity, kept separate from workspace/task identity."""

    REPOSITORY = "repository"
    WORKSPACE = "workspace"
    TASK = "task"


class GrantState(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    ACTIVE = "active"
    REVOKED = "revoked"


class WorkState(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    OPEN = "open"
    CLOSED = "closed"
    CANCELLED = "cancelled"
    ABANDONED = "abandoned"
    WRITTEN_OFF = "written_off"


class SessionHealth(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    ACTIVE = "active"
    CONTACT_LOST = "contact_lost"
    ENDED = "ended"


# One authenticated contact holds a task session ``active`` for this long.  Every catalog that
# stores a session lease and every evidence-anchored renewal share this value, so a lease derived
# from a host event's own time and a lease written by a workflow call have the same meaning.
SESSION_LEASE_SECONDS: Final = 60


class LineageOrigin(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    PARENT_MINTED = "parent_minted"
    SELF_REGISTERED = "self_registered"
    HOST_OBSERVED = "host_observed"


class LineageAcceptance(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class OverlapKind(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    """How two declared resources relate.

    ``PHYSICAL`` means the same consented workspace identity.  ``INTEGRATION`` means two
    worktrees of one repository declared the same relative resource.  Unrelated repositories have
    no overlap even when their path spellings match.
    """

    PHYSICAL = "physical"
    INTEGRATION = "integration"
    PLAN = "plan"


class CoordinationDisposition(str, Enum):  # noqa: UP042 - exact wire vocabulary
    """A typed response that addresses a declared coordination obligation."""

    SHARED_WORK = "shared_work"
    SEQUENCING = "sequencing"
    SCOPE_REVISION = "scope_revision"


class CoordinationGapCode(str, Enum):  # noqa: UP042 - exact wire vocabulary
    """Why an overlap detail is bounded or unavailable."""

    SOURCE_UNAVAILABLE = "source_unavailable"
    # On a service-stamped context, ``revoked`` closes the recipient's earlier delivery of the
    # same detection: its project generation was superseded, so it is history, not a current
    # coordination obligation (#842).
    REVOKED = "revoked"
    NOT_OBSERVABLE = "not_observable"
    DETAILS_TRUNCATED = "details_truncated"


class CoordinationErrorCode(str, Enum):  # noqa: UP042 - mirrors the exact wire vocabulary
    """Stable application errors; the control adapter maps these to its public reason vocabulary."""

    INVALID = "coordination_invalid"
    PROJECT_NOT_FOUND = "project_not_found"
    PROJECT_DISSOLVED = "project_dissolved"
    IMPLICIT_PROJECT_REQUIRES_OPT_OUT = "implicit_project_requires_opt_out"
    GENERAL_MEMBERSHIP_CONFLICT = "general_project_membership_conflict"
    MEMBER_NOT_FOUND = "project_member_not_found"
    SELECTOR_CONFLICT = "selector_conflict"
    CONSENT_REQUIRED = "coordination_consent_required"
    SOURCE_POLICY_DENIED = "coordination_source_policy_denied"
    GRANT_REQUIRED = "coordination_grant_required"
    GRANT_REVOKED = "coordination_generation_revoked"
    GENERATION_MISMATCH = "coordination_generation_mismatch"
    CROSS_REPOSITORY_LINEAGE = "cross_repository_lineage_requires_grant"
    ALREADY_UNBOUND = "project_member_already_unbound"


class CoordinationError(ValueError):
    """Bounded, user-safe coordination failure.

    The error carries a closed code and no caller supplied message.  Callers may choose a local
    human rendering, while a control adapter can map the code to the repository's public error
    envelope without putting title, description, or path text into it.
    """

    __slots__ = ("code",)

    code: CoordinationErrorCode

    def __init__(self, code: CoordinationErrorCode) -> None:
        if type(code) is not CoordinationErrorCode:
            raise TypeError("coordination_error_code_invalid")
        self.code = code
        super().__init__(code.value)


def _invalid() -> ValueError:
    return ValueError("coordination_value_invalid")


def _bounded_token(value: object, *, max_bytes: int = 128) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise _invalid()
    try:
        if not 1 <= len(value.encode("utf-8")) <= max_bytes:
            raise _invalid()
    except UnicodeEncodeError as exc:
        raise _invalid() from exc
    return value


def project_id(value: object) -> str:
    """Validate a project id, including compatibility with pre-#495 imports.

    ``IdKind.PROJECT`` is supplied by the protocol foundation slice.  Keeping the shape check here
    lets the application be imported while an old catalog adapter is being upgraded and still
    fails closed for malformed ids.
    """

    if type(value) is not str or _PROJECT_ID_RE.fullmatch(value) is None:
        raise _invalid()
    project_kind = getattr(IdKind, "PROJECT", None)
    if project_kind is not None:
        try:
            validate_id(cast(IdKind, project_kind), value)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid() from exc
    return value


def _commitment(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        return validate_commitment(value)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise _invalid() from exc


def _digest(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        return validate_sha256_digest(value)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise _invalid() from exc


def _positive(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
        raise _invalid()
    return value


def _nonnegative(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise _invalid()
    return value


def _timestamp(value: object) -> datetime:
    if type(value) is not datetime:
        raise _invalid()
    try:
        format_rfc3339_millis(value)
    except ValueError as exc:
        raise _invalid() from exc
    return value


def _optional_timestamp(value: object) -> datetime | None:
    return None if value is None else _timestamp(value)


def _enum[T: Enum](value: object, enum_type: type[T]) -> T:
    if type(value) is enum_type:
        return cast(T, value)
    try:
        return enum_type(cast(str, value))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


@dataclass(frozen=True, slots=True, repr=False)
class ProjectTextRef:
    """Structural pointer to encrypted project text."""

    object_id: str
    content_digest: str
    plaintext_size: int
    owner_task_id: str
    route_generation: int
    envelope_digest: str | None = None

    def __post_init__(self) -> None:
        try:
            object_id(self.object_id)
            _digest(self.content_digest)
            _nonnegative(self.plaintext_size)
            validate_id(IdKind.TASK, self.owner_task_id)
            _positive(self.route_generation)
            if self.envelope_digest is not None:
                _digest(self.envelope_digest)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc

    def __repr__(self) -> str:
        return "ProjectTextRef(<redacted>)"

    def as_wire(self) -> JsonObject:
        values: dict[str, JsonValue] = {
            "object_id": self.object_id,
            "content_digest": self.content_digest,
            "plaintext_size": self.plaintext_size,
            "owner_task_id": self.owner_task_id,
            "route_generation": str(self.route_generation),
        }
        if self.envelope_digest is not None:
            values["envelope_digest"] = self.envelope_digest
        return JsonObject(values)


class ProjectTextStore(Protocol):
    """Encrypted object boundary for title and description values.

    Implementations must persist ciphertext/object envelopes and return only a structural
    reference.  A store that keeps raw text in a catalog column is not a conforming implementation.
    """

    async def put(
        self,
        project_id: str,
        field: Literal["title", "description"],
        plaintext: str,
        *,
        owner_task_id: str,
        route_generation: int,
        reserved_object_id: str | None = None,
    ) -> ProjectTextRef: ...

    async def read(self, reference: ProjectTextRef) -> str: ...


@dataclass(frozen=True, slots=True, repr=False)
class ProjectDescriptor:
    project_id: str
    kind: ProjectKind
    repository_commitment: str | None
    auto_grouping: bool
    membership_generation: int
    title_ref: ProjectTextRef | None
    description_ref: ProjectTextRef | None
    created_at: datetime
    dissolved_at: datetime | None = None

    def __post_init__(self) -> None:
        project_id(self.project_id)
        object.__setattr__(self, "kind", _enum(self.kind, ProjectKind))
        if self.kind is ProjectKind.REPOSITORY and self.repository_commitment is None:
            raise _invalid()
        if self.kind is ProjectKind.GENERAL and self.repository_commitment is not None:
            raise _invalid()
        if self.repository_commitment is not None:
            _commitment(self.repository_commitment)
        if type(self.auto_grouping) is not bool:
            raise _invalid()
        _positive(self.membership_generation)
        if self.title_ref is not None and type(self.title_ref) is not ProjectTextRef:
            raise _invalid()
        if self.description_ref is not None and type(self.description_ref) is not ProjectTextRef:
            raise _invalid()
        _timestamp(self.created_at)
        _optional_timestamp(self.dissolved_at)
        if self.dissolved_at is not None and self.dissolved_at < self.created_at:
            raise _invalid()

    def __repr__(self) -> str:
        return "ProjectDescriptor(<redacted>)"

    def as_wire(self) -> JsonObject:
        """Return structural project state without title/description plaintext."""

        values: dict[str, JsonValue] = {
            "project_id": self.project_id,
            "kind": self.kind.value,
            "auto_grouping": self.auto_grouping,
            "membership_generation": str(self.membership_generation),
            "created_at": format_rfc3339_millis(self.created_at),
        }
        if self.repository_commitment is not None:
            values["repository_commitment"] = self.repository_commitment
        if self.title_ref is not None:
            values["title_ref"] = self.title_ref.as_wire()
        if self.description_ref is not None:
            values["description_ref"] = self.description_ref.as_wire()
        if self.dissolved_at is not None:
            values["dissolved_at"] = format_rfc3339_millis(self.dissolved_at)
        return JsonObject(values)


@dataclass(frozen=True, slots=True, repr=False)
class ProjectMembership:
    project_id: str
    membership_generation: int
    member_kind: MemberKind
    member_commitment_or_id: str
    bound_at: datetime
    unbound_at: datetime | None = None

    def __post_init__(self) -> None:
        project_id(self.project_id)
        _positive(self.membership_generation)
        kind = _enum(self.member_kind, MemberKind)
        object.__setattr__(self, "member_kind", kind)
        _bounded_token(self.member_commitment_or_id)
        if kind is MemberKind.TASK:
            try:
                validate_id(IdKind.TASK, self.member_commitment_or_id)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise _invalid() from exc
        elif kind in {MemberKind.REPOSITORY, MemberKind.WORKSPACE}:
            _commitment(self.member_commitment_or_id)
        _timestamp(self.bound_at)
        _optional_timestamp(self.unbound_at)
        if self.unbound_at is not None and self.unbound_at < self.bound_at:
            raise _invalid()

    @property
    def active(self) -> bool:
        return self.unbound_at is None

    def as_wire(self) -> JsonObject:
        values: dict[str, JsonValue] = {
            "project_id": self.project_id,
            "membership_generation": str(self.membership_generation),
            "member_kind": self.member_kind.value,
            "member_commitment_or_id": self.member_commitment_or_id,
            "bound_at": format_rfc3339_millis(self.bound_at),
        }
        if self.unbound_at is not None:
            values["unbound_at"] = format_rfc3339_millis(self.unbound_at)
        return JsonObject(values)


@dataclass(frozen=True, slots=True, repr=False)
class CoordinationGrant:
    project_id: str
    membership_generation: int
    state: GrantState
    audit_record_id: str
    granted_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        project_id(self.project_id)
        _positive(self.membership_generation)
        state = _enum(self.state, GrantState)
        object.__setattr__(self, "state", state)
        _bounded_token(self.audit_record_id)
        _timestamp(self.granted_at)
        _optional_timestamp(self.revoked_at)
        if state is GrantState.ACTIVE and self.revoked_at is not None:
            raise _invalid()
        if state is GrantState.REVOKED and self.revoked_at is None:
            raise _invalid()
        if self.revoked_at is not None and self.revoked_at < self.granted_at:
            raise _invalid()

    @property
    def active(self) -> bool:
        return self.state is GrantState.ACTIVE and self.revoked_at is None

    def as_wire(self) -> JsonObject:
        values: dict[str, JsonValue] = {
            "project_id": self.project_id,
            "membership_generation": str(self.membership_generation),
            "state": self.state.value,
            "audit_record_id": self.audit_record_id,
            "granted_at": format_rfc3339_millis(self.granted_at),
        }
        if self.revoked_at is not None:
            values["revoked_at"] = format_rfc3339_millis(self.revoked_at)
        return JsonObject(values)


@dataclass(frozen=True, slots=True)
class CoordinationAdmission:
    """Result of checking one source task before a cross-task read or delivery."""

    source_task_id: str
    source_workspace_commitment: str
    project_id: str
    membership_generation: int
    own_workspace_consent: bool
    grant_required: bool
    grant_active: bool
    cross_repository: bool = False

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.TASK, self.source_task_id)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid() from exc
        _commitment(self.source_workspace_commitment)
        project_id(self.project_id)
        _positive(self.membership_generation)
        if type(self.own_workspace_consent) is not bool:
            raise _invalid()
        if type(self.grant_required) is not bool or type(self.grant_active) is not bool:
            raise _invalid()
        if type(self.cross_repository) is not bool:
            raise _invalid()

    @property
    def allowed(self) -> bool:
        if not self.own_workspace_consent:
            return False
        return not self.grant_required or self.grant_active


@dataclass(frozen=True, slots=True)
class CoordinationObligationState:
    """Per-task obligation state for one advice-first detection."""

    detection_id: str
    task_id: str
    declared: bool
    addressed: bool = False
    resolved: bool = False
    obligation_id: ObligationId | None = None

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.EVENT, self.detection_id)
            validate_id(IdKind.TASK, self.task_id)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid() from exc
        if self.obligation_id is not None:
            try:
                object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise _invalid() from exc
        elif self.declared:
            # A detector may only mint a finding for a task's own, explicitly published
            # obligation.  Keeping a declared state without that durable identity would make
            # the state indistinguishable from the old helper-only path.
            raise _invalid()
        if (
            type(self.declared) is not bool
            or type(self.addressed) is not bool
            or type(self.resolved) is not bool
        ):
            raise _invalid()
        if (self.addressed or self.resolved) and not self.declared:
            raise _invalid()
        if self.resolved and not self.addressed:
            raise _invalid()


@dataclass(frozen=True, slots=True, repr=False)
class CoordinationCoverage:
    """One bounded per-task coverage row when attributable paths are unavailable.

    This value is deliberately independent from :class:`CoordinationDetection`: an unobservable
    source is useful coverage information, but it is not evidence that two tasks overlap.  The row
    keeps only the admitted task/project generation and closed gap vocabulary, so it cannot become
    a guessed path or a synthetic pair finding.
    """

    coverage_id: str
    project_id: str
    task_id: str
    membership_generation: int
    coverage: Literal["unobservable"] = "unobservable"
    gap_code: CoordinationGapCode = CoordinationGapCode.NOT_OBSERVABLE

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.EVENT, self.coverage_id)
            validate_id(IdKind.TASK, self.task_id)
            project_id(self.project_id)
        except (TypeError, ValueError) as exc:
            raise CoordinationError(CoordinationErrorCode.INVALID) from exc
        _positive(self.membership_generation)
        if (
            self.coverage != "unobservable"
            or self.gap_code is not CoordinationGapCode.NOT_OBSERVABLE
        ):
            raise CoordinationError(CoordinationErrorCode.INVALID)

    def as_wire(self) -> JsonObject:
        return JsonObject(
            {
                "coverage_id": self.coverage_id,
                "project_id": self.project_id,
                "task_id": self.task_id,
                "membership_generation": str(self.membership_generation),
                "coverage": self.coverage,
                "gap_code": self.gap_code.value,
            }
        )


@dataclass(frozen=True, slots=True, repr=False)
class CoordinationDetection:
    """One advice-first overlap for a task pair and a bounded resource set."""

    detection_id: str
    project_id: str
    membership_generation: int
    left_task_id: str
    right_task_id: str
    overlap_kind: OverlapKind
    resource_identities: tuple[str, ...]
    counterpart_task_id: str
    advice_only: bool = True
    obligation_declared: bool = False
    addressed: bool = False
    generation_valid: bool = True
    detail_ref: ProjectTextRef | None = None
    resolved: bool = False

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.EVENT, self.detection_id)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid() from exc
        project_id(self.project_id)
        _positive(self.membership_generation)
        for value in (self.left_task_id, self.right_task_id, self.counterpart_task_id):
            try:
                validate_id(IdKind.TASK, value)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise _invalid() from exc
        if self.left_task_id == self.right_task_id:
            raise _invalid()
        if self.counterpart_task_id not in {self.left_task_id, self.right_task_id}:
            raise _invalid()
        object.__setattr__(self, "overlap_kind", _enum(self.overlap_kind, OverlapKind))
        identities = _sorted_resources(self.resource_identities)
        if not identities:
            raise _invalid()
        if type(self.advice_only) is not bool:
            raise _invalid()
        if type(self.obligation_declared) is not bool or type(self.addressed) is not bool:
            raise _invalid()
        if type(self.resolved) is not bool:
            raise _invalid()
        if type(self.generation_valid) is not bool:
            raise _invalid()
        if self.detail_ref is not None and type(self.detail_ref) is not ProjectTextRef:
            raise _invalid()
        if (self.addressed or self.resolved) and not self.obligation_declared:
            raise _invalid()
        if not self.advice_only and not self.obligation_declared:
            raise _invalid()

    @property
    def finding_eligible(self) -> bool:
        """A detector never mints a finding until a coordination obligation exists."""

        return (
            not self.advice_only
            and self.obligation_declared
            and not self.addressed
            and not self.resolved
            and self.generation_valid
        )

    def finding_eligible_for(self, obligation: object) -> bool:
        """Apply the per-task obligation gate used when one detection has two participants."""

        if not self.generation_valid or self.resolved:
            return False
        if type(obligation) is not CoordinationObligationState:
            return False
        return (
            obligation.detection_id == self.detection_id
            and obligation.task_id in {self.left_task_id, self.right_task_id}
            and obligation.declared
            and not obligation.addressed
            and not obligation.resolved
        )

    def as_wire(self) -> JsonObject:
        values: dict[str, JsonValue] = {
            "detection_id": self.detection_id,
            "project_id": self.project_id,
            "membership_generation": str(self.membership_generation),
            "left_task_id": self.left_task_id,
            "right_task_id": self.right_task_id,
            "counterpart_task_id": self.counterpart_task_id,
            "overlap_kind": self.overlap_kind.value,
            "resource_identities": cast(JsonValue, list(self.resource_identities)),
            "advice_only": self.advice_only,
            "obligation_declared": self.obligation_declared,
            "addressed": self.addressed,
            "resolved": self.resolved,
            "generation_valid": self.generation_valid,
        }
        if self.detail_ref is not None:
            values["detail_ref"] = self.detail_ref.as_wire()
        return JsonObject(values)


def _sorted_resources(values: object) -> tuple[str, ...]:
    if type(values) not in {tuple, list, set, frozenset}:
        raise _invalid()
    raw = cast(Sequence[object] | set[object] | frozenset[object], values)
    result: list[str] = []
    for value in raw:
        if type(value) is not str or not _POSIX_RESOURCE_RE.fullmatch(value):
            raise _invalid()
        if len(value.encode("utf-8")) > _MAX_RESOURCE_BYTES:
            raise _invalid()
        # Detection/advice rows are structural.  The repository-relative spelling belongs only
        # in an encrypted detail object; accepting it here would let a caller bypass that
        # boundary by constructing a value directly instead of going through the detector.
        _digest(value)
        result.append(value)
    if len(result) > _MAX_RESOURCES or len(set(result)) != len(result):
        raise _invalid()
    ordered = tuple(sorted(result, key=str.encode))
    if ordered != tuple(result) and type(values) in {tuple, list}:
        # Callers crossing the wire must provide canonical ordering.  Sets are normalized here.
        raise _invalid()
    return ordered


def relative_resource_identity(path: str) -> str:
    """Normalize one declared repository-relative resource without touching the filesystem.

    Absolute paths, drive-like prefixes, empty components, and traversal are rejected.  The
    detector deliberately does not guess a path from a workspace diff; callers must provide an
    explicit declaration or an attributable host signal.
    """

    if type(path) is not str or not path or not _POSIX_RESOURCE_RE.fullmatch(path):
        raise CoordinationError(CoordinationErrorCode.INVALID)
    candidate = path.replace("\\", "/")
    if candidate.startswith("/") or candidate.startswith("//"):
        raise CoordinationError(CoordinationErrorCode.INVALID)
    # A leading drive marker is absolute even on a POSIX service receiving a Windows declaration.
    if len(candidate) >= 2 and candidate[1] == ":":
        raise CoordinationError(CoordinationErrorCode.INVALID)
    normalized = posixpath.normpath(candidate)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise CoordinationError(CoordinationErrorCode.INVALID)
    if any(part in {"", ".", ".."} for part in candidate.split("/")):
        raise CoordinationError(CoordinationErrorCode.INVALID)
    if len(normalized.encode("utf-8")) > _MAX_RESOURCE_BYTES:
        raise CoordinationError(CoordinationErrorCode.INVALID)
    return normalized


def canonical_resource_identity(
    path: str,
    *,
    repository_commitment: str,
    case_sensitive: bool = True,
) -> str:
    """Build a repository-bound resource identity used by overlap detection.

    The returned token is a commitment, so raw path text can remain in encrypted detail objects.
    Case folding is applied only when the host explicitly reports a case-insensitive filesystem;
    no platform default is guessed.
    """

    repository = _commitment(repository_commitment)
    relative = relative_resource_identity(path)
    canonical_path = relative if case_sensitive else relative.casefold()
    return canonical_digest(
        {
            "case_sensitive": case_sensitive,
            "path": canonical_path,
            "repository_commitment": repository,
        }
    )


def classify_resource_overlap(
    *,
    left_repository_commitment: str,
    right_repository_commitment: str,
    left_workspace_commitment: str,
    right_workspace_commitment: str,
    left_resource: str,
    right_resource: str,
    case_sensitive: bool = True,
) -> OverlapKind | None:
    """Classify explicit declarations without treating unrelated repositories as overlapping."""

    if left_repository_commitment != right_repository_commitment:
        return None
    left = relative_resource_identity(left_resource)
    right = relative_resource_identity(right_resource)
    if (left if case_sensitive else left.casefold()) != (
        right if case_sensitive else right.casefold()
    ):
        return None
    if left_workspace_commitment == right_workspace_commitment:
        return OverlapKind.PHYSICAL
    return OverlapKind.INTEGRATION


def overlap_resource_identities(
    left: Iterable[str], right: Iterable[str], *, case_sensitive: bool = True
) -> tuple[str, ...]:
    """Return the canonical intersection of two declared relative-resource sets."""

    left_ids = {relative_resource_identity(value) for value in left}
    right_ids = {relative_resource_identity(value) for value in right}
    if not case_sensitive:
        folded = {value.casefold(): value for value in left_ids}
        result = [folded[value.casefold()] for value in right_ids if value.casefold() in folded]
    else:
        result = list(left_ids & right_ids)
    return tuple(sorted(set(result), key=str.encode))


def overlap_resource_commitments(
    left: Iterable[str],
    right: Iterable[str],
    *,
    repository_commitment: str,
    case_sensitive: bool = True,
) -> tuple[str, ...]:
    """Return repository-bound commitments for one explicit resource intersection.

    Resource spellings are useful only inside the encrypted detail object.  Detection, advice,
    and finding structural rows carry these commitments instead, so a catalog read cannot reveal
    a caller-controlled path while still retaining a stable identity for idempotent delivery.
    """

    overlap = overlap_resource_identities(left, right, case_sensitive=case_sensitive)
    return tuple(
        sorted(
            {
                canonical_resource_identity(
                    value,
                    repository_commitment=repository_commitment,
                    case_sensitive=case_sensitive,
                )
                for value in overlap
            },
            key=str.encode,
        )
    )


def coordination_detection_identity(
    *,
    project_id_value: str,
    membership_generation: int,
    left_task_id: str,
    right_task_id: str,
    resource_identities: Iterable[str],
    left_route_generation: int | None = None,
    right_route_generation: int | None = None,
    left_route_identity_digest: str | None = None,
    right_route_identity_digest: str | None = None,
) -> str:
    """Return one stable identity per project/task/resource and route snapshot.

    The route fields are optional for compatibility with detections written before route-bound
    identities existed.  Omitting all four fields therefore reproduces the historical identity
    exactly; supplying a complete route snapshot creates a successor identity when either task's
    route changes.  Existing opaque event ids and released wire schemas are never decoded or
    rewritten here.
    """

    project_id(project_id_value)
    generation = _positive(membership_generation)
    try:
        validate_id(IdKind.TASK, left_task_id)
        validate_id(IdKind.TASK, right_task_id)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise _invalid() from exc
    if left_task_id == right_task_id:
        raise _invalid()
    resources = _sorted_resources(tuple(resource_identities))
    if not resources:
        raise _invalid()
    route_fields = (
        left_route_generation,
        right_route_generation,
        left_route_identity_digest,
        right_route_identity_digest,
    )
    if any(value is not None for value in route_fields):
        if left_route_generation is None or right_route_generation is None:
            raise _invalid()
        try:
            left_generation = _positive(left_route_generation)
            right_generation = _positive(right_route_generation)
        except ValueError as exc:
            raise _invalid() from exc
        if (left_route_identity_digest is None) != (right_route_identity_digest is None):
            raise _invalid()
        ordered_routes = sorted(
            (
                (left_task_id, left_generation, left_route_identity_digest),
                (right_task_id, right_generation, right_route_identity_digest),
            ),
            key=lambda item: item[0].encode("ascii"),
        )
        ordered_left_task, ordered_left_generation, ordered_left_digest = ordered_routes[0]
        ordered_right_task, ordered_right_generation, ordered_right_digest = ordered_routes[1]
        identity: dict[str, JsonValue] = {
            "left_route_generation": str(ordered_left_generation),
            "left_task_id": ordered_left_task,
            "membership_generation": str(generation),
            "project_id": project_id_value,
            "resource_identities": resources,
            "right_route_generation": str(ordered_right_generation),
            "right_task_id": ordered_right_task,
        }
        if ordered_left_digest is not None and ordered_right_digest is not None:
            try:
                validate_sha256_digest(ordered_left_digest)
                validate_sha256_digest(ordered_right_digest)
            except (TypeError, ValueError) as exc:
                raise _invalid() from exc
            identity["left_route_identity_digest"] = ordered_left_digest
            identity["right_route_identity_digest"] = ordered_right_digest
    else:
        identity = {
            "left_task_id": min(left_task_id, right_task_id),
            "membership_generation": str(generation),
            "project_id": project_id_value,
            "resource_identities": resources,
            "right_task_id": max(left_task_id, right_task_id),
        }
    digest = canonical_digest(identity)
    # Status and delivery contracts identify detections as durable event ids.  Derive a UUIDv4
    # shaped id from the canonical identity digest rather than minting a random id; retries and
    # service restarts therefore converge on the same event without retaining raw resource text.
    _, hexadecimal = digest.split(":", 1)
    bits = list(hexadecimal[:32])
    bits[12] = "4"
    bits[16] = "8" if int(bits[16], 16) < 8 else "a"
    return "evt_" + str(uuid.UUID(hex="".join(bits)))


def coordination_generation_is_current(
    expected_generation: int, current_generation: int, *, grant_active: bool
) -> bool:
    """The admission predicate shared by reads and queued delivery.

    A queued item from generation N is refused as soon as the project advances to N+1, before a
    cleanup sweep has a chance to run.  ``grant_active`` is a separate bit: a matching generation
    with a revoked grant is still refused.
    """

    try:
        return (
            _positive(expected_generation) == _positive(current_generation)
            and type(grant_active) is bool
            and grant_active
        )
    except ValueError:
        return False


def general_link_conflicts(
    *,
    target_project_id: str,
    member_kind: MemberKind,
    member: str,
    other_memberships: Iterable[tuple[str, MemberKind, str]],
    provenance: Iterable[tuple[str, str | None, str | None]],
) -> bool:
    """Return whether a general-project link would give one task two general projects.

    ``other_memberships`` are active memberships of other active general projects.  Provenance
    rows are ``(task_id, repository_commitment, workspace_commitment)``.  The implicit repository
    project is not represented here.  The result carries no project titles or sibling contents.
    """

    if type(member_kind) is not MemberKind or type(member) is not str or not member:
        raise _invalid()
    rows = tuple(provenance)
    candidate = _membership_anchors(member_kind, member, rows)
    by_project: dict[str, set[tuple[str, str]]] = {}
    for project_id, kind, identity in other_memberships:
        if project_id == target_project_id or type(kind) is not MemberKind:
            continue
        by_project.setdefault(project_id, set()).update(_membership_anchors(kind, identity, rows))
    return any(candidate & anchors for anchors in by_project.values())


def provenance_spans_general_projects(
    *,
    task_id: str,
    repository_commitment: str | None,
    workspace_commitment: str | None,
    memberships: Iterable[tuple[str, MemberKind, str]],
) -> bool:
    """Return whether this task provenance matches more than one active general project."""

    if type(task_id) is not str or not task_id:
        raise _invalid()
    matched: set[str] = set()
    for project_id, kind, identity in memberships:
        if kind is MemberKind.TASK and identity == task_id:
            matched.add(project_id)
        elif (
            kind is MemberKind.REPOSITORY
            and repository_commitment is not None
            and identity == repository_commitment
        ):
            matched.add(project_id)
        elif (
            kind is MemberKind.WORKSPACE
            and workspace_commitment is not None
            and identity == workspace_commitment
        ):
            matched.add(project_id)
    return len(matched) > 1


def _membership_anchors(
    kind: MemberKind,
    member: str,
    provenance: tuple[tuple[str, str | None, str | None], ...],
) -> set[tuple[str, str]]:
    # A membership includes tasks at its declared scope, not their ancestors.
    # Expanding a direct task or workspace to its repository would make two
    # disjoint memberships conflict merely because they share that repository.
    anchors = {(kind.value, member)}
    for task_id, repository, workspace in provenance:
        if (kind is MemberKind.REPOSITORY and repository == member) or (
            kind is MemberKind.WORKSPACE and workspace == member
        ):
            anchors.add((MemberKind.TASK.value, task_id))
    return anchors


def project_structural_digest(
    value: ProjectDescriptor | ProjectMembership | CoordinationGrant,
) -> str:
    """Digest one structural object while keeping this helper private to the module."""

    return canonical_digest(cast(Mapping[str, JsonValue], value.as_wire()))
