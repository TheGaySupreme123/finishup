"""Canonical, redacted capability evidence builder for ``tests/capability/*``.

Provides one strict evidence shape and safe writer for empirical external capability
observations. It binds each outcome to exact installed bytes, platform, external version,
fixture/test revision, and a private-source digest without leaking transcripts, prompts,
payloads, secrets, or local paths.

Every value on this surface is a bounded ASCII token, an ``sha256:``-prefixed digest, a bounded
non-negative integer, a boolean, or a closed enum. There is structurally no field capable of
carrying a freeform message, an argv string with values, an environment blob, an absolute path,
a repository/user name, a prompt, source/tool output, a provider response, a credential/key, SQL,
a traceback, or a raw transcript: those kinds of content simply have no representable shape here.
Private evidence (for example a captured transcript) is encrypted outside this module; only an
opaque locator ID and its SHA-256 digest may be recorded.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Final

from finishup.domain.values import format_rfc3339_millis, validate_sha256_digest
from finishup.observability.privacy import PrivacyFenceError, assert_plaintext_safe
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "CAPABILITY_EVIDENCE_SCHEMA",
    "MAX_OBSERVATIONS",
    "MAX_REASONS",
    "MAX_RECORD_BYTES",
    "CapabilityCase",
    "CapabilityContext",
    "CapabilityEvidence",
    "CapabilityEvidenceError",
    "EvidenceOutcome",
    "EvidenceRecorder",
    "Observation",
    "bytes_digest",
    "canonical_evidence_bytes",
    "capability_evidence_output_root",
    "codex_profiles_frozen",
    "live_codex_authorized",
    "live_keyring_authorized",
    "live_provider_authorized",
    "record_and_write",
    "runtime_capability_context",
    "validate_evidence",
    "write_evidence_atomic",
]

CAPABILITY_EVIDENCE_SCHEMA: Final = "yoetz.capability-evidence/1"

MAX_OBSERVATIONS: Final = 64
MAX_REASONS: Final = 16
MAX_RECORD_BYTES: Final = 65_536

_MAX_SAFE_INTEGER: Final = 2**53 - 1

# Bounded lowercase-snake tokens: observation codes, reason/limitation codes, capability family.
_TOKEN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# Stable identifiers referencing an ADR/requirement/claim: mixed case, digits, dot, dash, underscore.
_CASE_TOKEN: Final = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
# Version/tool/platform identity tokens: no slashes, spaces, or "@"/":" repo-style separators.
_IDENTITY: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


class CapabilityEvidenceError(ValueError):
    """A bounded, traceback-free capability-evidence failure. Never echoes matched input."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _invalid(reason: str) -> CapabilityEvidenceError:
    return CapabilityEvidenceError(reason)


def _token(value: object, pattern: re.Pattern[str], reason: str) -> str:
    if type(value) is not str or "/" in value or pattern.fullmatch(value) is None:
        raise _invalid(reason)
    return value


def _digest(value: object, reason: str) -> str:
    if type(value) is not str:
        raise _invalid(reason)
    try:
        return validate_sha256_digest(value)
    except ProtocolValueError as exc:
        raise _invalid(reason) from exc


def _millis_now() -> datetime:
    """Return the current UTC instant truncated to millisecond precision.

    ``format_rfc3339_millis`` requires exact millisecond precision (no sub-millisecond
    remainder); wall-clock capture truncates rather than rounds so bounds never advance past the
    monotonic reading taken alongside them.
    """

    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def _structural_text(value: object, reason: str, *, maximum: int = 128) -> str:
    """Validate a bounded, printable-ASCII opaque identity string (spaces/colons allowed).

    Used only for values such as ``apsw.sqlite3_sourceid()`` that are trusted structural
    identities but are not themselves bounded machine tokens (they may embed spaces). Still
    rejects control characters, non-ASCII, path separators, and leading/trailing whitespace.
    """

    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or "/" in value
        or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value)
    ):
        raise _invalid(reason)
    return value


class EvidenceOutcome(str, Enum):  # noqa: UP042 - durable enum
    PASS = "pass"
    FAIL = "fail"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class CapabilityCase:
    """Stable case/requirement/claim identity and this case's closed observation vocabulary."""

    case_id: str
    requirement_id: str
    claim_id: str
    capability_family: str
    required_observation_codes: frozenset[str]
    allowed_observation_codes: frozenset[str]

    def __post_init__(self) -> None:
        _token(self.case_id, _CASE_TOKEN, "case_id_invalid")
        _token(self.requirement_id, _CASE_TOKEN, "requirement_id_invalid")
        _token(self.claim_id, _CASE_TOKEN, "claim_id_invalid")
        _token(self.capability_family, _TOKEN, "capability_family_invalid")
        if (
            type(self.required_observation_codes) is not frozenset
            or type(self.allowed_observation_codes) is not frozenset
        ):
            raise _invalid("observation_codes_must_be_frozenset")
        for code in self.required_observation_codes | self.allowed_observation_codes:
            _token(code, _TOKEN, "observation_code_invalid")
        if not self.required_observation_codes <= self.allowed_observation_codes:
            raise _invalid("required_observation_not_allowed")
        if len(self.allowed_observation_codes) > MAX_OBSERVATIONS:
            raise _invalid("allowed_observation_codes_too_many")


@dataclass(frozen=True, slots=True)
class CapabilityContext:
    """Candidate/resource/fixture/test identity plus platform/external identity.

    Every field here must come from a verified manifest or a structurally validated probe result
    (for example a parsed ``VersionManifest`` or an externally verified tool version string) —
    never arbitrary ``--version`` output pasted in as-is. Optional external fields are ``None``
    when a case does not exercise that surface (for example a filesystem-only case has no
    ``provider_id``).
    """

    artifact_digest: str
    resource_set_digest: str
    fixture_digest: str
    test_revision: str
    os_name: str
    os_version: str
    cpu_arch: str
    python_implementation: str
    python_version: str
    python_abi: str
    apsw_version: str
    sqlite_version: str
    sqlite_source_id: str
    platform_tag: str
    external_tool: str
    external_version: str
    integration_channel: str
    config_profile_digest: str
    protocol_version: str | None = None
    sdk_version: str | None = None
    provider_id: str | None = None
    key_backend: str | None = None

    def __post_init__(self) -> None:
        _digest(self.artifact_digest, "artifact_digest_invalid")
        _digest(self.resource_set_digest, "resource_set_digest_invalid")
        _digest(self.fixture_digest, "fixture_digest_invalid")
        _digest(self.test_revision, "test_revision_invalid")
        _digest(self.config_profile_digest, "config_profile_digest_invalid")
        for name, value in (
            ("os_name", self.os_name),
            ("os_version", self.os_version),
            ("cpu_arch", self.cpu_arch),
            ("python_implementation", self.python_implementation),
            ("python_version", self.python_version),
            ("python_abi", self.python_abi),
            ("apsw_version", self.apsw_version),
            ("sqlite_version", self.sqlite_version),
            ("platform_tag", self.platform_tag),
            ("external_tool", self.external_tool),
            ("external_version", self.external_version),
            ("integration_channel", self.integration_channel),
        ):
            _token(value, _IDENTITY, f"{name}_invalid")
        _structural_text(self.sqlite_source_id, "sqlite_source_id_invalid")
        for name, optional in (
            ("protocol_version", self.protocol_version),
            ("sdk_version", self.sdk_version),
            ("provider_id", self.provider_id),
            ("key_backend", self.key_backend),
        ):
            if optional is not None:
                _token(optional, _IDENTITY, f"{name}_invalid")


@dataclass(frozen=True, slots=True)
class Observation:
    """One bounded observation: a closed-vocabulary code plus exactly one typed structural value."""

    code: str
    boolean_value: bool | None = None
    integer_value: int | None = None
    digest_value: str | None = None
    enum_value: str | None = None

    def __post_init__(self) -> None:
        _token(self.code, _TOKEN, "observation_code_invalid")
        present = [
            value
            for value in (
                self.boolean_value,
                self.integer_value,
                self.digest_value,
                self.enum_value,
            )
            if value is not None
        ]
        if len(present) != 1:
            raise _invalid("observation_value_not_exclusive")
        if self.boolean_value is not None and type(self.boolean_value) is not bool:
            raise _invalid("observation_boolean_invalid")
        if self.integer_value is not None and (
            type(self.integer_value) is bool
            or type(self.integer_value) is not int
            or not 0 <= self.integer_value <= _MAX_SAFE_INTEGER
        ):
            raise _invalid("observation_integer_invalid")
        if self.digest_value is not None:
            _digest(self.digest_value, "observation_digest_invalid")
        if self.enum_value is not None:
            _token(self.enum_value, _TOKEN, "observation_enum_invalid")


def _observation_json(observation: Observation) -> dict[str, JsonValue]:
    return {
        "code": observation.code,
        "boolean_value": observation.boolean_value,
        "integer_value": observation.integer_value,
        "digest_value": observation.digest_value,
        "enum_value": observation.enum_value,
    }


def _record_document(
    case: CapabilityCase,
    context: CapabilityContext,
    observations: tuple[Observation, ...],
    outcome: EvidenceOutcome,
    reasons: tuple[str, ...],
    started_at: datetime,
    finished_at: datetime,
    duration_ms: int,
    evidence_locator_id: str | None,
    evidence_locator_digest: str | None,
) -> dict[str, JsonValue]:
    """Build the canonical evidence document, excluding the self-digest field."""

    return {
        "schema": CAPABILITY_EVIDENCE_SCHEMA,
        "case_id": case.case_id,
        "requirement_id": case.requirement_id,
        "claim_id": case.claim_id,
        "capability_family": case.capability_family,
        "artifact_digest": context.artifact_digest,
        "resource_set_digest": context.resource_set_digest,
        "fixture_digest": context.fixture_digest,
        "test_revision": context.test_revision,
        "platform": context.platform_tag,
        "os_name": context.os_name,
        "os_version": context.os_version,
        "cpu_arch": context.cpu_arch,
        "python_implementation": context.python_implementation,
        "python_version": context.python_version,
        "python_abi": context.python_abi,
        "apsw_version": context.apsw_version,
        "sqlite_version": context.sqlite_version,
        "sqlite_source_id": context.sqlite_source_id,
        "external_tool": context.external_tool,
        "external_version": context.external_version,
        "protocol_version": context.protocol_version,
        "sdk_version": context.sdk_version,
        "provider_id": context.provider_id,
        "key_backend": context.key_backend,
        "integration_channel": context.integration_channel,
        "config_profile_digest": context.config_profile_digest,
        "observations": [_observation_json(item) for item in observations],
        "outcome": outcome.value,
        "limitation_codes": list(reasons),
        "started_at": format_rfc3339_millis(started_at),
        "finished_at": format_rfc3339_millis(finished_at),
        "duration_ms": duration_ms,
        "evidence_locator_id": evidence_locator_id,
        "evidence_locator_digest": evidence_locator_digest,
    }


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    """Immutable, complete, self-digested capability evidence record."""

    case: CapabilityCase
    context: CapabilityContext
    observations: tuple[Observation, ...]
    outcome: EvidenceOutcome
    reasons: tuple[str, ...]
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    evidence_locator_id: str | None
    evidence_locator_digest: str | None
    record_digest: str

    def __post_init__(self) -> None:
        if type(self.case) is not CapabilityCase:
            raise _invalid("case_invalid")
        if type(self.context) is not CapabilityContext:
            raise _invalid("context_invalid")
        if type(self.observations) is not tuple or any(
            type(item) is not Observation for item in self.observations
        ):
            raise _invalid("observations_invalid")
        if len(self.observations) > MAX_OBSERVATIONS:
            raise _invalid("observations_too_many")
        codes = tuple(item.code for item in self.observations)
        if len(set(codes)) != len(codes):
            raise _invalid("observation_codes_duplicate")
        if tuple(sorted(codes, key=str.encode)) != codes:
            raise _invalid("observations_not_canonically_ordered")
        if not set(codes) <= self.case.allowed_observation_codes:
            raise _invalid("observation_code_not_allowed")
        if type(self.outcome) is not EvidenceOutcome:
            raise _invalid("outcome_invalid")
        if type(self.reasons) is not tuple or any(type(item) is not str for item in self.reasons):
            raise _invalid("reasons_invalid")
        if len(self.reasons) > MAX_REASONS:
            raise _invalid("reasons_too_many")
        for reason in self.reasons:
            _token(reason, _TOKEN, "reason_invalid")
        if len(set(self.reasons)) != len(self.reasons):
            raise _invalid("reasons_duplicate")
        if tuple(sorted(self.reasons, key=str.encode)) != self.reasons:
            raise _invalid("reasons_not_canonically_ordered")
        if self.outcome is EvidenceOutcome.PASS:
            if self.reasons:
                raise _invalid("pass_outcome_forbids_reasons")
            if not self.case.required_observation_codes <= set(codes):
                raise _invalid("pass_missing_required_observation")
        elif not self.reasons:
            raise _invalid("non_pass_outcome_requires_reason")
        if type(self.started_at) is not datetime or type(self.finished_at) is not datetime:
            raise _invalid("timestamp_invalid")
        try:
            format_rfc3339_millis(self.started_at)
            format_rfc3339_millis(self.finished_at)
        except ProtocolValueError as exc:
            raise _invalid("timestamp_invalid") from exc
        if self.finished_at < self.started_at:
            raise _invalid("clock_skew_detected")
        if (
            type(self.duration_ms) is bool
            or type(self.duration_ms) is not int
            or not 0 <= self.duration_ms <= _MAX_SAFE_INTEGER
        ):
            raise _invalid("duration_invalid")
        if (self.evidence_locator_id is None) != (self.evidence_locator_digest is None):
            raise _invalid("evidence_locator_incomplete")
        if self.evidence_locator_id is not None:
            _token(self.evidence_locator_id, _IDENTITY, "evidence_locator_id_invalid")
        if self.evidence_locator_digest is not None:
            _digest(self.evidence_locator_digest, "evidence_locator_digest_invalid")
        _digest(self.record_digest, "record_digest_invalid")
        _validate_digest_and_scan(self)


def _validate_digest_and_scan(record: CapabilityEvidence) -> None:
    document = _record_document(
        record.case,
        record.context,
        record.observations,
        record.outcome,
        record.reasons,
        record.started_at,
        record.finished_at,
        record.duration_ms,
        record.evidence_locator_id,
        record.evidence_locator_digest,
    )
    if canonical_digest(document) != record.record_digest:
        raise _invalid("record_digest_mismatch")
    document["record_digest"] = record.record_digest
    full_bytes = canonical_encode(document)
    if len(full_bytes) > MAX_RECORD_BYTES:
        raise _invalid("record_too_large")
    try:
        assert_plaintext_safe(full_bytes, "capability_evidence")
    except PrivacyFenceError as exc:
        raise _invalid("record_sanitization_failed") from exc


def validate_evidence(record: CapabilityEvidence) -> None:
    """Re-validate a complete record: self-digest consistency, size cap, and content fence."""

    if type(record) is not CapabilityEvidence:
        raise _invalid("record_invalid")
    _validate_digest_and_scan(record)


def canonical_evidence_bytes(record: CapabilityEvidence) -> bytes:
    """Render the exact canonical bytes to persist for one complete evidence record."""

    if type(record) is not CapabilityEvidence:
        raise _invalid("record_invalid")
    document = _record_document(
        record.case,
        record.context,
        record.observations,
        record.outcome,
        record.reasons,
        record.started_at,
        record.finished_at,
        record.duration_ms,
        record.evidence_locator_id,
        record.evidence_locator_digest,
    )
    document["record_digest"] = record.record_digest
    return canonical_encode(document)


class EvidenceRecorder:
    """One-shot capability-case recorder: ``begin`` once, ``observe`` any number of times, ``finish`` once.

    A recorder that raises during ``observe``/``finish``, or that is simply never finished,
    produces no ``CapabilityEvidence`` at all — there is no implicit downgrade to
    ``inconclusive`` or ``pass``.
    """

    __slots__ = (
        "_case",
        "_context",
        "_finished",
        "_observations",
        "_seen_codes",
        "_started_at",
        "_started_monotonic",
    )

    def __init__(self, case: CapabilityCase, context: CapabilityContext) -> None:
        if type(case) is not CapabilityCase:
            raise _invalid("case_invalid")
        if type(context) is not CapabilityContext:
            raise _invalid("context_invalid")
        self._case = case
        self._context = context
        self._observations: list[Observation] = []
        self._seen_codes: set[str] = set()
        self._started_monotonic = time.monotonic()
        self._started_at = _millis_now()
        self._finished = False

    @classmethod
    def begin(cls, case: CapabilityCase, context: CapabilityContext) -> EvidenceRecorder:
        """Start recording one capability case under its fixed identity and context."""

        return cls(case, context)

    def observe(self, observation: Observation) -> EvidenceRecorder:
        """Record one observation. Its code must be in this case's allowed vocabulary, once each."""

        if self._finished:
            raise _invalid("recorder_already_finished")
        if type(observation) is not Observation:
            raise _invalid("observation_invalid")
        if observation.code not in self._case.allowed_observation_codes:
            raise _invalid("observation_code_not_allowed")
        if observation.code in self._seen_codes:
            raise _invalid("observation_code_duplicate")
        if len(self._observations) >= MAX_OBSERVATIONS:
            raise _invalid("observations_too_many")
        self._seen_codes.add(observation.code)
        self._observations.append(observation)
        return self

    def finish(
        self,
        outcome: EvidenceOutcome,
        reasons: Sequence[str] = (),
        *,
        evidence_locator_id: str | None = None,
        evidence_locator_digest: str | None = None,
    ) -> CapabilityEvidence:
        """Close out the case and return one immutable, self-digested evidence record."""

        if self._finished:
            raise _invalid("recorder_already_finished")
        if type(outcome) is not EvidenceOutcome:
            raise _invalid("outcome_invalid")
        if type(reasons) not in {tuple, list}:
            raise _invalid("reasons_invalid")
        reason_tuple = tuple(reasons)
        if any(type(item) is not str for item in reason_tuple):
            raise _invalid("reasons_invalid")
        for reason in reason_tuple:
            _token(reason, _TOKEN, "reason_invalid")
        if len(set(reason_tuple)) != len(reason_tuple):
            raise _invalid("reasons_duplicate")
        if len(reason_tuple) > MAX_REASONS:
            raise _invalid("reasons_too_many")
        ordered_reasons = tuple(sorted(reason_tuple, key=str.encode))

        observations = tuple(sorted(self._observations, key=lambda item: item.code.encode()))
        codes = frozenset(item.code for item in observations)

        if outcome is EvidenceOutcome.PASS:
            if ordered_reasons:
                raise _invalid("pass_outcome_forbids_reasons")
            if not self._case.required_observation_codes <= codes:
                raise _invalid("pass_missing_required_observation")
        elif not ordered_reasons:
            raise _invalid("non_pass_outcome_requires_reason")

        if (evidence_locator_id is None) != (evidence_locator_digest is None):
            raise _invalid("evidence_locator_incomplete")
        if evidence_locator_id is not None:
            _token(evidence_locator_id, _IDENTITY, "evidence_locator_id_invalid")
        if evidence_locator_digest is not None:
            _digest(evidence_locator_digest, "evidence_locator_digest_invalid")

        monotonic_elapsed = time.monotonic() - self._started_monotonic
        finished_at = _millis_now()
        if finished_at < self._started_at:
            raise _invalid("clock_skew_detected")
        duration_ms = max(0, round(monotonic_elapsed * 1000))

        document = _record_document(
            self._case,
            self._context,
            observations,
            outcome,
            ordered_reasons,
            self._started_at,
            finished_at,
            duration_ms,
            evidence_locator_id,
            evidence_locator_digest,
        )
        record_digest = canonical_digest(document)

        evidence = CapabilityEvidence(
            case=self._case,
            context=self._context,
            observations=observations,
            outcome=outcome,
            reasons=ordered_reasons,
            started_at=self._started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            evidence_locator_id=evidence_locator_id,
            evidence_locator_digest=evidence_locator_digest,
            record_digest=record_digest,
        )
        self._finished = True
        return evidence


def write_evidence_atomic(record: CapabilityEvidence, output_root: Path) -> Path:
    """Atomically publish one canonical evidence record under ``output_root``.

    The destination filename is the ASCII ``<case_id>__<digest_hex>.json``. Writing identical
    bytes at the same identity is idempotent; writing different bytes at the same identity fails
    rather than overwriting. The directory and staged file are non-symlink and owner-only.
    """

    validate_evidence(record)
    encoded = canonical_evidence_bytes(record)

    root = Path(output_root)
    if root.is_symlink():
        raise _invalid("output_root_is_symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)

    digest_hex = record.record_digest.removeprefix("sha256:")
    final_path = root / f"{record.case.case_id}__{digest_hex}.json"

    if final_path.is_symlink():
        raise _invalid("evidence_path_is_symlink")
    if final_path.exists():
        if final_path.read_bytes() == encoded:
            return final_path
        raise _invalid("evidence_identity_conflict")

    fd, tmp_name = tempfile.mkstemp(dir=str(root), prefix=".evidence-", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp_path, final_path)
        except FileExistsError:
            if final_path.read_bytes() != encoded:
                raise _invalid("evidence_identity_conflict") from None
        else:
            dir_fd = os.open(str(root), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)

    return final_path


def bytes_digest(data: bytes) -> str:
    """Return a ``sha256:`` digest over exact bytes without echoing content."""

    if type(data) is not bytes:
        raise _invalid("digest_input_invalid")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def live_codex_authorized() -> bool:
    """Return True only when the release/capability job explicitly opts into live Codex."""

    return os.environ.get("FINISHUP_LIVE_CODEX") == "1"


def live_provider_authorized() -> bool:
    """Return True only when the approved live-provider capability job opts in."""

    return os.environ.get("FINISHUP_LIVE_PROVIDER", "").strip().lower() in {"1", "true", "yes"}


def live_keyring_authorized() -> bool:
    """Return True only when the approved live OS-keyring capability job opts in."""

    return os.environ.get("FINISHUP_LIVE_KEYRING", "").strip().lower() in {"1", "true", "yes"}


def codex_profiles_frozen() -> bool:
    """Return True when runtime-support has at least one reviewed Codex capability profile."""

    from typing import cast

    from finishup.protocol.canonical import strict_json_parse
    from finishup.version import read_verified_resource

    support = strict_json_parse(read_verified_resource("support/runtime-support.json"))
    if type(support) is not dict:
        return False
    profiles = cast(dict[object, object], support).get("codex_profiles")
    return isinstance(profiles, list) and len(cast(list[object], profiles)) > 0


def capability_evidence_output_root(tmp_path: Path) -> Path:
    """Return the directory that should receive public capability evidence for this run.

    When ``FINISHUP_CAPABILITY_EVIDENCE_DIR`` is set (capability CI), write durable evidence there so
    ``generate_capability_matrix.py`` can aggregate it. Otherwise use an isolated temp directory.
    """

    configured = os.environ.get("FINISHUP_CAPABILITY_EVIDENCE_DIR", "").strip()
    if configured:
        root = Path(configured)
        if root.is_symlink():
            raise _invalid("output_root_is_symlink")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        return root
    evidence_root = Path(tmp_path) / "evidence"
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    return evidence_root


def runtime_capability_context(
    *,
    fixture_digest: str,
    test_revision: str,
    config_profile_digest: str,
    external_tool: str,
    external_version: str,
    integration_channel: str,
    protocol_version: str | None = None,
    sdk_version: str | None = None,
    provider_id: str | None = None,
    key_backend: str | None = None,
) -> CapabilityContext:
    """Build a ``CapabilityContext`` from the installed version/runtime probes.

    Digests and identities come from ``build_version_manifest`` / verified resources — never from
    freeform ``--version`` paste. Development builds bind ``artifact_digest`` to the package and
    resource identity rather than a release wheel digest.

    When ``FINISHUP_CANDIDATE_ARTIFACT_DIGEST`` is set (capability CI), that exact candidate digest
    replaces the development package identity so matrix aggregation can bind evidence to the
    prepared candidate without inventing support.
    """

    from finishup.protocol.canonical import canonical_digest
    from finishup.version import build_version_manifest

    manifest = build_version_manifest()
    apsw = manifest.apsw_version
    sqlite = manifest.sqlite_version
    sqlite_source = manifest.sqlite_source_id
    if apsw.get("status") != "present" or sqlite.get("status") != "present":
        raise _invalid("runtime_identity_absent")
    if sqlite_source.get("status") != "present":
        raise _invalid("sqlite_source_absent")
    apsw_version = apsw["version"]
    sqlite_version = sqlite["version"]
    source_id = sqlite_source["source_id"]
    if (
        type(apsw_version) is not str
        or type(sqlite_version) is not str
        or type(source_id) is not str
    ):
        raise _invalid("runtime_identity_invalid")

    candidate_override = os.environ.get("FINISHUP_CANDIDATE_ARTIFACT_DIGEST", "").strip()
    if candidate_override:
        artifact_digest = _digest(candidate_override, "artifact_digest_invalid")
    else:
        artifact_digest = canonical_digest(
            {
                "build_identity": manifest.build_identity,
                "package_version": manifest.package_version,
                "resource_manifest_digest": manifest.resource_manifest_digest,
                "support_status": manifest.support_status,
            }
        )
    mcp = manifest.mcp_sdk_version
    resolved_sdk = sdk_version
    if resolved_sdk is None and mcp.get("status") == "present":
        version = mcp.get("version")
        if type(version) is str:
            resolved_sdk = version

    return CapabilityContext(
        artifact_digest=artifact_digest,
        resource_set_digest=manifest.resource_manifest_digest,
        fixture_digest=fixture_digest,
        test_revision=test_revision,
        os_name=manifest.os_name,
        os_version=manifest.os_version.split("-", 1)[0][:64],
        cpu_arch=manifest.machine,
        python_implementation=manifest.python_implementation,
        python_version=manifest.python_version,
        python_abi=manifest.python_abi.replace("-", "_")[:64],
        apsw_version=apsw_version,
        sqlite_version=sqlite_version,
        sqlite_source_id=source_id,
        platform_tag=manifest.platform_tag.replace(".", "_")[:64],
        external_tool=external_tool,
        external_version=external_version,
        integration_channel=integration_channel,
        config_profile_digest=config_profile_digest,
        protocol_version=protocol_version,
        sdk_version=resolved_sdk,
        provider_id=provider_id,
        key_backend=key_backend,
    )


def record_and_write(
    case: CapabilityCase,
    context: CapabilityContext,
    observations: Sequence[Observation],
    outcome: EvidenceOutcome,
    reasons: Sequence[str] = (),
    *,
    output_root: Path,
    evidence_locator_id: str | None = None,
    evidence_locator_digest: str | None = None,
) -> CapabilityEvidence:
    """Record one complete case and atomically publish its public evidence bytes."""

    recorder = EvidenceRecorder.begin(case, context)
    for observation in observations:
        recorder.observe(observation)
    evidence = recorder.finish(
        outcome,
        reasons,
        evidence_locator_id=evidence_locator_id,
        evidence_locator_digest=evidence_locator_digest,
    )
    write_evidence_atomic(evidence, output_root)
    return evidence
