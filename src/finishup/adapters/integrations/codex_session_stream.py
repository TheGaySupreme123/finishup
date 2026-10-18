"""Incremental Codex session-stream observer (selective secondary source)."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import shlex
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, cast

from finishup.adapters.importers.codex_jsonl import (
    CodexCapabilityProfile,
    CodexParsedRecord,
)
from finishup.adapters.importers.codex_rollout_jsonl import (
    ROLLOUT_MAX_LINE_BYTES,
    SUPPORTED_ROLLOUT_PROFILES,
    parse_codex_rollout_jsonl_from_offset,
    profile_for_rollout_id,
    profile_for_rollout_version,
    rollout_admission_provenance,
)
from finishup.adapters.integrations.codex_lifecycle import load_mapping
from finishup.adapters.integrations.observation_admission import (
    AdmissionPlan,
    build_routine_read_summary,
)
from finishup.adapters.integrations.observation_local import (
    FINISHUP_TOOL_NAMES,
    MAX_PENDING_ROLLOUT_ITEMS,
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
    PendingRolloutItem,
    self_observation_deliverable,
)
from finishup.domain.command_segments import command_segment_commitments
from finishup.domain.finishup_tools import FINISHUP_SCOPED_TOOL_PREFIXES, finishup_tool_spelling
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
    normalize_observed_command,
    observed_command_commitment,
    stream_line_commitment,
)
from finishup.domain.observation_budget import ObservationMode
from finishup.domain.observation_selection import (
    OBSERVATION_CLASSIFICATION_VERSION,
    SHELL_TOOLS,
    ObservationClassification,
    ObservationContentRole,
    classify_observation,
    compound_verification_gap_required,
    native_command_runner_class,
    without_routine_read,
)
from finishup.domain.shell_writes import heredoc_patch_paths, shell_write_scope
from finishup.domain.values import JsonObject, JsonValue, Timestamp, timestamp_from_datetime
from finishup.domain.write_scope import (
    NON_COUNTING_WRITE_SCOPES,
    STALE_EXEMPT_WRITE_SCOPES,
    classify_write_path,
    edit_write_scope,
)
from finishup.ports.importer import ImportLineStatus
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "STREAM_ADMISSION_STATES",
    "CodexChildRolloutHeader",
    "CodexChildRolloutHeaderResult",
    "CodexSessionStreamLocator",
    "HELD_ROLLOUT_CHECK_RELEASE_SECONDS",
    "PERIODIC_RECONCILE_SECONDS",
    "SessionStreamAdvance",
    "SessionStreamReader",
    "default_stream_profile",
    "envelope_from_stream_record",
    "read_codex_child_rollout_header",
    "reconcile_session_stream",
    "reconcile_session_stream_path",
    "release_held_rollout_items_for_check",
    "rollout_filename_matches_token",
    "resolve_codex_home",
    "should_trigger_stream_reconcile",
    "stream_admission",
    "stream_profile_from_id",
    "structural_from_stream_record",
]

# Closed stream-admission states (issue #656). ``structurally_supported`` is an exact certified
# profile with every read line understood; ``partially_understood`` is the compatibility profile
# or any admitted profile with unknown/incompatible lines; ``incompatible`` is a refused header
# or a surface the hook pass cannot read; ``unadmitted`` is a stream whose header has not been
# read yet. None of these is host support: parser admission certifies nothing about hooks or MCP.
STREAM_ADMISSION_STATES: Final = (
    "incompatible",
    "partially_understood",
    "structurally_supported",
    "unadmitted",
)
# Closed per-line reason tokens the reader surfaces beside the admission state so a partial
# stream names the affected family (wrapper vs. nested item vs. shape) without echoing the
# unknown type text itself.
_ADMISSION_REASON_TOKENS: Final = frozenset(
    {
        "json_profile_unsupported",
        "line_oversized",
        "malformed_line",
        "truncated_final_line",
        "unknown_item_type",
        "unknown_wrapper_type",
        "unsupported_codex_profile",
        "wrapper_shape_unsupported",
    }
)

_MAX_READ_CHUNK: Final = 262_144
_EMPTY_COMMITMENT: Final = "hmac-sha256:" + ("0" * 64)
_MAX_SESSION_WALK: Final = 4_096
_MAX_CANONICAL_INTEGER: Final = (1 << 53) - 1
PERIODIC_RECONCILE_SECONDS: Final = 30.0
_MATERIAL_HOOK_EVENTS: Final = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PermissionRequest",
        "PreCompact",
        "PostCompact",
        "Stop",
        "SessionEnd",
        "SessionStart",
        "SubagentStart",
        "SubagentStop",
    }
)
_SUBAGENT_ACTIVITY_START_KINDS: Final = frozenset({"start", "started"})
_SUBAGENT_ACTIVITY_STOP_KINDS: Final = frozenset(
    {"cancelled", "completed", "failed", "interrupted", "stop", "stopped"}
)
# Known activity kinds that are neither a start nor a stop. Codex 0.153.4 multi-agent v2 reports
# every parent/child exchange after the spawn as ``interacted`` (issue #754, fixture IMP-015):
# it names no lifecycle transition, so it carries no phase and never opens or closes an
# annotation — but it is an understood kind, not an ``unsupported_event`` coverage gap.
_SUBAGENT_ACTIVITY_PROGRESS_KINDS: Final = frozenset({"interacted"})
_SUBAGENT_ACTIVITY_KINDS: Final = (
    _SUBAGENT_ACTIVITY_START_KINDS
    | _SUBAGENT_ACTIVITY_STOP_KINDS
    | _SUBAGENT_ACTIVITY_PROGRESS_KINDS
)
# Codex 0.153.4 multi-agent v2 identifies a delegated child in the child rollout's own
# ``session_meta`` header rather than in a parent ``SubAgentActivity`` item: ``thread_source`` is
# ``subagent``, ``id`` is the child thread, and ``parent_thread_id`` names the spawning thread
# (``session_id`` is the parent thread there, so it is never the child key). The header is the
# child's own start signal; the parent task it belongs to is resolved from admitted catalog
# lineage, never from these host tokens.
_SUBAGENT_THREAD_SOURCE: Final = "subagent"
# Codex 0.150.1+ rollouts record a finished host tool call as ``event_msg`` whose payload is
# ``item_completed`` and whose ``item.type`` names the tool family (issue #910, recorded 0.157.1
# shape in ``observations/codex-post-tool-outcomes-0.157.1.case.json``). ``status`` and
# ``exit_code`` on that item are the host's closed outcome facts. A command or patch item names no
# tool, so it is recorded under its item family in the ``codex exec --json`` spelling; an MCP item
# keeps its ``server`` and is named as its hook names it, ``mcp__<server>__<tool>`` (#1038).
_STREAM_COMPLETED_PAYLOAD: Final = "item_completed"
_STREAM_TOOL_ITEM_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {"CommandExecution": "command_execution", "FileChange": "file_change"}
)
_STREAM_COMPLETED_TOOL_ITEMS: Final = frozenset({"CommandExecution", "FileChange", "McpToolCall"})
# The response-item rows that pair a call with its output on their shared ``call_id`` (#1038).
_STREAM_CALL_PAIR_ITEMS: Final = frozenset(
    {"function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output"}
)


_JSONL_SUFFIXES: Final = (".jsonl", ".jsonl.zst")


def rollout_filename_matches_token(filename: str | Path, token: str) -> bool:
    """Return whether *token* occupies an admitted rollout filename slot.

    Codex rollout names end in ``-<session>`` or ``-<session>_<rollout>`` before
    the JSONL suffix. A raw substring is insufficient because one valid opaque
    id may prefix another (or occur in the timestamp).
    """

    if type(token) is not str or _token(token) is None:
        return False
    try:
        name = Path(filename).name
    except TypeError, ValueError:
        return False
    lower_name = name.lower()
    for suffix in _JSONL_SUFFIXES:
        if not lower_name.endswith(suffix):
            continue
        stem = name[: -len(suffix)]
        return stem == token or stem.endswith(f"-{token}") or f"-{token}_" in stem
    return False


# Union vocabularies are only a fallback for callers that map a record without naming the
# profile that admitted it; the reader always passes the exact admitted profile.
_ROLLOUT_ITEM_TYPES: Final = frozenset(
    item for profile in SUPPORTED_ROLLOUT_PROFILES.values() for item in profile.item_types
)
_ROLLOUT_WRAPPER_TYPES: Final = frozenset(
    wrapper for profile in SUPPORTED_ROLLOUT_PROFILES.values() for wrapper in profile.wrapper_types
)
# Frozen legacy identifier (ADR-048): the persisted oversized-line continuation marker.
_OVERSIZED_PARTIAL_PREFIX: Final = b"\x00yoetz-oversized-line/v1\x00"
_OVERSIZED_PARTIAL_DOMAIN: Final = b"yoetz/observation-stream-oversized-state/v1\x00"
_OVERSIZED_LINE_DOMAIN: Final = b"yoetz/observation-stream-oversized-line/v1\x00"
# The local stream call map predates selection and stores only tool names.  A
# candidate marker is kept in the same generation-fenced map so a shell call
# classified from its pre-event arguments can be paired with a later output
# without persisting the command itself.  The separator cannot occur in a
# token accepted by this adapter and is decoded before the value reaches an
# observation envelope.
_CALL_SELECTION_SEPARATOR: Final = "\x1f"
_CALL_SELECTION_MARKER: Final = "routine"
_ROUTINE_OUTCOME_FAILURE_REASONS: Final = frozenset(
    {"failure", "denied", "cancelled", "partial", "unknown"}
)
_OBSERVATION_GAP_CODES: Final = frozenset(code.value for code in ObservationGapCode)


@dataclass(frozen=True, slots=True)
class _OversizedLineState:
    line_start: int
    prefix_digest: str


def _encode_oversized_partial(
    *,
    line_start: int,
    prefix_commitment: str,
    session_commitment: str,
    source_generation: int,
    source_identity: str,
    key_material: bytes,
) -> bytes:
    digest = prefix_commitment.removeprefix("hmac-sha256:")
    if (
        type(line_start) is not int
        or line_start < 0
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise ValueError("session_stream_partial_invalid")
    body = f"{line_start}:{digest}".encode("ascii")
    context = (
        session_commitment.encode("ascii")
        + b"\x00"
        + str(source_generation).encode("ascii")
        + b"\x00"
        + source_identity.encode("ascii")
        + b"\x00"
        + body
    )
    tag = hmac.new(key_material, _OVERSIZED_PARTIAL_DOMAIN + context, hashlib.sha256).hexdigest()
    return _OVERSIZED_PARTIAL_PREFIX + tag.encode("ascii") + b":" + body


def _decode_oversized_partial(
    value: bytes,
    *,
    session_commitment: str,
    source_generation: int,
    source_identity: str,
    key_material: bytes,
) -> _OversizedLineState | None:
    if not value.startswith(_OVERSIZED_PARTIAL_PREFIX):
        return None
    try:
        tag, line_start_raw, prefix_digest_raw = value[len(_OVERSIZED_PARTIAL_PREFIX) :].split(b":")
        line_start = int(line_start_raw.decode("ascii"))
        prefix_digest = prefix_digest_raw.decode("ascii")
    except UnicodeError, ValueError:
        raise ValueError("session_stream_partial_invalid") from None
    body = line_start_raw + b":" + prefix_digest_raw
    context = (
        session_commitment.encode("ascii")
        + b"\x00"
        + str(source_generation).encode("ascii")
        + b"\x00"
        + source_identity.encode("ascii")
        + b"\x00"
        + body
    )
    expected_tag = (
        hmac.new(key_material, _OVERSIZED_PARTIAL_DOMAIN + context, hashlib.sha256)
        .hexdigest()
        .encode("ascii")
    )
    if (
        line_start < 0
        or line_start_raw != str(line_start).encode("ascii")
        or len(prefix_digest) != 64
        or any(char not in "0123456789abcdef" for char in prefix_digest)
        or not hmac.compare_digest(tag, expected_tag)
    ):
        raise ValueError("session_stream_partial_invalid")
    return _OversizedLineState(line_start, prefix_digest)


def _oversized_line_commitment(
    *,
    state: _OversizedLineState,
    byte_end: int,
    session_commitment: str,
    source_generation: int,
    source_identity: str,
    key_material: bytes,
) -> str:
    body = (
        session_commitment.encode("ascii")
        + b"\x00"
        + str(source_generation).encode("ascii")
        + b"\x00"
        + source_identity.encode("ascii")
        + b"\x00"
        + f"{state.line_start}:{byte_end}:{state.prefix_digest}".encode("ascii")
    )
    digest = hmac.new(key_material, _OVERSIZED_LINE_DOMAIN + body, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def default_stream_profile() -> CodexCapabilityProfile:
    """Return the baseline rollout profile.

    Session-stream reconciliation does not parse under this profile by default: the exact
    ``cli_version`` in each stream's session header selects the admitted profile, and the reader
    remembers that selection per source generation. The baseline exists for callers and tests
    that need one concrete supported profile.
    """

    try:
        return profile_for_rollout_version("0.148.0")
    except ValueError:
        return next(iter(SUPPORTED_ROLLOUT_PROFILES.values()))


def stream_profile_from_id(profile_id: str | None) -> CodexCapabilityProfile | None:
    """Resolve a persisted profile id (exact or compatible); unknown ids resolve to ``None``."""

    if profile_id is None:
        return None
    try:
        return profile_for_rollout_id(profile_id)
    except ValueError:
        return None


def _now() -> Timestamp:
    current = datetime.now(UTC)
    stamp = current.replace(microsecond=(current.microsecond // 1000) * 1000)
    return timestamp_from_datetime(stamp)


def _source_file_identity(facts: os.stat_result, key_material: bytes) -> str:
    """Return a private, path-free identity for one opened stream generation."""

    def bounded(value: int) -> int | str:
        if -_MAX_CANONICAL_INTEGER <= value <= _MAX_CANONICAL_INTEGER:
            return value
        return f"hex:{value:x}"

    payload = canonical_encode(
        JsonObject(
            {
                "device": bounded(facts.st_dev),
                "inode": bounded(facts.st_ino),
            }
        )
    )
    return "hmac-sha256:" + hmac.new(key_material, payload, hashlib.sha256).hexdigest()


def _token(value: object) -> str | None:
    if type(value) is not str or not value or len(value) > 128:
        return None
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/+-"
    if any(ch not in allowed for ch in value) or value[0] in "._:/+-":
        return None
    return value


def _consistent_alias_token(
    body: Mapping[str, JsonValue], names: tuple[str, ...]
) -> tuple[str | None, bool]:
    """Return one bounded alias value only when every supplied spelling agrees."""

    values: list[str] = []
    supplied = False
    for name in names:
        if name not in body:
            continue
        supplied = True
        raw = body.get(name)
        if raw is None:
            continue
        token = _token(raw)
        if token is None:
            return None, supplied
        values.append(token)
    if any(value != values[0] for value in values[1:]):
        return None, supplied
    return (values[0] if values else None), supplied


def resolve_codex_home(
    explicit: Path | str | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the selected owner-private Codex home for a bound local inspection."""

    if explicit is not None:
        return Path(explicit).expanduser()
    environ = os.environ if env is None else env
    for key in ("CODEX_HOME", "CODEX_TESTING_HOME"):
        raw = environ.get(key)
        if type(raw) is str and raw.strip():
            return Path(raw).expanduser()
    return Path.home() / ".codex"


@dataclass(frozen=True, slots=True, repr=False)
class CodexSessionStreamLocator:
    """Locate a Codex session JSONL path under one selected Codex home.

    Resolved paths are for local use only: never persist or emit them.
    """

    codex_home: Path

    def __repr__(self) -> str:
        return "CodexSessionStreamLocator(codex_home=<redacted>)"

    @property
    def session_root(self) -> Path:
        return self.codex_home / "sessions"

    def resolve(
        self,
        *,
        session_id: str,
        hook_provided_path: str | None = None,
    ) -> Path | None:
        """Return a validated session file or ``None`` when unsafe/ambiguous/absent."""

        token = _token(session_id)
        if token is None:
            return None
        home = self._validated_home()
        if home is None:
            return None
        if hook_provided_path is not None:
            candidate = self._validate_candidate(
                Path(hook_provided_path), home=home, session_id=token
            )
            if candidate is None:
                return None
            if candidate.name.lower().endswith(".jsonl.zst"):
                uncompressed = self._validate_candidate(
                    candidate.with_suffix(""), home=home, session_id=token
                )
                if uncompressed is not None:
                    return uncompressed
            return candidate
        return self._exact_session_match(home=home, session_id=token)

    def _validated_home(self) -> Path | None:
        try:
            home = self.codex_home.expanduser()
            if home.is_symlink() or not home.is_dir():
                return None
            resolved = home.resolve(strict=True)
        except OSError:
            return None
        if not self._owner_safe(resolved):
            return None
        return resolved

    def _exact_session_match(self, *, home: Path, session_id: str) -> Path | None:
        root = home / "sessions"
        try:
            if root.is_symlink() or not root.is_dir():
                return None
            root_resolved = root.resolve(strict=True)
        except OSError:
            return None
        if not self._is_beneath(root_resolved, home):
            return None
        uncompressed_matches: list[Path] = []
        compressed_matches: list[Path] = []
        walked = 0
        try:
            for dirpath, dirnames, filenames in os.walk(root_resolved, followlinks=False):
                walked += 1
                if walked > _MAX_SESSION_WALK:
                    return None
                # Never descend through symlinked directories.
                dirnames[:] = [name for name in dirnames if not (Path(dirpath) / name).is_symlink()]
                for name in filenames:
                    if not rollout_filename_matches_token(name, session_id):
                        continue
                    candidate = Path(dirpath) / name
                    validated = self._validate_candidate(
                        candidate, home=home, session_id=session_id
                    )
                    if validated is not None:
                        target = (
                            compressed_matches
                            if validated.name.lower().endswith(".jsonl.zst")
                            else uncompressed_matches
                        )
                        target.append(validated)
        except OSError:
            return None
        if len(uncompressed_matches) == 1:
            return uncompressed_matches[0]
        if uncompressed_matches or len(compressed_matches) != 1:
            return None
        return compressed_matches[0]

    def resolve_child_rollout(
        self,
        hook_provided_path: str | None,
        *,
        child_thread_id: str | None = None,
    ) -> tuple[Path | None, CodexChildRolloutHeaderResult]:
        """Resolve a delegated child's own v2 rollout and read its header.

        Codex multi-agent v2 gives every thread of one delegation tree the root ``session_id``,
        so a child's callback names a rollout that the session-id filename rule above can never
        select. The child's own thread id is the rollout filename token instead: a path selects a
        child rollout only when it is a safe owner-private ``.jsonl`` beneath this home's
        ``sessions`` root, its first line is a delegated-child header, and its filename carries
        that header's child thread. ``child_thread_id``, when supplied, must be that thread; with
        no path it selects the unique rollout named by it. The path stays local-only.
        """

        expected = None if child_thread_id is None else _token(child_thread_id)
        if child_thread_id is not None and expected is None:
            return None, _CHILD_HEADER_UNREADABLE
        home = self._validated_home()
        if home is None:
            return None, _CHILD_HEADER_UNREADABLE
        if hook_provided_path is not None:
            candidate = self._validate_location(Path(hook_provided_path), home=home)
        elif expected is not None:
            candidate = self._exact_session_match(home=home, session_id=expected)
        else:
            candidate = None
        if candidate is None or candidate.name.lower().endswith(".jsonl.zst"):
            return None, _CHILD_HEADER_UNREADABLE
        result = read_codex_child_rollout_header(candidate)
        header = result.header
        if header is None:
            return None, result
        if not rollout_filename_matches_token(candidate.name, header.child_thread_id) or (
            expected is not None and header.child_thread_id != expected
        ):
            # A header copied under another thread's filename, or a different child than the
            # caller named, proves nothing about the rollout that was asked for.
            return None, _CHILD_HEADER_UNREADABLE
        return candidate, result

    def _validate_location(self, candidate: Path, *, home: Path) -> Path | None:
        """Return a safe owner-private regular file beneath this home's ``sessions`` root."""

        try:
            if candidate.is_symlink() or not candidate.is_file():
                return None
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None
        if not self._is_beneath(resolved, home / "sessions"):
            return None
        if not self._is_beneath(resolved, home):
            return None
        if not self._owner_safe(resolved):
            return None
        lower_name = resolved.name.lower()
        if not any(lower_name.endswith(suffix) for suffix in _JSONL_SUFFIXES):
            return None
        return resolved

    def _validate_candidate(self, candidate: Path, *, home: Path, session_id: str) -> Path | None:
        try:
            if candidate.is_symlink() or not candidate.is_file():
                return None
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None
        if not self._is_beneath(resolved, home / "sessions"):
            return None
        if not self._is_beneath(resolved, home):
            return None
        if not rollout_filename_matches_token(resolved.name, session_id):
            return None
        if not self._owner_safe(resolved):
            return None
        lower_name = resolved.name.lower()
        if not any(lower_name.endswith(suffix) for suffix in _JSONL_SUFFIXES):
            return None
        compressed = lower_name.endswith(".jsonl.zst")
        if compressed:
            return resolved
        try:
            with resolved.open("rb") as handle:
                head = handle.read(1)
        except OSError:
            return None
        if head not in {b"{", b"", b"\n"}:
            return None
        return resolved

    @staticmethod
    def _is_beneath(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root.resolve(strict=False))
        except OSError, ValueError:
            return False
        return True

    @staticmethod
    def _owner_safe(path: Path) -> bool:
        try:
            stat = path.stat()
        except OSError:
            return False
        uid = getattr(os, "getuid", None)
        if callable(uid):
            return int(stat.st_uid) == cast(Callable[[], int], uid)()
        return True


def _normalize_tool_name(value: object) -> str | None:
    token = _token(value)
    if token is None:
        return None
    # Either server spelling, current or legacy (ADR-048); see ``FINISHUP_TOOL_NAMES``.
    if token.startswith(FINISHUP_SCOPED_TOOL_PREFIXES) and token in FINISHUP_TOOL_NAMES:
        return token
    if token in FINISHUP_TOOL_NAMES:
        return token
    return token


def _file_change_paths(changes: object) -> Iterator[str]:
    """Paths one Codex ``FileChange`` names: rollout mapping form or ``exec --json`` list form."""

    if isinstance(changes, Mapping):
        for path, change in cast(Mapping[object, object], changes).items():
            if type(path) is str:
                yield path
            if isinstance(change, Mapping):
                moved = cast(Mapping[str, object], change).get("move_path")
                if type(moved) is str:
                    yield moved
    elif isinstance(changes, list):
        for change in cast(list[object], changes):
            if isinstance(change, Mapping):
                path = cast(Mapping[str, object], change).get("path")
                if type(path) is str:
                    yield path


def _file_change_write_scope(changes: object) -> str | None:
    """The ``write_scope`` of a ``FileChange`` only when every path is FinishUP-owned, notes or
    project documentation (named by the path alone, so no workspace root is needed). With no
    root to strip, an absolute path is documentation only by a conventional name (``README.md``);
    a documentation extension needs a relative path (``domain.write_scope``)."""

    paths = tuple(_file_change_paths(changes))
    if not paths:
        return None
    scope = edit_write_scope(
        classify_write_path(path, workspace=None, inside=None) for path in paths
    )
    return scope if scope in NON_COUNTING_WRITE_SCOPES | STALE_EXEMPT_WRITE_SCOPES else None


def _completed_tool_item(record: CodexParsedRecord) -> bool:
    """True for an ``event_msg``/``item_completed`` record of a command, MCP or patch item."""

    if record.wrapper_type != "event_msg" or record.item_type not in _STREAM_COMPLETED_TOOL_ITEMS:
        return False
    payload = record.value.get("payload")
    return isinstance(payload, JsonObject) and payload.get("type") == _STREAM_COMPLETED_PAYLOAD


def _mcp_item_failed(body: JsonObject) -> bool:
    """A rollout ``McpToolCall`` item that states a failure beside its ``status``."""

    if body.get("error") not in (None, False, ""):
        return True
    result = body.get("result")
    return isinstance(result, JsonObject) and result.get("isError") is True


def _structural_body(record: CodexParsedRecord) -> JsonObject | None:
    payload = record.value.get("payload")
    if isinstance(payload, JsonObject):
        inner = payload.get("item")
        if isinstance(inner, JsonObject):
            return inner
        return payload
    item = record.value.get("item")
    if isinstance(item, JsonObject):
        return item
    return None


def _spawn_parent_thread(payload: JsonObject) -> tuple[str | None, bool]:
    """Read the nested spawn record's parent thread, reporting whether one was supplied."""

    source = payload.get("source")
    if not isinstance(source, JsonObject):
        return None, False
    subagent = source.get(_SUBAGENT_THREAD_SOURCE)
    if not isinstance(subagent, JsonObject):
        return None, False
    spawn = subagent.get("thread_spawn")
    if not isinstance(spawn, JsonObject):
        return None, False
    if "parent_thread_id" not in spawn:
        return None, False
    return _token(spawn.get("parent_thread_id")), True


def _child_session_header(
    record: CodexParsedRecord,
) -> tuple[str | None, tuple[str, ...], bool]:
    """Return a v2 child header's child thread, its spawning sessions, and whether it declared one.

    The spawning sessions are the host session tokens that may own the child's lane, strongest
    first: the header's ``session_id`` (v2 sets it to the root session that every thread of one
    delegation tree shares, which is the ``session_id`` the tree's hook callbacks carry) and then
    the agreed ``parent_thread_id``. The child's own thread is never one of them.
    """

    if record.wrapper_type != "session_meta":
        return None, (), False
    payload = _structural_body(record)
    if payload is None or payload.get("thread_source") != _SUBAGENT_THREAD_SOURCE:
        return None, (), False
    parent, spawn_supplied = _spawn_parent_thread(payload)
    if spawn_supplied and parent is None:
        return None, (), True
    declared = _token(payload.get("parent_thread_id"))
    if "parent_thread_id" in payload and declared is None:
        return None, (), True
    if parent is not None and declared is not None and parent != declared:
        return None, (), True
    parent = declared if declared is not None else parent
    child = _token(payload.get("id"))
    if child is None or parent is None or child == parent:
        return None, (), True
    spawning: list[str] = []
    for candidate in (_token(payload.get("session_id")), parent):
        if candidate is not None and candidate != child and candidate not in spawning:
            spawning.append(candidate)
    return child, tuple(spawning), True


def _child_session_identity(record: CodexParsedRecord) -> tuple[str | None, bool]:
    """Return one v2 child rollout header's bounded child identity.

    The second member says the header declared itself a delegated child (``thread_source`` is
    ``subagent``); the first is that child's thread id, or ``None`` when the declared identity is
    absent or self-contradictory. Only the second-with-``None`` shape is a genuine identity gap:
    an ordinary user thread declares no child at all.

    Both spellings of the spawning thread must agree, and a header whose child id equals its
    parent id is refused: v2 sets ``session_id`` to the parent thread, so an adapter that read the
    wrong field would publish the parent as its own child.
    """

    child, _spawning, declared = _child_session_header(record)
    return child, declared


CodexChildRolloutHeaderStatus = Literal["child", "not_child", "identity_invalid", "unreadable"]


@dataclass(frozen=True, slots=True, repr=False)
class CodexChildRolloutHeader:
    """One delegated child's own v2 rollout header, reduced to bounded thread tokens.

    ``child_thread_id`` is the child's own thread and ``spawning_sessions`` the host sessions that
    may own its lane (see ``_child_session_header``). These are local routing inputs only: never
    persist, log, or emit them.
    """

    child_thread_id: str
    spawning_sessions: tuple[str, ...]

    def __repr__(self) -> str:
        return "CodexChildRolloutHeader(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class CodexChildRolloutHeaderResult:
    """Closed outcome of reading one rollout's first line as a delegated-child header.

    ``child`` carries a usable header. ``identity_invalid`` is a header that declares a delegated
    child (``thread_source: subagent``) without a usable distinct identity. ``not_child`` is an
    admitted header that declares no delegation. ``unreadable`` is everything that proves nothing:
    an absent, unsafe, compressed, oversized, or unadmitted header.
    """

    status: CodexChildRolloutHeaderStatus
    header: CodexChildRolloutHeader | None = None

    def __repr__(self) -> str:
        return f"CodexChildRolloutHeaderResult(status={self.status!r})"


_CHILD_HEADER_UNREADABLE: Final = CodexChildRolloutHeaderResult("unreadable")
_CHILD_HEADER_READ_CHUNK: Final = 65_536


def read_codex_child_rollout_header(path: Path) -> CodexChildRolloutHeaderResult:
    """Read only the first line of one local rollout as a v2 delegated-child header.

    The read is bounded by the rollout line limit and stops at the first newline, so a large or
    still-growing rollout costs one small read. The caller owns path validation; this function
    only refuses a symlink, a non-regular file, and the compressed variant it cannot read.
    """

    if path.name.lower().endswith(".jsonl.zst"):
        return _CHILD_HEADER_UNREADABLE
    try:
        if path.is_symlink() or not path.is_file():
            return _CHILD_HEADER_UNREADABLE
        collected = bytearray()
        with path.open("rb") as handle:
            while len(collected) <= ROLLOUT_MAX_LINE_BYTES:
                chunk = handle.read(_CHILD_HEADER_READ_CHUNK)
                if not chunk:
                    break
                newline = chunk.find(b"\n")
                if newline >= 0:
                    collected += chunk[: newline + 1]
                    break
                collected += chunk
    except OSError:
        return _CHILD_HEADER_UNREADABLE
    if not collected.endswith(b"\n") or len(collected) > ROLLOUT_MAX_LINE_BYTES + 1:
        # An unterminated first line is a header still being written or an oversized one.
        return _CHILD_HEADER_UNREADABLE
    try:
        parsed = parse_codex_rollout_jsonl_from_offset(
            bytes(collected), None, start_ordinal=1, require_admission=True
        )
    except ProtocolValueError, TypeError, ValueError:
        return _CHILD_HEADER_UNREADABLE
    if parsed.profile is None or len(parsed.records) != 1:
        return _CHILD_HEADER_UNREADABLE
    child, spawning, declared = _child_session_header(parsed.records[0])
    if not declared:
        return CodexChildRolloutHeaderResult("not_child")
    if child is None or not spawning:
        return CodexChildRolloutHeaderResult("identity_invalid")
    return CodexChildRolloutHeaderResult("child", CodexChildRolloutHeader(child, spawning))


def _decode_stream_call_tool(value: object) -> tuple[str | None, bool]:
    """Decode a bounded call-map value and its service-derived candidate bit.

    Older state files contain a plain tool name.  Such values remain usable,
    but cannot prove that a shell call was read-only because the original
    arguments were intentionally never retained.  Only the marker written by
    this adapter can carry that fact across reconcile passes.
    """

    if type(value) is not str or not value:
        return None, False
    if _CALL_SELECTION_SEPARATOR not in value:
        return (value if _token(value) is not None else None), False
    tool_name, marker = value.rsplit(_CALL_SELECTION_SEPARATOR, 1)
    if marker != _CALL_SELECTION_MARKER or _token(tool_name) is None:
        return None, False
    return tool_name, True


def _encode_stream_call_tool(tool_name: str, *, routine_candidate: bool) -> str:
    """Encode a tool name plus a non-content selection fact for the call map."""

    if _token(tool_name) is None:
        raise ValueError("stream_call_tool_invalid")
    if not routine_candidate:
        return tool_name
    return f"{tool_name}{_CALL_SELECTION_SEPARATOR}{_CALL_SELECTION_MARKER}"


def _stream_classification_payload(
    record: CodexParsedRecord, structural: Mapping[str, JsonValue]
) -> Mapping[str, JsonValue]:
    """Build the ephemeral classifier input for one parsed stream record.

    Rollout arguments/results are already redacted by the importer.  Arguments
    are parsed only for the closed routine-read classifier and never copied to
    a structural envelope, state file, outbox row, or summary member.
    """

    payload: dict[str, JsonValue] = dict(structural)
    tool_name = structural.get("tool_name")
    if type(tool_name) is str:
        payload["tool_name"] = tool_name
    body = _structural_body(record)
    if body is None or structural.get("action") not in {"function_call", "custom_tool_call"}:
        return payload

    raw_arguments: object = body.get("arguments")
    if raw_arguments is None:
        raw_arguments = body.get("input")
    if raw_arguments is None:
        raw_arguments = body.get("tool_input")
    if type(raw_arguments) is str:
        try:
            parsed = strict_json_parse(raw_arguments.encode("utf-8"))
        except ProtocolValueError, TypeError, ValueError, UnicodeError:
            parsed = None
        if isinstance(parsed, Mapping):
            payload["tool_input"] = cast(JsonObject, parsed)
    elif isinstance(raw_arguments, Mapping):
        payload["tool_input"] = raw_arguments
    return payload


def _stream_record_classification(
    record: CodexParsedRecord, structural: Mapping[str, JsonValue]
) -> ObservationClassification | None:
    """Classify only tool-call phases; lifecycle/visible rows stay protected."""

    phase = _stream_phase(structural)
    if phase not in {"PreToolUse", "PostToolUse"}:
        return None
    return classify_observation(_stream_classification_payload(record, structural), phase)


def _stream_shell_tool(tool_name: object) -> bool:
    return type(tool_name) is str and (
        tool_name.casefold() in SHELL_TOOLS
        or any(hint in tool_name.casefold() for hint in ("shell", "exec", "terminal"))
    )


def _carry_stream_candidate(
    classification: ObservationClassification,
    *,
    routine_candidate: bool,
) -> ObservationClassification:
    """Carry a pre-event candidate to a later output after pairing.

    The post classifier still owns outcome truth.  The persisted candidate is
    only the result of an earlier classifier call bound to this call id and
    source generation; it cannot turn a failure, partial, denial, or unknown
    output into a successful summary.
    """

    if not routine_candidate or classification.routine_candidate:
        return classification
    reasons = list(classification.reason_tokens)
    if "routine_candidate" not in reasons:
        reasons.append("routine_candidate")
    proven = "success" in reasons and not set(reasons).intersection(
        _ROUTINE_OUTCOME_FAILURE_REASONS
    )
    if proven and "routine_success" not in reasons:
        reasons.append("routine_success")
    return ObservationClassification(
        protected=not proven,
        routine_candidate=True,
        proven_routine_success=proven,
        content_role=(ObservationContentRole.NONE if proven else ObservationContentRole.BOTH),
        reason_tokens=tuple(reasons),
        version=OBSERVATION_CLASSIFICATION_VERSION,
    )


def _selection_envelope(
    envelope: ObservationEnvelope,
    classification: ObservationClassification | None,
    *,
    focused: bool,
    routed: bool,
) -> ObservationEnvelope:
    """Adapt a stream tool row to the hook-shaped summary phase contract."""

    if not routed or classification is None or not classification.routine_candidate:
        return envelope
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    action = structural.get("action")
    if action in {"function_call", "custom_tool_call"}:
        if envelope.event_kind in {"response_item", "event_msg"}:
            return replace(
                envelope,
                event_kind="PreToolUse",
                structural_payload=JsonObject(
                    {
                        **dict(structural),
                        "action": "routine_read" if focused else "function_call",
                    }
                ),
            )
    if (
        action in {"function_call_output", "custom_tool_call_output"}
        and classification.proven_routine_success
        and envelope.event_kind in {"response_item", "event_msg"}
    ):
        return replace(
            envelope,
            event_kind="PostToolUse",
            structural_payload=JsonObject(
                {
                    **dict(structural),
                    "action": "routine_read" if focused else "function_call_output",
                }
            ),
        )
    return envelope


def _stream_read_protection_envelope(
    envelope: ObservationEnvelope,
    classification: ObservationClassification | None,
) -> ObservationEnvelope:
    """Normalize a candidate to the read-protection API's phase contract.

    Protection is independent of Focused/Detailed selection and of a live
    route.  The local store recognizes shell reads only through its
    service-owned ``routine_read`` marker, so failed and unknown outputs must
    use the same normalized probe before they are admitted individually.
    """

    if classification is None or not classification.routine_candidate:
        return envelope
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    action = structural.get("action")
    if action in {"function_call", "custom_tool_call"} and envelope.event_kind in {
        "response_item",
        "event_msg",
        "PreToolUse",
    }:
        return replace(
            envelope,
            event_kind="PreToolUse",
            structural_payload=JsonObject({**dict(structural), "action": "routine_read"}),
        )
    if action in {"function_call_output", "custom_tool_call_output"} and envelope.event_kind in {
        "response_item",
        "event_msg",
        "PostToolUse",
        "PostToolUseFailure",
    }:
        return replace(
            envelope,
            event_kind="PostToolUse",
            structural_payload=JsonObject({**dict(structural), "action": "routine_read"}),
        )
    return envelope


def _stream_read_protection_probe(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    envelope: ObservationEnvelope,
    classification: ObservationClassification | None,
) -> tuple[ObservationEnvelope | None, str | None]:
    """Reserve an explicitly protected logical read, if one matches.

    The probe remains separate from the stamped delivery envelope because the
    local store validates the service-owned ``routine_read`` marker while
    ``evidence_linked_read`` is the materialization marker.
    """

    probe = _stream_read_protection_envelope(envelope, classification)
    if probe is envelope:
        return None, None
    reader = getattr(store, "read_is_protected", None)
    if not callable(reader):
        return None, None
    try:
        protected = reader(workspace_commitment, session_commitment, probe)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return None, None
    if protected is not True:
        return None, None
    reference_reader = getattr(store, "read_protection_reference", None)
    if not callable(reference_reader):
        return probe, None
    try:
        reference = reference_reader(workspace_commitment, session_commitment, probe)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        reference = None
    return probe, reference if type(reference) is str else None


def _stamp_stream_read_protection(
    envelope: ObservationEnvelope,
    reference: str | None,
) -> ObservationEnvelope:
    """Mark a protected stream phase as individually retained evidence."""

    fields: dict[str, JsonValue] = {
        **dict(cast(Mapping[str, JsonValue], envelope.structural_payload)),
        "action": "evidence_linked_read",
    }
    if reference is not None:
        fields["protection_reference"] = reference
    return replace(envelope, structural_payload=JsonObject(fields))


def _restore_stream_individual(envelope: ObservationEnvelope) -> ObservationEnvelope:
    """Restore a selected stream row when it is delivered individually."""

    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    action = structural.get("action")
    if action == "routine_read":
        if envelope.event_kind == "PostToolUse":
            return replace(
                envelope,
                structural_payload=JsonObject(
                    {**dict(structural), "action": "function_call_output"}
                ),
            )
        if envelope.event_kind in {"response_item", "event_msg", "PreToolUse"}:
            return replace(
                envelope,
                event_kind="PreToolUse",
                structural_payload=JsonObject({**dict(structural), "action": "function_call"}),
            )
        return envelope
    if action not in {"function_call", "custom_tool_call"}:
        return envelope
    if envelope.event_kind not in {"response_item", "event_msg", "PreToolUse"}:
        return envelope
    return replace(envelope, event_kind="PreToolUse")


def _restore_stream_individual_deliveries(plan: AdmissionPlan) -> AdmissionPlan:
    """Keep failed/incomplete stream attempts individually materializable."""

    if not plan.deliveries:
        return plan
    return replace(
        plan,
        deliveries=tuple(
            (host_session, _restore_stream_individual(envelope))
            for host_session, envelope in plan.deliveries
        ),
    )


# Codex's own shell tools whose ``function_call`` arguments name the command their hook commits
# to: 0.159 ``exec_command`` sends ``tool_input: {"command": args.cmd}`` (``exec_command.rs``
# ``pre_tool_use_payload``), the legacy ``shell`` tools an argv. Never the code-mode ``exec``
# cell, whose input is a script, ``write_stdin`` (a poll names no command) or an MCP tool.
_STREAM_SHELL_CALL_TOOLS: Final = frozenset(
    {"exec_command", "shell", "shell_command", "local_shell", "bash"}
)
# The hook's argument keys, in its order (``cli.observe_hooks._COMMAND_ARGUMENT_KEYS``, #909).
_STREAM_COMMAND_ARGUMENT_KEYS: Final = ("cmd", "command", "argv")
# The header Codex 0.159 writes before a shell call's output (``codex-rs/core/src/tools/
# context.rs``): unified exec's ``response_header`` (``Chunk ID``, ``Wall time``, ``Process exited
# with code N`` once the process exited, ``Process running with session ID N`` while it runs,
# ``Original token count``) and the classic ``format_exec_output_for_model`` (``Exit code: N``,
# ``Wall time``, ``Total output lines``), each ending at the ``Output:`` line. Only that closed,
# anchored grammar is read; the output after it is never searched.
_EXEC_OUTPUT_HEADER: Final = re.compile(
    r"\A(?:"
    r"(?:Chunk ID: [A-Za-z0-9._-]{1,64}\n)?"
    r"Wall time: [0-9]{1,12}(?:\.[0-9]{1,12})? seconds\n"
    r"(?:Process exited with code (?P<exited>-?[0-9]{1,4})\n"
    r"|Process running with session ID [0-9]{1,20}\n)?"
    r"(?:Original token count: [0-9]{1,12}\n)?"
    r"|Exit code: (?P<classic>-?[0-9]{1,4})\n"
    r"Wall time: [0-9]{1,12}(?:\.[0-9]{1,12})? seconds\n"
    r"(?:Total output lines: [0-9]{1,12}\n)?"
    r")Output:(?:\n|\Z)",
    re.ASCII,
)
_EXEC_OUTPUT_HEADER_CHARS: Final = 512


def _stream_call_command(
    record: CodexParsedRecord, fields: Mapping[str, JsonValue]
) -> JsonValue | None:
    """The command a Codex shell ``function_call`` row's arguments name, or ``None``.

    The arguments are parsed transiently, exactly as for the routine-read classifier; only the
    keyed facts ``_command_facts`` derives from the value leave this adapter.
    """

    if fields.get("action") != "function_call":
        return None
    tool = fields.get("tool_name")
    if type(tool) is not str or tool.casefold() not in _STREAM_SHELL_CALL_TOOLS:
        return None
    tool_input = _stream_classification_payload(record, fields).get("tool_input")
    if not isinstance(tool_input, Mapping):
        return None
    arguments = cast(Mapping[str, JsonValue], tool_input)
    for key in _STREAM_COMMAND_ARGUMENT_KEYS:
        value = arguments.get(key)
        if value is not None:
            return value
    return None


def _command_facts(
    fields: dict[str, JsonValue],
    gaps: set[str],
    value: JsonValue | None,
    *,
    key_material: bytes | None,
    post: bool,
) -> None:
    """Add the closed command facts the call's hook copy carries for one rollout command.

    The commitment and segment commitments use the hook's normalization and the local store key,
    so a passing rerun seen here supersedes a failure seen by either path and a planned
    verification matches either copy (#909, #910, n7 RC2); the text itself is dropped here. The
    compound-outcome gap belongs to a result, so only a completed item (``post``) carries it, as
    only the hook's post event does.
    """

    if key_material is not None:
        normalized = normalize_observed_command(value)
        if normalized is not None:
            fields["command_commitment"] = observed_command_commitment(key_material, normalized)
            segments = command_segment_commitments(key_material, normalized)
            if segments is not None:
                fields["command_segment_commitments"] = segments[0]
                fields["command_composition"] = segments[1]
    # Identity normalization may recursively erase shell executable paths. Read-only
    # classification retains them beyond the one ordinary native host-shell layer.
    runner = native_command_runner_class(value)
    if runner is not None:
        fields["runner_class"] = runner
    if type(value) is str:
        raw_command = value
    elif isinstance(value, (list, tuple)) and value and all(type(word) is str for word in value):
        raw_command = shlex.join(cast(list[str], list(value)))
    else:
        return
    if "write_scope" not in fields:
        # ADR-045: the stream knows no workspace root, so it claims only a relative write
        # (a working directory makes it certain); an absolute path is left to the hook. A
        # heredoc-fed patch writes the files its headers name, as the hook reads them.
        scope = shell_write_scope(
            raw_command,
            workspace=None,
            inside=lambda _path: False,
            relative_only=True,
            also_written=heredoc_patch_paths(raw_command),
        )
        if scope is not None:
            # The closed token as the hook would send it (workspace, or the non-counting
            # notes / finishup_owned scope a declared output of that kind overrides).
            fields["write_scope"] = scope
    if post and compound_verification_gap_required({"command": raw_command}):
        # Preserve the host's outer result. The bounded gap records that a
        # masking-capable composition does not expose each nested outcome (#968).
        gaps.add(ObservationGapCode.COMPOUND_OUTCOME_UNAVAILABLE.value)


def _exec_output_exit_status(record: CodexParsedRecord) -> int | None:
    """The exit code Codex's own header states for one call output, read from that header only.

    A header that names a running process, no exit, or an exit outside ``-1..255`` states none.
    The caller keeps the fact only for the output of a Codex shell call (pairing decides), so an
    MCP or dynamic tool whose own text imitates the header never reads as a process exit.
    """

    if record.item_type != "function_call_output":
        return None
    body = _structural_body(record)
    text = None if body is None else _output_status_text(body)
    if text is None:
        return None
    match = _EXEC_OUTPUT_HEADER.match(text[:_EXEC_OUTPUT_HEADER_CHARS])
    if match is None:
        return None
    raw = match.group("exited") or match.group("classic")
    if raw is None:
        return None
    code = int(raw)
    return code if -1 <= code <= 255 else None


def structural_from_stream_record(
    record: CodexParsedRecord,
    *,
    profile: CodexCapabilityProfile | None = None,
    key_material: bytes | None = None,
) -> tuple[JsonObject, tuple[str, ...]]:
    """Map a parsed stream record to allowlisted structural fields + opaque gaps.

    ``profile`` is the exact profile that admitted the record; without it the union of every
    supported vocabulary decides which ``type`` tokens are semantic rather than tool names.
    ``key_material`` is the local observation store key: with it, a completed command item carries
    the same installation-keyed ``command_commitment`` its hook copy carries (#909, #910).
    """

    item_types = _ROLLOUT_ITEM_TYPES if profile is None else frozenset(profile.item_types)
    known_wrappers = _ROLLOUT_WRAPPER_TYPES if profile is None else frozenset(profile.wrapper_types)
    gaps: set[str] = set()
    fields: dict[str, JsonValue] = {"stream_kind": record.wrapper_type}
    item_type = record.item_type
    if item_type is not None:
        token = _token(item_type)
        if token is not None:
            fields["action"] = token
        else:
            gaps.add(ObservationGapCode.UNSUPPORTED_EVENT.value)
    body = _structural_body(record)
    if body is not None:
        tool = _normalize_tool_name(body.get("tool")) or _normalize_tool_name(body.get("name"))
        type_token = _token(body.get("type"))
        if tool is None and type_token is not None and type_token not in item_types:
            tool = _normalize_tool_name(type_token)
        if tool is None and item_type is not None:
            # A completed command or patch item names no tool of its own; use the host's own
            # item family, spelled as ``codex exec --json`` spells it, so the call keeps its
            # command/edit family instead of an anonymous one (#910).
            tool = _STREAM_TOOL_ITEM_NAMES.get(item_type)
        named_server = body.get("server") if item_type == "McpToolCall" else None
        if tool is not None and named_server is not None and not tool.startswith("mcp__"):
            # Keep the MCP server: ``mcp__<server>__<tool>`` is how the call's own hook names it,
            # so FinishUP's own call is told from another server's tool of the same name (#1038).
            server = _token(named_server)
            scoped = _token(f"mcp__{server}__{tool}") if server and "__" not in server else None
            if scoped is not None:
                tool = scoped
            elif finishup_tool_spelling(tool) is not None:
                # A server that cannot be folded into that spelling (it contains ``__`` or is no
                # plain token) is still a named server: only an item naming no server keeps a
                # FinishUP tool's bare name, which reads as FinishUP's own call. Such an item names no
                # tool, as for any unreadable tool name; any other name keeps its name rules.
                tool = None
        if tool is not None:
            fields["tool_name"] = tool
        status = _token(body.get("status")) or _token(body.get("result_status"))
        if item_type == "McpToolCall" and _mcp_item_failed(body):
            # Failure wins: an MCP item that names an error, or whose result carries the protocol
            # ``isError`` bit, failed whatever its ``status`` says (#910).
            status = "failed"
        if status is not None:
            fields["result_status"] = status
        exit_code = body.get("exit_code")
        if "exit_code" in body and exit_code is not None:
            # ``exit_code: null`` is a command that never exited (declined or still running):
            # no outcome fact, not an unsupported shape.
            if type(exit_code) is int and -1 <= exit_code <= 255:
                fields["exit_status"] = exit_code
            else:
                gaps.add(ObservationGapCode.UNSUPPORTED_EVENT.value)
        if item_type == "FileChange":
            # Name a patch whose every path is scratch or FinishUP-owned (ADR-042, tb4n2 R4) so it
            # never makes an earlier verification stale. The stream knows no workspace root, so it
            # never claims ``outside_workspace``; only the closed class token crosses.
            scope = _file_change_write_scope(body.get("changes"))
            if scope is not None:
                fields["write_scope"] = scope
        # ``SubAgentActivity.id`` identifies the rollout item itself, not the
        # parent tool call.  Keep it out of the parent correlation family; only
        # an explicit call alias may identify that parent.
        if item_type == "CommandExecution":
            # The rollout names the command as the argv Codex ran (``/bin/bash -lc <cmd>``).
            _command_facts(fields, gaps, body.get("command"), key_material=key_material, post=True)
        else:
            call_command = _stream_call_command(record, fields)
            if call_command is not None:
                # A direct shell call's own row: whichever copy of the call commits first, its
                # action carries the identity and runner class its hook copy carries (n7 RC2).
                _command_facts(fields, gaps, call_command, key_material=key_material, post=False)
        if item_type != "SubAgentActivity":
            # A response-item call and its output share ``call_id``; since Codex 0.150.1 each row
            # also carries an ``id`` naming the row itself (``fc_``/``fco_``, ``ctc_``/``ctco_``),
            # which never joins a call to its output (#1038). Any other record keeps its own ``id``
            # first: a completed tool item's id (``exec-<uuid>``, or the call id on a direct call)
            # is the one ADR-022 decision 15 compares with a hook's call id.
            first, second = (
                ("call_id", "id") if item_type in _STREAM_CALL_PAIR_ITEMS else ("id", "call_id")
            )
            call_id = _token(body.get(first)) or _token(body.get(second))
            if call_id is not None:
                fields["tool_call_id"] = call_id
        # Codex rollout records use the same child identifiers as its native
        # hook profile.  Preserve only the bounded structural pair; task
        # creation and acceptance stay service-owned.  Some historical stream
        # records use ``agent_id`` for the child, so normalize that alias to
        # the canonical ``subagent_id`` field.
        subagent_id, _subagent_aliases_supplied = _consistent_alias_token(
            body, ("subagent_id", "agent_id", "agent_thread_id")
        )
        if subagent_id is not None:
            fields["subagent_id"] = subagent_id
        if item_type == "SubAgentActivity":
            parent_tool_call_id, parent_aliases_supplied = _consistent_alias_token(
                body, ("parent_tool_call_id", "tool_call_id", "tool_use_id")
            )
            if parent_tool_call_id is not None:
                fields["parent_tool_call_id"] = parent_tool_call_id
            elif parent_aliases_supplied:
                # Invalid or conflicting supplied aliases cannot become a weaker child-only
                # identity. Retain the same durable gap as native subagent hook ingress.
                fields.pop("subagent_id", None)
                gaps.add(ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value)
            # The generic ``tool_call_id`` spelling is accepted above only as
            # an explicit parent alias for this item family.  Never leave a
            # conflicting/invalid value in the generic field where the domain
            # normalizer could reinterpret it as a parent call.
            fields.pop("tool_call_id", None)
            activity_kind = _token(body.get("kind"))
            if activity_kind not in _SUBAGENT_ACTIVITY_KINDS:
                gaps.add(ObservationGapCode.UNSUPPORTED_EVENT.value)
    child_session_id, child_session_header = _child_session_identity(record)
    if child_session_header:
        # The header's ``id`` is a thread, never a tool call: leaving it in the generic field
        # would let the domain normalizer read the child's own thread as its parent call.
        fields.pop("tool_call_id", None)
        if child_session_id is None:
            fields.pop("subagent_id", None)
            gaps.add(ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value)
        else:
            fields["subagent_id"] = child_session_id
    if record.wrapper_type not in known_wrappers:
        gaps.add(ObservationGapCode.UNSUPPORTED_EVENT.value)
    return JsonObject(fields), tuple(sorted(gaps, key=str.encode))


def envelope_from_stream_record(
    record: CodexParsedRecord,
    *,
    session_commitment: str,
    cursor: ObservationCursor,
    profile: CodexCapabilityProfile | None = None,
    key_material: bytes | None = None,
) -> ObservationEnvelope:
    structural, gaps = structural_from_stream_record(
        record, profile=profile, key_material=key_material
    )
    host_ids: dict[str, JsonValue] = {}
    body = _structural_body(record)
    if body is not None:
        for key in ("id", "call_id", "tool_call_id", "event_id"):
            token = _token(body.get(key))
            if token is not None:
                host_ids[key] = token
        subagent_id, _subagent_aliases_supplied = _consistent_alias_token(
            body, ("subagent_id", "agent_id", "agent_thread_id")
        )
        if subagent_id is not None:
            host_ids["subagent_id"] = subagent_id
        if record.item_type == "SubAgentActivity":
            parent_tool_call_id, _parent_aliases_supplied = _consistent_alias_token(
                body, ("parent_tool_call_id", "tool_call_id", "tool_use_id")
            )
            if parent_tool_call_id is not None:
                host_ids["parent_tool_call_id"] = parent_tool_call_id
    event_id = _token(record.value.get("event_id")) or _token(record.value.get("id"))
    if event_id is not None:
        host_ids.setdefault("event_id", event_id)
    identity = (
        "stream:"
        + canonical_digest(
            JsonObject(
                {
                    "byte_end": record.byte_end,
                    "source_generation": cursor.source_generation,
                    "host_ids": JsonObject(host_ids),
                    "ordinal": record.line_ordinal,
                    "structural": structural,
                    "wrapper": record.wrapper_type,
                }
            )
        ).removeprefix("sha256:")[:48]
    )
    event_kind = _token(record.wrapper_type) or "unsupported_event"
    if _completed_tool_item(record):
        # ``event_msg``/``item_completed`` carrying a command, MCP or patch item is a completed
        # host tool call with a closed ``status``/``exit_code`` outcome. Name its phase so the
        # materializer records a result instead of an opaque ``event_msg`` row (#910).
        event_kind = "item_completed"
    if record.item_type == "SubAgentActivity" and body is not None:
        activity_kind = _token(body.get("kind"))
        if activity_kind in _SUBAGENT_ACTIVITY_START_KINDS:
            event_kind = "SubagentStart"
        elif activity_kind in _SUBAGENT_ACTIVITY_STOP_KINDS:
            event_kind = "SubagentStop"
    child_session_id, child_session_header = _child_session_identity(record)
    if child_session_header:
        # A delegated child's own header is that child's start signal. A declared child with no
        # usable identity keeps the phase and earns ``missing_subagent_identity``; it is never
        # downgraded to an ordinary header, which would hide the delegation entirely.
        event_kind = "SubagentStart"
        if child_session_id is not None:
            host_ids["subagent_id"] = child_session_id
    return ObservationEnvelope(
        session_commitment=session_commitment,
        event_kind=event_kind,
        source_identity=identity,
        source=ObservationSource.CODEX_SESSION_STREAM,
        cursor=cursor,
        receipt_time=_now(),
        structural_payload=structural,
        content_object_refs=(),
        gap_codes=gaps,
    )


def _opaque_stream_envelope(
    *,
    session_commitment: str,
    cursor: ObservationCursor,
) -> ObservationEnvelope:
    """Retain one unsupported complete line without interpreting its payload."""

    identity = (
        "stream:"
        + canonical_digest(
            JsonObject(
                {
                    "byte_end": cursor.byte_position,
                    "line_commitment": cursor.last_source_commitment,
                    "ordinal": cursor.event_position,
                    "source_generation": cursor.source_generation,
                    "wrapper": "unsupported_event",
                }
            )
        ).removeprefix("sha256:")[:48]
    )
    return ObservationEnvelope(
        session_commitment=session_commitment,
        event_kind="unsupported_event",
        source_identity=identity,
        source=ObservationSource.CODEX_SESSION_STREAM,
        cursor=cursor,
        receipt_time=_now(),
        structural_payload=JsonObject({}),
        content_object_refs=(),
        gap_codes=(ObservationGapCode.UNSUPPORTED_EVENT.value,),
    )


@dataclass(frozen=True, slots=True)
class SessionStreamAdvance:
    envelopes: tuple[ObservationEnvelope, ...]
    cursor: ObservationCursor
    partial_line: bytes
    gaps: tuple[str, ...]
    restarted: bool
    truncated: bool
    rotated: bool
    # Closed parser reason tokens for the terminated lines this advance did not map (sorted,
    # unique). Never the offending type text: a partial stream names its affected family only.
    reason_codes: tuple[str, ...] = ()
    # Per-envelope classifier results are ephemeral adapter facts.  They are
    # kept parallel to ``envelopes`` so a function-call's original arguments
    # can be classified before structural mapping discards them.
    classifications: tuple[ObservationClassification | None, ...] = ()
    # Per-envelope code-mode facts (#1038 follow-up): the host's ``exec``/``wait`` status header
    # and a ``wait`` call's target cell, read before structural mapping discards the output text.
    cell_facts: tuple[CodeModeCellFact | None, ...] = ()
    # Per-envelope exit codes Codex's own header states for a call output (n7 RC2), read before
    # structural mapping discards the output text. Reconcile keeps one only for the output of a
    # Codex shell call, which pairing names: the output row itself names no tool.
    output_exits: tuple[int | None, ...] = ()


def stream_admission(
    profile: CodexCapabilityProfile | None,
    gaps: tuple[str, ...],
    reason_codes: tuple[str, ...],
) -> str:
    """Classify one stream's admission from its profile and bounded gaps (issue #656)."""

    if ObservationGapCode.UNSUPPORTED_FORMAT.value in gaps:
        return "incompatible"
    if profile is None:
        return "unadmitted"
    if (
        rollout_admission_provenance(profile) == "structural"
        or ObservationGapCode.UNSUPPORTED_EVENT.value in gaps
        or any(token in _ADMISSION_REASON_TOKENS for token in reason_codes)
    ):
        return "partially_understood"
    return "structurally_supported"


@dataclass
class SessionStreamReader:
    """Incremental JSONL reader with generation-fenced cursor and partial-line hold."""

    session_commitment: str
    # The exact profile the current source generation's header admitted, or ``None`` until the
    # header is read. Never a default: every generation re-selects from its own header.
    profile: CodexCapabilityProfile | None
    cursor: ObservationCursor
    key_material: bytes
    partial_line: bytes = b""
    _inode: int | None = None
    _source_identity: str | None = None
    _size_at_generation: int = 0

    def __post_init__(self) -> None:
        if type(self.partial_line) is not bytes:
            raise ValueError("session_stream_partial_invalid")
        if type(self.key_material) is not bytes or not 16 <= len(self.key_material) <= 64:
            raise ValueError("session_stream_key_invalid")

    @property
    def source_identity(self) -> str | None:
        """Return the private identity of the source inspected by the latest advance."""

        return self._source_identity

    def advance(self, path: Path) -> SessionStreamAdvance:
        gaps: set[str] = set()
        restarted = False
        truncated = False
        rotated = False
        try:
            stat = path.stat()
        except OSError:
            gaps.add(ObservationGapCode.SOURCE_LAG.value)
            return SessionStreamAdvance(
                (), self.cursor, self.partial_line, tuple(sorted(gaps)), False, False, False
            )

        inode = getattr(stat, "st_ino", None)
        source_identity = _source_file_identity(stat, self.key_material)
        size = stat.st_size
        generation = self.cursor.source_generation
        byte_position = self.cursor.byte_position
        event_position = self.cursor.event_position
        last_commitment = self.cursor.last_source_commitment

        if (self._source_identity is not None and source_identity != self._source_identity) or (
            self._inode is not None and inode is not None and inode != self._inode
        ):
            # Rotation: new inode → new generation.
            rotated = True
            generation += 1
            byte_position = 0
            event_position = 0
            self.partial_line = b""
            self.profile = None
            last_commitment = _EMPTY_COMMITMENT
            gaps.add(ObservationGapCode.CURSOR_STALE.value)
        elif size < byte_position:
            # Truncation / rewrite in place.
            truncated = True
            generation += 1
            byte_position = 0
            event_position = 0
            self.partial_line = b""
            self.profile = None
            last_commitment = _EMPTY_COMMITMENT
            gaps.add(ObservationGapCode.CURSOR_STALE.value)
        elif event_position > 0 and self.profile is None:
            # An admitted generation whose exact profile is not recorded cannot be parsed
            # under any vocabulary without inferring one. Replay it from the header under a
            # fresh generation instead; earlier bytes are re-read, never skipped.
            restarted = True
            generation += 1
            byte_position = 0
            event_position = 0
            self.partial_line = b""
            last_commitment = _EMPTY_COMMITMENT
            gaps.add(ObservationGapCode.CURSOR_STALE.value)
        elif byte_position == 0 and event_position == 0 and self.partial_line == b"":
            restarted = generation > 1 or (self._inode is not None)

        oversized_state: _OversizedLineState | None = None
        if self.partial_line.startswith(_OVERSIZED_PARTIAL_PREFIX):
            try:
                oversized_state = _decode_oversized_partial(
                    self.partial_line,
                    session_commitment=self.session_commitment,
                    source_generation=generation,
                    source_identity=source_identity,
                    key_material=self.key_material,
                )
                if (
                    oversized_state is None
                    or oversized_state.line_start > byte_position
                    or byte_position - oversized_state.line_start <= ROLLOUT_MAX_LINE_BYTES
                ):
                    raise ValueError("session_stream_partial_invalid")
            except ValueError:
                # The private continuation marker is authenticated and bound to this session,
                # generation, and source. An invalid/transplanted marker cannot authorize a skip;
                # restart the generation and replay from admission instead.
                restarted = True
                generation += 1
                byte_position = 0
                event_position = 0
                last_commitment = _EMPTY_COMMITMENT
                self.partial_line = b""
                self.profile = None
                oversized_state = None
                gaps.add(ObservationGapCode.CURSOR_STALE.value)
                gaps.add(ObservationGapCode.TRUNCATED_PAYLOAD.value)

        self._inode = inode if type(inode) is int else self._inode
        self._source_identity = source_identity
        self._size_at_generation = size

        if event_position == 0 and byte_position > 0 and not self.partial_line:
            # Refused admission is durable for this generation: consumed bytes with
            # no admitted event mean the first complete line was rejected, so no
            # later append may materialize without an accepted exact header. Only
            # rotation or truncation (a fresh generation) re-opens admission.
            cursor = ObservationCursor(
                source_generation=generation,
                byte_position=byte_position,
                event_position=0,
                last_source_commitment=last_commitment,
                mapping_version=STREAM_MAPPING_VERSION,
            )
            self.cursor = cursor
            gaps.add(ObservationGapCode.UNSUPPORTED_FORMAT.value)
            return SessionStreamAdvance(
                (), cursor, b"", tuple(sorted(gaps, key=str.encode)), restarted, truncated, rotated
            )

        partial_source_bytes = 0 if oversized_state is not None else len(self.partial_line)
        to_read = min(_MAX_READ_CHUNK, max(0, size - (byte_position + partial_source_bytes)))
        if to_read == 0 and not self.partial_line:
            cursor = ObservationCursor(
                source_generation=generation,
                byte_position=byte_position,
                event_position=event_position,
                last_source_commitment=last_commitment,
                mapping_version=STREAM_MAPPING_VERSION,
            )
            self.cursor = cursor
            return SessionStreamAdvance(
                (), cursor, self.partial_line, tuple(sorted(gaps)), restarted, truncated, rotated
            )

        # A retained partial first line has not established admission. Keep requiring the exact
        # session header until a complete admitted line advances the durable cursor.
        require_admission = event_position == 0
        try:
            with path.open("rb") as handle:
                handle.seek(byte_position + partial_source_bytes)
                chunk = handle.read(to_read)
                data = chunk if oversized_state is not None else self.partial_line + chunk
                if oversized_state is None and b"\n" not in data:
                    # A live JSONL writer can leave a legal line unterminated across hook passes.
                    # Read ahead only when the ordinary chunk contains no delimiter, and never
                    # beyond the profile's admitted line bound plus its terminator. This lets a
                    # previously dropped read-cache tail recover as soon as the newline arrives
                    # without making every routine reconcile scan a full maximum-sized line.
                    unread = max(0, size - (byte_position + len(data)))
                    read_ahead = min(
                        unread,
                        max(0, ROLLOUT_MAX_LINE_BYTES + 1 - len(data)),
                    )
                    if read_ahead:
                        data += handle.read(read_ahead)
        except OSError:
            gaps.add(ObservationGapCode.SOURCE_LAG.value)
            return SessionStreamAdvance(
                (),
                self.cursor,
                self.partial_line,
                tuple(sorted(gaps)),
                restarted,
                truncated,
                rotated,
            )

        if oversized_state is not None:
            newline = data.find(b"\n")
            if newline < 0:
                cursor = ObservationCursor(
                    source_generation=generation,
                    byte_position=byte_position + len(data),
                    event_position=event_position,
                    last_source_commitment=last_commitment,
                    mapping_version=STREAM_MAPPING_VERSION,
                )
                self.cursor = cursor
                self.partial_line = _encode_oversized_partial(
                    line_start=oversized_state.line_start,
                    prefix_commitment=f"hmac-sha256:{oversized_state.prefix_digest}",
                    session_commitment=self.session_commitment,
                    source_generation=generation,
                    source_identity=source_identity,
                    key_material=self.key_material,
                )
                gaps.add(ObservationGapCode.TRUNCATED_PAYLOAD.value)
                if not data and size > byte_position:
                    gaps.add(ObservationGapCode.SOURCE_LAG.value)
                return SessionStreamAdvance(
                    (),
                    cursor,
                    self.partial_line,
                    tuple(sorted(gaps, key=str.encode)),
                    restarted,
                    truncated,
                    rotated,
                )

            byte_end = byte_position + newline + 1
            last_commitment = _oversized_line_commitment(
                state=oversized_state,
                byte_end=byte_end,
                session_commitment=self.session_commitment,
                source_generation=generation,
                source_identity=source_identity,
                key_material=self.key_material,
            )
            if not require_admission:
                event_position += 1
            cursor = ObservationCursor(
                source_generation=generation,
                byte_position=byte_end,
                event_position=event_position,
                last_source_commitment=last_commitment,
                mapping_version=STREAM_MAPPING_VERSION,
            )
            self.cursor = cursor
            self.partial_line = b""
            if require_admission:
                # The oversized first line never established admission. Leaving
                # the ordinal at zero with consumed bytes keeps this generation
                # durably refused instead of quietly admitting later appends.
                gaps.add(ObservationGapCode.UNSUPPORTED_FORMAT.value)
                oversized_envelopes: tuple[ObservationEnvelope, ...] = ()
            else:
                gaps.add(ObservationGapCode.UNSUPPORTED_EVENT.value)
                oversized_envelopes = (
                    _opaque_stream_envelope(
                        session_commitment=self.session_commitment,
                        cursor=cursor,
                    ),
                )
            return SessionStreamAdvance(
                oversized_envelopes,
                cursor,
                b"",
                tuple(sorted(gaps, key=str.encode)),
                restarted,
                truncated,
                rotated,
                classifications=tuple(None for _ in oversized_envelopes),
            )

        if b"\n" not in data and len(data) > ROLLOUT_MAX_LINE_BYTES:
            prefix_commitment = stream_line_commitment(self.key_material, data)
            self.partial_line = _encode_oversized_partial(
                line_start=byte_position,
                prefix_commitment=prefix_commitment,
                session_commitment=self.session_commitment,
                source_generation=generation,
                source_identity=source_identity,
                key_material=self.key_material,
            )
            cursor = ObservationCursor(
                source_generation=generation,
                byte_position=byte_position + len(data),
                event_position=event_position,
                last_source_commitment=last_commitment,
                mapping_version=STREAM_MAPPING_VERSION,
            )
            self.cursor = cursor
            gaps.add(ObservationGapCode.TRUNCATED_PAYLOAD.value)
            return SessionStreamAdvance(
                (),
                cursor,
                self.partial_line,
                tuple(sorted(gaps, key=str.encode)),
                restarted,
                truncated,
                rotated,
            )

        if not data:
            cursor = ObservationCursor(
                source_generation=generation,
                byte_position=byte_position,
                event_position=event_position,
                last_source_commitment=last_commitment,
                mapping_version=STREAM_MAPPING_VERSION,
            )
            self.cursor = cursor
            return SessionStreamAdvance(
                (), cursor, b"", tuple(sorted(gaps)), restarted, truncated, rotated
            )

        try:
            # Admission always re-selects from the header: the profile is the one the exact
            # ``cli_version`` names, never a caller default or the previous generation's choice.
            parsed = parse_codex_rollout_jsonl_from_offset(
                data,
                None if require_admission else self.profile,
                start_ordinal=1,
                require_admission=require_admission,
            )
        except ValueError:
            gaps.add(ObservationGapCode.TRUNCATED_PAYLOAD.value)
            cursor = ObservationCursor(
                source_generation=generation,
                byte_position=byte_position,
                event_position=event_position,
                last_source_commitment=last_commitment,
                mapping_version=STREAM_MAPPING_VERSION,
            )
            self.cursor = cursor
            return SessionStreamAdvance(
                (), cursor, self.partial_line, tuple(sorted(gaps)), restarted, truncated, rotated
            )

        if parsed.profile is not None:
            self.profile = parsed.profile
        consumed = 0
        envelopes: list[ObservationEnvelope] = []
        classifications: list[ObservationClassification | None] = []
        cell_facts: list[CodeModeCellFact | None] = []
        output_exits: list[int | None] = []
        reason_codes: set[str] = set()
        hold = b""
        for index, line in enumerate(parsed.lines):
            if not line.terminated:
                # A tail Codex is still writing is held and re-read once its newline lands; it
                # lost nothing, so it is no ``truncated_payload`` (#1041). Oversize lines and
                # unreadable chunks above keep the gap.
                hold = line.content
                break
            consumed = line.byte_end
            last_commitment = stream_line_commitment(self.key_material, line.content)
            record = next(
                (item for item in parsed.records if item.line_ordinal == line.ordinal),
                None,
            )
            if record is None:
                reason = parsed.reason_codes[index] if index < len(parsed.reason_codes) else None
                status = parsed.statuses[index] if index < len(parsed.statuses) else None
                if reason in _ADMISSION_REASON_TOKENS:
                    reason_codes.add(reason)
                if reason == "unsupported_codex_profile" or (
                    require_admission
                    and index == 0
                    and status in {ImportLineStatus.MALFORMED, ImportLineStatus.OVERSIZED}
                ):
                    # A refused or never-admitted line consumes its bytes but
                    # never advances the event ordinal, so admission stays
                    # required instead of silently lapsing after a rejected
                    # header once event_position moved past zero.
                    gaps.add(ObservationGapCode.UNSUPPORTED_FORMAT.value)
                    continue
                event_position += 1
                if index < len(parsed.statuses):
                    gaps.add(ObservationGapCode.UNSUPPORTED_EVENT.value)
                    envelopes.append(
                        _opaque_stream_envelope(
                            session_commitment=self.session_commitment,
                            cursor=ObservationCursor(
                                source_generation=generation,
                                byte_position=byte_position + consumed,
                                event_position=event_position,
                                last_source_commitment=last_commitment,
                                mapping_version=STREAM_MAPPING_VERSION,
                            ),
                        )
                    )
                    classifications.append(None)
                    cell_facts.append(None)
                    output_exits.append(None)
                continue
            event_position += 1
            abs_cursor = ObservationCursor(
                source_generation=generation,
                byte_position=byte_position + consumed,
                event_position=event_position,
                last_source_commitment=last_commitment,
                mapping_version=STREAM_MAPPING_VERSION,
            )
            # Rewrite record ordinal to the absolute event position for identity stability.
            positioned = CodexParsedRecord(
                event_position,
                record.byte_start,
                record.byte_end,
                record.wrapper_type,
                record.item_type,
                record.value,
            )
            envelopes.append(
                envelope_from_stream_record(
                    positioned,
                    session_commitment=self.session_commitment,
                    cursor=abs_cursor,
                    profile=self.profile,
                    key_material=self.key_material,
                )
            )
            structural, _structural_gaps = structural_from_stream_record(
                record, profile=self.profile
            )
            classifications.append(_stream_record_classification(record, structural))
            cell_facts.append(_code_mode_cell_fact(record))
            output_exits.append(_exec_output_exit_status(record))

        if "unsupported_codex_profile" in parsed.stream_gaps and consumed > 0:
            # A refused chunk holds no tail: the durable refused state is exactly
            # (event_position == 0, consumed bytes, empty partial), and every
            # later line of a refused generation is equally unsupported.
            hold = b""
        new_byte = byte_position + consumed
        self.partial_line = hold
        cursor = ObservationCursor(
            source_generation=generation,
            byte_position=new_byte,
            event_position=event_position,
            last_source_commitment=last_commitment,
            mapping_version=STREAM_MAPPING_VERSION,
        )
        self.cursor = cursor
        # ``truncated_final_line``/``final_newline_absent`` name the held tail: not a loss.
        if "unsupported_codex_profile" in parsed.stream_gaps:
            gaps.add(ObservationGapCode.UNSUPPORTED_FORMAT.value)
        return SessionStreamAdvance(
            tuple(envelopes),
            cursor,
            self.partial_line,
            tuple(sorted(gaps, key=str.encode)),
            restarted,
            truncated,
            rotated,
            tuple(sorted(reason_codes, key=str.encode)),
            tuple(classifications),
            tuple(cell_facts),
            tuple(output_exits),
        )


def should_trigger_stream_reconcile(
    event_name: str,
    *,
    last_reconcile_mono: float | None,
    now_mono: float | None = None,
    session_source: str | None = None,
) -> bool:
    """Decide whether an observe hook should run incremental stream reconciliation."""

    if event_name in {"Stop", "SessionEnd", "PostCompact", "PreCompact"}:
        return True
    if event_name == "SessionStart" and session_source in {"resume", "compact"}:
        return True
    if event_name in _MATERIAL_HOOK_EVENTS:
        return True
    current = time.monotonic() if now_mono is None else now_mono
    if last_reconcile_mono is None:
        return False
    return (current - last_reconcile_mono) >= PERIODIC_RECONCILE_SECONDS


# Codex code mode runs model-written JavaScript in one custom ``exec`` tool; the
# nested ``tools.*`` calls inside a cell fire their own hooks (#917).
_CODE_MODE_CELL_TOOLS: Final = frozenset({"exec"})
# Codex's code-mode poll tool: ``wait`` resumes a yielded ``exec`` cell named by its
# ``cell_id`` argument and returns the cell's further output (#1038 follow-up).
_CODE_MODE_WAIT_TOOL: Final = "wait"
# Codex prepends one host-written status header to every ``exec`` and ``wait`` output
# (``format_script_status`` and ``prepend_script_status`` in ``codex-rs/core/src/tools/code_mode``):
# ``Script running with cell ID <id>`` when the cell yielded, else ``Script completed``,
# ``Script failed`` or ``Script terminated``; then ``Wall time <s> seconds`` and ``Output:``.
# The header is the output's first text item (or the prefix of a plain-text output), so the cell's
# own printed output, which follows it, can never forge it.
_SCRIPT_STATUS_HEADER: Final = re.compile(
    r"\AScript (?:running with cell ID (?P<cell>[A-Za-z0-9][A-Za-z0-9._:-]{0,63})"
    r"|(?P<terminal>completed|failed|terminated))\nWall time [0-9]{1,12}(?:\.[0-9]{1,6})? seconds\n"
    r"Output:\n",
    re.ASCII,
)
_RUNTIME_CELL_ID: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z", re.ASCII)
# Rollout ``event_msg`` item families that never record a tool call. Any other item family read
# while a code-mode cell is open is a nested tool call (or an unknown one) and keeps the cell from
# reading as tool-less (ADR-029 amendment, tb4n5).
_NON_TOOL_ITEM_FAMILIES: Final = frozenset(
    {"AgentMessage", "ContextCompaction", "HookPrompt", "Reasoning", "UserMessage"}
)
# A turn's end, as the rollout records it: a yielded cell nobody waited on is decided here.
_STREAM_TURN_END_ACTIONS: Final = frozenset({"task_complete", "turn_aborted"})


@dataclass(frozen=True, slots=True)
class CodeModeCellFact:
    """One host-written code-mode fact read from a rollout row (#1038 follow-up).

    ``script_status`` is an ``exec``/``wait`` output header: ``running`` with the host's runtime
    ``cell_id`` when the cell yielded, or ``completed``/``failed``/``terminated``. ``wait_call`` is a
    ``wait`` call naming the runtime ``cell_id`` it resumes. Ephemeral adapter facts, parallel to
    the envelopes like the classifications: never copied into an envelope, outbox row or ledger.
    """

    kind: Literal["script_status", "wait_call"]
    status: Literal["running", "completed", "failed", "terminated"] | None
    cell_id: str | None


def _output_status_text(body: JsonObject) -> str | None:
    """The first text of a call output: a plain string, or the first content item's text."""

    output = body.get("output")
    if type(output) is str:
        return output
    if isinstance(output, (tuple, list)) and output:
        first = cast(tuple[JsonValue, ...] | list[JsonValue], output)[0]
        if isinstance(first, Mapping):
            text = cast(Mapping[str, JsonValue], first).get("text")
            if type(text) is str:
                return text
    return None


def _code_mode_cell_fact(record: CodexParsedRecord) -> CodeModeCellFact | None:
    """Read the host's code-mode status header or ``wait`` target from one rollout row."""

    if record.item_type not in _STREAM_CALL_PAIR_ITEMS:
        return None
    body = _structural_body(record)
    if body is None:
        return None
    if record.item_type in {"function_call_output", "custom_tool_call_output"}:
        text = _output_status_text(body)
        match = None if text is None else _SCRIPT_STATUS_HEADER.match(text[:256])
        if match is None:
            return None
        cell = match.group("cell")
        if cell is not None:
            return CodeModeCellFact("script_status", "running", cell)
        terminal = cast(Literal["completed", "failed", "terminated"], match.group("terminal"))
        return CodeModeCellFact("script_status", terminal, None)
    if record.item_type != "function_call" or body.get("name") != _CODE_MODE_WAIT_TOOL:
        return None
    if body.get("namespace") not in (None, ""):
        return None
    raw = body.get("arguments")
    arguments: object = None
    if type(raw) is str and len(raw) <= 4096:
        try:
            arguments = strict_json_parse(raw.encode("utf-8"))
        except ProtocolValueError, TypeError, ValueError, UnicodeError:
            arguments = None
    elif isinstance(raw, Mapping):
        arguments = raw
    if not isinstance(arguments, Mapping):
        return None
    cell = cast(Mapping[str, JsonValue], arguments).get("cell_id")
    if type(cell) is not str or _RUNTIME_CELL_ID.match(cell) is None:
        return None
    return CodeModeCellFact("wait_call", None, cell)


def _code_mode_cell_wrapper(structural: Mapping[str, JsonValue]) -> bool:
    """True for the stream call/output record of one code-mode ``exec`` cell."""

    return (
        structural.get("action") in {"custom_tool_call", "custom_tool_call_output"}
        and structural.get("tool_name") in _CODE_MODE_CELL_TOOLS
    )


def _hooked_tool_item(envelope: ObservationEnvelope) -> bool:
    """True for a rollout ``item_completed`` command, MCP or patch record (#910).

    The same host call fires its own ``PostToolUse`` hook, and since #910 that hook row carries
    the call's exit status itself; the rollout item is normally a second copy under a different
    id (``exec-<uuid>``) that no pairing can join to the hook row.
    """

    return (
        envelope.event_kind == "item_completed"
        and envelope.structural_payload.get("action") in _STREAM_COMPLETED_TOOL_ITEMS
    )


def _hook_post_stated(structural: Mapping[str, JsonValue]) -> bool:
    return (
        type(structural.get("exit_status")) is int
        or type(structural.get("success")) is bool
        or structural.get("denied") is True
    )


_ITEM_CARRIER: Final = "carrier"
_ITEM_COPY: Final = "copy"
_ITEM_PENDING: Final = "pending"
# Closed by the turn's end with no proof of which call it belongs to.
_ITEM_UNPAIRED: Final = "unpaired"
# Workspace reconciles an undecided item may survive while its session stays silent.
PENDING_ROLLOUT_IDLE_RECONCILES: Final = 8
# A turn's end: every tool call of the turn has fired whatever hooks it will fire.
_PAIRING_CLOSE_EVENTS: Final = frozenset({"Stop", "SessionEnd"})


@dataclass(frozen=True, slots=True)
class _PendingRolloutItem:
    source_identity: str
    call_id: str | None
    commitment: str | None
    exit_status: int | None


def _rollout_item_decisions(
    envelopes: tuple[ObservationEnvelope, ...],
    session_commitment: str,
    evicted_open_calls: tuple[tuple[str, str], ...] = (),
) -> dict[str, str]:
    """Decide every rollout tool item of one session against its hook rows (#910).

    The session's stored rows are replayed in arrival order, so an item is decided with exactly
    the hook rows that preceded it, and a later row never changes a decision already made:

    * an item whose id is an outcome-less hook call is that call's outcome (``carrier``; ADR-022
      decision 15 then corrects the hook's ``unknown`` row), and an item whose id is a stated
      hook call is that post's ``copy``;
    * a command item whose exit equals an unpaired stated exit of a hook post for the same
      command commitment is that post's ``copy``;
    * otherwise a command item is ``pending`` until the outcome-less hook calls of its
      commitment can be told apart from the calls it may still be a copy of.

    Items and posts can arrive in either order: the rollout can record a completed call before
    its ``PostToolUse`` is stored. A later post takes a pending item with its own call id, or, if
    stated, a pending item of its commitment with the same exit, as its copy. While an
    outcome-less call of a commitment is owed, its pending items become carriers only once no
    other call of that commitment is open (its ``PreToolUse`` seen, its post not yet): with
    parallel same-command runs, an open call's post may still claim one of them as its copy, and
    taking the oldest or the newest would misattribute a pass and lose a failure. When several
    items remain for fewer owed calls, every one is delivered; a second record is disclosed as
    #909's later run, a lost failure would not be. ``Stop``/``SessionEnd`` close the turn: owed
    calls take every pending item of their commitment. Any other pending command item is a copy
    only when a stored stated post proves it (same call id, or same commitment and exit);
    otherwise it is ``unpaired`` and delivered with ``unpaired_event`` rather than lost. The
    replay is bounded by the local envelope ring. It starts with ``evicted_open_calls`` open:
    calls whose ``PreToolUse`` the ring evicted before their post was evicted or the turn
    ended, so a truncated window never makes a still-running parallel call look finished.
    """

    unstated_calls: dict[str, str | None] = {}
    owed: dict[str, int] = {}
    stated_exits: dict[str, list[int | None]] = {}
    stated_calls: set[str] = set()
    seen_exits: dict[str, set[int | None]] = {}
    open_calls: dict[str, set[str]] = {}
    for open_commitment, open_call in evicted_open_calls:
        open_calls.setdefault(open_commitment, set()).add(open_call)
    pending: list[_PendingRolloutItem] = []
    decisions: dict[str, str] = {}

    def proven_copy(item: _PendingRolloutItem) -> bool:
        """A stored stated post names this item's call, or its command with the same exit.

        An MCP or patch item has no command commitment and no join key beyond its id, so the
        turn's end leaves it local as its hooked call's copy (a disclosed limit, #910).
        """

        if item.commitment is None:
            return True
        if item.call_id is not None and item.call_id in stated_calls:
            return True
        return item.exit_status in seen_exits.get(item.commitment, set())

    def decide(item: _PendingRolloutItem, decision: str) -> None:
        pending.remove(item)
        decisions[item.source_identity] = decision

    def settle(commitment: str | None, *, closing: bool = False) -> None:
        if commitment is None or owed.get(commitment, 0) <= 0:
            return
        if open_calls.get(commitment) and not closing:
            return
        waiting = [item for item in pending if item.commitment == commitment]
        for item in waiting:
            decide(item, _ITEM_CARRIER)
        owed[commitment] = max(0, owed[commitment] - len(waiting))

    for envelope in envelopes:
        if envelope.session_commitment != session_commitment:
            continue
        structural = envelope.structural_payload
        call_id = _token(structural.get("tool_call_id"))
        commitment = _token(structural.get("command_commitment"))
        exit_status = structural.get("exit_status")
        exit_fact = exit_status if type(exit_status) is int else None
        if envelope.source is ObservationSource.CODEX_HOOK:
            kind = envelope.event_kind
            if kind == "PreToolUse":
                if call_id is not None and commitment is not None:
                    open_calls.setdefault(commitment, set()).add(call_id)
                continue
            if kind in _PAIRING_CLOSE_EVENTS:
                open_calls.clear()
                for owed_commitment in {item.commitment for item in pending}:
                    settle(owed_commitment, closing=True)
                for item in tuple(pending):
                    decide(item, _ITEM_COPY if proven_copy(item) else _ITEM_UNPAIRED)
                continue
            if kind != "PostToolUse":
                continue
            if call_id is not None and commitment is not None:
                open_calls.get(commitment, set()).discard(call_id)
            joined = (
                None
                if call_id is None
                else next((item for item in pending if item.call_id == call_id), None)
            )
            if not _hook_post_stated(structural):
                if joined is not None:
                    decide(joined, _ITEM_CARRIER)
                else:
                    if call_id is not None:
                        unstated_calls[call_id] = commitment
                    if commitment is not None:
                        owed[commitment] = owed.get(commitment, 0) + 1
                settle(commitment)
                continue
            if call_id is not None and call_id in unstated_calls:
                # A later stated post of the same call settles it.
                earlier = unstated_calls.pop(call_id)
                if earlier is not None and owed.get(earlier, 0) > 0:
                    owed[earlier] -= 1
            if call_id is not None:
                stated_calls.add(call_id)
            if commitment is not None:
                seen_exits.setdefault(commitment, set()).add(exit_fact)
            if joined is None and commitment is not None:
                joined = next(
                    (
                        item
                        for item in pending
                        if item.commitment == commitment and item.exit_status == exit_fact
                    ),
                    None,
                )
            if joined is not None:
                decide(joined, _ITEM_COPY)
            elif commitment is not None:
                stated_exits.setdefault(commitment, []).append(exit_fact)
            settle(commitment)
            continue
        if envelope.source is not ObservationSource.CODEX_SESSION_STREAM or not _hooked_tool_item(
            envelope
        ):
            continue
        if envelope.source_identity in decisions or any(
            item.source_identity == envelope.source_identity for item in pending
        ):
            continue
        if call_id is not None and call_id in unstated_calls:
            decisions[envelope.source_identity] = _ITEM_CARRIER
            earlier = unstated_calls.pop(call_id)
            if earlier is not None and owed.get(earlier, 0) > 0:
                owed[earlier] -= 1
        elif call_id is not None and call_id in stated_calls:
            decisions[envelope.source_identity] = _ITEM_COPY
        elif commitment is not None and exit_fact in stated_exits.get(commitment, []):
            stated_exits[commitment].remove(exit_fact)
            decisions[envelope.source_identity] = _ITEM_COPY
        else:
            pending.append(
                _PendingRolloutItem(envelope.source_identity, call_id, commitment, exit_fact)
            )
            settle(commitment)
    for item in pending:
        decisions[item.source_identity] = _ITEM_PENDING
    return decisions


def _session_rollout_decisions(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
) -> dict[str, str] | None:
    """The session's rollout item decisions, or ``None`` when no tool hook fired or unreadable."""

    counter = getattr(store, "codex_tool_hook_count", None)
    lister = getattr(store, "list_envelopes", None)
    if not callable(counter) or not callable(lister):
        return None
    try:
        count: object = counter(workspace_commitment, session_commitment)
        if type(count) is not int or count <= 0:
            return None
        envelopes = cast(tuple[ObservationEnvelope, ...], lister(workspace_commitment))
        evicted = getattr(store, "evicted_open_calls", None)
        open_calls = (
            cast(tuple[tuple[str, str], ...], evicted(workspace_commitment, session_commitment))
            if callable(evicted)
            else ()
        )
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return None
    return _rollout_item_decisions(envelopes, session_commitment, open_calls)


def _hooked_tool_item_decision(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    envelope: ObservationEnvelope,
) -> str | None:
    """How one rollout tool item is handled on arrival (#910, beside #917's cells).

    ``None`` delivers it: the envelope is not a completed tool item, no Codex tool hook fired
    in the session, or the store lacks the seams or is unreadable. Otherwise it is held (kept
    in the local store only) unless it is the ``carrier`` of a hooked call's outcome; a
    ``pending`` item is held until a later hook post decides it.
    """

    if not _hooked_tool_item(envelope):
        return None
    decisions = _session_rollout_decisions(store, workspace_commitment, session_commitment)
    if decisions is None:
        return None
    return decisions.get(envelope.source_identity, _ITEM_PENDING)


def _deliver_pending_rollout_item(
    store: LocalObservationStore,
    workspace_commitment: str,
    item: PendingRolloutItem,
    *,
    unpaired: bool,
) -> bool:
    """Deliver one held rollout item and settle its account in one batch (#910).

    Later stream rows may already have reached the task, whose per-source cursor refuses an
    older position (``cursor_stale``), so the item is stamped with the session's committed
    stream frontier at release time. An item whose pairing was forgotten carries
    ``unpaired_event``, so the receipt discloses that its attribution is unproven.
    """

    envelope = item.envelope
    if not _stream_self_observation_deliverable(envelope):
        # A held FinishUP self-read (an item an older build held, or one no hook post decided) is
        # settled locally: releasing it would append FinishUP's own read to the ledger it read.
        try:
            store.settle_pending_rollout_item(
                workspace_commitment, item.session_commitment, item.source_identity
            )
        except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
            return False
        return True
    frontier = store.get_stream_cursor(workspace_commitment, item.session_commitment)
    if frontier is not None and envelope.cursor.is_stale_relative_to(frontier):
        envelope = replace(envelope, cursor=frontier)
    if unpaired:
        envelope = replace(
            envelope,
            gap_codes=tuple(
                sorted(
                    {*envelope.gap_codes, ObservationGapCode.UNPAIRED_EVENT.value},
                    key=str.encode,
                )
            ),
        )
    try:
        with store.batched(workspace_commitment):
            if not store.flush_selected_admission(
                workspace_commitment,
                summary_builder=build_routine_read_summary,
                force=True,
                material_boundary=True,
            ):
                return False
            plan = _restore_stream_individual_deliveries(
                store.prepare_selected_admission(
                    workspace_commitment,
                    item.codex_session_id,
                    envelope,
                    fence="",
                    focused=False,
                    routine_candidate=False,
                    proven_routine_success=False,
                    summary_builder=build_routine_read_summary,
                )
            )
            if not store.commit_selected_admission(
                workspace_commitment,
                plan,
                incoming=envelope,
                newly_observed=True,
                replayable=True,
            ):
                return False
            store.settle_pending_rollout_item(
                workspace_commitment, item.session_commitment, item.source_identity
            )
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return False
    return True


def _release_decided_rollout_items(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
) -> bool:
    """Deliver, exactly once, each held rollout item a later hook row made a carrier (#910).

    A pending item a later post, or the turn's end with a stored proof, made a copy is settled
    and stays local. One the turn's end could not prove, one the envelope ring no longer holds,
    one idle for ``PENDING_ROLLOUT_IDLE_RECONCILES`` workspace reconciles, and the oldest past
    ``MAX_PENDING_ROLLOUT_ITEMS`` are delivered with ``unpaired_event`` rather than lost. Returns ``False`` when an admission could not commit; the item stays pending.
    """

    lister = getattr(store, "pending_rollout_items", None)
    ager = getattr(store, "age_pending_rollout_items", None)
    if not callable(lister) or not callable(ager):
        return True
    try:
        aged = cast(tuple[PendingRolloutItem, ...], ager(workspace_commitment))
        own = cast(tuple[PendingRolloutItem, ...], lister(workspace_commitment, session_commitment))
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return True
    # A session that stopped storing rows (a crash, or a call that never finishes) cannot
    # decide its items any more; after a bounded number of workspace reconciles they are
    # delivered with ``unpaired_event`` instead of waiting for the account's size bound.
    for item in aged:
        if item.idle_reconciles < PENDING_ROLLOUT_IDLE_RECONCILES:
            continue
        if not _deliver_pending_rollout_item(store, workspace_commitment, item, unpaired=True):
            return False
    if aged:
        stale = {
            item.source_identity
            for item in aged
            if item.idle_reconciles >= PENDING_ROLLOUT_IDLE_RECONCILES
        }
        own = tuple(item for item in own if item.source_identity not in stale)
    decisions = (
        _session_rollout_decisions(store, workspace_commitment, session_commitment) if own else None
    )
    if decisions is not None:
        for item in own:
            decision = decisions.get(item.source_identity)
            if decision == _ITEM_PENDING:
                continue
            if decision == _ITEM_COPY:
                try:
                    store.settle_pending_rollout_item(
                        workspace_commitment, session_commitment, item.source_identity
                    )
                except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
                    return False
                continue
            if not _deliver_pending_rollout_item(
                store, workspace_commitment, item, unpaired=decision != _ITEM_CARRIER
            ):
                return False
    try:
        remaining = cast(tuple[PendingRolloutItem, ...], lister(workspace_commitment))
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return True
    for item in remaining[: max(0, len(remaining) - MAX_PENDING_ROLLOUT_ITEMS)]:
        if not _deliver_pending_rollout_item(store, workspace_commitment, item, unpaired=True):
            return False
    return True


def _profile_records_tool_items(profile: CodexCapabilityProfile | None) -> bool:
    """Whether a rollout profile records every completed host tool call as an item (0.150.1+)."""

    return profile is not None and "CommandExecution" in profile.item_types


# A held rollout item read at least this long before a check's observation wait is released by
# that wait (tb4n5): its hook post, if one is coming, would normally have landed by now.
HELD_ROLLOUT_CHECK_RELEASE_SECONDS: Final = 10.0


def release_held_rollout_items_for_check(
    store: LocalObservationStore,
    workspace_commitment: str,
    include: Callable[[PendingRolloutItem], bool],
    *,
    now: float | None = None,
    min_age_seconds: float = HELD_ROLLOUT_CHECK_RELEASE_SECONDS,
) -> tuple[str, ...]:
    """Deliver a check's held rollout items before it freezes; return those still held (tb4n5).

    An undecided item (#910) waits for a hook post that may never come; in tb4n5 biped S one was
    held 13 minutes and delivered 3 s after the check that awaited observations, so it made that
    check stale. A check's observation wait now releases each of its task's items (``include``)
    read at least ``min_age_seconds`` ago, exactly as the idle bound would: delivered once with
    ``unpaired_event``, so its unproven attribution stays disclosed and no outcome is decided for
    it. A younger item stays held; its source identity is returned so the wait counts it as the
    bounded remainder instead of reporting ``complete``. A release that cannot commit leaves the
    item held and counted.
    """

    try:
        items = store.pending_rollout_items(workspace_commitment)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return ()
    current = time.time() if now is None else now
    held: list[str] = []
    for item in items:
        if not include(item):
            continue
        read_at = item.envelope.receipt_time.as_datetime().timestamp()
        if current - read_at < min_age_seconds or not _deliver_pending_rollout_item(
            store, workspace_commitment, item, unpaired=True
        ):
            held.append(item.source_identity)
    return tuple(held)


def _code_mode_cell_held(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    envelope: ObservationEnvelope,
    fact: CodeModeCellFact | None = None,
    *,
    tool_items_recorded: bool = False,
) -> bool:
    """Whether one code-mode ``exec`` cell row stays in the local store only (#917).

    The decision is per cell: its call is always held, and its output stays
    local only when a tool hook of the session was ingested after the call was
    read and settled by a complete earlier pass that did not see the output, so
    a cell whose tools fire no hook keeps its record through its output. A cell
    that made no tool call, or only FinishUP's own, stays local too. A yield output
    (``Script running with cell ID``) is held with its still-open cell, which its
    terminal ``wait`` output decides (#1038 follow-up). A store without the seams,
    an unreadable one, or a row without a call id answers ``False`` so the row is
    delivered as before.
    """

    structural = envelope.structural_payload
    if not _code_mode_cell_wrapper(structural):
        return False
    call_id = _token(structural.get("tool_call_id"))
    if call_id is None:
        return False
    try:
        if structural.get("action") == "custom_tool_call":
            begin = getattr(store, "begin_code_mode_cell", None)
            return (
                callable(begin) and begin(workspace_commitment, session_commitment, call_id) is True
            )
        if fact is not None and fact.status == "running" and fact.cell_id is not None:
            hold = getattr(store, "yield_code_mode_cell", None)
            if callable(hold):
                return (
                    hold(workspace_commitment, session_commitment, call_id, fact.cell_id, envelope)
                    is True
                )
        finish = getattr(store, "finish_code_mode_cell", None)
        if not callable(finish):
            return False
        return (
            finish(
                workspace_commitment,
                session_commitment,
                call_id,
                tool_items_recorded=tool_items_recorded,
            )
            is True
        )
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return False


def _note_code_mode_wait(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    envelope: ObservationEnvelope,
    fact: CodeModeCellFact | None,
) -> bool:
    """Link a ``wait`` call to the yielded cell it names; ``False`` only when it could not persist."""

    structural = envelope.structural_payload
    if (
        fact is None
        or fact.kind != "wait_call"
        or fact.cell_id is None
        or structural.get("action") != "function_call"
        or structural.get("tool_name") != _CODE_MODE_WAIT_TOOL
    ):
        return True
    wait_call = _token(structural.get("tool_call_id"))
    note = getattr(store, "note_code_mode_wait", None)
    if wait_call is None or not callable(note):
        return True
    try:
        note(workspace_commitment, session_commitment, wait_call, fact.cell_id)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return False
    return True


def _owed_code_mode_cell_outputs(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    envelope: ObservationEnvelope,
    fact: CodeModeCellFact | None,
    *,
    tool_items_recorded: bool,
) -> tuple[tuple[str, ObservationEnvelope], ...] | None:
    """Held yield outputs this row decides to deliver as their cells' records (#1038 follow-up).

    A terminal ``wait`` output (``Script completed``/``failed``/``terminated``) decides the cell
    its ``wait`` call named; a turn's end decides every yielded cell of the session nobody
    waited on. Returns ``None`` only when the store could not decide.
    """

    structural = envelope.structural_payload
    action = structural.get("action")
    try:
        if action in _STREAM_TURN_END_ACTIONS:
            close = getattr(store, "close_yielded_code_mode_cells", None)
            if not callable(close):
                return ()
            return cast(
                tuple[tuple[str, ObservationEnvelope], ...],
                close(
                    workspace_commitment,
                    session_commitment,
                    tool_items_recorded=tool_items_recorded,
                ),
            )
        if (
            fact is None
            or fact.kind != "script_status"
            or fact.status in (None, "running")
            or action != "function_call_output"
            or structural.get("tool_name") != _CODE_MODE_WAIT_TOOL
        ):
            return ()
        wait_call = _token(structural.get("tool_call_id"))
        decide = getattr(store, "decide_yielded_code_mode_cell", None)
        if wait_call is None or not callable(decide):
            return ()
        owed = decide(
            workspace_commitment,
            session_commitment,
            wait_call,
            tool_items_recorded=tool_items_recorded,
        )
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return None
    return () if owed is None else (cast(tuple[str, ObservationEnvelope], owed),)


def _deliver_held_cell_output(
    store: LocalObservationStore,
    workspace_commitment: str,
    codex_session_id: str,
    cell_key: str,
    held: ObservationEnvelope,
    cursor: ObservationCursor,
) -> bool:
    """Deliver a decided yielded cell's held output as the cell's record (#1038 follow-up).

    Rows after the yield already reached the task, whose per-source cursor refuses an older
    position, so the output is stamped with the position of the row that decided the cell.
    """

    envelope = (
        held if not held.cursor.is_stale_relative_to(cursor) else replace(held, cursor=cursor)
    )
    try:
        with store.batched(workspace_commitment):
            if not store.flush_selected_admission(
                workspace_commitment,
                summary_builder=build_routine_read_summary,
                force=True,
                material_boundary=True,
            ):
                return False
            plan = _restore_stream_individual_deliveries(
                store.prepare_selected_admission(
                    workspace_commitment,
                    codex_session_id,
                    envelope,
                    fence="",
                    focused=False,
                    routine_candidate=False,
                    proven_routine_success=False,
                    summary_builder=build_routine_read_summary,
                )
            )
            if not store.commit_selected_admission(
                workspace_commitment,
                plan,
                incoming=envelope,
                newly_observed=True,
                replayable=True,
            ):
                return False
            settle = getattr(store, "settle_code_mode_cell_output", None)
            if callable(settle):
                settle(workspace_commitment, cell_key)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return False
    return True


def _note_code_mode_nested_item(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    envelope: ObservationEnvelope,
) -> bool:
    """Mark the session's open code-mode cells with one nested rollout row (#1038).

    A completed tool item is the rollout's record of a call a cell made: a FinishUP MCP item keeps
    an open cell FinishUP-only, any other tool item or an uninterpretable row does not. "FinishUP MCP
    item" is the later-material rule's reading (``finishup_tool_spelling``): ``mcp__<FinishUP
    server>__<tool>``, or the bare FinishUP tool name only an item without a ``server`` keeps;
    another server's tool of the same name is ``mcp__<server>__<tool>``, or names no tool when
    that server cannot be spelled so, and is not FinishUP's. Returns
    ``False`` only when the mark could not persist, so the cursor never passes a row whose mark
    a later output decision would miss.
    """

    action = envelope.structural_payload.get("action")
    tool_item = False
    if envelope.event_kind == "unsupported_event":
        finishup_owned = False
    elif _hooked_tool_item(envelope):
        structural = envelope.structural_payload
        finishup_owned = (
            structural.get("action") == "McpToolCall"
            and finishup_tool_spelling(structural.get("tool_name")) is not None
        )
        tool_item = True
    elif (
        type(action) is str
        and action[:1].isupper()
        and action not in _NON_TOOL_ITEM_FAMILIES
        and envelope.source is ObservationSource.CODEX_SESSION_STREAM
    ):
        # Any other completed item family (a spawned agent, a web search, a family this reader
        # does not name) is a tool call too: the cell is not FinishUP-only, nor tool-less (tb4n5).
        finishup_owned = False
    else:
        return True
    note = getattr(store, "note_code_mode_nested_item", None)
    if not callable(note):
        return True
    try:
        note(
            workspace_commitment,
            session_commitment,
            finishup_owned=finishup_owned,
            tool_item=tool_item,
        )
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return False
    return True


def _close_pre_only_attempt(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    envelope: ObservationEnvelope,
) -> None:
    """Let a newly read ``FileChange`` item close a pre-only shell patch attempt (#1041).

    Codex intercepts a shell ``apply_patch <<EOF`` and fires only its ``PreToolUse``; the patch
    item the rollout writes is the observed change that closes that pending attempt. A failed
    write only leaves the attempt to expire with ``pending_attempt_expired``, as before.
    """

    if not (
        envelope.event_kind == "item_completed"
        and envelope.structural_payload.get("action") == "FileChange"
    ):
        return
    close = getattr(store, "close_pre_only_attempt", None)
    if not callable(close):
        return
    try:
        close(
            workspace_commitment,
            session_commitment,
            _token(envelope.structural_payload.get("tool_call_id")),
        )
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return


def _code_mode_pass_snapshot(
    store: LocalObservationStore, workspace_commitment: str, session_commitment: str
) -> int | None:
    """Read the session's tool-hook stamp before a pass reads; ``None`` settles nothing."""

    snapshot = getattr(store, "code_mode_pass_snapshot", None)
    if not callable(snapshot):
        return None
    try:
        value = snapshot(workspace_commitment, session_commitment)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return None
    return value if type(value) is int and value > 0 else None


def _settle_code_mode_pass(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
    snapshot: int,
) -> None:
    """Settle the pre-pass tool hooks after a complete pass; failure only delays (#917).

    An unsettled hook never keeps a cell local, so a failed write can at most
    deliver a cell's output beside its nested hooks, never lose the cell.
    """

    settle = getattr(store, "settle_code_mode_pass", None)
    if not callable(settle):
        return
    try:
        settle(workspace_commitment, session_commitment, snapshot)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        pass


def _stream_phase(structural: Mapping[str, JsonValue]) -> str:
    """Map a rollout tool record to the hook phase the delivery policy speaks."""

    action = structural.get("action")
    if action in {"function_call", "custom_tool_call"}:
        return "PreToolUse"
    if action in {"function_call_output", "custom_tool_call_output"}:
        return "PostToolUse"
    return ""


def _self_observation_phase(envelope: ObservationEnvelope) -> str:
    """The hook phase the self-observation policy (#564) reads for one stream envelope.

    A completed ``McpToolCall`` item (``event_msg``/``item_completed``) is the rollout's record of
    a finished MCP call, the stream twin of that call's ``PostToolUse`` hook. Read as phase-less,
    a successful FinishUP ``status`` read was delivered and materialized as action, result and
    evidence, moving the very ledger the agent was polling (tb4 n5 S arm). The item keeps its
    closed outcome facts, so an explicit failure is still delivered by the policy. Only the policy
    reads this phase; the routine classifier keeps reading ``_stream_phase``.
    """

    if _hooked_tool_item(envelope) and envelope.structural_payload.get("action") == "McpToolCall":
        return "PostToolUse"
    return _stream_phase(envelope.structural_payload)


def _stream_self_observation_deliverable(envelope: ObservationEnvelope) -> bool:
    """Whether a stream envelope carries evidence beyond FinishUP serving its own call (#564)."""

    return self_observation_deliverable(
        _self_observation_phase(envelope), envelope.structural_payload
    )


def _pair_stream_tool_name(
    envelope: ObservationEnvelope,
    call_tools: dict[str, str],
    *,
    routine_candidate: bool = False,
) -> ObservationEnvelope:
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    action = structural.get("action")
    call_id = _token(structural.get("tool_call_id"))
    tool_name = _token(structural.get("tool_name"))
    if call_id is None:
        return envelope
    if action in {"function_call", "custom_tool_call"} and tool_name is not None:
        if call_id not in call_tools and len(call_tools) >= 256:
            call_tools.pop(next(iter(call_tools)))
        call_tools[call_id] = _encode_stream_call_tool(
            tool_name, routine_candidate=routine_candidate
        )
        return envelope
    if action not in {"function_call_output", "custom_tool_call_output"}:
        return envelope
    paired, _candidate = _decode_stream_call_tool(call_tools.get(call_id))
    if paired is None:
        return replace(
            envelope,
            gap_codes=tuple(
                sorted(
                    {*envelope.gap_codes, ObservationGapCode.UNPAIRED_EVENT.value},
                    key=str.encode,
                )
            ),
        )
    gaps = set(envelope.gap_codes)
    if tool_name is not None and tool_name != paired:
        gaps.add(ObservationGapCode.DEDUP_CONFLICT.value)
    return replace(
        envelope,
        structural_payload=JsonObject({**dict(structural), "tool_name": paired}),
        gap_codes=tuple(sorted(gaps, key=str.encode)),
    )


def _stream_selection_context(
    store: LocalObservationStore,
    workspace_commitment: str,
    codex_session_id: str,
    envelope: ObservationEnvelope,
    *,
    mode: ObservationMode,
    classification: ObservationClassification,
) -> tuple[ObservationEnvelope, str]:
    """Attach route-bound selection metadata when the local authority is real.

    A stream may be readable before a Codex session has an active FinishUP route.
    In that case the caller must use individual admission.  Empty fences are
    deliberately not synthesized from workspace/session values.
    """

    try:
        state_root = getattr(store, "_state_root", None)
        mapping = load_mapping(codex_session_id, _state=state_root)
        authority = store.content_capture_authority(workspace_commitment)
        if mapping is None or authority is None or not authority.active:
            return envelope, ""
        epoch = store.selection_epoch(workspace_commitment)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return envelope, ""
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    annotated = JsonObject(
        {
            **dict(structural),
            "selection_task_id": mapping.yoetz_task_id,
            "selection_session_id": mapping.yoetz_session_id,
            "selection_writer_id": mapping.yoetz_writer_id,
            "selection_authority_generation": authority.generation,
        }
    )
    delegate = structural.get("subagent_id")
    parent_call = structural.get("parent_tool_call_id")
    fence = canonical_digest(
        JsonObject(
            {
                "route": mapping.yoetz_task_id,
                "task": mapping.yoetz_task_id,
                "session": mapping.yoetz_session_id,
                "writer": mapping.yoetz_writer_id,
                "host_session": envelope.session_commitment,
                "source": envelope.source.value,
                "generation": envelope.cursor.source_generation,
                "authority": authority.generation,
                "epoch": epoch,
                "delegate": delegate,
                "parent_call": parent_call,
                "policy": classification.version,
                "classification": classification.version,
                "mode": mode.value,
            }
        )
    )
    return replace(envelope, structural_payload=annotated), fence


def _stream_selection_pressure(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_commitment: str,
) -> object | None:
    """Read the store's pressure decision without making it a stream dependency.

    Older local stores have no pressure projection.  They retain the historic
    individual stream path; once the selection-aware store is present, any
    failed pressure read is treated as a closed safety failure by the caller.
    """

    updater = getattr(store, "update_selection_pressure", None)
    if not callable(updater):
        return None
    try:
        return updater(workspace_commitment, session_commitment)
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return False


def _stream_selection_history_gaps(
    store: LocalObservationStore,
    workspace_commitment: str,
    envelope: ObservationEnvelope,
) -> tuple[str, ...]:
    """Return exact-lane selection loss that must travel with this admission.

    The store can only attribute a prior non-replayable loss after the current
    envelope has the authenticated route fields attached.  Keep this lookup
    optional for older stores and fail closed to the envelope's own gaps when
    the projection is unavailable or malformed.
    """

    lookup = getattr(store, "selection_history_gaps", None)
    if not callable(lookup):
        return ()
    try:
        inherited = cast(tuple[object, ...], lookup(workspace_commitment, envelope))
    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
        return ()
    if type(inherited) is not tuple:
        return ()
    return tuple(gap for gap in inherited if type(gap) is str and gap in _OBSERVATION_GAP_CODES)


def reconcile_session_stream(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    session_commitment: str,
    codex_session_id: str,
    locator: CodexSessionStreamLocator,
    hook_provided_path: str | None = None,
) -> dict[str, JsonValue]:
    """Advance the session stream cursor and ingest envelopes. Path stays local-only."""

    path = locator.resolve(session_id=codex_session_id, hook_provided_path=hook_provided_path)
    if path is None:
        return {
            "accepted": 0,
            "duplicates": 0,
            "gaps": (ObservationGapCode.SOURCE_LAG.value,),
            "resolved": False,
        }
    return reconcile_session_stream_path(
        store,
        workspace_commitment=workspace_commitment,
        session_commitment=session_commitment,
        codex_session_id=codex_session_id,
        path=path,
    )


def reconcile_session_stream_path(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    session_commitment: str,
    codex_session_id: str,
    path: Path,
) -> dict[str, JsonValue]:
    """Reconcile one path under one durable local-store batch."""

    with store.batched(workspace_commitment):
        return _reconcile_session_stream_path(
            store,
            workspace_commitment=workspace_commitment,
            session_commitment=session_commitment,
            codex_session_id=codex_session_id,
            path=path,
        )


def _reconcile_session_stream_path(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    session_commitment: str,
    codex_session_id: str,
    path: Path,
) -> dict[str, JsonValue]:
    """Reconcile a locally selected path with the same durable frontier on every entry point."""

    if path.name.lower().endswith(".jsonl.zst"):
        store.note_coverage_gap(workspace_commitment, ObservationGapCode.UNSUPPORTED_FORMAT.value)
        store.note_stream_reconcile(workspace_commitment)
        return {
            "accepted": 0,
            "duplicates": 0,
            "gaps": (ObservationGapCode.UNSUPPORTED_FORMAT.value,),
            "byte_position": 0,
            "event_position": 0,
            "generation": 1,
            "admission": "incompatible",
            "admission_provenance": None,
            "admission_reasons": (),
            "rotated": False,
            "truncated": False,
            "resolved": True,
        }
    existing = store.get_stream_cursor(workspace_commitment, session_commitment)
    mapping_reset = existing is not None and existing.mapping_version != STREAM_MAPPING_VERSION
    if existing is None or mapping_reset:
        existing = ObservationCursor(
            source_generation=(1 if existing is None else existing.source_generation + 1),
            byte_position=0,
            event_position=0,
            last_source_commitment=_EMPTY_COMMITMENT,
            mapping_version=STREAM_MAPPING_VERSION,
        )
    partial = (
        b"" if mapping_reset else store.get_stream_partial(workspace_commitment, session_commitment)
    )
    call_tools = (
        {}
        if mapping_reset
        else store.stream_call_tools_for_session(
            workspace_commitment,
            session_commitment,
            source_generation=existing.source_generation,
        )
    )
    prior_call_tools = dict(call_tools)
    source_identity = (
        None
        if mapping_reset
        else store.stream_source_identity_for_session(workspace_commitment, session_commitment)
    )
    # The profile persisted with the cursor is the one this generation's header admitted. A
    # missing or no-longer-supported id makes the reader replay from the header (CURSOR_STALE)
    # rather than parse admitted lines under a guessed vocabulary.
    prior_profile_id = (
        None
        if mapping_reset
        else store.stream_profile_for_session(workspace_commitment, session_commitment)
    )
    reader = SessionStreamReader(
        session_commitment=session_commitment,
        profile=stream_profile_from_id(prior_profile_id),
        cursor=existing,
        key_material=store.key_material(),
        partial_line=partial,
        _source_identity=source_identity,
    )
    # Tool hooks ingested before this pass reads fired before any row it does
    # not see was written; a complete pass settles them for code-mode cells (#917).
    hook_snapshot = _code_mode_pass_snapshot(store, workspace_commitment, session_commitment)
    advance = reader.advance(path)
    if advance.cursor.source_generation != existing.source_generation:
        call_tools.clear()
    accepted = 0
    duplicates = 0
    overflow = False
    delivery_blocked = False
    committed_cursor = existing
    # Source rotation/truncation starts a new selection lane.  Flush the old
    # lane before any new-generation envelope can move the stream frontier.
    if advance.rotated or advance.truncated or advance.restarted:
        try:
            boundary_ok = store.flush_selected_admission(
                workspace_commitment,
                summary_builder=build_routine_read_summary,
                force=True,
                material_boundary=True,
            )
        except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
            boundary_ok = False
        if not boundary_ok:
            delivery_blocked = True

    # Hook posts stored since the last pass may decide rollout items held as pending; deliver
    # those first, in their stream order, ahead of anything this pass reads (#910).
    if not delivery_blocked and not _release_decided_rollout_items(
        store, workspace_commitment, session_commitment
    ):
        overflow = True
        delivery_blocked = True

    advance_classifications = advance.classifications
    advance_cell_facts = advance.cell_facts
    advance_output_exits = advance.output_exits
    tool_items_recorded = _profile_records_tool_items(reader.profile)
    for index, unpaired_envelope in enumerate(advance.envelopes):
        if delivery_blocked:
            break
        base_classification = (
            advance_classifications[index] if index < len(advance_classifications) else None
        )
        cell_fact = advance_cell_facts[index] if index < len(advance_cell_facts) else None
        candidate_call_tools = dict(call_tools)
        structural = cast(Mapping[str, JsonValue], unpaired_envelope.structural_payload)
        call_id = _token(structural.get("tool_call_id"))
        paired_tool, paired_candidate = _decode_stream_call_tool(
            candidate_call_tools.get(call_id) if call_id is not None else None
        )
        # PR #1080: the stream sees no before/after workspace fingerprint, and command text cannot
        # prove a shell call read only, so a shell call never joins a routine-read summary here.
        # It may still be an explicitly protected read, which is delivered individually anyway.
        shell_call = _stream_shell_tool(
            paired_tool
            if paired_tool is not None
            else unpaired_envelope.structural_payload.get("tool_name")
        )
        envelope = _pair_stream_tool_name(
            unpaired_envelope,
            candidate_call_tools,
            routine_candidate=(
                False if base_classification is None else base_classification.routine_candidate
            ),
        )
        output_exit = advance_output_exits[index] if index < len(advance_output_exits) else None
        if (
            output_exit is not None
            and paired_tool is not None
            and paired_tool.casefold() in _STREAM_SHELL_CALL_TOOLS
            and "exit_status" not in envelope.structural_payload
        ):
            # A direct shell call's output states its exit only in Codex's own header, and a
            # Codex 0.159 ``PostToolUse`` for it states none: this is the call's only exit (n7 RC2).
            envelope = replace(
                envelope,
                structural_payload=JsonObject(
                    {**envelope.structural_payload, "exit_status": output_exit}
                ),
            )
        classification = base_classification
        action = envelope.structural_payload.get("action")
        if action in {"function_call_output", "custom_tool_call_output"}:
            # Pairing is authoritative for both the tool family and the
            # conservative pre-event candidate.  A conflicting or unpaired
            # output must not select itself into a routine summary merely by
            # carrying a read-looking name in its own payload.
            output_structural = dict(envelope.structural_payload)
            if not paired_candidate:
                output_structural.pop("tool_name", None)
            classification = classify_observation(output_structural, "PostToolUse")
            classification = _carry_stream_candidate(
                classification,
                routine_candidate=paired_candidate,
            )

        # A protected input is a subject-state boundary.  Flush any earlier
        # summary before attempting its individual delivery.  Routine pre
        # events are pending identities and remain in the shared buffer.
        # Keep every candidate in the planner until its paired post result is
        # handled.  A failed/unknown post is still a protected individual
        # outcome, but letting the planner flush it preserves the original
        # pending call instead of exposing the summary marker as a pre row.
        optional_routine = (
            classification is not None and classification.routine_candidate and not shell_call
        )
        try:
            flush_ok = store.flush_selected_admission(
                workspace_commitment,
                summary_builder=build_routine_read_summary,
                force=not optional_routine,
                material_boundary=not optional_routine,
            )
        except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
            flush_ok = False
        if not flush_ok:
            delivery_blocked = True
            break

        result = store.ingest(envelope)
        if result.disposition.value not in {"accepted", "duplicate"}:
            delivery_blocked = True
            break
        # Re-read pressure after every committed input: one stream pass can
        # contain enough routine calls to cross a profile boundary.
        current_pressure = _stream_selection_pressure(
            store, workspace_commitment, session_commitment
        )
        if current_pressure is False:
            effective_focused = False
            effective_mode = ObservationMode.FOCUSED
        elif current_pressure is None:
            effective_focused = True
            effective_mode = ObservationMode.FOCUSED
        else:
            raw_mode = getattr(current_pressure, "effective_mode", None)
            effective_mode = (
                raw_mode if isinstance(raw_mode, ObservationMode) else ObservationMode.FOCUSED
            )
            effective_focused = effective_mode is ObservationMode.FOCUSED

        selection_envelope = envelope
        selection_fence = ""
        read_protection_probe: ObservationEnvelope | None = None
        read_protected = False
        admitted = False
        if classification is not None and classification.routine_candidate:
            selection_envelope, selection_fence = _stream_selection_context(
                store,
                workspace_commitment,
                codex_session_id,
                envelope,
                mode=effective_mode,
                classification=classification,
            )
            if selection_fence:
                inherited_gaps = _stream_selection_history_gaps(
                    store,
                    workspace_commitment,
                    selection_envelope,
                )
                if inherited_gaps:
                    selection_envelope = replace(
                        selection_envelope,
                        gap_codes=tuple(
                            sorted(
                                {*selection_envelope.gap_codes, *inherited_gaps},
                                key=str.encode,
                            )
                        ),
                    )
            # Read protection is an explicit retention request and therefore
            # outranks Focused/Detailed selection.  Its attempt identity is
            # source-scoped by the store, so a native hook copy and this
            # session-stream copy intentionally reserve independent slots.
            read_protection_probe, protection_reference = _stream_read_protection_probe(
                store,
                workspace_commitment,
                session_commitment,
                selection_envelope,
                classification,
            )
            read_protected = read_protection_probe is not None
            if read_protected:
                assert read_protection_probe is not None
                selection_envelope = _stamp_stream_read_protection(
                    read_protection_probe,
                    protection_reference,
                )
            if not read_protected and shell_call:
                # PR #1080: delivered individually, in its original stream shape.
                classification = without_routine_read(classification)
                selection_envelope = envelope
                selection_fence = ""
            # ``routine_read`` is a service-owned summary marker. Keep the
            # original stream shape when the route is absent or Detailed mode
            # is active so individual materialization still produces action and
            # result records without captured content.
            elif not read_protected:
                selection_envelope = _selection_envelope(
                    selection_envelope,
                    classification,
                    focused=effective_focused,
                    routed=bool(selection_fence),
                )

        # A code-mode ``exec`` cell is a container: Codex fires no hook for it, and
        # a host action inside it is a nested tool call that may fire its own
        # hooks. When the cell's nested calls are hook-observed, those hook rows
        # are the ledger's record of the cell, so the wrapper stays in the local
        # store only instead of adding an independent action; a cell whose tools
        # fire no hook keeps its own record (#917), unless every tool item the
        # rollout wrote inside it was FinishUP's own MCP call (#1038). A completed
        # command, MCP or patch item follows the same rule unless it is the only
        # carrier of a hooked call's outcome (#910).
        if not _note_code_mode_nested_item(
            store, workspace_commitment, session_commitment, envelope
        ):
            delivery_blocked = True
            break
        if result.disposition.value == "accepted":
            _close_pre_only_attempt(store, workspace_commitment, session_commitment, envelope)
        item_decision = _hooked_tool_item_decision(
            store, workspace_commitment, session_commitment, envelope
        )
        if item_decision == _ITEM_PENDING and _stream_self_observation_deliverable(envelope):
            # Read before the hook post it pairs with: a later post decides it (#910). A FinishUP
            # self-read is never delivered whatever the decision, so it is not held for one: a
            # held item would also count against a check's observation wait.
            note_pending = getattr(store, "note_pending_rollout_item", None)
            if callable(note_pending):
                try:
                    note_pending(
                        workspace_commitment, session_commitment, codex_session_id, envelope
                    )
                except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
                    # The cursor must not pass an item whose later decision could not persist.
                    delivery_blocked = True
                    break
        if not _note_code_mode_wait(
            store, workspace_commitment, session_commitment, envelope, cell_fact
        ):
            delivery_blocked = True
            break
        # A terminal ``wait`` output or the turn's end decides a yielded cell; its held yield
        # output is delivered as the cell's record ahead of this row (#1038 follow-up).
        owed_outputs = _owed_code_mode_cell_outputs(
            store,
            workspace_commitment,
            session_commitment,
            envelope,
            cell_fact,
            tool_items_recorded=tool_items_recorded,
        )
        if owed_outputs is None:
            delivery_blocked = True
            break
        if not all(
            _deliver_held_cell_output(
                store,
                workspace_commitment,
                codex_session_id,
                cell_key,
                held,
                envelope.cursor,
            )
            for cell_key, held in owed_outputs
        ):
            overflow = True
            delivery_blocked = True
            break
        cell_wrapper = _code_mode_cell_held(
            store,
            workspace_commitment,
            session_commitment,
            envelope,
            cell_fact,
            tool_items_recorded=tool_items_recorded,
        ) or item_decision not in {None, _ITEM_CARRIER}
        deliverable = not cell_wrapper and _stream_self_observation_deliverable(envelope)
        if deliverable:
            try:
                plan = store.prepare_selected_admission(
                    workspace_commitment,
                    codex_session_id,
                    selection_envelope,
                    fence=selection_fence,
                    focused=effective_focused and not read_protected,
                    routine_candidate=(
                        False if classification is None else classification.routine_candidate
                    ),
                    proven_routine_success=(
                        False if classification is None else classification.proven_routine_success
                    ),
                    summary_builder=build_routine_read_summary,
                )
                plan = _restore_stream_individual_deliveries(plan)
                admitted = store.commit_selected_admission(
                    workspace_commitment,
                    plan,
                    incoming=envelope,
                    newly_observed=result.disposition.value == "accepted",
                    replayable=True,
                )
            except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
                admitted = False
            if not admitted:
                # The local envelope is retained, but its source position is
                # replayed until either its individual row or its summary
                # account is durably admitted.
                overflow = True
                delivery_blocked = True
                break
            if (
                admitted
                and read_protected
                and read_protection_probe is not None
                and action in {"function_call_output", "custom_tool_call_output"}
            ):
                consume = getattr(store, "consume_read_protection", None)
                if callable(consume):
                    try:
                        consume(workspace_commitment, session_commitment, read_protection_probe)
                    except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
                        pass
        elif result.disposition.value == "accepted" and not cell_wrapper:
            # Self-observation suppression is intentional selection, not a
            # missing observation.  Count each accepted stream input once so
            # status/check accounting can distinguish it from queue loss.
            note_omission = getattr(store, "note_selection_omission", None)
            if callable(note_omission):
                try:
                    note_omission(workspace_commitment)
                except AttributeError, OSError, ProtocolValueError, TypeError, ValueError:
                    # The source cursor must not pass an accepted input when
                    # its intentional-omission accounting could not commit.
                    delivery_blocked = True
                    break
        # Pairing provenance is needed even for FinishUP-owned calls that stay
        # local-only. It is committed with the same stream cursor below.
        call_tools = candidate_call_tools
        # FinishUP-owned calls remain local-only where the self-observation policy
        # says the service already has the authoritative record.
        committed_cursor = envelope.cursor
        if result.disposition.value == "accepted":
            accepted += 1
        else:
            duplicates += 1
    if not overflow and not delivery_blocked:
        committed_cursor = advance.cursor
    source_read_complete = ObservationGapCode.SOURCE_LAG.value not in advance.gaps
    progress_committed = committed_cursor != existing
    if progress_committed or (not overflow and not delivery_blocked and source_read_complete):
        persisted_partial = (
            advance.partial_line
            if not overflow and not delivery_blocked and committed_cursor == advance.cursor
            else (
                partial
                if partial.startswith(_OVERSIZED_PARTIAL_PREFIX) and committed_cursor == existing
                else b""
            )
        )
        persisted_call_tools = call_tools
        same_generation = committed_cursor.source_generation == advance.cursor.source_generation
        persisted_identity = reader.source_identity if same_generation else source_identity
        persisted_profile_id = (
            (None if reader.profile is None else reader.profile.profile_id)
            if same_generation
            else prior_profile_id
        )
    else:
        # No cursor progress means no new source identity or pairing state may
        # commit: the next process must rediscover rotation and replay line 1.
        persisted_partial = partial
        persisted_call_tools = prior_call_tools
        persisted_identity = source_identity
        persisted_profile_id = prior_profile_id
    store.set_stream_reconcile_state(
        workspace_commitment,
        session_commitment,
        cursor=committed_cursor,
        partial=persisted_partial,
        call_tools=persisted_call_tools,
        source_identity=persisted_identity,
        profile_id=persisted_profile_id,
    )
    store.note_stream_reconcile(workspace_commitment)
    if hook_snapshot is not None and not overflow and not delivery_blocked and source_read_complete:
        _settle_code_mode_pass(store, workspace_commitment, session_commitment, hook_snapshot)
    gaps = advance.gaps
    for durable_gap in (
        ObservationGapCode.UNSUPPORTED_EVENT.value,
        ObservationGapCode.UNSUPPORTED_FORMAT.value,
    ):
        if durable_gap in gaps:
            store.note_coverage_gap(workspace_commitment, durable_gap)
    if overflow and ObservationGapCode.OUTBOX_OVERFLOW.value not in gaps:
        gaps = (*gaps, ObservationGapCode.OUTBOX_OVERFLOW.value)
    admitted_profile = stream_profile_from_id(persisted_profile_id)
    return {
        "accepted": accepted,
        "duplicates": duplicates,
        "gaps": gaps,
        "byte_position": committed_cursor.byte_position,
        "event_position": committed_cursor.event_position,
        "generation": committed_cursor.source_generation,
        "profile_id": persisted_profile_id,
        # Structural admission is a parser fact about this pass, never host support (#656).
        "admission": stream_admission(admitted_profile, gaps, advance.reason_codes),
        "admission_provenance": (
            None if admitted_profile is None else rollout_admission_provenance(admitted_profile)
        ),
        "admission_reasons": advance.reason_codes,
        "rotated": advance.rotated,
        "truncated": advance.truncated,
        "resolved": True,
    }
