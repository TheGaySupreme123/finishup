"""Durable SQLite registry for host-observed subagent annotations.

The registry is deliberately separate from the delegation lifecycle catalog.  Host adapters
produce a normalized observation; this adapter turns the host values into installation-keyed
commitments, records one provisional annotation, and later binds that annotation to a child task.
No raw host identifier is written to SQLite or returned through the status view.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import TracebackType
from typing import Final, Literal, cast

import apsw

from finishup.domain.host_lineage import (
    HostLineageHost,
    HostLineageObservation,
    HostLineagePhase,
    host_lineage_from_payload,
)
from finishup.domain.observation import ObservationSource
from finishup.domain.values import (
    JsonObject,
    JsonValue,
    Timestamp,
    timestamp_from_datetime,
    timestamp_from_string,
    validate_commitment,
)
from finishup.ports.clock import ClockPort
from finishup.ports.host_lineage import (
    HOST_LINEAGE_MAC_DOMAIN,
    HostLineageAnnotation,
    HostLineageRegistryError,
    HostLineageRegistryPort,
    HostLineageRegistryReason,
    source_mask_for,
)
from finishup.ports.keys import MacKeyHandle
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.ids import IdKind, validate_id

__all__ = ["SqliteHostLineageRegistry"]


_MAX_LIMIT: Final = 100
_PHASE_BITS: Final = {"start": 1, "stop": 2}
_PHASE_NAMES: Final = {1: ("start",), 2: ("stop",), 3: ("start", "stop")}
_HOSTS: Final = frozenset({"claude", "codex", "cursor"})
_SOURCE_HOSTS: Final = {
    ObservationSource.CLAUDE_HOOK: "claude",
    ObservationSource.CODEX_HOOK: "codex",
    ObservationSource.CODEX_SESSION_STREAM: "codex",
    ObservationSource.CURSOR_HOOK: "cursor",
}
_ROW_FIELDS: Final = """
correlation_id, parent_task_id, host_profile, subagent_id_commitment,
parent_tool_call_id_commitment, parent_conversation_id_commitment,
conversation_id_commitment, phase_mask, source_mask, last_session_commitment,
first_observed_at, last_observed_at, bound_child_task_id, bound_at
"""
_QUALIFIED_ROW_FIELDS: Final = (
    "h.correlation_id, h.parent_task_id, h.host_profile, h.subagent_id_commitment, "
    "h.parent_tool_call_id_commitment, h.parent_conversation_id_commitment, "
    "h.conversation_id_commitment, h.phase_mask, h.source_mask, h.last_session_commitment, "
    "h.first_observed_at, h.last_observed_at, h.bound_child_task_id, h.bound_at"
)


def _id(kind: IdKind, value: object) -> str:
    try:
        return validate_id(kind, value)
    except (TypeError, ValueError) as exc:
        raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc


def _commitment(value: object) -> str:
    if type(value) is not str:
        raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
    try:
        return validate_commitment(value)
    except (TypeError, ValueError) as exc:
        raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc


def _timestamp(value: object) -> Timestamp:
    try:
        return timestamp_from_string(value)
    except (TypeError, ValueError) as exc:
        raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc


def _source_host(source: ObservationSource) -> HostLineageHost:
    try:
        return cast(HostLineageHost, _SOURCE_HOSTS[source])
    except (KeyError, TypeError) as exc:
        raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT) from exc


def _phase_mask(phase: HostLineagePhase) -> int:
    try:
        return _PHASE_BITS[phase]
    except KeyError as exc:
        raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT) from exc


def _ordered_phases(mask: object) -> tuple[HostLineagePhase, ...]:
    if type(mask) is not int or mask not in _PHASE_NAMES:
        raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
    return cast(tuple[HostLineagePhase, ...], _PHASE_NAMES[mask])


class _Transaction:
    def __init__(self, db: apsw.Connection) -> None:
        self.db = db

    def __enter__(self) -> None:
        try:
            self.db.execute("BEGIN IMMEDIATE")
        except apsw.BusyError as exc:
            raise HostLineageRegistryError(
                HostLineageRegistryReason.STORAGE_BUSY, retryable=True
            ) from exc

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc_value, traceback
        if exc_type is None:
            self.db.execute("COMMIT")
        else:
            self.db.execute("ROLLBACK")
        return False


class _Commitments:
    def __init__(
        self,
        *,
        correlation_id: str,
        subagent_id: str,
        parent_tool_call_id: str | None,
        parent_conversation_id: str | None,
        conversation_id: str | None,
        aliases: tuple[tuple[str, str], ...],
    ) -> None:
        self.correlation_id = correlation_id
        self.subagent_id = subagent_id
        self.parent_tool_call_id = parent_tool_call_id
        self.parent_conversation_id = parent_conversation_id
        self.conversation_id = conversation_id
        self.aliases = aliases


class SqliteHostLineageRegistry(HostLineageRegistryPort):
    """Installation-scoped host annotation registry over a shared catalog connection."""

    def __init__(
        self,
        connection: apsw.Connection,
        *,
        installation_id: str,
        mac: MacKeyHandle,
        clock: ClockPort,
    ) -> None:
        if type(connection) is not apsw.Connection:
            raise TypeError("host_lineage_connection_invalid")
        if not callable(getattr(mac, "mac", None)):
            raise TypeError("host_lineage_mac_invalid")
        if not callable(getattr(clock, "now_utc", None)):
            raise TypeError("host_lineage_clock_invalid")
        self._db = connection
        self._installation_id = _id(IdKind.INSTALLATION, installation_id)
        self._mac_handle = mac
        self._clock = clock
        self._validate_tables()

    @property
    def connection(self) -> apsw.Connection:
        """Return the shared connection for composition and migration inspection."""

        return self._db

    def _validate_tables(self) -> None:
        expected = {
            "host_lineage_annotations",
            "host_lineage_annotation_aliases",
        }
        rows = self._db.execute(
            "SELECT name FROM sqlite_schema WHERE name IN "
            "('host_lineage_annotations', 'host_lineage_annotation_aliases')"
        )
        present = {cast(str, row[0]) for row in rows if len(row) == 1 and type(row[0]) is str}
        if present != expected:
            raise HostLineageRegistryError(HostLineageRegistryReason.MIGRATION_REQUIRED)

    def _rows(
        self,
        sql: str,
        bindings: tuple[str | int | float | bytes | None, ...] = (),
    ) -> list[tuple[object, ...]]:
        try:
            return [cast(tuple[object, ...], row) for row in self._db.execute(sql, bindings)]
        except apsw.BusyError as exc:
            raise HostLineageRegistryError(
                HostLineageRegistryReason.STORAGE_BUSY, retryable=True
            ) from exc
        except apsw.Error as exc:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc

    def _mac(self, body: Mapping[str, JsonValue]) -> str:
        try:
            value = self._mac_handle.mac(
                HOST_LINEAGE_MAC_DOMAIN,
                canonical_encode(cast(JsonValue, JsonObject(body))),
            )
            return _commitment(value)
        except HostLineageRegistryError:
            raise
        except Exception as exc:
            raise HostLineageRegistryError(HostLineageRegistryReason.KEY_UNAVAILABLE) from exc

    def _commitments(
        self, parent_task_id: str, observation: HostLineageObservation
    ) -> _Commitments:
        correlation = observation.correlation
        base: dict[str, JsonValue] = {
            "parent_task_id": parent_task_id,
            "host_profile": correlation.host,
            "subagent_id": correlation.subagent_id,
        }

        def field(kind: str, value: str | None) -> str | None:
            if value is None:
                return None
            return self._mac({**base, "field": kind, "value": value})

        child_commitment = cast(str, field("subagent_id", correlation.subagent_id))
        parent_tool_commitment = field("parent_tool_call_id", correlation.parent_tool_call_id)
        parent_conversation_commitment = field(
            "parent_conversation_id", correlation.parent_conversation_id
        )
        conversation_commitment = field("conversation_id", correlation.conversation_id)

        aliases: list[tuple[str, str]] = []

        def alias(kind: str, optional_field: str | None, value: str | None) -> None:
            material: dict[str, JsonValue] = {**base, "alias_kind": kind}
            if optional_field is not None and value is not None:
                material[optional_field] = value
            aliases.append((kind, self._mac(material)))

        if correlation.parent_tool_call_id is not None:
            alias("strong", "parent_tool_call_id", correlation.parent_tool_call_id)
            alias("parent_tool", "parent_tool_call_id", correlation.parent_tool_call_id)
        if correlation.parent_conversation_id is not None:
            alias(
                "parent_conversation", "parent_conversation_id", correlation.parent_conversation_id
            )
        if correlation.conversation_id is not None:
            alias("conversation", "conversation_id", correlation.conversation_id)
        alias("child", None, None)

        anchor_kind = "strong" if correlation.parent_tool_call_id is not None else "child"
        anchor: dict[str, JsonValue] = {**base, "anchor_kind": anchor_kind}
        if correlation.parent_tool_call_id is not None:
            anchor["parent_tool_call_id"] = correlation.parent_tool_call_id
        correlation_id = self._mac({"kind": "correlation", **anchor})
        return _Commitments(
            correlation_id=correlation_id,
            subagent_id=child_commitment,
            parent_tool_call_id=parent_tool_commitment,
            parent_conversation_id=parent_conversation_commitment,
            conversation_id=conversation_commitment,
            aliases=tuple(aliases),
        )

    def _row_for_correlation_locked(
        self, parent_task_id: str, correlation_id: str
    ) -> tuple[object, ...] | None:
        rows = self._rows(
            f"SELECT {_ROW_FIELDS} FROM host_lineage_annotations "
            "WHERE installation_id = ? AND parent_task_id = ? AND correlation_id = ? LIMIT 2",
            (self._installation_id, parent_task_id, correlation_id),
        )
        if len(rows) > 1:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
        return None if not rows else rows[0]

    def _annotation_from_row(self, row: tuple[object, ...]) -> HostLineageAnnotation:
        if len(row) != 14:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
        correlation_id = _commitment(row[0])
        parent_task_id = _id(IdKind.TASK, row[1])
        host = row[2]
        if type(host) is not str or host not in _HOSTS:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
        subagent = _commitment(row[3])
        parent_tool = None if row[4] is None else _commitment(row[4])
        parent_conversation = None if row[5] is None else _commitment(row[5])
        conversation = None if row[6] is None else _commitment(row[6])
        phases = _ordered_phases(row[7])
        source_mask = row[8]
        if type(source_mask) is not int or not 1 <= source_mask <= 3:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
        session = _commitment(row[9])
        first = _timestamp(row[10])
        last = _timestamp(row[11])
        bound_child = None if row[12] is None else _id(IdKind.TASK, row[12])
        bound_at = None if row[13] is None else _timestamp(row[13])
        try:
            return HostLineageAnnotation(
                parent_task_id=parent_task_id,
                host_profile=cast(HostLineageHost, host),
                correlation_id=correlation_id,
                subagent_id=subagent,
                parent_tool_call_id=parent_tool,
                parent_conversation_id=parent_conversation,
                conversation_id=conversation,
                origin="host_observed",
                acceptance="pending",
                observed_phases=phases,
                source_mask=source_mask,
                last_session_commitment=session,
                first_observed_at=first,
                last_observed_at=last,
                bound_child_task_id=bound_child,
                bound_at=bound_at,
            )
        except (TypeError, ValueError) as exc:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc

    def _alias_rows_locked(
        self,
        parent_task_id: str,
        *,
        host: HostLineageHost | None,
        aliases: tuple[tuple[str, str], ...],
        alias_kind: str | None = None,
    ) -> list[tuple[object, ...]]:
        if not aliases:
            return []
        commitments = tuple(dict.fromkeys(value for _kind, value in aliases))
        placeholders = ", ".join("?" for _ in commitments)
        host_bindings: tuple[str, ...] = () if host is None else (host,)
        kind_clause = "" if alias_kind is None else " AND a.alias_kind = ?"
        kind_bindings: tuple[object, ...] = () if alias_kind is None else (alias_kind,)
        bindings: tuple[str | int | float | bytes | None, ...] = (
            self._installation_id,
            parent_task_id,
            *host_bindings,
            *kind_bindings,
            *commitments,
        )
        host_clause = "" if host is None else " AND a.host_profile = ?"
        return self._rows(
            f"SELECT DISTINCT {_QUALIFIED_ROW_FIELDS} "
            "FROM host_lineage_annotation_aliases AS a "
            "JOIN host_lineage_annotations AS h ON h.installation_id = a.installation_id "
            "AND h.correlation_id = a.correlation_id "
            "WHERE a.installation_id = ? AND a.parent_task_id = ?"
            f"{host_clause}{kind_clause} AND a.alias_commitment IN ({placeholders})",
            bindings,
        )

    @staticmethod
    def _compatible(row: tuple[object, ...], commitments: _Commitments) -> bool:
        if len(row) != 14 or row[3] != commitments.subagent_id:
            return False
        if row[12] is not None and row[4] is None and commitments.parent_tool_call_id is not None:
            # Binding fixes the child attribution. A later strong pair cannot prove that a
            # bound child-only observation belonged to that call, even with the same worker.
            return False
        for index, incoming in (
            (4, commitments.parent_tool_call_id),
            (5, commitments.parent_conversation_id),
            (6, commitments.conversation_id),
        ):
            current = row[index]
            if incoming is not None and current is not None and current != incoming:
                return False
        return True

    def _insert_aliases_locked(
        self,
        parent_task_id: str,
        host: HostLineageHost,
        correlation_id: str,
        aliases: tuple[tuple[str, str], ...],
    ) -> None:
        self._db.executemany(
            "INSERT OR IGNORE INTO host_lineage_annotation_aliases "
            "(installation_id, parent_task_id, host_profile, alias_kind, alias_commitment, correlation_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                (self._installation_id, parent_task_id, host, kind, commitment, correlation_id)
                for kind, commitment in aliases
            ),
        )

    def _record_locked(
        self,
        parent_task_id: str,
        observation: HostLineageObservation,
        source: ObservationSource,
        session_commitment: str,
        observed_at: Timestamp,
    ) -> HostLineageAnnotation:
        host = observation.correlation.host
        commitments = self._commitments(parent_task_id, observation)
        candidate_rows = self._alias_rows_locked(
            parent_task_id,
            host=host,
            aliases=commitments.aliases,
        )
        strong_aliases = tuple(
            (kind, value) for kind, value in commitments.aliases if kind == "strong"
        )
        exact_rows = self._alias_rows_locked(
            parent_task_id,
            host=host,
            aliases=strong_aliases,
            alias_kind="strong",
        )
        # A full pair wins over a child-only alias. This also resolves a partial first row that
        # later receives its stronger parent-tool alias before binding to a cooperative child.
        compatible = [row for row in candidate_rows if self._compatible(row, commitments)]
        if exact_rows:
            if len(exact_rows) > 1:
                raise HostLineageRegistryError(HostLineageRegistryReason.ANNOTATION_AMBIGUOUS)
            if not self._compatible(exact_rows[0], commitments):
                raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
            row = exact_rows[0]
        elif len(compatible) > 1:
            raise HostLineageRegistryError(HostLineageRegistryReason.ANNOTATION_AMBIGUOUS)
        elif compatible:
            row = compatible[0]
        else:
            # Child-only correlations intentionally stay stable when optional
            # conversation context is absent.  If a later event reuses that
            # anchor with contradictory optional context, do not fall through
            # to a duplicate primary-key insert (which would surface as a
            # generic storage error); retain an explicit identity conflict.
            anchored = self._row_for_correlation_locked(parent_task_id, commitments.correlation_id)
            if anchored is not None:
                raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
            now_wire = observed_at.wire
            phase_mask = _phase_mask(observation.phase)
            source_mask = source_mask_for(source)
            self._db.execute(
                "INSERT INTO host_lineage_annotations ("
                "installation_id, correlation_id, parent_task_id, host_profile, "
                "subagent_id_commitment, parent_tool_call_id_commitment, "
                "parent_conversation_id_commitment, conversation_id_commitment, phase_mask, "
                "source_mask, last_session_commitment, first_observed_at, last_observed_at, "
                "bound_child_task_id, bound_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    self._installation_id,
                    commitments.correlation_id,
                    parent_task_id,
                    host,
                    commitments.subagent_id,
                    commitments.parent_tool_call_id,
                    commitments.parent_conversation_id,
                    commitments.conversation_id,
                    phase_mask,
                    source_mask,
                    session_commitment,
                    now_wire,
                    now_wire,
                ),
            )
            self._insert_aliases_locked(
                parent_task_id,
                host,
                commitments.correlation_id,
                commitments.aliases,
            )
            created = self._row_for_correlation_locked(parent_task_id, commitments.correlation_id)
            if created is None:
                raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
            return self._annotation_from_row(created)

        correlation_id = cast(str, row[0])
        current = self._annotation_from_row(row)
        merged_tool = current.parent_tool_call_id or commitments.parent_tool_call_id
        merged_parent_conversation = (
            current.parent_conversation_id or commitments.parent_conversation_id
        )
        merged_conversation = current.conversation_id or commitments.conversation_id
        first = min(current.first_observed_at, observed_at)
        last = max(current.last_observed_at, observed_at)
        last_session = (
            session_commitment
            if observed_at >= current.last_observed_at
            else current.last_session_commitment
        )
        current_phase_mask = sum(_phase_mask(phase) for phase in current.observed_phases)
        self._db.execute(
            "UPDATE host_lineage_annotations SET "
            "parent_tool_call_id_commitment = ?, parent_conversation_id_commitment = ?, "
            "conversation_id_commitment = ?, phase_mask = ?, source_mask = ?, "
            "last_session_commitment = ?, first_observed_at = ?, last_observed_at = ? "
            "WHERE installation_id = ? AND correlation_id = ? AND parent_task_id = ?",
            (
                merged_tool,
                merged_parent_conversation,
                merged_conversation,
                current_phase_mask | _phase_mask(observation.phase),
                current.source_mask | source_mask_for(source),
                last_session,
                first.wire,
                last.wire,
                self._installation_id,
                correlation_id,
                parent_task_id,
            ),
        )
        self._insert_aliases_locked(parent_task_id, host, correlation_id, commitments.aliases)
        updated = self._row_for_correlation_locked(parent_task_id, correlation_id)
        if updated is None:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
        return self._annotation_from_row(updated)

    async def record_host_lineage_observation(
        self,
        parent_task_id: str,
        observation: HostLineageObservation,
        *,
        observed_session_commitment: str,
        source: ObservationSource,
    ) -> HostLineageAnnotation:
        parent = _id(IdKind.TASK, parent_task_id)
        session = _commitment(observed_session_commitment)
        if type(observation) is not HostLineageObservation or type(source) is not ObservationSource:
            raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
        if _source_host(source) != observation.correlation.host:
            raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
        observed_at = timestamp_from_datetime(self._clock.now_utc())
        try:
            with _Transaction(self._db):
                return self._record_locked(parent, observation, source, session, observed_at)
        except HostLineageRegistryError:
            raise
        except apsw.ConstraintError as exc:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc
        except apsw.BusyError as exc:
            raise HostLineageRegistryError(
                HostLineageRegistryReason.STORAGE_BUSY, retryable=True
            ) from exc
        except apsw.Error as exc:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc

    async def find_host_lineage_observation(
        self,
        parent_task_id: str,
        observation: HostLineageObservation,
    ) -> HostLineageAnnotation | None:
        """Resolve a recorded annotation without updating its observation clocks.

        Advice refreshes may revisit retained host envelopes after the original ingest.  This
        lookup recomputes only the keyed aliases and reads the existing row, so rebuilding advice
        cannot mutate ``last_session_commitment`` or observed timestamps.
        """

        parent = _id(IdKind.TASK, parent_task_id)
        if type(observation) is not HostLineageObservation:
            raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
        commitments = self._commitments(parent, observation)
        candidate_rows = self._alias_rows_locked(
            parent,
            host=observation.correlation.host,
            aliases=commitments.aliases,
        )
        strong_aliases = tuple(
            (kind, value) for kind, value in commitments.aliases if kind == "strong"
        )
        exact_rows = self._alias_rows_locked(
            parent,
            host=observation.correlation.host,
            aliases=strong_aliases,
            alias_kind="strong",
        )
        compatible = [row for row in candidate_rows if self._compatible(row, commitments)]
        if exact_rows:
            if len(exact_rows) > 1:
                raise HostLineageRegistryError(HostLineageRegistryReason.ANNOTATION_AMBIGUOUS)
            if not self._compatible(exact_rows[0], commitments):
                raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
            return self._annotation_from_row(exact_rows[0])
        if len(compatible) > 1:
            raise HostLineageRegistryError(HostLineageRegistryReason.ANNOTATION_AMBIGUOUS)
        return None if not compatible else self._annotation_from_row(compatible[0])

    async def list_provisional_annotations(
        self,
        parent_task_id: str,
        *,
        correlation_id: str | None = None,
        limit: int = 100,
        after_correlation_id: str | None = None,
    ) -> tuple[HostLineageAnnotation, ...]:
        parent = _id(IdKind.TASK, parent_task_id)
        if type(limit) is not int or isinstance(limit, bool) or not 1 <= limit <= _MAX_LIMIT:
            raise ValueError("host_lineage_limit_invalid")
        bindings: tuple[str | int | float | bytes | None, ...]
        selector = ""
        selector_bindings: tuple[str, ...] = ()
        if correlation_id is not None:
            selected = _commitment(correlation_id)
            selector = " AND correlation_id = ?"
            selector_bindings = (selected,)
        after_selector = ""
        after_bindings: tuple[str, ...] = ()
        if after_correlation_id is not None:
            after = _commitment(after_correlation_id)
            after_selector = " AND correlation_id > ?"
            after_bindings = (after,)
        bindings = (
            self._installation_id,
            parent,
            *selector_bindings,
            *after_bindings,
            limit,
        )
        rows = self._rows(
            f"SELECT {_ROW_FIELDS} FROM host_lineage_annotations "
            "WHERE installation_id = ? AND parent_task_id = ? "
            "AND bound_child_task_id IS NULL"
            f"{selector}{after_selector} ORDER BY correlation_id ASC LIMIT ?",
            bindings,
        )
        return tuple(self._annotation_from_row(row) for row in rows)

    async def latest_open_host_operation(
        self,
        parent_task_id: str,
        *,
        not_before: Timestamp,
        session_commitment: str,
    ) -> Timestamp | None:
        parent = _id(IdKind.TASK, parent_task_id)
        if type(not_before) is not Timestamp:
            raise ValueError("host_lineage_timestamp_invalid")
        session = _commitment(session_commitment)
        # ``phase_mask = 1`` is a start without its stop.  Wire timestamps share one fixed-width
        # UTC millisecond form, so text order is time order.
        rows = self._rows(
            "SELECT MAX(first_observed_at) FROM host_lineage_annotations "
            "WHERE installation_id = ? AND parent_task_id = ? AND phase_mask = ? "
            "AND first_observed_at >= ? AND last_session_commitment = ?",
            (
                self._installation_id,
                parent,
                _PHASE_BITS["start"],
                not_before.wire,
                session,
            ),
        )
        if len(rows) != 1 or len(rows[0]) != 1:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
        value = rows[0][0]
        return None if value is None else _timestamp(value)

    def _child_belongs_to_parent(self, parent_task_id: str, child_task_id: str) -> bool:
        rows = self._rows(
            "SELECT parent_task_id FROM task_routes WHERE task_id = ? LIMIT 2", (child_task_id,)
        )
        if len(rows) > 1:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
        return bool(rows) and rows[0][0] == parent_task_id

    async def bind_provisional_annotation(
        self,
        parent_task_id: str,
        correlation_id: str,
        child_task_id: str,
    ) -> HostLineageAnnotation:
        parent = _id(IdKind.TASK, parent_task_id)
        correlation = _commitment(correlation_id)
        child = _id(IdKind.TASK, child_task_id)
        try:
            with _Transaction(self._db):
                row = self._row_for_correlation_locked(parent, correlation)
                if row is None:
                    raise HostLineageRegistryError(HostLineageRegistryReason.ANNOTATION_NOT_FOUND)
                current = self._annotation_from_row(row)
                if current.bound_child_task_id is not None:
                    if current.bound_child_task_id != child:
                        raise HostLineageRegistryError(HostLineageRegistryReason.BINDING_CONFLICT)
                    return current
                if not self._child_belongs_to_parent(parent, child):
                    raise HostLineageRegistryError(HostLineageRegistryReason.CHILD_NOT_FOUND)
                bound_at = timestamp_from_datetime(self._clock.now_utc())
                self._db.execute(
                    "UPDATE host_lineage_annotations SET bound_child_task_id = ?, bound_at = ? "
                    "WHERE installation_id = ? AND parent_task_id = ? AND correlation_id = ?",
                    (child, bound_at.wire, self._installation_id, parent, correlation),
                )
                updated = self._row_for_correlation_locked(parent, correlation)
                if updated is None:
                    raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)
                return self._annotation_from_row(updated)
        except HostLineageRegistryError:
            raise
        except apsw.ConstraintError as exc:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc
        except apsw.BusyError as exc:
            raise HostLineageRegistryError(
                HostLineageRegistryReason.STORAGE_BUSY, retryable=True
            ) from exc
        except apsw.Error as exc:
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT) from exc

    async def bind_host_lineage_identity(
        self,
        parent_task_id: str,
        child_task_id: str,
        *,
        host: HostLineageHost | None = None,
        subagent_id: str | None = None,
        parent_tool_call_id: str | None = None,
        correlation_id: str | None = None,
        validate_only: bool = False,
    ) -> HostLineageAnnotation | None:
        parent = _id(IdKind.TASK, parent_task_id)
        child = _id(IdKind.TASK, child_task_id)
        if host is not None and (type(host) is not str or host not in _HOSTS):
            raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
        if parent_tool_call_id is not None and subagent_id is None:
            # Parent-call commitments are scoped to the raw child token. Without it this
            # independent selector cannot be verified, even with a direct correlation id.
            raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)

        async def finish(annotation: HostLineageAnnotation) -> HostLineageAnnotation:
            if validate_only:
                if annotation.bound_child_task_id not in {None, child}:
                    raise HostLineageRegistryError(HostLineageRegistryReason.BINDING_CONFLICT)
                if not self._child_belongs_to_parent(parent, child):
                    raise HostLineageRegistryError(HostLineageRegistryReason.CHILD_NOT_FOUND)
                return annotation
            return await self.bind_provisional_annotation(parent, annotation.correlation_id, child)

        if correlation_id is not None:
            try:
                direct = _commitment(correlation_id)
            except HostLineageRegistryError as exc:
                raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT) from exc
            try:
                row = self._row_for_correlation_locked(parent, direct)
                if row is not None:
                    annotation = self._annotation_from_row(row)
                    if host is not None and host != annotation.host_profile:
                        raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
                    if subagent_id is not None:
                        normalized = host_lineage_from_payload(
                            annotation.host_profile,
                            "SubagentStart",
                            {
                                "subagent_id": subagent_id,
                                **(
                                    {}
                                    if parent_tool_call_id is None
                                    else {"parent_tool_call_id": parent_tool_call_id}
                                ),
                            },
                        )
                        if normalized is None:
                            raise HostLineageRegistryError(
                                HostLineageRegistryReason.IDENTITY_CONFLICT
                            )
                        commitments = self._commitments(parent, normalized)
                        if annotation.subagent_id != commitments.subagent_id or (
                            parent_tool_call_id is not None
                            and annotation.parent_tool_call_id != commitments.parent_tool_call_id
                        ):
                            raise HostLineageRegistryError(
                                HostLineageRegistryReason.IDENTITY_CONFLICT
                            )
                    return await finish(annotation)
                raise HostLineageRegistryError(HostLineageRegistryReason.ANNOTATION_NOT_FOUND)
            except HostLineageRegistryError as exc:
                if exc.reason is not HostLineageRegistryReason.ANNOTATION_NOT_FOUND:
                    raise
                # A supplied correlation commitment is a selector, never a hint that
                # permits falling back to a different raw-identity annotation.
                return None
        if subagent_id is None:
            return None
        hosts = (
            (host,)
            if host is not None
            else cast(tuple[HostLineageHost, ...], tuple(sorted(_HOSTS)))
        )
        candidates: list[HostLineageAnnotation] = []
        for selected_host in hosts:
            normalized = host_lineage_from_payload(
                selected_host,
                "SubagentStart",
                {
                    "subagent_id": subagent_id,
                    **(
                        {}
                        if parent_tool_call_id is None
                        else {"parent_tool_call_id": parent_tool_call_id}
                    ),
                },
            )
            if normalized is None:
                raise HostLineageRegistryError(HostLineageRegistryReason.IDENTITY_CONFLICT)
            commitments = self._commitments(parent, normalized)
            rows = self._alias_rows_locked(
                parent,
                host=selected_host,
                aliases=commitments.aliases,
            )
            for row in rows:
                if self._compatible(row, commitments):
                    candidates.append(self._annotation_from_row(row))
        unique = {item.correlation_id: item for item in candidates}
        if len(unique) > 1:
            raise HostLineageRegistryError(HostLineageRegistryReason.ANNOTATION_AMBIGUOUS)
        if not unique:
            return None
        selected = next(iter(unique.values()))
        return await finish(selected)
