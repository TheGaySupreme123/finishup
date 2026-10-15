"""SQLite repository for generation-fenced observation-advice AI-powered review attempts (#619)."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import cast

import apsw

from finishup.application.observation_advice_semantic import (
    ADVICE_SEMANTIC_FAILURE_REASONS,
    MAX_ADVICE_SEMANTIC_ATTEMPTS,
    AttemptStatus,
    ObservationAdviceSemanticAttempt,
    ObservationAdviceSemanticDeferral,
    ObservationAdviceSemanticOutcome,
    advice_semantic_retry_delay_seconds,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = ["SqliteObservationAdviceSemanticRepository"]

_COLUMNS = (
    "attempt_id,workspace_commitment,yoetz_session_id,basis_digest,subject_digest,"
    "coverage_gaps_json,packet_json,status,state_token,attempt_count,failure_reason,"
    "attempt_receipt,provider_identity,finding_ids_json,evidence_digest,summaries_json,"
    "details_json"
)


def _string_tuple(raw: object) -> tuple[str, ...]:
    if type(raw) is not bytes:
        return ()
    try:
        parsed = strict_json_parse(raw)
    except Exception:
        return ()
    if type(parsed) is not list:
        return ()
    return tuple(item for item in cast(list[object], parsed) if type(item) is str)


def _row(values: tuple[object, ...]) -> ObservationAdviceSemanticAttempt:
    return ObservationAdviceSemanticAttempt(
        attempt_id=str(values[0]),
        workspace_commitment=str(values[1]),
        yoetz_session_id=str(values[2]),
        basis_digest=str(values[3]),
        subject_digest=str(values[4]),
        coverage_gaps=_string_tuple(values[5]),
        packet_json=cast(bytes, values[6]),
        status=cast(AttemptStatus, str(values[7])),
        state_token=int(cast(int, values[8])),
        attempt_count=int(cast(int, values[9])),
        failure_reason=None if values[10] is None else str(values[10]),
        attempt_receipt=None if values[11] is None else str(values[11]),
        provider_identity=None if values[12] is None else str(values[12]),
        finding_ids=_string_tuple(values[13]),
        evidence_digest=None if values[14] is None else str(values[14]),
        summaries=_string_tuple(values[15]),
        details=_string_tuple(values[16]),
    )


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _encode(values: tuple[str, ...]) -> bytes:
    return canonical_encode(cast(JsonValue, list(values)))


class SqliteObservationAdviceSemanticRepository:
    def __init__(self, connection: apsw.Connection) -> None:
        self._db = connection

    def schedule(
        self,
        *,
        workspace: str,
        yoetz_session_id: str,
        basis_digest: str,
        subject_digest: str,
        coverage_gaps: tuple[str, ...],
        packet_json: bytes,
        enqueued_at: str,
        max_pending: int,
        min_interval_seconds: int = 0,
        retry_base_seconds: int = 0,
    ) -> ObservationAdviceSemanticAttempt | ObservationAdviceSemanticDeferral:
        """Admit, reuse, or defer one candidate identity for a session (#619, #888).

        ``basis_digest`` is the stable identity key. Its rows form one family: the first is
        stored under the key itself and each retry under ``<key>#<generation>``. A pending,
        running, or succeeded latest row is reused. A terminal non-success is re-admitted once
        its backoff elapses. Admission is refused while the
        session's last provider-reaching attempt is younger than ``min_interval_seconds``.
        Every check and the insert share one transaction, so a reopened service cannot reset
        either bound, and a refusal writes no row.
        """

        now = _parse_time(enqueued_at)
        inserted: object = None
        with self._db:
            family = self._family(yoetz_session_id, basis_digest)
            latest = family[0][0] if family else None
            if latest is not None:
                if latest.status in {"pending", "running", "succeeded"}:
                    return latest
                delay = advice_semantic_retry_delay_seconds(
                    latest, generation=len(family), base_seconds=retry_base_seconds
                )
                eligible = _parse_time(family[0][1]) + timedelta(seconds=delay)
                if now < eligible:
                    return ObservationAdviceSemanticDeferral(
                        reason="retry_backoff",
                        retry_after_seconds=(eligible - now).total_seconds(),
                        previous=latest,
                    )
            if min_interval_seconds > 0:
                # Only attempts that could have reached a provider consume the session budget.
                # Unattempted pending rows are superseded below instead, never double-counted.
                anchor_row = self._db.execute(
                    "SELECT MAX(updated_at) FROM observation_advice_semantic_attempts "
                    "WHERE yoetz_session_id=? AND attempt_count>0 AND (failure_reason IS NULL "
                    "OR failure_reason NOT IN ('authorization_missing','provider_unavailable'))",
                    (yoetz_session_id,),
                ).fetchone()
                if anchor_row is not None and anchor_row[0] is not None:
                    eligible = _parse_time(str(anchor_row[0])) + timedelta(
                        seconds=min_interval_seconds
                    )
                    if now < eligible:
                        return ObservationAdviceSemanticDeferral(
                            reason="rate_limited",
                            retry_after_seconds=(eligible - now).total_seconds(),
                            previous=latest,
                        )
            key = basis_digest if not family else f"{basis_digest}#{len(family)}"
            attempt_id = (
                "sadv_"
                + hashlib.sha256(f"{workspace}\0{yoetz_session_id}\0{key}".encode()).hexdigest()[
                    :48
                ]
            )
            # A new admission for the same session supersedes that session's unattempted rows:
            # the provider would otherwise review evidence the advice no longer stands on. A
            # row already running finishes and keeps its own receipt.
            self._db.execute(
                "UPDATE observation_advice_semantic_attempts SET status='cancelled',"
                "failure_reason='superseded',updated_at=? "
                "WHERE yoetz_session_id=? AND status='pending'",
                (enqueued_at, yoetz_session_id),
            )
            pending_row = self._db.execute(
                "SELECT COUNT(*) FROM observation_advice_semantic_attempts "
                "WHERE status IN ('pending','running')"
            ).fetchone()
            pending = int(cast(int, pending_row[0])) if pending_row is not None else 0
            token_row = self._db.execute(
                "SELECT COALESCE(MAX(state_token),0) FROM observation_advice_semantic_attempts"
            ).fetchone()
            token = (int(cast(int, token_row[0])) if token_row is not None else 0) + 1
            status = "pending"
            failure_reason: str | None = None
            if pending >= max_pending:
                status = "unavailable"
                failure_reason = "queue_full"
            self._db.execute(
                "INSERT INTO observation_advice_semantic_attempts("
                "attempt_id,workspace_commitment,yoetz_session_id,basis_digest,subject_digest,"
                "coverage_gaps_json,packet_json,status,failure_reason,attempt_count,state_token,"
                "service_generation,lease_owner,lease_expires_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,0,?,NULL,NULL,NULL,?,?)",
                (
                    attempt_id,
                    workspace,
                    yoetz_session_id,
                    key,
                    subject_digest,
                    _encode(coverage_gaps),
                    packet_json,
                    status,
                    failure_reason,
                    token,
                    enqueued_at,
                    enqueued_at,
                ),
            )
            inserted = self._db.execute(
                f"SELECT {_COLUMNS} FROM observation_advice_semantic_attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        if inserted is None:
            raise RuntimeError("advice_semantic_attempt_missing")
        return _row(tuple(cast(Sequence[object], inserted)))

    def _family(
        self, yoetz_session_id: str, identity: str
    ) -> list[tuple[ObservationAdviceSemanticAttempt, str]]:
        """Every row of one identity for a session, newest first, with its ``updated_at``."""

        rows = self._db.execute(
            f"SELECT {_COLUMNS},updated_at FROM observation_advice_semantic_attempts "
            "WHERE yoetz_session_id=? AND (basis_digest=? OR "
            "(basis_digest>=? AND basis_digest<?)) ORDER BY state_token DESC",
            (yoetz_session_id, identity, identity + "#", identity + "$"),
        ).fetchall()
        return [
            (_row(cast(tuple[object, ...], tuple(row)[:-1])), str(tuple(row)[-1])) for row in rows
        ]

    def latest_for_identity(
        self, *, yoetz_session_id: str, identity: str
    ) -> ObservationAdviceSemanticAttempt | None:
        family = self._family(yoetz_session_id, identity)
        return family[0][0] if family else None

    def lookup(
        self, *, yoetz_session_id: str, basis_digest: str
    ) -> ObservationAdviceSemanticAttempt | None:
        row = self._db.execute(
            f"SELECT {_COLUMNS} FROM observation_advice_semantic_attempts "
            "WHERE yoetz_session_id=? AND basis_digest=?",
            (yoetz_session_id, basis_digest),
        ).fetchone()
        return None if row is None else _row(cast(tuple[object, ...], tuple(row)))

    def claim_next(
        self,
        *,
        service_generation: int,
        lease_owner: str,
        lease_expires_at: str,
        now: str,
    ) -> ObservationAdviceSemanticAttempt | None:
        claimed: object = None
        with self._db:
            # Reclaim leases left by a previous service generation or an expired holder. The
            # row returns to pending, never to succeeded: an interrupted attempt proved nothing.
            self._db.execute(
                "UPDATE observation_advice_semantic_attempts SET status='pending',"
                "service_generation=NULL,lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE status='running' AND (service_generation<>? OR lease_expires_at<=?)",
                (now, service_generation, now),
            )
            self._db.execute(
                "UPDATE observation_advice_semantic_attempts SET status='failed',"
                "failure_reason='interrupted',updated_at=? "
                "WHERE status='pending' AND attempt_count>=?",
                (now, MAX_ADVICE_SEMANTIC_ATTEMPTS),
            )
            row = self._db.execute(
                f"SELECT {_COLUMNS} FROM observation_advice_semantic_attempts AS a "
                "WHERE a.status='pending' AND NOT EXISTS ("
                "SELECT 1 FROM observation_advice_semantic_attempts AS running "
                "WHERE running.status='running') "
                "ORDER BY a.state_token ASC,a.attempt_id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            self._db.execute(
                "UPDATE observation_advice_semantic_attempts SET status='running',"
                "service_generation=?,lease_owner=?,lease_expires_at=?,"
                "attempt_count=attempt_count+1,updated_at=? "
                "WHERE attempt_id=? AND status='pending'",
                (service_generation, lease_owner, lease_expires_at, now, row[0]),
            )
            if self._db.changes() != 1:
                return None
            claimed = self._db.execute(
                f"SELECT {_COLUMNS} FROM observation_advice_semantic_attempts WHERE attempt_id=?",
                (row[0],),
            ).fetchone()
        if claimed is None:
            return None
        return _row(tuple(cast(Sequence[object], claimed)))

    def list_pending_workspaces(self) -> tuple[str, ...]:
        rows = self._db.execute(
            "SELECT DISTINCT workspace_commitment FROM observation_advice_semantic_attempts "
            "WHERE status IN ('pending','running') ORDER BY workspace_commitment"
        ).fetchall()
        return tuple(str(row[0]) for row in rows if type(row[0]) is str)

    def complete(
        self,
        *,
        attempt: ObservationAdviceSemanticAttempt,
        service_generation: int,
        lease_owner: str,
        outcome: ObservationAdviceSemanticOutcome,
        recorded_at: str,
    ) -> None:
        if outcome.status != "succeeded" and (
            outcome.failure_reason not in ADVICE_SEMANTIC_FAILURE_REASONS
        ):
            raise ValueError("advice_semantic_outcome_invalid")
        with self._db:
            lease = self._db.execute(
                "SELECT status,service_generation,lease_owner,state_token "
                "FROM observation_advice_semantic_attempts WHERE attempt_id=?",
                (attempt.attempt_id,),
            ).fetchone()
            if lease is None or tuple(lease) != (
                "running",
                service_generation,
                lease_owner,
                attempt.state_token,
            ):
                raise PublicOperationError(
                    PublicErrorCode.SESSION_CONFLICT,
                    "AI-powered advice lease is stale.",
                    retryable=True,
                )
            self._db.execute(
                "UPDATE observation_advice_semantic_attempts SET status=?,failure_reason=?,"
                "attempt_receipt=?,provider_identity=?,finding_ids_json=?,evidence_digest=?,"
                "summaries_json=?,details_json=?,service_generation=NULL,lease_owner=NULL,"
                "lease_expires_at=NULL,updated_at=? WHERE attempt_id=?",
                (
                    outcome.status,
                    outcome.failure_reason,
                    outcome.attempt_receipt,
                    outcome.provider_identity,
                    _encode(outcome.finding_ids),
                    outcome.evidence_digest,
                    _encode(outcome.summaries),
                    _encode(outcome.details),
                    recorded_at,
                    attempt.attempt_id,
                ),
            )
