"""SQLite repository for generation-fenced observation verification work."""

from __future__ import annotations

import hashlib

import apsw

from finishup.adapters.approved_checks import ApprovedCheckResult
from finishup.application.observation_verification import ObservationVerificationJob
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = ["SqliteObservationVerificationRepository"]


class SqliteObservationVerificationRepository:
    def __init__(self, connection: apsw.Connection) -> None:
        self._db = connection

    def enqueue_latest(
        self,
        *,
        workspace: str,
        policy_digest: str,
        approvals: tuple[str, ...],
        subject_state_digest: str,
        enqueued_at: str,
    ) -> tuple[str, ...]:
        created: list[str] = []
        with self._db:
            # Pending superseded state never executes; a running lease may finish
            # but its result is marked non-current by the worker's post-capture.
            self._db.execute(
                "UPDATE observation_verification_jobs SET status='stale',updated_at=? "
                "WHERE workspace_commitment=? AND status='pending' "
                "AND subject_state_digest<>?",
                (enqueued_at, workspace, subject_state_digest),
            )
            row = self._db.execute(
                "SELECT COALESCE(MAX(state_token),0) "
                "FROM observation_verification_jobs WHERE workspace_commitment=?",
                (workspace,),
            ).fetchone()
            token = int(row[0]) if row is not None else 0
            for approval in approvals:
                existing = self._db.execute(
                    "SELECT job_id FROM observation_verification_jobs "
                    "WHERE workspace_commitment=? AND policy_digest=? "
                    "AND approval_commitment=? AND subject_state_digest=?",
                    (workspace, policy_digest, approval, subject_state_digest),
                ).fetchone()
                if existing is not None:
                    continue
                token += 1
                job_id = (
                    "job_"
                    + hashlib.sha256(
                        f"{workspace}\0{policy_digest}\0{approval}\0{subject_state_digest}".encode(
                            "ascii"
                        )
                    ).hexdigest()[:48]
                )
                self._db.execute(
                    "INSERT INTO observation_verification_jobs("
                    "job_id,workspace_commitment,policy_digest,approval_commitment,"
                    "subject_state_digest,status,state_token,service_generation,lease_owner,"
                    "lease_generation,lease_expires_at,enqueued_at,updated_at) "
                    "VALUES(?,?,?,?,?,'pending',?,NULL,NULL,NULL,NULL,?,?)",
                    (
                        job_id,
                        workspace,
                        policy_digest,
                        approval,
                        subject_state_digest,
                        token,
                        enqueued_at,
                        enqueued_at,
                    ),
                )
                created.append(job_id)
        return tuple(created)

    def claim_next(
        self,
        *,
        service_generation: int,
        lease_owner: str,
        lease_expires_at: str,
        now: str,
    ) -> ObservationVerificationJob | None:
        with self._db:
            self._db.execute(
                "UPDATE observation_verification_jobs SET status='pending',"
                "service_generation=NULL,lease_owner=NULL,lease_generation=NULL,"
                "lease_expires_at=NULL,updated_at=? "
                "WHERE status='running' AND (service_generation<>? OR lease_expires_at<=?)",
                (now, service_generation, now),
            )
            row = self._db.execute(
                "SELECT j.job_id,j.workspace_commitment,j.policy_digest,"
                "j.approval_commitment,j.subject_state_digest,j.state_token "
                "FROM observation_verification_jobs AS j "
                "WHERE j.status='pending' AND NOT EXISTS ("
                "SELECT 1 FROM observation_verification_jobs AS running "
                "WHERE running.workspace_commitment=j.workspace_commitment "
                "AND running.status='running') "
                "ORDER BY j.state_token DESC,j.job_id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            self._db.execute(
                "UPDATE observation_verification_jobs SET status='running',"
                "service_generation=?,lease_owner=?,lease_generation=1,"
                "lease_expires_at=?,updated_at=? "
                "WHERE job_id=? AND status='pending'",
                (service_generation, lease_owner, lease_expires_at, now, row[0]),
            )
            changed = self._db.changes()
            if changed != 1:
                return None
            return ObservationVerificationJob(
                job_id=str(row[0]),
                workspace_commitment=str(row[1]),
                policy_digest=str(row[2]),
                approval_commitment=str(row[3]),
                subject_state_digest=str(row[4]),
                state_token=int(row[5]),
            )

    def list_pending_workspaces(self) -> tuple[str, ...]:
        rows = self._db.execute(
            "SELECT DISTINCT workspace_commitment FROM observation_verification_jobs "
            "WHERE status IN ('pending', 'running') "
            "ORDER BY workspace_commitment"
        ).fetchall()
        return tuple(str(row[0]) for row in rows if type(row[0]) is str)

    def complete(
        self,
        *,
        job: ObservationVerificationJob,
        service_generation: int,
        lease_owner: str,
        check_id: str,
        result: ApprovedCheckResult,
        subject_state_after: str | None,
        result_commitment: str,
        output_object_id: str | None,
        limitations_json: bytes,
        is_current: bool,
        recorded_at: str,
    ) -> None:
        status = (
            result.status.value
            if result.status.value in {"passed", "failed", "rejected", "stale"}
            else "unavailable"
        )
        result_id = (
            "vres_"
            + canonical_digest(
                {
                    "job_id": job.job_id,
                    "check_id": check_id,
                    "result_commitment": result_commitment,
                }
            ).removeprefix("sha256:")[:48]
        )
        with self._db:
            lease = self._db.execute(
                "SELECT status,service_generation,lease_owner,state_token "
                "FROM observation_verification_jobs WHERE job_id=?",
                (job.job_id,),
            ).fetchone()
            if lease != ("running", service_generation, lease_owner, job.state_token):
                raise PublicOperationError(
                    PublicErrorCode.SESSION_CONFLICT,
                    "Verification lease is stale.",
                    retryable=True,
                )
            self._db.execute(
                "INSERT INTO observation_verification_results("
                "result_id,job_id,workspace_commitment,check_id,status,"
                "subject_state_before,subject_state_after,result_commitment,"
                "output_object_id,limitations_json,is_current,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(job_id,check_id) DO NOTHING",
                (
                    result_id,
                    job.job_id,
                    job.workspace_commitment,
                    check_id,
                    status,
                    job.subject_state_digest,
                    subject_state_after,
                    result_commitment,
                    output_object_id,
                    limitations_json,
                    int(is_current),
                    recorded_at,
                ),
            )
            self._db.execute(
                "UPDATE observation_verification_jobs SET status=?,"
                "service_generation=NULL,lease_owner=NULL,lease_generation=NULL,"
                "lease_expires_at=NULL,updated_at=? WHERE job_id=?",
                ("complete" if is_current else "stale", recorded_at, job.job_id),
            )
