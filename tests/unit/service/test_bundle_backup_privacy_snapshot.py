"""The bundle-upgrade backup orders privacy rows the way its snapshot validates them (#1293)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import cast

import apsw

from finishup.ports.privacy import PrivacyAuditObjectRoots
from finishup.protocol.canonical import canonical_encode
from finishup.service.bundle_upgrade import BundleUpgradeTarget
from finishup.service.ready_composition import (  # pyright: ignore[reportPrivateUsage]
    _PRIVACY_AUDIT_COLUMNS,  # pyright: ignore[reportPrivateUsage]
    _load_privacy_audit_snapshot,  # pyright: ignore[reportPrivateUsage]
)

_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_INSTALLATION = "ins_00000000-0000-4000-8000-000000000001"
_ROUTE = "sha256:" + "1" * 64
_ROOTS = "sha256:" + "2" * 64


def _catalog(rows: list[dict[str, str | int]]) -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA user_version=7")
    db.execute(f"CREATE TABLE privacy_audit_records ({', '.join(_PRIVACY_AUDIT_COLUMNS)})")
    for row in rows:
        values: dict[str, str | int] = {"task_id": _TASK, "audit_store_version": 1, **row}
        columns = tuple(values)
        db.execute(
            f"INSERT INTO privacy_audit_records ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            tuple(values[column] for column in columns),
        )
    return db


def _snapshot(db: apsw.Connection):  # noqa: ANN202 - the private loader's return type
    target = cast(
        BundleUpgradeTarget,
        SimpleNamespace(
            task_id=_TASK,
            route_identity_digest=_ROUTE,
            privacy_root_generation=0,
            privacy_root_digest=_ROOTS,
        ),
    )
    roots = PrivacyAuditObjectRoots(
        task_id=_TASK,
        route_identity_digest=_ROUTE,
        privacy_root_generation=0,
        object_refs=(),
        root_set_digest=_ROOTS,
    )
    return asyncio.run(
        _load_privacy_audit_snapshot(db, installation_id=_INSTALLATION, target=target, roots=roots)
    )


def test_terminal_receipts_whose_receipt_ids_sort_against_their_proposals_back_up() -> None:
    # Receipt ids ascend opposite to proposal ids. The canonical encoding leads with
    # proposal_id, so ordering by receipt_id was rejected as unsorted_set_field.
    db = _catalog(
        [
            {"proposal_id": "ppr_b", "receipt_id": "prc_a", "receipt_outcome": "sent"},
            {"proposal_id": "ppr_a", "receipt_id": "prc_b", "receipt_outcome": "sent"},
        ]
    )

    snapshot = _snapshot(db)

    assert [row["proposal_id"] for row in snapshot.terminal_receipts] == ["ppr_a", "ppr_b"]
    encoded = [canonical_encode(row) for row in snapshot.terminal_receipts]
    assert encoded == sorted(encoded)


def test_open_audit_rows_follow_their_canonical_order_not_their_proposal_order() -> None:
    # An open row's canonical encoding leads with approval_binding_commitment.
    db = _catalog(
        [
            {"proposal_id": "ppr_a", "approval_binding_commitment": "sha256:" + "f" * 64},
            {"proposal_id": "ppr_b", "approval_binding_commitment": "sha256:" + "0" * 64},
        ]
    )

    snapshot = _snapshot(db)

    assert [row["proposal_id"] for row in snapshot.audit_rows] == ["ppr_b", "ppr_a"]
    assert snapshot.terminal_receipts == ()
