"""Import boundary API; native stream status does not load ledger publication models."""

from __future__ import annotations

from enum import Enum
from importlib import import_module
from typing import TYPE_CHECKING


class ImportLineStatus(str, Enum):  # noqa: UP042 - exact durable wire enum
    MAPPED = "mapped"
    UNKNOWN = "unknown"
    MALFORMED = "malformed"
    OVERSIZED = "oversized"
    UNSUPPORTED = "unsupported"


__all__ = [
    "CapturedImportSource",
    "EncryptedImportReportRef",
    "ImportAllocation",
    "ImportAllocationOutcome",
    "ImportBatch",
    "ImportBatchSelection",
    "ImportByteSource",
    "ImportCaptureInput",
    "ImportCommand",
    "ImportEventCandidate",
    "ImportGap",
    "ImportLineOutcome",
    "ImportLineStatus",
    "ImportPhase",
    "ImportReviewSource",
    "ImportSafeReason",
    "ImportSourceIdentity",
    "ImportState",
    "ImportStatusSnapshot",
    "ImporterPort",
    "PreparedImportPlan",
]

if TYPE_CHECKING:
    from yoetz.ports._importer_impl import (
        CapturedImportSource,
        EncryptedImportReportRef,
        ImportAllocation,
        ImportAllocationOutcome,
        ImportBatch,
        ImportBatchSelection,
        ImportByteSource,
        ImportCaptureInput,
        ImportCommand,
        ImporterPort,
        ImportEventCandidate,
        ImportGap,
        ImportLineOutcome,
        ImportPhase,
        ImportReviewSource,
        ImportSafeReason,
        ImportSourceIdentity,
        ImportState,
        ImportStatusSnapshot,
        PreparedImportPlan,
    )


def __getattr__(name: str) -> object:
    if name.startswith("__"):
        raise AttributeError(name)
    implementation = import_module("yoetz.ports._importer_impl")
    value: object = getattr(implementation, name)
    globals()[name] = value
    return value
