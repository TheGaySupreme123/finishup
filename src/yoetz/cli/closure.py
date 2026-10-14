"""CLI adapter for read-only closure preparation and durable file output."""

from __future__ import annotations

import errno
import hashlib
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from yoetz.domain.closure import PREPARATION_REMEDIATIONS, Selection, prepare_closure
from yoetz.protocol.canonical import JsonValue, canonical_encode

__all__ = [
    "PREPARATION_REMEDIATIONS",
    "Selection",
    "prepare_closure",
    "write_prepared_output",
]

# Filesystems and platforms that cannot open or flush a directory report these; the rename is then
# as durable as that filesystem makes it, which is all the command can promise there.
_DIRECTORY_FSYNC_UNSUPPORTED = frozenset(
    {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EBADF, errno.EACCES, errno.EPERM}
)


def _fsync_directory(directory: Path) -> None:
    """Flush *directory* so a rename into it survives a crash (ADR-003's final durable step).

    Skipped where the filesystem cannot open or flush a directory; any other failure raises.
    """

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as error:
        if error.errno in _DIRECTORY_FSYNC_UNSUPPORTED:
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in _DIRECTORY_FSYNC_UNSUPPORTED:
            raise
    finally:
        os.close(descriptor)


def write_prepared_output(result: Mapping[str, JsonValue], path: Path) -> dict[str, JsonValue]:
    """Save the complete preparation result to *path* and return the summary printed instead.

    The file holds exactly the canonical JSON line the command prints without ``--output``, so an
    agent can query it repeatedly instead of re-reading every status page (issue #916). It is
    written owner-only to a temporary file in the same directory, flushed, renamed into place, and
    the directory flushed: a reader never sees a partial inventory, preparing again replaces it
    whole, and a crash after the summary is printed does not lose the rename.
    """

    data = canonical_encode(cast(JsonValue, dict(result))) + b"\n"
    target = Path(os.path.abspath(path))
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
    except OSError as error:
        raise ValueError("closure_output_unwritable") from error
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException as error:
        # Never leave a stray temporary beside the target, even on an interrupt.
        temporary.unlink(missing_ok=True)
        if isinstance(error, OSError):
            raise ValueError("closure_output_unwritable") from error
        raise
    try:
        _fsync_directory(target.parent)
    except OSError as error:
        # The new file is already in place; say so rather than claim nothing was saved.
        raise ValueError("closure_output_not_durable") from error
    inventory = result.get("inventory")
    rows: dict[str, JsonValue] = (
        {
            str(view): len(cast(list[JsonValue], items))
            for view, items in cast(Mapping[str, JsonValue], inventory).items()
        }
        if isinstance(inventory, Mapping)
        else {}
    )
    return {
        "preparatory_only": True,
        "output": str(target),
        "bytes": len(data),
        "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "frontier": result.get("frontier"),
        "inventory_rows": rows,
        "operation": result.get("operation"),
    }
