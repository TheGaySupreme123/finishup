"""Which workspace on this machine each claim of a remote target root stands for (ADR-051).

Approach A, the edge relay. A connection to a FinishUP server on another machine names its
workspace by a keyed claim and never sends the path. The connector that relays those connections
keeps one long-lived workspace agent per claimed workspace, so a detached server job (the
AI-powered review loop, observation verification) still reaches the workspace after the call
that started it returned. A claim is a digest; the connector learns which folder it stands for
from this owner-only index, written by the client process that made the claim:

``<target root>/state/claimed-workspaces/<64 hex>.json`` (``yoetz.claimed-workspace/1``): the
claim's identity kind and the workspace locator path the claim was computed from.

The index never leaves this machine and nothing reads it but this installation's own client
processes. A record is only a hint: the connector derives the claim again from the recorded path
with the target's own salt and serves the workspace only when the two match, so a stale or edited
record never makes it answer for another folder. Removing the target removes its root and with it
the index.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from pathlib import Path
from typing import Final, cast

from finishup.ports.control import WorkspaceClaim, WorkspaceLocator
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "CLAIMED_WORKSPACES_DIRECTORY",
    "CLAIMED_WORKSPACE_SCHEMA",
    "claimed_workspace",
    "record_claimed_workspace",
]

CLAIMED_WORKSPACE_SCHEMA: Final = "yoetz.claimed-workspace/1"
CLAIMED_WORKSPACES_DIRECTORY: Final = "claimed-workspaces"
_DIGEST_PREFIX: Final = "sha256:"
_MAX_RECORD_BYTES: Final = 16_384


def _record_path(root: Path, claim: WorkspaceClaim) -> Path:
    if type(claim) is not WorkspaceClaim:
        raise TypeError("workspace_claim_invalid")
    # The claim's own validation pins the digest to ``sha256:`` and 64 lowercase hex.
    return (
        root
        / "state"
        / CLAIMED_WORKSPACES_DIRECTORY
        / f"{claim.digest[len(_DIGEST_PREFIX) :]}.json"
    )


def _encode(claim: WorkspaceClaim, workspace: WorkspaceLocator) -> bytes:
    document: dict[str, JsonValue] = {
        "schema": CLAIMED_WORKSPACE_SCHEMA,
        "identity_kind": claim.identity_kind,
        "workspace": workspace.path,
    }
    return canonical_encode(document) + b"\n"


def _read_owner_only(path: Path) -> bytes | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_RECORD_BYTES
        ):
            return None
        data = os.read(descriptor, _MAX_RECORD_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return data if len(data) <= _MAX_RECORD_BYTES else None


def _owner_only_directory(path: Path) -> bool:
    try:
        facts = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(facts.st_mode)
        and facts.st_uid == os.geteuid()
        and not stat.S_IMODE(facts.st_mode) & 0o077
    )


def record_claimed_workspace(
    root: Path, claim: WorkspaceClaim, workspace: WorkspaceLocator
) -> bool:
    """Record that ``claim`` stands for ``workspace``; True when the record now says so.

    Best effort and idempotent: an identical record is left untouched, and a folder that cannot
    be written safely (not owner-only, a link, a full disk) leaves the index as it was and returns
    False. The connection that made the claim works either way; only the connector's background
    agent for that workspace waits for a record it can read.
    """

    if type(workspace) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    path = _record_path(root, claim)
    encoded = _encode(claim, workspace)
    if _read_owner_only(path) == encoded:
        return True
    state = path.parent.parent
    if not _owner_only_directory(state):
        return False
    with contextlib.suppress(FileExistsError, OSError):
        path.parent.mkdir(mode=0o700)
    if not _owner_only_directory(path.parent):
        return False
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
    except OSError:
        return False
    try:
        try:
            view = memoryview(encoded)
            while view:
                view = view[os.write(descriptor, view) :]
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except OSError:
        temporary.unlink(missing_ok=True)
        return False
    return True


def claimed_workspace(root: Path, claim: WorkspaceClaim) -> WorkspaceLocator | None:
    """The workspace locator recorded for ``claim``; None when absent, unsafe or malformed.

    The caller must still derive the claim from this locator and compare it before serving it.
    """

    data = _read_owner_only(_record_path(root, claim))
    if data is None or not data.endswith(b"\n"):
        return None
    try:
        parsed = strict_json_parse(data[:-1])
        if type(parsed) is not dict:
            return None
        source = cast(dict[str, JsonValue], parsed)
        workspace = source.get("workspace")
        if (
            set(source) != {"schema", "identity_kind", "workspace"}
            or source["schema"] != CLAIMED_WORKSPACE_SCHEMA
            or source["identity_kind"] != claim.identity_kind
            or type(workspace) is not str
        ):
            return None
        locator = WorkspaceLocator(workspace)
    except (TypeError, ValueError):
        return None
    return locator if _encode(claim, locator) == data else None
