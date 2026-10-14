"""Read-only proof of this runtime's installed console script, never a PATH probe."""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
import sysconfig
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from yoetz import __version__
from yoetz.config.foreign_write import writable_by_others
from yoetz.config.installation import (
    InstanceIdentityError,
    read_instance_identity,
    runtime_prefix_digest,
    verify_instance_binding,
)
from yoetz.config.paths import PathSafetyError, isolated_root, read_runtime_pin


def installed_launcher() -> tuple[str, str] | None:
    """Return the exact script and digest only while its installed RECORD still matches.

    The candidate comes from this interpreter's scripts directory and its Yoetz distribution,
    not the host entry or a caller-supplied pathname. Symlinks, writable-by-others paths,
    missing/ambiguous RECORD entries and modified scripts never establish ownership. This
    proves local installation identity, not publisher authenticity against the machine owner.
    """

    try:
        pin = read_runtime_pin()
        if pin is not None:
            root = isolated_root()
            if root is None:
                return None
            identity = read_instance_identity(root / "state")
            verify_instance_binding(identity, isolated=True, pin=pin, now=datetime.now(UTC))
            if identity is None or (
                identity.runtime_prefix_digest != runtime_prefix_digest(Path(sys.prefix))
                or identity.package_version != __version__
            ):
                return None
        candidate = Path(sysconfig.get_path("scripts")) / "yoetz"
        if not candidate.is_absolute() or len(str(candidate)) > 4096:
            return None
        if any(ord(c) < 32 or ord(c) == 127 for c in str(candidate)):
            return None
        for path in (candidate, *candidate.parents):
            facts = path.lstat()
            if stat.S_ISLNK(facts.st_mode) or writable_by_others(facts):
                return None
            if facts.st_uid not in {0, os.geteuid()}:
                return None
        facts = candidate.lstat()
        if not stat.S_ISREG(facts.st_mode) or not os.access(candidate, os.X_OK):
            return None
        if facts.st_size > 65_536:
            return None
        package = distribution("yoetz")
        matches = [
            entry
            for entry in package.files or ()
            if Path(os.path.abspath(str(package.locate_file(entry)))) == candidate
        ]
        if len(matches) != 1:
            return None
        entry = matches[0]
        expected = entry.hash
        if expected is None or expected.mode != "sha256" or entry.size != facts.st_size:
            return None
        with candidate.open("rb") as stream:
            raw = stream.read(65_537)
        if len(raw) != entry.size:
            return None
        digest = hashlib.sha256(raw)
        if base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode() != expected.value:
            return None
        return str(candidate), "sha256:" + digest.hexdigest()
    except OSError, ValueError, PackageNotFoundError, InstanceIdentityError, PathSafetyError:
        return None
