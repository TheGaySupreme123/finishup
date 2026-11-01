"""FinishUP environment variables and their legacy ``YOETZ_`` spellings (ADR-048).

Every runtime variable is read under its ``FINISHUP_`` name first. The ``YOETZ_`` spelling that
0.1-0.2 installs, shells, CI jobs, test instances, and host registrations still export is read only
when the ``FINISHUP_`` name is unset. Both set to the same value is the same setting; both set to
different values is ambiguous and fails closed rather than choosing either.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Final

from finishup.legacy_names import ENV_PREFIX, LEGACY_ENV_PREFIX

__all__ = [
    "ENV_PREFIXES",
    "EnvNameConflictError",
    "canonical_env_name",
    "env_names",
    "read_env",
]

# Recognized prefixes, FinishUP first (ADR-048).
ENV_PREFIXES: Final = (ENV_PREFIX, LEGACY_ENV_PREFIX)


class EnvNameConflictError(Exception):
    """Both spellings of one variable are set to different values.

    ``name`` is the reviewed ``FINISHUP_`` spelling; neither value is ever carried.
    """

    name: str

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__("env_name_conflict")


def env_names(suffix: str) -> tuple[str, str]:
    """Return the ``FINISHUP_`` name and its legacy ``YOETZ_`` spelling (ADR-048) for a suffix."""

    return ENV_PREFIX + suffix, LEGACY_ENV_PREFIX + suffix


def canonical_env_name(name: str) -> str | None:
    """Return the ``FINISHUP_`` spelling of a product variable name, or ``None`` for others.

    A legacy ``YOETZ_`` name maps to its ``FINISHUP_`` twin (ADR-048); any other name, including
    underscore-prefixed harness variables, is not a product variable.
    """

    if name.startswith(ENV_PREFIX):
        return name
    if name.startswith(LEGACY_ENV_PREFIX):
        return ENV_PREFIX + name[len(LEGACY_ENV_PREFIX) :]
    return None


def read_env(suffix: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Return the value of ``FINISHUP_<suffix>``, else of its legacy spelling, else ``None``.

    Raises ``EnvNameConflictError`` when both spellings are set to different values (ADR-048).
    """

    source = os.environ if environ is None else environ
    name, legacy_name = env_names(suffix)
    value = source.get(name)
    legacy_value = source.get(legacy_name)
    if value is not None and legacy_value is not None and value != legacy_value:
        raise EnvNameConflictError(name)
    return legacy_value if value is None else value
