"""Pre-rename spellings FinishUP still recognizes (ADR-048).

The product shipped as Yoetz through 0.2.5 and is FinishUP from 0.3.0. Existing installs keep
data, host registrations, environment variables, and repository files written under the old
name, so every surface that reads one of those spellings accepts the legacy form alongside the
new one. New output always uses the FinishUP spelling.

Names that live inside stored or released bytes (ledger protocol tags, object formats, crypto
domain separators, keyring service names, SQL columns, wire enum values, released schemas) are
not here: they never changed, so there is nothing to recognize. They stay spelled ``yoetz``
in place, each labeled as a frozen legacy identifier.

This module is dependency-free so the lowest layers (configuration, paths) can import it.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "APP_NAME",
    "ENV_PREFIX",
    "GUIDANCE_SCHEME",
    "LAUNCHER_NAME",
    "LAUNCHER_NAMES",
    "LEGACY_APP_NAME",
    "LEGACY_ENV_PREFIX",
    "LEGACY_GUIDANCE_SCHEME",
    "LEGACY_LAUNCHER_NAME",
    "LEGACY_MCP_SERVER_NAME",
    "LEGACY_PRODUCT_NAME",
    "LEGACY_REPOSITORY_DIRECTORY",
    "MCP_SERVER_NAME",
    "MCP_SERVER_NAMES",
    "PRODUCT_NAME",
    "REPOSITORY_DIRECTORY",
]

PRODUCT_NAME: Final = "FinishUP"
LEGACY_PRODUCT_NAME: Final = "Yoetz"

# Platform directory application name (state, data, config, cache, runtime roots).
APP_NAME: Final = "finishup"
LEGACY_APP_NAME: Final = "yoetz"

# Console launcher and distribution names. The legacy launcher is the deprecated alias.
LAUNCHER_NAME: Final = "finishup"
LEGACY_LAUNCHER_NAME: Final = "yoetz"
LAUNCHER_NAMES: Final = frozenset({LAUNCHER_NAME, LEGACY_LAUNCHER_NAME})

# Environment variable namespace. A legacy name is read only when its new name is unset.
ENV_PREFIX: Final = "FINISHUP_"
LEGACY_ENV_PREFIX: Final = "YOETZ_"

# MCP server registration key in host configuration.
MCP_SERVER_NAME: Final = "finishup"
LEGACY_MCP_SERVER_NAME: Final = "yoetz"
MCP_SERVER_NAMES: Final = frozenset({MCP_SERVER_NAME, LEGACY_MCP_SERVER_NAME})

# Packaged guidance resource URI scheme.
GUIDANCE_SCHEME: Final = "finishup"
LEGACY_GUIDANCE_SCHEME: Final = "yoetz"

# Repository-local configuration directory (for example ``.finishup/checks.toml``).
REPOSITORY_DIRECTORY: Final = ".finishup"
LEGACY_REPOSITORY_DIRECTORY: Final = ".yoetz"
