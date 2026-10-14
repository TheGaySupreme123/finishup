"""The deliberately small, side-effect-free FinishUP package boundary."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Wave F owns this module; retain the required type-only edge without materializing it early.
    from finishup.version import (  # pyright: ignore[reportMissingImports]
        VersionManifest,  # pyright: ignore[reportMissingImports, reportUnknownVariableType]
    )

# Always the ``finishup`` distribution: a transitional ``yoetz`` distribution installed beside it
# (ADR-048) carries its own metadata and must never stand in for this package's version.
try:
    __version__ = version("finishup")
except PackageNotFoundError:
    __version__ = "0.0.0+uninstalled"

__all__ = ("__version__", "get_version_manifest")


def get_version_manifest() -> VersionManifest:  # pyright: ignore[reportUnknownParameterType]
    """Build the installed runtime manifest without widening ordinary package import."""

    # The runtime import is intentionally lazy and becomes statically resolvable in Wave F.
    from finishup.version import (  # pyright: ignore[reportMissingImports]
        build_version_manifest,  # pyright: ignore[reportMissingImports, reportUnknownVariableType]
    )

    return build_version_manifest()  # pyright: ignore[reportUnknownVariableType]
