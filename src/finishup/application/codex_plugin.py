"""Owning application service for Codex trusted-project plugin install/inspect.

Callers (including the setup wizard) must go through this service rather than
duplicating filesystem writes around ``install_plugin``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from finishup.adapters.integrations.codex_plugin import (
    PluginHookPresence,
    PluginInspection,
    inspect_plugin,
    install_plugin,
    render_plugin_tree,
)
from finishup.ports.integrations import IntegrationError, IntegrationTarget

__all__ = [
    "CodexPluginPreview",
    "CodexPluginService",
]

_MAX_PREVIEW_FILES: Final = 64


@dataclass(frozen=True, slots=True, repr=False)
class CodexPluginPreview:
    """Path-free preview of the managed plugin tree before mutation."""

    presence_before: PluginHookPresence
    planned_file_count: int
    trust_observable: bool
    installed_digest: str | None
    notes: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            "CodexPluginPreview("
            f"presence_before={self.presence_before.value!r}, "
            f"planned_file_count={self.planned_file_count!r})"
        )


class CodexPluginService:
    """Thin ownership boundary over the Codex plugin adapter."""

    __slots__ = ()

    def preview(
        self, target: IntegrationTarget, *, codex_version: str | None = None
    ) -> CodexPluginPreview:
        inspection = inspect_plugin(target, codex_version=codex_version)
        planned = len(render_plugin_tree(codex_version=codex_version))
        if planned > _MAX_PREVIEW_FILES:
            planned = _MAX_PREVIEW_FILES
        return CodexPluginPreview(
            presence_before=inspection.presence,
            planned_file_count=planned,
            trust_observable=inspection.trust_observable,
            installed_digest=inspection.installed_digest,
            notes=inspection.notes,
        )

    def inspect(
        self, target: IntegrationTarget, *, codex_version: str | None = None
    ) -> PluginInspection:
        return inspect_plugin(target, codex_version=codex_version)

    def install(
        self,
        target: IntegrationTarget,
        *,
        replace_modified: bool = False,
        allow_untested: bool = False,
        codex_version: str | None = None,
    ) -> PluginInspection:
        """Install via the adapter installer; never rewrite plugin files here."""

        try:
            return install_plugin(
                target,
                replace_modified=replace_modified,
                allow_untested=allow_untested,
                codex_version=codex_version,
            )
        except IntegrationError:
            raise
