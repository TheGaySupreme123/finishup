"""The reviewer's own Codex model catalog: the bundled reviewer-model entry minus forced tools.

Codex 0.162.1's bundled catalog entry for ``gpt-6.1-sol`` forces three tool families onto every
turn that no ordinary config key turns off (#1118, ADR-006):

* ``tool_mode: "code_mode_only"`` overrides every ``features.code_mode*`` key and registers the
  code-mode ``exec``/``wait`` tools (``codex-rs/core/src/tools/mod.rs`` ``requested_tool_mode``);
* ``experimental_supported_tools: ["send_user_message_async", ...]`` registers
  ``request_user_input_async`` (``core/src/tools/spec_plan.rs``);
* ``experimental_supported_tools: [..., "clock"]`` registers ``clock.curr_time``.

Codex's supported ``model_catalog_json`` config key replaces the whole model catalog for the
process with a file (``core/src/config/mod.rs`` ``load_catalog_json``; the provider then serves a
``StaticModelsManager`` and never fetches ``/models``). FinishUP ships one derived file for that
key: the entry exactly as the pinned runtime exposes it (``codex debug models --bundled``), minus
``tool_mode`` and with those two experimental tools removed. Every other field (context window,
efforts, truncation, instructions, messages) is byte-for-byte the bundled value, so model
behaviour does not drift.

Codex 0.164.0's bundled ``gpt-6.1-sol`` entry is byte-identical to 0.162.1's (same source-entry
digest, same derived file; #1228), so one derived file serves both releases.

The file is applied only when the runtime release, the model and the bundled entry the exact
launched bytes expose all match the pins below, and the packaged file still has its pinned digest.
Otherwise the launch is unchanged and the closed reason is recorded. Nothing here reads a
credential or starts a model session.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Final, Literal, cast

from finishup.domain.reviewer_context import ReviewerContextWindow
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "REVIEWER_CATALOG_DERIVED_SHA256",
    "REVIEWER_CATALOG_MODEL",
    "REVIEWER_CATALOG_RESOURCE",
    "REVIEWER_CATALOG_RUNTIME_VERSION",
    "REVIEWER_CATALOG_RUNTIME_VERSIONS",
    "REVIEWER_CATALOG_SOURCE_ENTRY_SHA256",
    "ReviewerCatalogDecision",
    "ReviewerCatalogReason",
    "bundled_entry_sha256",
    "derive_reviewer_catalog",
    "packaged_reviewer_catalog_path",
    "resolve_reviewer_catalog",
    "restore_source_entry",
    "reviewer_model_context_window",
]

# The release the derived file was generated from (Codex tag ``rust-v0.162.1``,
# ``codex-rs/models-manager/models.json``, exposed by ``codex debug models --bundled``).
REVIEWER_CATALOG_RUNTIME_VERSION: Final = "0.162.1"
# Every release the derivation is pinned for: each exposes the same bundled entry digest, which
# every launch re-measures from its own bytes (0.164.0 checked 2026-10-26, #1228).
REVIEWER_CATALOG_RUNTIME_VERSIONS: Final = frozenset({REVIEWER_CATALOG_RUNTIME_VERSION, "0.164.0"})
REVIEWER_CATALOG_MODEL: Final = "gpt-6.1-sol"
# Package-relative path of the generated file (source: ``support/codex-evaluator/``).
REVIEWER_CATALOG_RESOURCE: Final = "support/codex-evaluator/reviewer-model-catalog-0.162.1.json"
# SHA-256 of the FinishUP canonical encoding of the bundled ``gpt-6.1-sol`` entry as Codex
# 0.162.1 and 0.164.0 expose it. The launch measures the same digest from the exact bytes it
# launches.
REVIEWER_CATALOG_SOURCE_ENTRY_SHA256: Final = (
    "sha256:2723b11fc3c0791615cb5a14f6c1abade723228bd7b3d269f5eebeb7264d2cb6"
)
# SHA-256 of the derived file's exact bytes (canonical JSON plus one final LF).
REVIEWER_CATALOG_DERIVED_SHA256: Final = (
    "sha256:f2d4fd66291e1a62ed51d29555407804a3d67a4eb4791841e0b620708a58aadb"
)
# Exactly what the derivation removes; ``restore_source_entry`` puts it back to prove the pin.
_REMOVED_TOOL_MODE: Final = "code_mode_only"
_REMOVED_EXPERIMENTAL_TOOLS: Final = ("send_user_message_async", "clock")

ReviewerCatalogReason = Literal[
    "applied",
    "runtime_release_not_pinned",
    "model_not_pinned",
    "bundled_entry_unavailable",
    "bundled_entry_changed",
    "derived_catalog_unavailable",
    "derived_catalog_changed",
]


@dataclass(frozen=True, slots=True)
class ReviewerCatalogDecision:
    """Whether one launch passes ``model_catalog_json`` and, when it does not, the closed reason."""

    path: Path | None
    reason: ReviewerCatalogReason


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _models(catalog: object) -> list[object]:
    if not isinstance(catalog, Mapping):
        raise ValueError("codex_reviewer_catalog_invalid")
    models = cast(Mapping[str, object], catalog).get("models")
    if not isinstance(models, list):
        raise ValueError("codex_reviewer_catalog_invalid")
    return cast(list[object], models)


def _entry(catalog: object, model: str) -> Mapping[str, JsonValue]:
    matches: list[object] = [
        item
        for item in _models(catalog)
        if isinstance(item, Mapping) and cast(Mapping[str, object], item).get("slug") == model
    ]
    if len(matches) != 1:
        raise ValueError("codex_reviewer_catalog_entry_missing")
    return cast(Mapping[str, JsonValue], matches[0])


def bundled_entry_sha256(catalog: object, model: str = REVIEWER_CATALOG_MODEL) -> str:
    """Digest of one model's entry in a parsed ``codex debug models --bundled`` catalog."""

    try:
        return _sha256(canonical_encode(cast(JsonValue, _entry(catalog, model))))
    except ProtocolValueError as error:
        raise ValueError("codex_reviewer_catalog_invalid") from error


def derive_reviewer_catalog(bundled_catalog: object) -> bytes:
    """Derive the reviewer catalog file from the pinned runtime's bundled catalog.

    The source entry must have the pinned digest. The result is a one-model catalog holding that
    entry without ``tool_mode`` and without the two forced experimental tools, encoded as
    FinishUP canonical JSON with one final LF.
    """

    if bundled_entry_sha256(bundled_catalog) != REVIEWER_CATALOG_SOURCE_ENTRY_SHA256:
        raise ValueError("codex_reviewer_catalog_source_changed")
    entry = copy.deepcopy(dict(_entry(bundled_catalog, REVIEWER_CATALOG_MODEL)))
    if entry.get("tool_mode") != _REMOVED_TOOL_MODE or entry.get(
        "experimental_supported_tools"
    ) != list(_REMOVED_EXPERIMENTAL_TOOLS):
        raise ValueError("codex_reviewer_catalog_source_changed")
    del entry["tool_mode"]
    entry["experimental_supported_tools"] = []
    return canonical_encode({"models": [entry]}) + b"\n"


def restore_source_entry(derived: bytes) -> Mapping[str, JsonValue]:
    """Undo exactly the derivation, so a test can prove the file against the source pin."""

    if not derived.endswith(b"\n"):
        raise ValueError("codex_reviewer_catalog_invalid")
    parsed = strict_json_parse(derived[:-1])
    models = _models(parsed)
    if len(models) != 1:
        raise ValueError("codex_reviewer_catalog_invalid")
    entry = cast(dict[str, JsonValue], copy.deepcopy(_entry(parsed, REVIEWER_CATALOG_MODEL)))
    if "tool_mode" in entry or entry.get("experimental_supported_tools") != []:
        raise ValueError("codex_reviewer_catalog_invalid")
    entry["tool_mode"] = _REMOVED_TOOL_MODE
    entry["experimental_supported_tools"] = list(_REMOVED_EXPERIMENTAL_TOOLS)
    return entry


def packaged_reviewer_catalog_path() -> Path | None:
    """The installed derived file as a real, non-symlinked regular file, or ``None``."""

    try:
        node = resources.files("finishup.resources").joinpath(REVIEWER_CATALOG_RESOURCE)
    except (ModuleNotFoundError, OSError):
        return None
    if not isinstance(node, Path):
        return None
    path = node.absolute()
    try:
        if path.is_symlink() or not path.is_file():
            return None
    except OSError:
        return None
    return path


def resolve_reviewer_catalog(
    *,
    runtime_version: str,
    model: str,
    measured_entry_sha256: str | None,
    catalog_path: Path | None,
) -> ReviewerCatalogDecision:
    """Decide one launch: apply the derived catalog only when every pin matches.

    ``measured_entry_sha256`` is the bundled entry digest measured from the exact executable
    bytes being launched (``None`` when it could not be measured); ``catalog_path`` is the
    packaged derived file (``None`` when it is not installed as a regular file).
    """

    if runtime_version not in REVIEWER_CATALOG_RUNTIME_VERSIONS:
        return ReviewerCatalogDecision(None, "runtime_release_not_pinned")
    if model != REVIEWER_CATALOG_MODEL:
        return ReviewerCatalogDecision(None, "model_not_pinned")
    if measured_entry_sha256 is None:
        return ReviewerCatalogDecision(None, "bundled_entry_unavailable")
    if measured_entry_sha256 != REVIEWER_CATALOG_SOURCE_ENTRY_SHA256:
        return ReviewerCatalogDecision(None, "bundled_entry_changed")
    if catalog_path is None:
        return ReviewerCatalogDecision(None, "derived_catalog_unavailable")
    try:
        data = catalog_path.read_bytes()
    except OSError:
        return ReviewerCatalogDecision(None, "derived_catalog_unavailable")
    if _sha256(data) != REVIEWER_CATALOG_DERIVED_SHA256:
        return ReviewerCatalogDecision(None, "derived_catalog_changed")
    return ReviewerCatalogDecision(catalog_path, "applied")


def reviewer_model_context_window(model: str) -> ReviewerContextWindow | None:
    """The pinned reviewer model's context window, read from the packaged derived catalog.

    ``context_window`` and ``effective_context_window_percent`` are the bundled values (0.162.1 and
    0.164.0) byte for byte, so they hold whether or not a launch applies the file: without it a
    ChatGPT login serves the live ``/models`` entry, whose window was larger (500,000) when
    measured.
    ``None`` for any other model, or when the packaged file is missing or not its pinned bytes;
    such a route keeps the unsized exchange bound.
    """

    if model != REVIEWER_CATALOG_MODEL:
        return None
    path = packaged_reviewer_catalog_path()
    if path is None:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if _sha256(data) != REVIEWER_CATALOG_DERIVED_SHA256:
        return None
    try:
        entry = _entry(strict_json_parse(data[:-1]), model)
        window = entry.get("context_window")
        percent = entry.get("effective_context_window_percent")
        if type(window) is not int or type(percent) is not int:
            return None
        return ReviewerContextWindow(window, percent)
    except (ProtocolValueError, ValueError):
        return None
