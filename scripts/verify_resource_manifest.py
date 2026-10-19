"""Synchronize and prove packaged resource parity between public sources and the installed wheel.

This is the sole repository tool allowed to copy canonical resources into
``src/finishup/resources/`` and regenerate ``src/finishup/resources/manifest.json``. Its default
``--check`` mode is strictly read-only; ``--sync`` stages a complete tree, atomically replaces
current inventory-owned destination files, and retires destinations from the prior inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)

__all__ = [
    "CollectedResource",
    "ResourceDiff",
    "ResourceInventory",
    "ResourceInventoryEntry",
    "build_manifest",
    "build_codex_skill_manifest",
    "collect_source_entries",
    "load_inventory_config",
    "main",
    "sync_resource_tree",
    "uninventoried_sources",
    "verify_codex_skill_manifest",
    "verify_resource_tree",
    "verify_source_coverage",
]


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResourceInventoryEntry:
    logical_name: str
    source_path: str
    package_path: str
    kind: str
    media_type: str
    size_cap: int
    text: bool
    contract_version: str | None = None


@dataclass(frozen=True, slots=True)
class ResourceInventory:
    package: str
    resource_set_version: str
    entries: tuple[ResourceInventoryEntry, ...]


@dataclass(frozen=True, slots=True)
class CollectedResource:
    entry: ResourceInventoryEntry
    size: int
    sha256: str
    data: bytes


@dataclass(frozen=True, slots=True)
class ResourceDiff:
    missing: tuple[str, ...]
    extra: tuple[str, ...]
    changed: tuple[str, ...]
    manifest_mismatch: bool

    @property
    def is_clean(self) -> bool:
        return not (self.missing or self.extra or self.changed or self.manifest_mismatch)


class ResourceManifestError(Exception):
    """A bounded, traceback-free resource inventory/collection/integrity failure."""

    def __init__(self, reason: str, *, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

_PACKAGE_NAME: Final = "finishup"
_RESOURCE_SET_VERSION: Final = "0.1.0"
# Frozen legacy identifier (ADR-048): resource-manifest format tag (lockstep with version.py).
_MANIFEST_SCHEMA: Final = "yoetz.resource-manifest/1"
_PACKAGE_RESOURCE_ROOT: Final = "src/finishup/resources"
_ALLOWED_SOURCE_ROOTS: Final = (
    "schemas/",
    "migrations/",
    "skills/",
    "guidance/",
    "fixtures/",
    "support/",
)
_MAX_TEXT_BYTES: Final = 2_000_000
_MAX_BINARY_BYTES: Final = 20_000_000
_CODEX_SKILL_MANIFEST = "skills/codex/finishup/manifest.json"
_CODEX_SKILL_MEMBERS: Final = (
    ("SKILL.md", "harness_owned", "skill", "skills/codex/finishup/SKILL.md"),
    (
        "references/agent-instructions.md",
        "shared_guidance",
        "guidance",
        "guidance/agent-instructions.md",
    ),
    (
        "references/coverage-and-receipts.md",
        "shared_guidance",
        "guidance",
        "guidance/coverage-and-receipts.md",
    ),
    (
        "references/publication-policy.md",
        "shared_guidance",
        "guidance",
        "guidance/publication-policy.md",
    ),
    (
        "references/request-templates.md",
        "shared_guidance",
        "guidance",
        "guidance/request-templates.md",
    ),
    ("references/workflow.md", "shared_guidance", "guidance", "guidance/workflow.md"),
    ("references/startup.md", "shared_guidance", "guidance", "guidance/startup.md"),
    ("references/recovery.md", "shared_guidance", "guidance", "guidance/recovery.md"),
    ("references/publication.md", "shared_guidance", "guidance", "guidance/publication.md"),
    ("references/review.md", "shared_guidance", "guidance", "guidance/review.md"),
    ("references/receipt.md", "shared_guidance", "guidance", "guidance/receipt.md"),
    ("references/delegation.md", "shared_guidance", "guidance", "guidance/delegation.md"),
    ("references/consent.md", "shared_guidance", "guidance", "guidance/consent.md"),
    ("references/page-delivery.md", "shared_guidance", "guidance", "guidance/page-delivery.md"),
)

# Source-root content that is deliberately NOT packaged: test corpora and repository-only artifacts
# that the runtime never reads. Every other file beneath an allowed source root must appear in the
# inventory below, so a new vector, schema, guidance page, or support file cannot silently miss the
# wheel: ``--check`` and ``--sync`` both fail closed on an uninventoried source (``source_unpackaged``).
# Each prefix is either a directory (trailing ``/``) or one exact file.
_UNPACKAGED_SOURCE_PREFIXES: Final[tuple[str, ...]] = (
    "fixtures/adversarial/",
    "fixtures/backward-read/",
    "fixtures/codex-tool-boundary/",
    "fixtures/imports/",
    "fixtures/integrations/",
    "fixtures/manifest.json",
    "fixtures/observations/",
    "fixtures/privacy/",
    "fixtures/receipts/",
    "fixtures/replay/",
    "fixtures/service/",
    "support/npm-launcher/",
)
# Editor, OS, and interpreter droppings never count as sources.
_IGNORED_SOURCE_NAMES: Final = frozenset({".DS_Store", "__pycache__"})

# The reviewed, explicit v0.1 inventory across 6 canonical source roots. Every entry
# is deliberately listed here; nothing is discovered by scanning the repository.
_INVENTORY_ENTRIES: Final[tuple[tuple[str, str, str, bool], ...]] = (
    (
        "schemas/privacy/review-packet-row-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "fixtures/canonical/review-packet-rows-2.0.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/advice-egress-1.1.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/check-agent-next-1.5.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/check-inspection-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/check-observations-awaited-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/check-totals-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/deferred-before-first-edit-1.5.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/check-reviewer-record-1.6.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/review-mode-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    ("guidance/startup.md", "guidance", "text/markdown", True),
    ("guidance/recovery.md", "guidance", "text/markdown", True),
    ("guidance/publication.md", "guidance", "text/markdown", True),
    ("guidance/review.md", "guidance", "text/markdown", True),
    ("guidance/receipt.md", "guidance", "text/markdown", True),
    ("guidance/delegation.md", "guidance", "text/markdown", True),
    ("guidance/consent.md", "guidance", "text/markdown", True),
    ("guidance/page-delivery.md", "guidance", "text/markdown", True),
    (
        "schemas/events/check-recorded-1.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/check-recorded-1.5.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/check-recorded-1.6.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/finding-recorded-1.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    ("schemas/findings/finding-1.4.0.schema.json", "json_schema", "application/schema+json", True),
    (
        "schemas/findings/provider-judgment-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/reviewer-reply-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-result-1.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-result-1.5.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-result-1.6.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "fixtures/canonical/check-conclusion-1.3.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/review-dialogue-1.3.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "schemas/integrations/mcp-removal-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/integrations/setup-readiness-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/integrations/host-connection-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/integrations/setup-status-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "fixtures/agent-plugins/codex-project-plugin-managed-mcp.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/codex-project-root.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/cursor-cli-portable-2026.07.09.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/cursor-ide-native-3.17.8.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/claude-code-cli-native-project-2.1.241.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/claude-code-cli-native-project-2.1.261.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/cursor-sdk-python-1.0.24.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/cursor-sdk-typescript-1.0.23.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/agent-plugins/cursor-stale-shared-mcp-runtime.case.json",
        "compatibility_manifest",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/accepted-entry-identity.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/claim-correction-1.1.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/task-statement.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/control-native-capture-2.5.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/control-observation-status-2.6.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/control-observation-status-2.9.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/control-project-policy-2.7.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    ("fixtures/canonical/identifiers.case.json", "canonical_vector", "application/json", True),
    ("fixtures/canonical/object-envelope.case.json", "canonical_vector", "application/json", True),
    (
        "fixtures/canonical/publish-action-notices-1.1.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/publication-request-identity.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/restricted-json-positive.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/restricted-json-rejections.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/rfc8785-applicable.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/server-filled-brief-status-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/status-check-admission-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/status-check-outcome-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/status-evidence-author-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/status-finding-frontier-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/status-semantic-progress-1.4.0.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/unicode-normalization-distinct.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        "fixtures/canonical/utf16-property-order.case.json",
        "canonical_vector",
        "application/json",
        True,
    ),
    (
        # Frozen legacy identifier (ADR-048): released canonical vector path and media type.
        "fixtures/canonical/OBS-001-captured-evidence.case.json",
        "canonical_vector",
        "application/vnd.yoetz.fixture-case+json",
        True,
    ),
    ("guidance/agent-instructions.md", "guidance", "text/markdown", True),
    ("guidance/coverage-and-receipts.md", "guidance", "text/markdown", True),
    ("guidance/publication-policy.md", "guidance", "text/markdown", True),
    ("guidance/request-templates.md", "guidance", "text/markdown", True),
    ("guidance/workflow.md", "guidance", "text/markdown", True),
    ("migrations/bundle/0001.sql", "migration", "application/sql", True),
    ("migrations/bundle/0002.sql", "migration", "application/sql", True),
    ("migrations/bundle/0003.sql", "migration", "application/sql", True),
    ("migrations/bundle/0004.sql", "migration", "application/sql", True),
    ("migrations/bundle/0005.sql", "migration", "application/sql", True),
    ("migrations/bundle/0006.sql", "migration", "application/sql", True),
    ("migrations/bundle/0007.sql", "migration", "application/sql", True),
    ("migrations/bundle/0008.sql", "migration", "application/sql", True),
    ("migrations/bundle/0009.sql", "migration", "application/sql", True),
    ("migrations/bundle/0010.sql", "migration", "application/sql", True),
    ("migrations/bundle/0011.sql", "migration", "application/sql", True),
    ("migrations/bundle/0012.sql", "migration", "application/sql", True),
    ("migrations/bundle/0013.sql", "migration", "application/sql", True),
    ("migrations/bundle/0014.sql", "migration", "application/sql", True),
    ("migrations/bundle/0015.sql", "migration", "application/sql", True),
    ("migrations/bundle/0016.sql", "migration", "application/sql", True),
    ("migrations/bundle/0017.sql", "migration", "application/sql", True),
    ("migrations/catalog/0001.sql", "migration", "application/sql", True),
    ("migrations/catalog/0002.sql", "migration", "application/sql", True),
    ("migrations/catalog/0003.sql", "migration", "application/sql", True),
    ("migrations/catalog/0004.sql", "migration", "application/sql", True),
    ("migrations/catalog/0005.sql", "migration", "application/sql", True),
    (
        "schemas/common/actor-assertion-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/common/client-info-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    ("schemas/common/coverage-1.0.0.schema.json", "json_schema", "application/schema+json", True),
    ("schemas/common/frontier-1.0.0.schema.json", "json_schema", "application/schema+json", True),
    (
        "schemas/common/operation-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/common/public-error-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/common/subject-state-ref-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    # Frozen legacy identifier (ADR-048): released config schema family "yoetz-config".
    (
        "schemas/config/yoetz-config-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/config/yoetz-config-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/config/yoetz-config-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/config/yoetz-config-1.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/catalog-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/catalog-3.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/catalog-4.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/catalog-5.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/catalog-6.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/chat-user-attestation-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/pending-agent-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/pending-agent-3.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/pending-agent-4.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/pending-agent-5.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/pending-agent-6.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/prepare-result-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/prepare-result-3.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/prepare-result-4.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/prepare-result-5.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/prepare-result-6.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/review-result-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/review-result-3.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/review-result-4.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/review-result-5.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/review-result-6.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/status-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/status-3.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/status-4.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/status-5.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/status-6.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/accepted-event-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/action-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/assignment-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/check-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/check-recorded-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/check-recorded-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/check-recorded-1.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/claim-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/claim-recorded-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/decision-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/decision-recorded-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/event-draft-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/event-draft-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/evidence-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/evidence-recorded-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/evidence-recorded-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/finding-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/finding-recorded-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/finding-recorded-1.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/finding-recorded-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/obligation-published-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/opaque-unknown-event-draft-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/opaque-unknown-event-draft-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/plan-published-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/plan-revised-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/receipt-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/redaction-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/response-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/response-recorded-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/result-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/session-opened-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/session-opened-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/session-resumed-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/session-resumed-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    ("schemas/findings/finding-1.0.0.schema.json", "json_schema", "application/schema+json", True),
    ("schemas/findings/finding-1.1.0.schema.json", "json_schema", "application/schema+json", True),
    ("schemas/findings/finding-1.2.0.schema.json", "json_schema", "application/schema+json", True),
    ("schemas/findings/finding-1.3.0.schema.json", "json_schema", "application/schema+json", True),
    (
        "schemas/events/coordination-context-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/coordination-disposition-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/coordination-obligation-declared-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-request-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/closure-prepare-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/closure-prepare-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/provider-judgment-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/provider-judgment-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/semantic-provenance-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/semantic-provenance-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/semantic-provenance-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/runtime-attempt-evidence-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/child-accepted-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/child-dependencies-recorded-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/child-rejected-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/child-written-off-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/delegation-cancelled-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/delegation-declared-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/event-draft-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/opaque-unknown-event-draft-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/session-opened-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/session-resumed-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/plan-published-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/plan-revised-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/obligation-published-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/privacy-policy-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/work-abandoned-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/work-cancelled-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/work-closed-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/events/work-written-off-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-result-1.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-result-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/publish-work-request-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/receipt-result-1.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/receipt-result-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/start-request-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/start-result-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-request-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-result-1.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-result-1.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/receipts/receipt-document-1.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/receipts/receipt-document-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/common/lineage-acceptance-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/common/lineage-origin-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/common/session-health-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/common/work-state-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/catalog-7.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/pending-agent-7.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/prepare-result-7.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/review-result-7.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/consent/status-7.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/findings/runtime-attempt-evidence-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    ("schemas/manifest.json", "json_schema", "application/json", True),
    (
        "schemas/observations/routine-read-summary-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/check-result-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/publish-work-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/publish-work-request-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/publish-work-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/publish-work-result-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/read-guidance-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/read-guidance-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/read-guidance-request-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/read-guidance-result-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/receipt-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/receipt-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/receipt-result-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/respond-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/respond-request-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/respond-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/respond-result-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/start-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/start-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-request-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-result-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/operations/status-result-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/egress-receipt-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/egress-receipt-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/outbound-case-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/outbound-case-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/outbound-case-1.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/privacy-policy-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/privacy-policy-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/privacy/setup-wizard-contract-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/receipts/receipt-document-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/receipts/receipt-document-1.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.4.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.5.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.5.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.5.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.5.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.6.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.6.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.6.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.6.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.6.1.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.6.1.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.7.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.7.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.7.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.7.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.8.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.8.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.8.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.8.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-2.9.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-hello-result-2.9.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-request-2.9.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/control-result-2.9.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/isolation-report-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/service/service-status-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-1.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.0.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.1.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.3.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.2.0.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.2.1.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.2.2.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.2.3.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    (
        "schemas/version/version-manifest-2.2.4.schema.json",
        "json_schema",
        "application/schema+json",
        True,
    ),
    ("skills/claude-code/finishup/SKILL.md", "skill", "text/markdown", True),
    ("skills/codex/finishup/SKILL.md", "skill", "text/markdown", True),
    ("skills/codex/finishup/manifest.json", "compatibility_manifest", "application/json", True),
    ("skills/cursor/finishup/SKILL.md", "skill", "text/markdown", True),
    ("skills/portable/finishup/SKILL.md", "skill", "text/markdown", True),
    (
        "support/agent-plugins/1.0.0/mcp.schema.json",
        "json_schema",
        "application/schema+json",
        False,
    ),
    (
        "support/agent-plugins/1.0.0/plugin.schema.json",
        "json_schema",
        "application/schema+json",
        False,
    ),
    ("support/runtime-support.json", "runtime_support", "application/json", True),
    (
        "support/codex-evaluator/config.toml",
        "runtime_config",
        "application/toml",
        True,
    ),
)


# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------


def _is_safe_relative_path(path: str) -> bool:
    if not path or path != unicodedata.normalize("NFC", path):
        return False
    if path.startswith("/") or path.endswith("/") or "\\" in path or "\x00" in path:
        return False
    if "//" in path:
        return False
    if any(ord(ch) < 0x20 for ch in path):
        return False
    return all(segment not in {"", ".", ".."} for segment in path.split("/"))


def _within_allowed_root(path: str) -> bool:
    return any(path.startswith(root) for root in _ALLOWED_SOURCE_ROOTS)


def _assert_no_symlink_path(path: Path, *, root: Path) -> None:
    """Reject a path or any existing component beneath the selected repository root."""

    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ResourceManifestError("path_outside_root", detail=str(path)) from exc
    current = root
    if current.is_symlink():
        raise ResourceManifestError("symlink_forbidden", detail=str(current))
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ResourceManifestError("symlink_forbidden", detail=str(current))


def _package_files(resource_root: Path, *, repo_root: Path) -> tuple[Path, ...]:
    """Enumerate package files without following symlinked roots, directories, or files."""

    _assert_no_symlink_path(resource_root, root=repo_root)
    if not resource_root.exists():
        return ()
    if not resource_root.is_dir():
        raise ResourceManifestError("resource_root_invalid", detail=str(resource_root))

    files: list[Path] = []
    pending = [resource_root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_symlink():
                    raise ResourceManifestError("symlink_forbidden", detail=str(path))
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    files.append(path)
                else:
                    raise ResourceManifestError("resource_entry_invalid", detail=str(path))
    return tuple(
        sorted(files, key=lambda path: path.relative_to(resource_root).as_posix().encode())
    )


# --------------------------------------------------------------------------
# Public surface
# --------------------------------------------------------------------------


def load_inventory_config() -> ResourceInventory:
    """Return the checked-in, code-owned source/destination resource inventory."""

    entries: list[ResourceInventoryEntry] = []
    for source_path, kind, media_type, text in _INVENTORY_ENTRIES:
        if not _is_safe_relative_path(source_path) or not _within_allowed_root(source_path):
            raise ResourceManifestError("inventory_path_unsafe", detail=source_path)
        size_cap = _MAX_TEXT_BYTES if text else _MAX_BINARY_BYTES
        entries.append(
            ResourceInventoryEntry(
                logical_name=source_path,
                source_path=source_path,
                package_path=source_path,
                kind=kind,
                media_type=media_type,
                size_cap=size_cap,
                text=text,
            )
        )

    ordered = tuple(sorted(entries, key=lambda item: item.logical_name.encode("utf-8")))
    logical_names = [entry.logical_name for entry in ordered]
    if len(set(logical_names)) != len(logical_names):
        raise ResourceManifestError("duplicate_logical_name")

    return ResourceInventory(
        package=_PACKAGE_NAME, resource_set_version=_RESOURCE_SET_VERSION, entries=ordered
    )


def _is_unpackaged_source(path: str) -> bool:
    return any(
        path.startswith(prefix) if prefix.endswith("/") else path == prefix
        for prefix in _UNPACKAGED_SOURCE_PREFIXES
    )


def uninventoried_sources(inventory: ResourceInventory, *, repo_root: Path) -> tuple[str, ...]:
    """Return source-root files that are neither inventoried nor declared repository-only."""

    inventoried = {entry.source_path for entry in inventory.entries}
    found: list[str] = []
    for source_root in _ALLOWED_SOURCE_ROOTS:
        root = repo_root / source_root.rstrip("/")
        if root.is_symlink():
            raise ResourceManifestError("symlink_forbidden", detail=source_root.rstrip("/"))
        if not root.is_dir():
            continue
        pending = [root]
        while pending:
            current = pending.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.name in _IGNORED_SOURCE_NAMES:
                        continue
                    path = Path(entry.path)
                    relative = path.relative_to(repo_root).as_posix()
                    if entry.is_symlink():
                        raise ResourceManifestError("symlink_forbidden", detail=relative)
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                        continue
                    if relative in inventoried or _is_unpackaged_source(relative):
                        continue
                    found.append(relative)
    return tuple(sorted(found, key=str.encode))


def verify_source_coverage(inventory: ResourceInventory, *, repo_root: Path) -> None:
    """Fail closed when a source file would silently miss the package."""

    missing = uninventoried_sources(inventory, repo_root=repo_root)
    if missing:
        raise ResourceManifestError("source_unpackaged", detail=" ".join(missing))


def build_codex_skill_manifest(*, repo_root: Path) -> bytes:
    """Render nested managed-member identities from their single owning source bytes."""

    path = repo_root / _CODEX_SKILL_MANIFEST
    data = _read_guarded(path, root=repo_root, size_cap=_MAX_TEXT_BYTES)
    try:
        parsed = strict_json_parse(data[:-1] if data.endswith(b"\n") else data)
    except Exception as exc:  # noqa: BLE001 - normalized into bounded verification failure
        raise ResourceManifestError("codex_skill_manifest_invalid", detail=str(path)) from exc
    if not isinstance(parsed, Mapping):
        raise ResourceManifestError("codex_skill_manifest_invalid", detail=str(path))
    source = cast(Mapping[str, JsonValue], parsed)
    # Frozen legacy identifier (ADR-048): codex skill manifest format tag.
    if (
        source.get("schema") != "yoetz.codex-skill-manifest/1"
        or source.get("skill") != "finishup"
        or source.get("harness") != "codex"
    ):
        raise ResourceManifestError("codex_skill_manifest_invalid", detail=str(path))
    document = dict(source)
    managed: list[JsonValue] = []
    for logical_name, origin, role, source_path in _CODEX_SKILL_MEMBERS:
        member_data = _read_guarded(
            repo_root / source_path, root=repo_root, size_cap=_MAX_TEXT_BYTES
        )
        member: dict[str, JsonValue] = {
            "logical_name": logical_name,
            "origin": origin,
            "role": role,
            "sha256": f"sha256:{hashlib.sha256(member_data).hexdigest()}",
            "size": len(member_data),
        }
        if origin == "shared_guidance":
            member["source_logical_name"] = source_path
        managed.append(member)
    managed.insert(
        1,
        {
            "identity_status": "self_excluded",
            "logical_name": "manifest.json",
            "origin": "harness_owned",
            "role": "compatibility_manifest",
        },
    )
    document["managed_members"] = managed
    document.pop("member_digest", None)
    document["member_digest"] = canonical_digest(cast(JsonValue, document))
    return canonical_encode(cast(JsonValue, document)) + b"\n"


def verify_codex_skill_manifest(*, repo_root: Path) -> bytes:
    """Return expected bytes or fail when nested managed-member metadata is stale."""

    expected = build_codex_skill_manifest(repo_root=repo_root)
    actual = _read_guarded(
        repo_root / _CODEX_SKILL_MANIFEST, root=repo_root, size_cap=_MAX_TEXT_BYTES
    )
    if actual != expected:
        raise ResourceManifestError("codex_skill_manifest_stale", detail=_CODEX_SKILL_MANIFEST)
    return expected


def _read_guarded(path: Path, *, root: Path, size_cap: int) -> bytes:
    _assert_no_symlink_path(path, root=root)
    if path.is_symlink():
        raise ResourceManifestError("symlink_forbidden", detail=str(path))
    if not path.is_file():
        raise ResourceManifestError("source_missing", detail=str(path))
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if before.st_mtime_ns != after.st_mtime_ns or before.st_size != after.st_size:
        raise ResourceManifestError("read_race_detected", detail=str(path))
    if len(data) > size_cap:
        raise ResourceManifestError("size_cap_exceeded", detail=str(path))
    return data


# Wire/protocol canonical artifacts (frozen schemas and canonical vectors) are rendered compact
# with no trailing newline. Hand-maintained JSON config (compatibility manifests, the runtime
# support allowlist) is canonical JSON *content* but keeps the ordinary final-LF text convention.
_NO_TRAILING_NEWLINE_JSON_KINDS: Final = frozenset({"json_schema", "canonical_vector"})
_FINAL_LF_JSON_KINDS: Final = frozenset({"compatibility_manifest", "runtime_support"})


def _validate_text_policy(entry: ResourceInventoryEntry, data: bytes) -> None:
    if not entry.text:
        return
    if data.startswith(b"\xef\xbb\xbf"):
        raise ResourceManifestError("byte_order_mark_forbidden", detail=entry.logical_name)
    if b"\r" in data:
        raise ResourceManifestError("crlf_forbidden", detail=entry.logical_name)
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ResourceManifestError("invalid_utf8", detail=entry.logical_name) from exc

    if entry.kind in _NO_TRAILING_NEWLINE_JSON_KINDS:
        _require_canonical_json(entry, data)
        return

    if data and not data.endswith(b"\n"):
        raise ResourceManifestError("missing_final_newline", detail=entry.logical_name)

    if entry.kind in _FINAL_LF_JSON_KINDS:
        _require_canonical_json(entry, data[:-1] if data.endswith(b"\n") else data)


def _require_canonical_json(entry: ResourceInventoryEntry, body: bytes) -> None:
    try:
        parsed = strict_json_parse(body)
        if canonical_encode(parsed) != body:
            raise ResourceManifestError("noncanonical_json", detail=entry.logical_name)
    except ResourceManifestError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalized into a bounded resource error
        raise ResourceManifestError("noncanonical_json", detail=entry.logical_name) from exc


def collect_source_entries(
    inventory: ResourceInventory, *, repo_root: Path
) -> tuple[CollectedResource, ...]:
    """Read, size/format-validate, and digest every inventory-declared canonical source file."""

    collected: list[CollectedResource] = []
    for entry in inventory.entries:
        source = repo_root / entry.source_path
        data = _read_guarded(source, root=repo_root, size_cap=entry.size_cap)
        _validate_text_policy(entry, data)
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        collected.append(CollectedResource(entry=entry, size=len(data), sha256=digest, data=data))
    return tuple(collected)


def _manifest_entry_json(resource: CollectedResource) -> dict[str, JsonValue]:
    entry = resource.entry
    payload: dict[str, JsonValue] = {
        "kind": entry.kind,
        "logical_name": entry.logical_name,
        "media_type": entry.media_type,
        "package_path": entry.package_path,
        "sha256": resource.sha256,
        "size": resource.size,
        "source_path": entry.source_path,
    }
    if entry.contract_version is not None:
        payload["contract_version"] = entry.contract_version
    return payload


def _resource_set_digest(
    inventory: ResourceInventory, resources: Sequence[CollectedResource]
) -> str:
    ordered = sorted(resources, key=lambda item: item.entry.logical_name.encode("utf-8"))
    digest_entries: list[JsonValue] = []
    for resource in ordered:
        entry = resource.entry
        if entry.kind == "runtime_support":
            fields: dict[str, JsonValue] = {
                "kind": entry.kind,
                "logical_name": entry.logical_name,
                "media_type": entry.media_type,
                "package_path": entry.package_path,
                "source_path": entry.source_path,
            }
            if entry.contract_version is not None:
                fields["contract_version"] = entry.contract_version
            digest_entries.append(fields)
        else:
            digest_entries.append(_manifest_entry_json(resource))
    material: dict[str, JsonValue] = {
        "entries": digest_entries,
        "package": inventory.package,
        "resource_set_version": inventory.resource_set_version,
        "schema": _MANIFEST_SCHEMA,
    }
    return canonical_digest(material)


def build_manifest(inventory: ResourceInventory, resources: Sequence[CollectedResource]) -> bytes:
    """Render the canonical package resource manifest for a collected resource set."""

    ordered = sorted(resources, key=lambda item: item.entry.logical_name.encode("utf-8"))
    document: dict[str, JsonValue] = {
        "entries": [_manifest_entry_json(resource) for resource in ordered],
        "package": inventory.package,
        "resource_set_digest": _resource_set_digest(inventory, resources),
        "resource_set_version": inventory.resource_set_version,
        "schema": _MANIFEST_SCHEMA,
    }
    # The resource manifest is checked-in, hand-reviewed text; unlike wire schema/vector bytes it
    # keeps the repository's ordinary canonical-JSON-plus-final-LF text convention.
    return canonical_encode(document) + b"\n"


def verify_resource_tree(
    resources: Sequence[CollectedResource], manifest_bytes: bytes, *, repo_root: Path
) -> ResourceDiff:
    """Compare collected sources, the checked-in manifest, and installed package bytes."""

    inventory_paths = {resource.entry.package_path for resource in resources}
    resource_root = repo_root / _PACKAGE_RESOURCE_ROOT

    package_files = _package_files(resource_root, repo_root=repo_root)
    package_paths = {path.relative_to(resource_root).as_posix(): path for path in package_files}

    missing: list[str] = []
    changed: list[str] = []
    for resource in resources:
        destination = resource_root / resource.entry.package_path
        if destination.is_symlink() or not destination.is_file():
            missing.append(resource.entry.package_path)
            continue
        if destination.read_bytes() != resource.data:
            changed.append(resource.entry.package_path)

    extra: list[str] = []
    for relative in sorted(package_paths):
        if relative == "manifest.json":
            continue
        if relative not in inventory_paths:
            extra.append(relative)

    manifest_path = resource_root / "manifest.json"
    manifest_mismatch = True
    if manifest_path.is_file() and not manifest_path.is_symlink():
        manifest_mismatch = manifest_path.read_bytes() != manifest_bytes

    return ResourceDiff(
        missing=tuple(sorted(missing)),
        extra=tuple(sorted(extra)),
        changed=tuple(sorted(changed)),
        manifest_mismatch=manifest_mismatch,
    )


def sync_resource_tree(
    resources: Sequence[CollectedResource], manifest_bytes: bytes, *, repo_root: Path
) -> None:
    """Atomically stage, replace, and retire the prior inventory's package files."""

    resource_root = repo_root / _PACKAGE_RESOURCE_ROOT
    _assert_no_symlink_path(resource_root, root=repo_root)
    resource_root.mkdir(parents=True, exist_ok=True)
    package_files = _package_files(resource_root, repo_root=repo_root)

    known_destinations = {resource.entry.package_path for resource in resources}
    previous_destinations: set[str] = set()
    previous_manifest = resource_root / "manifest.json"
    if previous_manifest.is_file() and not previous_manifest.is_symlink():
        try:
            previous_document = strict_json_parse(previous_manifest.read_bytes())
        except TypeError, ValueError:
            previous_document = None
        if isinstance(previous_document, Mapping):
            previous_entries = previous_document.get("entries")
            if isinstance(previous_entries, list):
                for item in previous_entries:
                    if not isinstance(item, Mapping):
                        continue
                    package_path = item.get("package_path")
                    if type(package_path) is not str:
                        continue
                    if (
                        _is_safe_relative_path(package_path)
                        and _within_allowed_root(package_path)
                        and package_path != "manifest.json"
                    ):
                        previous_destinations.add(package_path)
    stale_destinations = previous_destinations - known_destinations
    for candidate in package_files:
        relative = candidate.relative_to(resource_root).as_posix()
        if (
            relative != "manifest.json"
            and relative not in known_destinations
            and relative not in previous_destinations
        ):
            raise ResourceManifestError("unknown_destination_file", detail=relative)

    with tempfile.TemporaryDirectory(
        dir=resource_root.parent, prefix=".verify-resource-manifest-"
    ) as staging:
        staging_root = Path(staging)
        for resource in resources:
            destination = staging_root / resource.entry.package_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(resource.data)
            with open(destination, "rb") as handle:
                os.fsync(handle.fileno())
        manifest_destination = staging_root / "manifest.json"
        manifest_destination.write_bytes(manifest_bytes)
        with open(manifest_destination, "rb") as handle:
            os.fsync(handle.fileno())

        for resource in resources:
            source = staging_root / resource.entry.package_path
            target = resource_root / resource.entry.package_path
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
        for relative in sorted(stale_destinations, key=str.encode):
            target = resource_root / relative
            _assert_no_symlink_path(target, root=repo_root)
            if target.is_file() or target.is_symlink():
                target.unlink()
        os.replace(staging_root / "manifest.json", resource_root / "manifest.json")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_resource_manifest.py",
        description="Verify or synchronize packaged resource parity with canonical public sources.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Read-only parity verification.")
    mode.add_argument("--sync", action="store_true", help="Regenerate the packaged resource tree.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Test-only: validate against a synthetic repository root instead of this checkout.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    repo_root = args.repo_root.absolute() if args.repo_root is not None else _default_repo_root()
    if not repo_root.is_dir():
        print(
            f"verify_resource_manifest: invocation error: repo root not found: {repo_root}",
            file=sys.stderr,
        )
        return 2

    try:
        if args.sync:
            expected_skill_manifest = build_codex_skill_manifest(repo_root=repo_root)
            (repo_root / _CODEX_SKILL_MANIFEST).write_bytes(expected_skill_manifest)
        inventory = load_inventory_config()
        verify_source_coverage(inventory, repo_root=repo_root)
        resources = collect_source_entries(inventory, repo_root=repo_root)
        if not args.sync:
            verify_codex_skill_manifest(repo_root=repo_root)
        manifest_bytes = build_manifest(inventory, resources)
    except ResourceManifestError as exc:
        print(f"verify_resource_manifest: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
        return 1

    if args.sync:
        try:
            sync_resource_tree(resources, manifest_bytes, repo_root=repo_root)
        except ResourceManifestError as exc:
            print(f"verify_resource_manifest: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
            return 1

    try:
        diff = verify_resource_tree(resources, manifest_bytes, repo_root=repo_root)
    except ResourceManifestError as exc:
        print(f"verify_resource_manifest: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
        return 1
    if diff.is_clean:
        print(f"verify_resource_manifest: PASS ({len(resources)} resource(s))")
        return 0

    print("verify_resource_manifest: FAIL (drift detected)", file=sys.stderr)
    for path in diff.missing:
        print(f"  missing {path}", file=sys.stderr)
    for path in diff.extra:
        print(f"  extra {path}", file=sys.stderr)
    for path in diff.changed:
        print(f"  changed {path}", file=sys.stderr)
    if diff.manifest_mismatch:
        print("  manifest.json mismatch", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
