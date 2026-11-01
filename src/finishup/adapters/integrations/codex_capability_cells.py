"""Exact Codex rollout-parser evidence identities.

These constructed fixtures lock one session-file grammar per exact Codex
release. They are parser proof only: not an installed skill, MCP, hook,
activation, or model-use capture, and therefore they do not populate any
support surface consumed by ordinary installation/status. Adding the next
release is a fixture-plus-profile change: a new ``CodexRolloutParserProof``
row here and a matching exact profile in ``codex_rollout_jsonl``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from finishup.protocol.canonical import JsonValue

__all__ = [
    "CODEX_ROLLOUT_CLI_VERSION",
    "CODEX_ROLLOUT_EVIDENCE_CASE_IDS",
    "CODEX_ROLLOUT_HISTORY_MODES",
    "CODEX_ROLLOUT_IMPORTER_PROFILE_ID",
    "CODEX_ROLLOUT_PARSER_PROOFS",
    "CODEX_ROLLOUT_COMPATIBLE_EVIDENCE_CASE_IDS",
    "CODEX_ROLLOUT_STREAM_MAPPING_VERSION",
    "CODEX_ROLLOUT_SURFACE",
    "CODEX_ROLLOUT_UNSUPPORTED_EVIDENCE_CASE_IDS",
    "CodexRolloutParserProof",
    "codex_version_manifest_profiles",
    "rollout_parser_proof",
    "rollout_parser_proven_versions",
    "skill_manifest_capability_fields",
]


@dataclass(frozen=True, slots=True)
class CodexRolloutParserProof:
    """Fixture evidence that one exact release's rollout grammar parses.

    ``host_support`` is always ``unproven``: parser proof never promotes the
    installed skill/MCP/hook matrix, which needs its own isolated-artifact run.
    """

    cli_version: str
    profile_id: str
    evidence_case_ids: tuple[str, ...]
    fixture_history_modes: tuple[str, ...]
    host_support: Literal["unproven"] = "unproven"


# Baseline release; kept as named constants for the surfaces that predate
# multi-version proofs. ``CODEX_ROLLOUT_PARSER_PROOFS`` is the authority.
CODEX_ROLLOUT_CLI_VERSION: Final = "0.148.0"
CODEX_ROLLOUT_IMPORTER_PROFILE_ID: Final = "codex-rollout-jsonl/0.148.0/v1"
CODEX_ROLLOUT_STREAM_MAPPING_VERSION: Final = "codex-obs-stream/1.4.0"
CODEX_ROLLOUT_SURFACE: Final = "session_stream_rollout"
CODEX_ROLLOUT_HISTORY_MODES: Final = ("legacy", "paginated")
CODEX_ROLLOUT_EVIDENCE_CASE_IDS: Final = ("IMP-006", "IMP-007", "IMP-008", "IMP-009")
CODEX_ROLLOUT_PARSER_PROOFS: Final = (
    CodexRolloutParserProof(
        cli_version=CODEX_ROLLOUT_CLI_VERSION,
        profile_id=CODEX_ROLLOUT_IMPORTER_PROFILE_ID,
        evidence_case_ids=CODEX_ROLLOUT_EVIDENCE_CASE_IDS,
        fixture_history_modes=CODEX_ROLLOUT_HISTORY_MODES,
    ),
    CodexRolloutParserProof(
        cli_version="0.150.1",
        profile_id="codex-rollout-jsonl/0.150.1/v1",
        evidence_case_ids=("IMP-011", "IMP-012"),
        fixture_history_modes=("paginated",),
    ),
)
# Fixture proving a structurally unsupported header (unknown ``history_mode``) is refused, and
# fixture proving an unproven release is admitted under the structural compatibility profile
# without inheriting a parser proof (issue #656).
CODEX_ROLLOUT_UNSUPPORTED_EVIDENCE_CASE_IDS: Final = ("IMP-013",)
CODEX_ROLLOUT_COMPATIBLE_EVIDENCE_CASE_IDS: Final = ("IMP-014", "IMP-015")


def rollout_parser_proven_versions() -> tuple[str, ...]:
    return tuple(proof.cli_version for proof in CODEX_ROLLOUT_PARSER_PROOFS)


def rollout_parser_proof(cli_version: str) -> CodexRolloutParserProof | None:
    """Exact-version lookup; a neighbouring release never inherits a proof."""

    for proof in CODEX_ROLLOUT_PARSER_PROOFS:
        if proof.cli_version == cli_version:
            return proof
    return None


def skill_manifest_capability_fields() -> Mapping[str, JsonValue]:
    """Keep skill support empty until the installed-artifact matrix is proven."""

    body: dict[str, JsonValue] = {
        "capability_profile_ids": [],
        "codex_version_bounds": {
            "denied": [],
            "supported": [],
            "tested": [],
        },
        "hooks_by_capability_profile": {},
    }
    return MappingProxyType(body)


def codex_version_manifest_profiles() -> tuple[Mapping[str, JsonValue], ...]:
    """Do not advertise a support cell from parser-only fixture evidence.

    ``CODEX_ROLLOUT_PARSER_PROOFS`` stays out of the version manifest: its
    cells are parser proof, and the manifest's profile rows mean host support.
    """

    return ()
