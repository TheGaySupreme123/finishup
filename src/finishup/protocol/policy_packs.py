"""Built-in policy-pack identities: the current set and the earlier ones a ledger may carry.

A pack version names the rule table that produced a check execution or a local finding. A version
moves whenever a pack's rules change meaning, so a recorded check or finding always says which
rules produced it. New checks run only the current version of each pack. Every earlier version
stays decodable, because recorded ``check_recorded`` and ``finding_recorded`` events, check
results replayed from the ledger, and receipts keep the identity they were written with.

The versions of one pack form one lineage: an issue a newer version re-raises is the same issue,
and a later qualifying check at the same or a newer version of the pack can resolve it.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

__all__ = [
    "COORDINATION_POLICY_ID",
    "COORDINATION_POLICY_VERSION",
    "CURRENT_POLICY_PACKS",
    "CURRENT_POLICY_VERSIONS",
    "LEGACY_POLICY_VERSIONS",
    "POLICY_PACK_GENERATIONS",
    "RECORDED_POLICY_PACKS",
    "RECORDED_POLICY_VERSION_VALUES",
    "RESEARCH_EVIDENCE_POLICY_ID",
    "RESEARCH_EVIDENCE_POLICY_VERSION",
    "WORK_INTEGRITY_POLICY_ID",
    "WORK_INTEGRITY_POLICY_VERSION",
    "current_policy_pack",
    "is_current_policy_identity",
    "is_recorded_policy_identity",
    "policy_pack_id",
    "policy_version_supersedes_or_equals",
]

COORDINATION_POLICY_ID: Final = "coordination"
RESEARCH_EVIDENCE_POLICY_ID: Final = "research-evidence"
WORK_INTEGRITY_POLICY_ID: Final = "work-integrity"

COORDINATION_POLICY_VERSION: Final = "0.1.0"
# 0.2.0: ``task_requirement_unmet`` when no effective obligation cites the task statement, and
# statement-sourced file items justify a pre-existing test edit.
RESEARCH_EVIDENCE_POLICY_VERSION: Final = "0.2.0"
# 0.2.0: ``claim_without_admissible_evidence`` names a completion no observed run backs, and only
# observed edits or runs trigger the corroboration rule.
# 0.3.0 (#977): ``requested_item_never_attempted`` waits until the agent has started acting, names
# a requested file the check-time workspace read found absent whatever was published, and skips
# obligations a confirmed blocker decision names (a claimed blocker suppresses nothing, #985), and
# ``action_without_result`` never counts a sibling action of the same ``publish_work`` batch as later
# work (tb4n5 follow-up). 0.3.0 is unreleased, so the 0.3 line amends it in place.
WORK_INTEGRITY_POLICY_VERSION: Final = "0.3.0"

CURRENT_POLICY_VERSIONS: Final = MappingProxyType(
    {
        COORDINATION_POLICY_ID: COORDINATION_POLICY_VERSION,
        RESEARCH_EVIDENCE_POLICY_ID: RESEARCH_EVIDENCE_POLICY_VERSION,
        WORK_INTEGRITY_POLICY_ID: WORK_INTEGRITY_POLICY_VERSION,
    }
)
# Earlier versions, oldest first. They are decoded and displayed, never run.
LEGACY_POLICY_VERSIONS: Final = MappingProxyType(
    {
        COORDINATION_POLICY_ID: (),
        RESEARCH_EVIDENCE_POLICY_ID: ("0.1.0",),
        WORK_INTEGRITY_POLICY_ID: ("0.1.0", "0.2.0"),
    }
)
# Every recorded check ran one consistent generation of the built-in packs, oldest first.
POLICY_PACK_GENERATIONS: Final = (
    MappingProxyType(
        {
            COORDINATION_POLICY_ID: "0.1.0",
            RESEARCH_EVIDENCE_POLICY_ID: "0.1.0",
            WORK_INTEGRITY_POLICY_ID: "0.1.0",
        }
    ),
    MappingProxyType(
        {
            COORDINATION_POLICY_ID: "0.1.0",
            RESEARCH_EVIDENCE_POLICY_ID: "0.2.0",
            WORK_INTEGRITY_POLICY_ID: "0.2.0",
        }
    ),
    CURRENT_POLICY_VERSIONS,
)
_LINEAGES: Final = MappingProxyType(
    {
        policy_id: (*LEGACY_POLICY_VERSIONS[policy_id], version)
        for policy_id, version in CURRENT_POLICY_VERSIONS.items()
    }
)


def policy_pack_id(policy_id: str, policy_version: str) -> str:
    """Render the public ``<policy_id>/<policy_version>`` pack identity."""

    return f"{policy_id}/{policy_version}"


def current_policy_pack(policy_id: str) -> str:
    """The current public pack identity for one built-in pack."""

    return policy_pack_id(policy_id, CURRENT_POLICY_VERSIONS[policy_id])


CURRENT_POLICY_PACKS: Final = tuple(
    sorted(
        (current_policy_pack(policy_id) for policy_id in CURRENT_POLICY_VERSIONS), key=str.encode
    )
)
RECORDED_POLICY_PACKS: Final = tuple(
    sorted(
        (
            policy_pack_id(policy_id, version)
            for policy_id, versions in _LINEAGES.items()
            for version in versions
        ),
        key=str.encode,
    )
)
RECORDED_POLICY_VERSION_VALUES: Final = tuple(
    sorted({version for versions in _LINEAGES.values() for version in versions}, key=str.encode)
)


def is_current_policy_identity(policy_id: object, policy_version: object) -> bool:
    """Whether a pair names the version of a built-in pack that new checks run."""

    return (
        type(policy_id) is str
        and type(policy_version) is str
        and CURRENT_POLICY_VERSIONS.get(policy_id) == policy_version
    )


def is_recorded_policy_identity(policy_id: object, policy_version: object) -> bool:
    """Whether a pair names any version of a built-in pack a ledger may have recorded."""

    return (
        type(policy_id) is str
        and type(policy_version) is str
        and policy_version in _LINEAGES.get(policy_id, ())
    )


def policy_version_supersedes_or_equals(
    policy_id: str, candidate_version: str, baseline_version: str
) -> bool:
    """Whether ``candidate_version`` is ``baseline_version`` or a later version of the same pack."""

    lineage = _LINEAGES.get(policy_id, ())
    if candidate_version not in lineage or baseline_version not in lineage:
        return False
    return lineage.index(candidate_version) >= lineage.index(baseline_version)
