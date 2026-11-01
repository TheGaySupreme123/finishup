"""#982: deterministic checks judge their own local evidence; privacy filtering is egress-only.

TB4 tb4n1 (sglang-qwen-burst): local findings carried ``coverage:content_redacted`` that nothing
the agent did could clear, and both arms spent half their actions re-checking them. The owner's
rule (2026-10-07): privacy filtering exists for content leaving the machine. Local checks,
closure readiness and the Stop gate judge the full local ledger and captured evidence; redaction
and withholding apply only to what is sent. These cases pin the rule as one set: every privacy
gap a check can carry leaves a repaired local finding provable, the captured evidence a local
check reads keeps the value, and the only place it is replaced is the outbound packet.
"""

from __future__ import annotations

import pytest

from finishup.domain.receipts import (
    SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP,
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP,
    SEMANTIC_REVIEW_VALUE_REDACTED_GAP,
)
from finishup.kernel.finding_resolution import DETERMINISTIC_PROOF_TOLERATED_GAPS
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
from unit.application.test_semantic_case import (
    _captured_case_values,  # pyright: ignore[reportPrivateUsage]
)
from unit.kernel.test_finding_resolution import (
    _check,  # pyright: ignore[reportPrivateUsage]
    _coverage,  # pyright: ignore[reportPrivateUsage]
    _finding,  # pyright: ignore[reportPrivateUsage]
    _resolves,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _minimize_everything,  # pyright: ignore[reportPrivateUsage]
)

# Every code a privacy decision about the external reviewer can put on a check: capture-time
# high-confidence redaction, egress value replacement, item withholding, the owner's opt-out, and
# a review refused at the privacy boundary and carried forward unchanged (#1138).
_PRIVACY_GAPS = (
    "content_redacted",
    SEMANTIC_REVIEW_VALUE_REDACTED_GAP,
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP,
    SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP,
)
_TOKEN = b"x9Fq2LmZ7vRt4KpW8sYd3NcB6hJe1QaU"


@pytest.mark.parametrize("gap", _PRIVACY_GAPS)
def test_no_privacy_gap_keeps_a_repaired_local_finding_open(gap: str) -> None:
    assert gap in DETERMINISTIC_PROOF_TOLERATED_GAPS
    later = _check(coverage=_coverage(gaps=(gap, "semantic_review_not_requested")))
    assert _resolves(_finding(), later) is True


def test_local_evidence_keeps_the_value_and_only_the_outbound_packet_replaces_it() -> None:
    from finishup.application.semantic_case import build_semantic_case
    from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy

    content = b"bot.token = " + _TOKEN + b"\nlauncher ready\n"
    frozen, captured, scope = _captured_case_values(content)
    # What a local check reads: the captured evidence, digested over the bytes as captured.
    evidence = next(iter(frozen.projection.evidence.values())).payload
    assert evidence is not None
    import hashlib

    assert evidence.content_digest == "sha256:" + hashlib.sha256(content).hexdigest()
    assert captured.manifest.redacted is False
    case = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,),
        captured_content_scope=scope,
    )
    # The case composed for review still holds the value (it is local until egress)...
    assert any(_TOKEN in item.content for item in case.items)
    # ...and the bytes that would leave the machine carry only the placeholder.
    minimized = _minimize_everything(_candidate(case))
    assert _TOKEN not in minimized.prepared_bytes
    assert EGRESS_CREDENTIAL_PLACEHOLDER in minimized.prepared_bytes
