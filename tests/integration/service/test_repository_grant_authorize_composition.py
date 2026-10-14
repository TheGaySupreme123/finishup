"""Repository-privacy-grant authorization over the real composition (#519, #552).

The defect the granted lane locks against: an exact prepared `repository_privacy_grant` was
authorized, the durable policy transition committed, the real confidential server sent the
terminal result — and a lost close confirmation collapsed the whole ceremony to
`elevated_bootstrap: repository_privacy_grant_failed` while `finishup provider status` already
reported the grant effective. Both named external-review recipes (Assisted and Expanded) run
that lane: PR #542 switched the single lane to Expanded, which silently dropped the Assisted
end-to-end coverage this file restores (#552).

The tightened lane (#552) starts from a granted Expanded repository and applies the strictly
tighter Assisted recipe through the same chat-consent lane. The lattice (ADR-009 / ADR-016) says a
tightening needs no human decision: the service applies it immediately, the consent result reports
`tightened`, and the ledger shows exactly which row was recorded.

These tests run real agent attestation, the real ordinary-control propose path, and the real
YZH1/YZS1 decide ceremony against the production daemon composition, mocking only the OS keyring
backend and the configured provider binding.
"""

from __future__ import annotations

import asyncio
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from unittest.mock import patch

import apsw
import pytest

import finishup.service.daemon as daemon_module
from finishup.adapters.privacy.catalog import decode_privacy_policy_canonical
from finishup.cli import elevated
from finishup.cli.privacy_setup import (
    PrivacySetupSnapshot,
    build_candidate_policy,
    get_privacy_setup_snapshot,
    recipe_answers,
)
from finishup.domain.privacy import (
    PrivacyPolicy,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.protocol.schemas import validate_schema_instance
from finishup.service.confidential_protocol import ServerCloseEnvelope
from finishup.service.daemon import ServiceDaemon
from finishup.service.elevated_bootstrap import load_pending, repository_grant_binding
from integration.service.test_consent_vault_initialize_composition import (
    _approve_attestation,  # pyright: ignore[reportPrivateUsage]
    _approved_store,  # pyright: ignore[reportPrivateUsage]
    _MemoryKeyring,  # pyright: ignore[reportPrivateUsage]
    _production_daemon,  # pyright: ignore[reportPrivateUsage]
    runtime_directory,  # noqa: F401 - imported pytest fixture  # pyright: ignore[reportUnusedImport]
)

_GrantRecipe = Literal["assisted_review", "expanded_review"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


_EXTERNAL_BINDING = ProviderBinding(
    "fireworks",
    "accounts/fireworks/models/minimax-m3",
    "fireworks-responses",
    "1.0.0",
    "external",
)

# The two named recipes that widen a fresh repository through the chat-consent lane; each is one
# end-to-end lane of its own because they commit different review-context profiles.
_GRANT_RECIPES: tuple[_GrantRecipe, ...] = ("assisted_review", "expanded_review")
_RECIPE_REVIEW_CONTEXT: dict[_GrantRecipe, ReviewContextProfile] = {
    "assisted_review": ReviewContextProfile.ASSISTED,
    "expanded_review": ReviewContextProfile.EXPANDED,
}


async def _authorize_current_pending(consent_state: Path) -> dict[str, Any]:
    pending = load_pending(_state=consent_state)
    assert pending is not None
    return cast(
        dict[str, Any],
        await asyncio.wait_for(
            elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
        ),
    )


async def _initialize_vault(consent_state: Path) -> None:
    elevated.prepare_elevated("vault_initialize")
    result = await _authorize_current_pending(consent_state)
    assert result["result"] == {"state": "ready", "reason": "succeeded"}


async def _prepare_grant(
    recipe: _GrantRecipe,
    *,
    expected_grant_state: Literal["granted", "missing"],
) -> PrivacySetupSnapshot:
    """Prepare one exact named-recipe grant from the live repository snapshot."""

    snapshot = await get_privacy_setup_snapshot()
    commitment = snapshot.bound_scope.get("workspace_ref_commitment")
    assert type(commitment) is str
    assert snapshot.grant_state == expected_grant_state
    candidate = build_candidate_policy(
        snapshot.composed_policy,
        recipe_answers(recipe, snapshot.composed_policy, _EXTERNAL_BINDING),
        now=datetime.now(UTC),
    )
    elevated.prepare_elevated(
        "repository_privacy_grant",
        grant_binding=repository_grant_binding(
            recipe=recipe,
            repository_privacy_commitment=commitment,
            authority_digest=snapshot.authority_digest,
            current_policy=snapshot.composed_policy,
            candidate_policy=candidate,
        ),
    )
    return snapshot


def _audit_lines(consent_state: Path) -> list[str]:
    return (
        (consent_state / "elevated-bootstrap" / "elevated-bootstrap-audit.jsonl")
        .read_text("utf-8")
        .splitlines()
    )


def _assert_approvals(consent_state: Path, *, approved: int) -> None:
    """Every consumed review was approved exactly once and nothing failed or was applied twice."""

    assert load_pending(_state=consent_state) is None
    audit = _audit_lines(consent_state)
    approvals = [line for line in audit if '"outcome":"approved"' in line]
    assert len(approvals) == approved
    assert not any('"outcome":"failed"' in line for line in audit)


def _assert_granted_once(
    consent_state: Path, snapshot_after: PrivacySetupSnapshot, recipe: _GrantRecipe
) -> None:
    assert snapshot_after.grant_state == "granted"
    assert snapshot_after.composed_policy.review_context_profile is _RECIPE_REVIEW_CONTEXT[recipe]
    # Vault initialization plus exactly one grant approval; nothing was applied twice.
    _assert_approvals(consent_state, approved=2)


class _WorkspacePolicyRow:
    """One durable `privacy_policy_versions` row for the bound repository scope."""

    def __init__(self, row: tuple[Any, ...]) -> None:
        self.policy_id = cast(str, row[0])
        self.version = cast(int, row[1])
        self.digest = cast(str, row[2])
        self.generation = cast(int, row[3])
        self.change_kind = cast(str, row[4])
        self.source_proposal_id = cast(str | None, row[5])
        self.state = cast(str, row[6])
        self.policy: PrivacyPolicy = decode_privacy_policy_canonical(cast(bytes, row[7]))


def _workspace_policy_rows(catalog: Path, commitment: str) -> list[_WorkspacePolicyRow]:
    """Read the repository-scope policy lineage from the isolated catalog, read-only."""

    db = apsw.Connection(str(catalog), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        rows = db.execute(
            """SELECT policy_id, policy_version, policy_digest, policy_generation, change_kind,
                      source_proposal_id, state, policy_canonical
               FROM privacy_policy_versions
               WHERE scope_kind = 'workspace' AND workspace_ref_commitment = ?
               ORDER BY policy_generation""",
            (commitment,),
        ).fetchall()
    finally:
        db.close()
    return [_WorkspacePolicyRow(cast(tuple[Any, ...], row)) for row in rows]


class _GrantCell:
    """The production daemon plus the consent-state and keyring patches the CLI lane needs."""

    def __init__(self, tmp_path: Path) -> None:
        tmp_path.chmod(0o700)
        self.tmp_path = tmp_path
        self.consent_state = tmp_path / "consent"
        self.consent_state.mkdir(mode=0o700)
        self.catalog = tmp_path / "data" / "catalog.sqlite3"
        self._store = _approved_store(tmp_path / "data", _MemoryKeyring())
        self._daemon: ServiceDaemon | None = None
        self._serving: asyncio.Task[None] | None = None

    async def __aenter__(self) -> _GrantCell:
        daemon: ServiceDaemon = await _production_daemon(self.tmp_path, pristine=True)
        await daemon.start()
        self._daemon = daemon
        self._serving = asyncio.create_task(daemon.serve())
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._daemon is not None and self._serving is not None
        await self._daemon.stop()
        await asyncio.wait_for(self._serving, timeout=10)

    def patches(self) -> ExitStack:
        store = self._store
        stack = ExitStack()
        for item in (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=self.consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
            patch(
                "finishup.cli.elevated._load_auto_unlock_passphrase",
                side_effect=lambda: store.load(),
            ),
            patch(
                "finishup.cli.privacy_setup.configured_bindings",
                return_value=(_EXTERNAL_BINDING, None),
            ),
        ):
            stack.enter_context(item)
        return stack


async def _run_grant_flow(
    tmp_path: Path,
    recipe: _GrantRecipe,
    *,
    authorize_patches: Any = None,
) -> None:
    async with _GrantCell(tmp_path) as cell:
        with cell.patches():
            await _initialize_vault(cell.consent_state)
            await _prepare_grant(recipe, expected_grant_state="missing")
            if authorize_patches is None:
                result = await _authorize_current_pending(cell.consent_state)
            else:
                with authorize_patches:
                    result = await _authorize_current_pending(cell.consent_state)

            assert result["outcome"] == "completed"
            assert result["authority_channel"] == "agent_attested_chat_instruction"
            assert result["result"] == {"recipe": recipe, "outcome": "granted"}
            validate_schema_instance("review-result", "6.0.0", result)
            snapshot_after = await get_privacy_setup_snapshot()
            _assert_granted_once(cell.consent_state, snapshot_after, recipe)


@pytest.mark.anyio
@pytest.mark.parametrize("recipe", _GRANT_RECIPES)
async def test_agent_authorized_repository_grant_completes_with_truthful_result(
    tmp_path: Path,
    runtime_directory: Path,  # noqa: F811 - imported pytest fixture
    recipe: _GrantRecipe,
) -> None:
    """#519 acceptance: prepare, exact agent authorize, real client/server, truthful result."""

    await _run_grant_flow(tmp_path, recipe)


@pytest.mark.anyio
@pytest.mark.parametrize("recipe", _GRANT_RECIPES)
async def test_lost_close_confirmation_after_committed_grant_recovers_the_stored_result(
    tmp_path: Path,
    runtime_directory: Path,  # noqa: F811 - imported pytest fixture
    recipe: _GrantRecipe,
) -> None:
    """#519 acceptance: the close frame is lost after the durable commit and the sent result;
    authorize recovers the stored terminal result exactly once instead of reporting failure."""

    original_write = daemon_module._write_human_envelope  # pyright: ignore[reportPrivateUsage]

    async def drop_completed_close(stream: object, envelope: object) -> None:
        # The exact injection: the durable transition committed, the result frame was written,
        # and the correlated "completed" close never reaches the client (the daemon then closes
        # the connection, so the client observes the ambiguous end-of-stream).
        if type(envelope) is ServerCloseEnvelope and envelope.outcome == "completed":
            return
        await original_write(cast(Any, stream), envelope)

    await _run_grant_flow(
        tmp_path,
        recipe,
        authorize_patches=patch.object(
            daemon_module, "_write_human_envelope", drop_completed_close
        ),
    )


@pytest.mark.anyio
async def test_tighter_recipe_over_an_expanded_grant_is_applied_as_tightened(
    tmp_path: Path,
    runtime_directory: Path,  # noqa: F811 - imported pytest fixture
) -> None:
    """#552 acceptance: Expanded → Assisted through the chat-consent lane reports `tightened`.

    The reverse state of a grant: the repository already holds an Expanded grant, the user asks
    for the strictly tighter Assisted recipe, and the lane must apply it without a human decision
    ceremony, report the wire outcome `tightened`, keep the grant in place, and record exactly one
    `tightening` policy row superseding the granted one.
    """

    async with _GrantCell(tmp_path) as cell:
        with cell.patches():
            await _initialize_vault(cell.consent_state)
            await _prepare_grant("expanded_review", expected_grant_state="missing")
            granted = await _authorize_current_pending(cell.consent_state)
            assert granted["result"] == {"recipe": "expanded_review", "outcome": "granted"}
            expanded = await _prepare_grant("assisted_review", expected_grant_state="granted")
            assert expanded.composed_policy.review_context_profile is ReviewContextProfile.EXPANDED
            commitment = cast(str, expanded.bound_scope["workspace_ref_commitment"])

            result = await _authorize_current_pending(cell.consent_state)

            assert result["outcome"] == "completed"
            assert result["authority_channel"] == "agent_attested_chat_instruction"
            assert result["result"] == {"recipe": "assisted_review", "outcome": "tightened"}
            validate_schema_instance("review-result", "6.0.0", result)

            tightened = await get_privacy_setup_snapshot()
            # The grant survives: tightening narrows the repository's permission, it never
            # revokes it. The composed policy now meets at the Assisted profile exactly, and the
            # repository authority moved so the next proposal must re-read before it can commit.
            assert tightened.grant_state == "granted"
            assert tightened.authority_digest != expanded.authority_digest
            composed = tightened.composed_policy
            assert composed.review_context_profile is ReviewContextProfile.ASSISTED
            assert composed.review_selection == ReviewSelectionPolicy.for_profile(
                ReviewContextProfile.ASSISTED
            )
            assert composed.require_current_provider_data_use_evidence is True
            assert composed.network_egress_permitted is True
            # Vault initialization, the Expanded grant, and the Assisted tightening: three
            # consumed reviews, all approved, none failed, nothing left pending.
            _assert_approvals(cell.consent_state, approved=3)

    rows = _workspace_policy_rows(cell.catalog, commitment)
    assert [(row.change_kind, row.state, row.version) for row in rows] == [
        ("human_expansion", "superseded", 1),
        ("tightening", "current", 2),
    ]
    granted_row, tightened_row = rows
    # The Expanded grant was the approved compound transition; the tightening is a direct
    # store commit with no proposal behind it, on the same repository policy lineage.
    assert granted_row.source_proposal_id is not None
    assert tightened_row.source_proposal_id is None
    assert tightened_row.policy_id == granted_row.policy_id
    assert tightened_row.generation > granted_row.generation
    assert granted_row.policy.review_context_profile is ReviewContextProfile.EXPANDED
    assert tightened_row.policy.review_context_profile is ReviewContextProfile.ASSISTED
    assert tightened_row.policy.supersedes_policy_digest == granted_row.digest
    assert tightened_row.policy.policy_digest == tightened_row.digest
