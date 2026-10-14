"""The production provenance resolver applies the INTERFACES rule to ledger authorship (#914)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.privacy.provenance import LedgerAuthorshipProvenanceResolver
from finishup.application.egress import PrivacyCoordinator
from finishup.domain.privacy import (
    CandidateContext,
    CandidateContextItem,
    ClassifiedContext,
    DataClass,
    DisclosureProvenance,
    LocalDisclosureSink,
    PrivacyDecision,
    PrivacyOutcome,
    ProjectionItemAuthorship,
    ProjectionProvenanceContext,
    SourceAuthorship,
    authorship_provenance,
)
from finishup.domain.values import Frontier
from finishup.protocol.coverage import PublicationChannel
from finishup.protocol.models import DataCategory
from finishup.service.ready_composition import build_local_privacy_enforcer
from unit.privacy.test_local_enforcer import (
    _DIGEST,  # pyright: ignore[reportPrivateUsage]
    _REQUEST,  # pyright: ignore[reportPrivateUsage]
    _effective,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
)

_SESSION = "ses_20000000-0000-4000-8000-000000000001"
_OTHER_SESSION = "ses_20000000-0000-4000-8000-000000000002"
_WRITER = "wri_20000000-0000-4000-8000-000000000003"
_OTHER_WRITER = "wri_20000000-0000-4000-8000-000000000004"
_FRONTIER = Frontier(10, f"sha256:{'5' * 64}")


def _source(
    *,
    writer: str = _WRITER,
    session: str = _SESSION,
    sequence: int = 7,
    channel: PublicationChannel = PublicationChannel.COOPERATIVE_MCP,
    observation: bool = False,
) -> SourceAuthorship:
    return SourceAuthorship(writer, session, sequence, channel, observation)


def _rule(*sources: SourceAuthorship) -> DisclosureProvenance:
    return authorship_provenance(
        sources, writer_id=_WRITER, session_id=_SESSION, frontier_sequence=_FRONTIER.sequence
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (_source(), DisclosureProvenance.SELF_AUTHORED),
        (_source(channel=PublicationChannel.LOCAL_CLI), DisclosureProvenance.SELF_AUTHORED),
        (_source(sequence=_FRONTIER.sequence), DisclosureProvenance.SELF_AUTHORED),
        (_source(writer=_OTHER_WRITER), DisclosureProvenance.OTHER_WRITER),
        # Reattach: same writer identity, earlier session.
        (_source(session=_OTHER_SESSION), DisclosureProvenance.OTHER_WRITER),
        # A contribution past the frozen frontier never counts as the writer's own.
        (_source(sequence=_FRONTIER.sequence + 1), DisclosureProvenance.OTHER_WRITER),
        # Session and writer matching is not authorship: host rows stay other_writer.
        (_source(channel=PublicationChannel.HOOK_OBSERVED), DisclosureProvenance.OTHER_WRITER),
        (
            _source(channel=PublicationChannel.HOOK_OBSERVED, observation=True),
            DisclosureProvenance.OTHER_WRITER,
        ),
        (_source(observation=True), DisclosureProvenance.OTHER_WRITER),
        (_source(channel=PublicationChannel.ENGINE_DERIVED), DisclosureProvenance.OTHER_WRITER),
        # Imports are imported even when the importing writer and session match.
        (_source(channel=PublicationChannel.CODEX_JSONL_IMPORT), DisclosureProvenance.IMPORTED),
        (_source(channel=PublicationChannel.HUMAN_IMPORT), DisclosureProvenance.IMPORTED),
    ),
)
def test_rule_requires_every_fact_of_self_authorship(
    source: SourceAuthorship, expected: DisclosureProvenance
) -> None:
    assert _rule(source) is expected


def test_every_contributing_event_must_be_self_authored() -> None:
    assert _rule(_source(), _source(sequence=8)) is DisclosureProvenance.SELF_AUTHORED
    assert _rule(_source(), _source(writer=_OTHER_WRITER)) is DisclosureProvenance.OTHER_WRITER
    assert (
        _rule(_source(), _source(channel=PublicationChannel.CODEX_JSONL_IMPORT))
        is DisclosureProvenance.IMPORTED
    )
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        _rule()


def _context(*rows: ProjectionItemAuthorship) -> ProjectionProvenanceContext:
    return ProjectionProvenanceContext(_SESSION, _WRITER, _FRONTIER, rows)


def _item(item_id: str, pointer: str, text: bytes = b"text") -> CandidateContextItem:
    return CandidateContextItem(item_id, DataCategory.EVIDENCE_EXCERPT, _scope(), pointer, text)


def _candidate(
    context: ProjectionProvenanceContext, *items: CandidateContextItem
) -> CandidateContext:
    return CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=items,
        provenance_context=context,
    )


def test_resolver_attributes_only_leaves_inside_an_attributed_row() -> None:
    resolver = LedgerAuthorshipProvenanceResolver()
    context = _context(
        ProjectionItemAuthorship("/page/items/1", (_source(),)),
        ProjectionItemAuthorship("/page/items/2", (_source(writer=_OTHER_WRITER),)),
    )
    own = _item("own", "/page/items/1/description")
    other = _item("other", "/page/items/2/reference")
    # "/page/items/10" is not a child of "/page/items/1".
    unattributed = _item("unattributed", "/page/items/10/description")
    finding = _item("finding", "/page/items/1")
    opaque = _item("opaque", "finding:summary")
    candidate = _candidate(context, own, other, unattributed, finding, opaque)

    assert resolver.resolve(context, candidate, own) is DisclosureProvenance.SELF_AUTHORED
    assert resolver.resolve(context, candidate, other) is DisclosureProvenance.OTHER_WRITER
    for item in (unattributed, finding, opaque):
        assert resolver.resolve(context, candidate, item) is None
    assert resolver.resolve(_context(), candidate, own) is None


def _decision(classified: ClassifiedContext) -> PrivacyDecision:
    coordinator = object.__new__(PrivacyCoordinator)
    return coordinator._local_decision(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        classified, _effective()
    )


def test_production_enforcer_widens_own_rows_and_keeps_absolute_classes() -> None:
    """The composed enforcer resolves provenance; never-send and sensitive stay absolute."""

    enforcer = build_local_privacy_enforcer()
    assert type(enforcer) is LocalPrivacyEnforcer
    context = _context(
        ProjectionItemAuthorship("/page/items/0", (_source(),)),
        ProjectionItemAuthorship("/page/items/1", (_source(),)),
        ProjectionItemAuthorship("/page/items/2", (_source(writer=_OTHER_WRITER),)),
    )
    own = _item("own", "/page/items/0/description", b"the agent's own evidence")
    secret = _item(
        "secret", "/page/items/1/description", b"api_key=sk-proj-abcdefghijklmnopqrstuvwxyz012345"
    )
    other = _item("other", "/page/items/2/description", b"another writer's evidence")
    classified = enforcer.classify(_candidate(context, own, secret, other), _effective())
    by_id = {item.candidate.item_id: item for item in classified.items}
    assert by_id["own"].provenance is DisclosureProvenance.SELF_AUTHORED
    # The never-send scan runs before, and independently of, provenance.
    assert by_id["secret"].provenance is None
    assert by_id["secret"].forbidden_findings
    assert by_id["other"].provenance is DisclosureProvenance.OTHER_WRITER

    clean = enforcer.classify(_candidate(context, own, other), _effective())
    decision = _decision(clean)
    assert decision.outcome is PrivacyOutcome.COMPLETED
    assert decision.approved_item_ids == ("own",)
    assert DataCategory.EVIDENCE_EXCERPT in decision.blocked_categories

    sensitive = ClassifiedContext(
        clean.candidate,
        tuple(
            replace(item, data_class=DataClass.SENSITIVE_CONFIDENTIAL)
            if item.candidate.item_id == "own"
            else item
            for item in clean.items
        ),
    )
    assert _decision(sensitive).approved_item_ids == ()


def test_context_rejects_duplicate_or_unbounded_row_authorship() -> None:
    row = ProjectionItemAuthorship("/page/items/0", (_source(),))
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        _context(row, row)
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        _context(
            *(
                ProjectionItemAuthorship(f"/page/items/{index}", (_source(),))
                for index in range(101)
            )
        )
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        ProjectionItemAuthorship("/page/items/0", ())
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        SourceAuthorship(_WRITER, _SESSION, 0, PublicationChannel.COOPERATIVE_MCP, False)


# --- tb4n5 (ADR-035 amendment): an undeclared-reference name returns only to its publisher -----

_LEAF = "/closure_readiness/undeclared_references/0/paths/0"
_OTHER_LEAF = "/closure_readiness/undeclared_references/1/paths/0"


def _leaf_context(*rows: ProjectionItemAuthorship) -> ProjectionProvenanceContext:
    return ProjectionProvenanceContext(_SESSION, _WRITER, _FRONTIER, (), rows)


def _path_item(item_id: str, pointer: str, category: DataCategory) -> CandidateContextItem:
    return CandidateContextItem(item_id, category, _scope(), pointer, b'"checks/case_0/walk.npz"')


def _projection_candidate(
    context: ProjectionProvenanceContext,
    *items: CandidateContextItem,
    purpose: str = "client_result_projection",
) -> CandidateContext:
    from finishup.domain.privacy import ProjectionAuditContext

    projection = purpose == "client_result_projection"
    return CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose=purpose,
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=items,
        provenance_context=context,
        projection_audit_context=(
            ProjectionAuditContext(
                "rpc_20000000-0000-4000-8000-000000000005",
                "status",
                "svc_20000000-0000-4000-8000-000000000006",
                1,
                None,
                _DIGEST,
                b"{}",
                b"{}",
            )
            if projection
            else None
        ),
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (_source(), DisclosureProvenance.SELF_AUTHORED),
        # Another writer, or the same writer's earlier session (an attach), did not author it.
        (_source(writer=_OTHER_WRITER), DisclosureProvenance.OTHER_WRITER),
        (_source(session=_OTHER_SESSION), DisclosureProvenance.OTHER_WRITER),
        # A hook-observed or imported record is never the requester's own publication.
        (_source(channel=PublicationChannel.HOOK_OBSERVED), DisclosureProvenance.OTHER_WRITER),
        (_source(observation=True), DisclosureProvenance.OTHER_WRITER),
        (_source(channel=PublicationChannel.CODEX_JSONL_IMPORT), DisclosureProvenance.IMPORTED),
        # Published after the page's frontier: not yet the writer's.
        (_source(sequence=_FRONTIER.sequence + 1), DisclosureProvenance.OTHER_WRITER),
    ),
)
def test_an_undeclared_reference_name_resolves_by_its_publisher_only(
    source: SourceAuthorship, expected: DisclosureProvenance
) -> None:
    resolver = LedgerAuthorshipProvenanceResolver()
    context = _leaf_context(ProjectionItemAuthorship(_LEAF, (source,)))
    name = _path_item("name", _LEAF, DataCategory.REPOSITORY_EXCERPT)
    unattributed = _path_item("other", _OTHER_LEAF, DataCategory.REPOSITORY_EXCERPT)
    # Another category at the same pointer never borrows the authorship.
    wrong_category = _path_item("wrong", _LEAF, DataCategory.EVIDENCE_EXCERPT)
    candidate = _projection_candidate(context, name, unattributed, wrong_category)

    assert resolver.resolve(context, candidate, name) is expected
    assert resolver.resolve(context, candidate, unattributed) is None
    assert resolver.resolve(context, candidate, wrong_category) is None
    assert resolver.resolve(_leaf_context(), candidate, name) is None


def test_leaf_authorship_admits_only_the_undeclared_reference_path_leaves() -> None:
    for pointer in (
        "/page/items/0/description",
        "/closure_readiness/undeclared_references/0/paths",
        "/closure_readiness/undeclared_references/0/paths/8",
        "/closure_readiness/undeclared_references/100/paths/0",
        "/closure_readiness/undeclared_references/0/total",
        "/document/gaps/0/detail",
    ):
        with pytest.raises(ValueError, match="invalid_privacy_value"):
            _leaf_context(ProjectionItemAuthorship(pointer, (_source(),)))
    row = ProjectionItemAuthorship(_LEAF, (_source(),))
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        _leaf_context(row, row)


def test_a_published_name_reaches_only_its_author_under_the_private_ceiling() -> None:
    """The biped ceiling (no ``repository_excerpt`` grant): the requester's own published name
    comes back; another writer's stays omitted; never-send and the data-class ceiling still win."""

    enforcer = build_local_privacy_enforcer()
    context = _leaf_context(
        ProjectionItemAuthorship(_LEAF, (_source(),)),
        ProjectionItemAuthorship(_OTHER_LEAF, (_source(writer=_OTHER_WRITER),)),
    )
    own = _path_item("own", _LEAF, DataCategory.REPOSITORY_EXCERPT)
    other = _path_item("other", _OTHER_LEAF, DataCategory.REPOSITORY_EXCERPT)
    effective = _effective()
    assert DataCategory.REPOSITORY_EXCERPT not in effective.policy.agent_context_categories

    classified = enforcer.classify(_projection_candidate(context, own, other), effective)
    decision = _decision(classified)
    assert decision.outcome is PrivacyOutcome.COMPLETED
    assert decision.approved_item_ids == ("own",)
    assert DataCategory.REPOSITORY_EXCERPT in decision.blocked_categories

    narrowed = ClassifiedContext(
        classified.candidate,
        tuple(
            replace(item, data_class=DataClass.SENSITIVE_CONFIDENTIAL) for item in classified.items
        ),
    )
    assert _decision(narrowed).approved_item_ids == ()
    secret = CandidateContextItem(
        "secret",
        DataCategory.REPOSITORY_EXCERPT,
        _scope(),
        _LEAF,
        b"api_key=sk-proj-abcdefghijklmnopqrstuvwxyz012345",
    )
    scanned = enforcer.classify(_projection_candidate(context, secret), effective)
    assert scanned.items[0].provenance is None
    assert _decision(scanned).approved_item_ids == ()
