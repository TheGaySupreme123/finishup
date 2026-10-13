"""The production provenance resolver applies the INTERFACES rule to ledger authorship (#914)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from unit.privacy.test_local_enforcer import (
    _DIGEST,  # pyright: ignore[reportPrivateUsage]
    _REQUEST,  # pyright: ignore[reportPrivateUsage]
    _effective,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.adapters.privacy.provenance import LedgerAuthorshipProvenanceResolver
from yoetz.application.egress import PrivacyCoordinator
from yoetz.domain.privacy import (
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
from yoetz.domain.values import Frontier
from yoetz.protocol.coverage import PublicationChannel
from yoetz.protocol.models import DataCategory
from yoetz.service.ready_composition import build_local_privacy_enforcer

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


# --- tb4n5 (owner decision 2026-10-13, ADR-035 amendment): task-created file names ------------

_CREATED = "/closure_readiness/undeclared_references/0/paths/0"
_UNPROVEN = "/closure_readiness/undeclared_references/1/paths/0"


def _created_context(*pointers: str) -> ProjectionProvenanceContext:
    return ProjectionProvenanceContext(_SESSION, _WRITER, _FRONTIER, (), pointers)


def _path_item(item_id: str, pointer: str, category: DataCategory) -> CandidateContextItem:
    return CandidateContextItem(item_id, category, _scope(), pointer, b'"checks/case_0/walk.npz"')


def _projection_candidate(
    context: ProjectionProvenanceContext,
    *items: CandidateContextItem,
    sink: LocalDisclosureSink = LocalDisclosureSink.AGENT_CONTEXT,
    purpose: str = "client_result_projection",
) -> CandidateContext:
    from yoetz.domain.privacy import ProjectionAuditContext

    projection = purpose == "client_result_projection"
    return CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=sink,
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


def test_a_task_created_name_resolves_only_at_its_own_leaf_and_category() -> None:
    resolver = LedgerAuthorshipProvenanceResolver()
    context = _created_context(_CREATED)
    created = _path_item("created", _CREATED, DataCategory.REPOSITORY_EXCERPT)
    unproven = _path_item("unproven", _UNPROVEN, DataCategory.REPOSITORY_EXCERPT)
    # Another category at the same pointer never borrows the class.
    wrong_category = _path_item("wrong", _CREATED, DataCategory.EVIDENCE_EXCERPT)
    candidate = _projection_candidate(context, created, unproven, wrong_category)

    assert resolver.resolve(context, candidate, created) is DisclosureProvenance.TASK_CREATED_FILE
    assert resolver.resolve(context, candidate, unproven) is None
    assert resolver.resolve(context, candidate, wrong_category) is None
    assert resolver.resolve(_created_context(), candidate, created) is None


def test_the_created_pointers_admit_only_the_undeclared_reference_path_leaves() -> None:
    for pointer in (
        "/page/items/0/description",
        "/closure_readiness/undeclared_references/0/paths",
        "/closure_readiness/undeclared_references/0/paths/8",
        "/closure_readiness/undeclared_references/100/paths/0",
        "/closure_readiness/undeclared_references/0/total",
        "/document/gaps/0/detail",
    ):
        with pytest.raises(ValueError, match="invalid_privacy_value"):
            _created_context(pointer)
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        _created_context(_CREATED, _CREATED)
    assert _created_context(_CREATED, _UNPROVEN).created_file_pointers == (_CREATED, _UNPROVEN)


def test_a_task_created_name_reaches_only_the_agent_context_projection_under_the_private_ceiling() -> (
    None
):
    """The biped ceiling (no ``repository_excerpt`` grant) shows a task-created name to the agent,
    keeps an unproven one omitted, and never widens a non-projection or another local sink."""

    enforcer = build_local_privacy_enforcer()
    context = _created_context(_CREATED)
    created = _path_item("created", _CREATED, DataCategory.REPOSITORY_EXCERPT)
    unproven = _path_item("unproven", _UNPROVEN, DataCategory.REPOSITORY_EXCERPT)
    effective = _effective()
    assert DataCategory.REPOSITORY_EXCERPT not in effective.policy.agent_context_categories

    classified = enforcer.classify(_projection_candidate(context, created, unproven), effective)
    by_id = {item.candidate.item_id: item for item in classified.items}
    assert by_id["created"].provenance is DisclosureProvenance.TASK_CREATED_FILE
    decision = _decision(classified)
    assert decision.outcome is PrivacyOutcome.COMPLETED
    assert decision.approved_item_ids == ("created",)
    assert DataCategory.REPOSITORY_EXCERPT in decision.blocked_categories

    # Not a projection (another local disclosure purpose): the class widens nothing.
    other_purpose = enforcer.classify(
        _projection_candidate(context, created, purpose="client-result-projection"), effective
    )
    assert _decision(other_purpose).approved_item_ids == ()
    # The data-class ceiling still applies: a narrower one keeps the name withheld.
    narrowed = ClassifiedContext(
        classified.candidate,
        tuple(
            replace(item, data_class=DataClass.SENSITIVE_CONFIDENTIAL) for item in classified.items
        ),
    )
    assert _decision(narrowed).approved_item_ids == ()
    # A never-send match in the name is still withheld: the scan runs before provenance.
    secret = CandidateContextItem(
        "secret",
        DataCategory.REPOSITORY_EXCERPT,
        _scope(),
        _CREATED,
        b"api_key=sk-proj-abcdefghijklmnopqrstuvwxyz012345",
    )
    scanned = enforcer.classify(_projection_candidate(context, secret), effective)
    assert scanned.items[0].provenance is None
    assert _decision(scanned).approved_item_ids == ()
