"""Production provenance resolver for agent-context projections (issue #914).

``docs/INTERFACES.md`` conditions the ``agent_context`` ceiling on ``DisclosureProvenance``: an
item the requesting writer authored in this session, at or before the frozen frontier, returns to
that writer without a category grant. The rule was implemented by the egress decision but never
fired, because production composed ``LocalPrivacyEnforcer`` without a resolver and provenance was
always ambiguous. This resolver supplies it from ledger authorship the service itself read.
"""

from __future__ import annotations

import re

from finishup.domain.privacy import (
    CandidateContext,
    CandidateContextItem,
    DataCategory,
    DisclosureProvenance,
    ProjectionProvenanceContext,
    authorship_provenance,
)

__all__ = ["LedgerAuthorshipProvenanceResolver"]


_RECEIPT_NAME_SPAN = re.compile(
    r"/(?:document/.+|human_text)/@repository_name/(0|[1-9][0-9]*)", re.ASCII
)


class LedgerAuthorshipProvenanceResolver:
    """Resolve provenance from service-read ledger authorship of the projected row.

    The inputs are ``ProjectionProvenanceContext.item_authorship``, which the service builds
    from accepted event envelopes at the page's frozen frontier, and its ``leaf_authorship``
    (tb4n5): the same envelope authorship for the publication that spelled each
    undeclared-reference name, keyed by that exact leaf (a receipt name span by the name's
    canonical index); no caller-supplied field is consulted. A leaf that belongs to no attributed
    row stays ambiguous (``None``), which grants no widening: other views, findings (including
    every AI-powered finding), other receipt prose and any row the ledger could not attribute keep
    the ordinary category ceiling. The decision is made per
    leaf and per request, so nothing is cached across frontiers or writers.
    """

    __slots__ = ()

    def resolve(
        self,
        context: ProjectionProvenanceContext,
        candidate: CandidateContext,
        item: CandidateContextItem,
    ) -> DisclosureProvenance | None:
        pointer = item.origin_ref
        if not pointer.startswith("/"):
            return None
        if item.category is DataCategory.REPOSITORY_EXCERPT:
            # A receipt name span (``<leaf>/@repository_name/<n>``) is attributed by the name's
            # canonical index, once per name however many prose leaves spell it.
            span = _RECEIPT_NAME_SPAN.fullmatch(pointer)
            audit = candidate.projection_audit_context
            if span is not None and audit is not None and audit.method == "receipt":
                pointer = f"/receipt_repository_names/{span[1]}"
            # tb4n5 (ADR-035 amendment): an undeclared-reference name returns only to the writer
            # who published that exact name in this session; exact leaf, this category only.
            for leaf in context.leaf_authorship:
                if pointer == leaf.item_pointer:
                    return authorship_provenance(
                        leaf.sources,
                        writer_id=context.writer_id,
                        session_id=context.session_id,
                        frontier_sequence=context.frontier.sequence,
                    )
        for row in context.item_authorship:
            if pointer.startswith(row.item_pointer + "/"):
                return authorship_provenance(
                    row.sources,
                    writer_id=context.writer_id,
                    session_id=context.session_id,
                    frontier_sequence=context.frontier.sequence,
                )
        return None
