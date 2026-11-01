"""How the kernel folds a call's workspace facts (PR #1080 round 6, review findings 1 and 3).

A later delivery's fact arrives as an observed evidence annotation under the call's action; it is
folded with the result's own fact, ``changed``/``unavailable`` winning. A task that declares a
delivery where the fingerprint does not fully walk gets no ``unchanged`` command at all.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.domain.events import (
    ClientKind,
    EventSchema,
    IntegrationKind,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    RuntimeProfile,
    SessionOpenedPayload,
)
from finishup.domain.values import obligation_id
from finishup.domain.workspace_effect import path_beyond_workspace_fingerprint
from finishup.kernel.closing_review_delta import closing_material_frontier, closing_review_delta
from finishup.kernel.later_material import (
    LaterMaterialClass,
    classify_later_material,
    counted_later_material,
    workspace_effects,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key, task_workspace_root


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def test_a_later_unchanged_annotation_quiets_a_call_recorded_without_a_fact() -> None:
    ledger = ObservedLedger()
    result = ledger.passes("date -u")
    state = replay(ledger.prefix)
    assert closing_material_frontier(state, ledger.prefix) > 0
    annotation = ledger.annotate_workspace_effect(result, "unchanged")
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert effects.quiet and dict(effects.annotations) == {annotation: next(iter(effects.quiet))}
    assert not any(closing_review_delta(row, state, effects=effects) for row in ledger.prefix)
    assert closing_material_frontier(state, ledger.prefix) == 0
    row = ledger.records[-1]
    classified = classify_later_material(row, state, effects=effects)
    assert classified.material_class is LaterMaterialClass.EXPLORATION
    assert classified.rule == "workspace_effect_of_action"
    assert counted_later_material(ledger.records, state, all_records=ledger.prefix) == ()


@pytest.mark.parametrize("later", ["changed", "unavailable"])
def test_a_contradicting_annotation_rearms_at_its_own_position(later: str) -> None:
    ledger = ObservedLedger()
    result = ledger.passes("date -u", workspace_effect="unchanged")
    reviewed = len(ledger.records)
    ledger.annotate_workspace_effect(result, later)
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert not effects.quiet
    assert closing_review_delta(ledger.records[-1], state, effects=effects)
    # A closing review taken after the original result is stale once the contradiction lands.
    assert closing_material_frontier(state, ledger.prefix) > reviewed
    counted = counted_later_material(ledger.records[reviewed:], state, all_records=ledger.prefix)
    assert counted == (ledger.records[-1],)


def test_an_agent_published_or_unlinked_annotation_says_nothing() -> None:
    ledger = ObservedLedger()
    result = ledger.passes("date -u")
    ledger.annotate_workspace_effect(result, "unchanged", observed=False)
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert effects.quiet == frozenset() and not effects.annotations
    assert closing_material_frontier(state, ledger.prefix) > 0


def test_another_tools_annotation_follows_its_tool_rule() -> None:
    """A non-shell tool is material only on ``changed``, whichever row carries the fact."""

    from finishup.domain.events import ActionKind, ResultOutcome

    for effect, material in (("changed", True), ("unavailable", False), ("unchanged", False)):
        ledger = ObservedLedger()
        result = ledger.run(
            None, ResultOutcome.SUCCESS, kind=ActionKind.OTHER, tool="write_stdin", runner="other"
        )
        ledger.annotate_workspace_effect(result, effect)
        state = replay(ledger.prefix)
        assert (closing_material_frontier(state, ledger.prefix) > 0) is material, effect


def _open_session(ledger: ObservedLedger, workspace_ref: str | None) -> None:
    ledger.append(
        EventSchema("session_opened", "1.0.0"),
        SessionOpenedPayload(
            task_title="Deliver the report",
            client_kind=ClientKind.FINISHUP_CLI,
            client_version="0.3.0",
            integration=IntegrationKind.LOCAL_CLI,
            profile=RuntimeProfile.STRICT_LOCAL,
            workspace_ref=workspace_ref,
        ),
        observed=False,
    )


def _declare(
    ledger: ObservedLedger,
    value: str,
    role: RequestedItemRole | None,
    *,
    kind: RequestedItemKind = RequestedItemKind.FILE,
) -> None:
    obligation = obligation_id("obl_00000000-0000-4000-8000-000000001086")
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Deliver the report",
            evidence_expectation="A report",
            status=ObligationStatus.OPEN,
            requested_items=(RequestedItem(kind, value, role),),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Deliver the report", (obligation,)),
        observed=False,
    )


def _quiet_after_declaring(
    value: str,
    role: RequestedItemRole,
    *,
    root: str | None,
    kind: RequestedItemKind = RequestedItemKind.FILE,
) -> tuple[bool, bool]:
    """Whether an unchanged command is quiet, and whether it re-arms the closing review."""

    ledger = ObservedLedger()
    if root is not None:
        _open_session(ledger, root)
    _declare(ledger, value, role, kind=kind)
    start = len(ledger.records)
    ledger.passes("python generate.py", workspace_effect="unchanged")
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    rearms = any(
        closing_review_delta(row, state, effects=effects) for row in ledger.records[start:]
    )
    assert (closing_material_frontier(state, ledger.prefix) > start) is rearms
    return bool(effects.quiet), rearms


@pytest.mark.parametrize(
    "value,root,kind",
    [
        # Below the first level of a dependency environment: recorded by identity only.
        (".venv/lib/python3.12/site-packages/pkg/patch.py", None, RequestedItemKind.FILE),
        ("node_modules/pkg/index.js", None, RequestedItemKind.FILE),
        ("node_modules/pkg/lib/index.js", None, RequestedItemKind.FILE),
        ("node_modules/pkg", None, RequestedItemKind.DIRECTORY),
        # Absolute and inside the task's root, or with no known root (a TB-style ``/app`` path).
        ("/app/node_modules/pkg/index.js", "/app", RequestedItemKind.FILE),
        ("/app/node_modules/x/y.js", None, RequestedItemKind.FILE),
        # VCS internals the walk records by identity or skips.
        (".git/objects/ab/cdef0123", None, RequestedItemKind.FILE),
        ("/app/.git/refs/heads/main", "/app", RequestedItemKind.FILE),
        (".git/HEAD", None, RequestedItemKind.FILE),
        ("src/__pycache__/module.cpython-312.pyc", None, RequestedItemKind.FILE),
        ("out/finishup-receipt.md", None, RequestedItemKind.FILE),
    ],
)
def test_a_declared_delivery_the_fingerprint_cannot_fully_see_quiets_nothing(
    value: str, root: str | None, kind: RequestedItemKind
) -> None:
    """A quiet command never outranks a delivery the walk does not compare."""

    directory = kind is RequestedItemKind.DIRECTORY
    assert path_beyond_workspace_fingerprint(value, directory=directory, workspace_root=root)
    assert _quiet_after_declaring(value, RequestedItemRole.OUTPUT, root=root, kind=kind) == (
        False,
        True,
    )


@pytest.mark.parametrize(
    "value,role,root",
    [
        ("report.txt", RequestedItemRole.OUTPUT, None),
        ("src/__pycache__/notes.txt", RequestedItemRole.OUTPUT, None),
        ("node_modules/pkg/index.js", RequestedItemRole.INPUT, None),
        # Files the walk compares: the first level of a dependency environment or tool cache,
        # and VCS configuration and hooks.
        ("node_modules/x.js", RequestedItemRole.OUTPUT, None),
        ("venv/report.txt", RequestedItemRole.OUTPUT, None),
        (".pytest_cache/report.txt", RequestedItemRole.OUTPUT, None),
        (".git/hooks/pre-commit", RequestedItemRole.OUTPUT, None),
        (".git/config", RequestedItemRole.OUTPUT, None),
        ("/app/.git/config", RequestedItemRole.OUTPUT, "/app"),
        ("/app/node_modules/x.js", RequestedItemRole.OUTPUT, None),
        # Outside the task's root: out of the walk's scope (PR #1080 round 7).
        ("/usr/local/lib/node_modules/left-pad/index.js", RequestedItemRole.OUTPUT, "/app"),
        ("/opt/venv/lib/python3.12/site-packages/pkg/core.py", RequestedItemRole.OUTPUT, "/app"),
        ("/srv/git/project/.git/hooks/post-receive", RequestedItemRole.OUTPUT, "/app"),
        ("../other/node_modules/pkg/index.js", RequestedItemRole.OUTPUT, None),
    ],
)
def test_an_ordinary_or_input_declaration_keeps_unchanged_commands_quiet(
    value: str, role: RequestedItemRole, root: str | None
) -> None:
    beyond = path_beyond_workspace_fingerprint(value, workspace_root=root)
    assert beyond is (role is RequestedItemRole.INPUT)
    assert _quiet_after_declaring(value, role, root=root) == (True, False)


def test_the_tasks_root_is_known_only_when_every_session_names_the_same_absolute_one() -> None:
    """Out-of-root declarations stay quiet only against one root every session agrees on."""

    outside = "/usr/local/lib/node_modules/left-pad/index.js"
    ledger = ObservedLedger()
    assert task_workspace_root(ledger.prefix) is None
    _open_session(ledger, "/app/")
    _open_session(ledger, "/app")
    assert task_workspace_root(ledger.prefix) == "/app"
    for other in ("/srv/other", "my-repo", None):
        mixed = ObservedLedger()
        _open_session(mixed, "/app")
        _open_session(mixed, other)
        assert task_workspace_root(mixed.prefix) is None
        _declare(mixed, outside, RequestedItemRole.OUTPUT)
        mixed.passes("python generate.py", workspace_effect="unchanged")
        state = replay(mixed.prefix)
        # Unknown root: every ancestor may be the root, so the declaration quiets nothing.
        assert workspace_effects(mixed.prefix, state).quiet == frozenset(), other
