from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from finishup.application import recommendations
from finishup.application.package_update import PackageUpdateAdvisory, build_package_update_advisory
from finishup.application.recommendations import (
    RECOMMENDED_DEFAULTS,
    RecommendationContext,
    RecommendationStoreError,
    RecommendationTarget,
    cached_pending_recommendations,
    decline_cached_recommendation,
    evaluate_recommendation_context,
    load_recommendation_state,
    record_recommendation_decision,
    refresh_pending,
)

_NOW = datetime(2026, 8, 12, 9, 30, tzinfo=UTC)


def _target_from_fields(fields: dict[str, str]) -> RecommendationTarget:
    target_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
    )
    return RecommendationTarget(target_digest=target_digest, **fields)


def _activation_target(seed: str) -> RecommendationTarget:
    values = [f"sha256:{character * 64}" for character in seed[:5]]
    return _target_from_fields(
        {
            "executable_path_digest": values[0],
            "executable_digest": values[1],
            "codex_version": "0.148.0",
            "codex_home_digest": values[2],
            "activation_preview_digest": values[3],
            "plugin_install_digest": values[4],
        }
    )


def _rebound_target(
    target: RecommendationTarget, *, home: str | None = None, preview: str | None = None
) -> RecommendationTarget:
    return _target_from_fields(
        {
            "executable_path_digest": target.executable_path_digest,
            "executable_digest": target.executable_digest,
            "codex_version": target.codex_version,
            "codex_home_digest": target.codex_home_digest if home is None else home,
            "activation_preview_digest": (
                target.activation_preview_digest if preview is None else preview
            ),
            "plugin_install_digest": target.plugin_install_digest,
        }
    )


def _newer() -> PackageUpdateAdvisory:
    return build_package_update_advisory(
        installed_version="0.1.0", latest_version="0.2.0", source="cache"
    )


@pytest.mark.anyio
async def test_registry_evaluates_all_three_recommended_defaults(tmp_path: Path) -> None:
    target = _activation_target("abcdef")
    state = await refresh_pending(
        context=RecommendationContext(
            observation_enabled=False,
            codex_activation_state="installed_not_activated",
            codex_activation_target=target,
            package_update=_newer(),
        ),
        root=tmp_path,
        version="0.1.0",
    )

    assert state.pending == tuple(item.id for item in RECOMMENDED_DEFAULTS)
    assert [item.id for item in cached_pending_recommendations(root=tmp_path)] == list(
        state.pending
    )
    assert state.pending_targets == {"codex-plugin-activation": target}
    store = tmp_path / "recommendations.json"
    assert stat.S_IMODE(store.stat().st_mode) == 0o600


@pytest.mark.anyio
async def test_decline_is_remembered_across_release_frontiers(tmp_path: Path) -> None:
    target = _activation_target("abcdef")
    context = RecommendationContext(
        observation_enabled=True,
        codex_activation_state="installed_not_activated",
        codex_activation_target=target,
    )
    await refresh_pending(context=context, root=tmp_path, version="0.1.0")
    declined = record_recommendation_decision(
        "codex-plugin-activation",
        "declined",
        root=tmp_path,
        version="0.1.0",
        now=_NOW,
        target=target,
    )
    assert declined.pending == ()

    reevaluated = await refresh_pending(context=context, root=tmp_path, version="0.2.0")

    assert reevaluated.pending == ()
    assert next(iter(reevaluated.decisions.values())).decision == "declined"


@pytest.mark.anyio
async def test_activation_acceptance_is_exact_target_and_drift_bound(tmp_path: Path) -> None:
    first_target = _activation_target("abcde")
    second_home = _rebound_target(first_target, home="sha256:" + ("1" * 64))
    drifted_first_target = _rebound_target(first_target, preview="sha256:" + ("2" * 64))
    context = RecommendationContext(
        codex_activation_state="installed_not_activated",
        codex_activation_target=first_target,
    )
    await refresh_pending(context=context, root=tmp_path, version="0.1.0", force=True)
    accepted = record_recommendation_decision(
        "codex-plugin-activation",
        "accepted",
        root=tmp_path,
        version="0.1.0",
        now=_NOW,
        target=first_target,
    )
    assert accepted.pending == ()

    same_inactive = await refresh_pending(
        context=context, root=tmp_path, version="0.1.0", force=True
    )
    assert same_inactive.pending == ("codex-plugin-activation",)

    active = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="active",
            codex_activation_target=None,
        ),
        root=tmp_path,
        version="0.1.0",
        force=True,
    )
    assert active.pending == ()

    other = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=second_home,
        ),
        root=tmp_path,
        version="0.1.0",
        force=True,
    )
    assert other.pending == ("codex-plugin-activation",)
    assert other.pending_targets["codex-plugin-activation"] == second_home

    drifted = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=drifted_first_target,
        ),
        root=tmp_path,
        version="0.1.0",
        force=True,
    )
    assert drifted.pending == ("codex-plugin-activation",)
    assert drifted.pending_targets["codex-plugin-activation"] == drifted_first_target


@pytest.mark.anyio
async def test_foreign_or_nonpreviewable_activation_clears_stale_advice(tmp_path: Path) -> None:
    target = _activation_target("abcde")
    await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=target,
        ),
        root=tmp_path,
        force=True,
    )

    foreign = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="foreign",
            codex_activation_target=None,
        ),
        root=tmp_path,
        force=True,
    )
    assert foreign.pending == ()

    nonpreviewable = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=None,
        ),
        root=tmp_path,
        force=True,
    )
    assert nonpreviewable.pending == ()


def test_activation_decision_history_is_bounded_without_losing_current_decision(
    tmp_path: Path,
) -> None:
    base = _activation_target("abcde")
    accepted_targets: list[RecommendationTarget] = []
    for index in range(12):
        target = _rebound_target(base, preview=f"sha256:{index:064x}")
        accepted_targets.append(target)
        record_recommendation_decision(
            "codex-plugin-activation",
            "accepted",
            root=tmp_path,
            now=_NOW + timedelta(seconds=index),
            target=target,
        )
    accepted = load_recommendation_state(root=tmp_path)
    accepted_rows = [row for row in accepted.decisions.values() if row.decision == "accepted"]
    assert len(accepted_rows) == 8
    assert {row.target for row in accepted_rows} == set(accepted_targets[-8:])

    declined_targets: list[RecommendationTarget] = []
    for index in range(24):
        target = _rebound_target(base, home=f"sha256:{index + 100:064x}")
        declined_targets.append(target)
        record_recommendation_decision(
            "codex-plugin-activation",
            "declined",
            root=tmp_path,
            now=_NOW + timedelta(minutes=index),
            target=target,
        )
    full = load_recommendation_state(root=tmp_path)
    declined_rows = [row for row in full.decisions.values() if row.decision == "declined"]
    assert len(full.decisions) == 24
    assert len(declined_rows) == 16
    assert {row.target for row in declined_rows} == set(declined_targets[-16:])

    current = _rebound_target(base, home="sha256:" + ("f" * 64))
    record_recommendation_decision(
        "codex-plugin-activation",
        "declined",
        root=tmp_path,
        now=_NOW - timedelta(days=1),
        target=current,
    )
    bounded = load_recommendation_state(root=tmp_path)
    assert len(bounded.decisions) == 24
    assert any(row.target == current for row in bounded.decisions.values())


@pytest.mark.anyio
async def test_activation_decline_is_target_aware_and_active_target_stays_quiet(
    tmp_path: Path,
) -> None:
    declined_target = _activation_target("abcde")
    other_target = _activation_target("12345")
    await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=declined_target,
        ),
        root=tmp_path,
        version="0.1.0",
        force=True,
    )
    decline_cached_recommendation(
        "codex-plugin-activation", root=tmp_path, version="0.1.0", now=_NOW
    )

    declined = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=declined_target,
        ),
        root=tmp_path,
        version="0.2.0",
        force=True,
    )
    assert declined.pending == ()

    other = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=other_target,
        ),
        root=tmp_path,
        version="0.2.0",
        force=True,
    )
    assert other.pending == ("codex-plugin-activation",)

    active = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="active",
            codex_activation_target=other_target,
        ),
        root=tmp_path,
        version="0.2.0",
        force=True,
    )
    assert active.pending == ()


@pytest.mark.anyio
async def test_legacy_global_activation_decision_never_suppresses_exact_target(
    tmp_path: Path,
) -> None:
    legacy: dict[str, object] = {
        "schema": "yoetz.recommendations/1",
        "last_evaluated_version": "0.1.0",
        "decisions": {
            "codex-plugin-activation": {
                "decision": "accepted",
                "decided_at": "2026-08-12T09:30:00Z",
                "version": "0.1.0",
            }
        },
        "pending": ["codex-plugin-activation"],
    }
    path = tmp_path / "recommendations.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    path.chmod(0o600)
    assert load_recommendation_state(root=tmp_path).pending == ()

    target = _activation_target("abcde")
    refreshed = await refresh_pending(
        context=RecommendationContext(
            codex_activation_state="installed_not_activated",
            codex_activation_target=target,
        ),
        root=tmp_path,
        version="0.1.0",
        force=True,
    )

    assert refreshed.pending == ("codex-plugin-activation",)
    assert refreshed.pending_targets["codex-plugin-activation"] == target
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == "yoetz.recommendations/3"


@pytest.mark.anyio
async def test_acceptance_suppresses_only_the_same_release_frontier(tmp_path: Path) -> None:
    context = RecommendationContext(observation_enabled=False)
    await refresh_pending(context=context, root=tmp_path, version="0.1.0")
    record_recommendation_decision(
        "observation-enabled", "accepted", root=tmp_path, version="0.1.0", now=_NOW
    )

    same = await refresh_pending(context=context, root=tmp_path, version="0.1.0")
    changed = await refresh_pending(context=context, root=tmp_path, version="0.2.0")

    assert "observation-enabled" not in same.pending
    assert "observation-enabled" in changed.pending


@pytest.mark.anyio
async def test_supplied_context_reconciles_even_without_version_change(tmp_path: Path) -> None:
    satisfied = RecommendationContext(observation_enabled=True, codex_activation_state="active")
    first = await refresh_pending(context=satisfied, root=tmp_path, version="0.1.0")
    assert first.pending == ()

    stale_same_version = await refresh_pending(
        context=RecommendationContext(observation_enabled=False),
        root=tmp_path,
        version="0.1.0",
    )
    changed_version = await refresh_pending(
        context=RecommendationContext(observation_enabled=False),
        root=tmp_path,
        version="0.2.0",
    )

    assert stale_same_version.pending == ("observation-enabled",)
    assert changed_version.pending == ("observation-enabled",)


@pytest.mark.anyio
async def test_pending_cache_is_reconciled_on_every_heavy_touchpoint(tmp_path: Path) -> None:
    await refresh_pending(
        context=RecommendationContext(observation_enabled=False),
        root=tmp_path,
        version="0.1.0",
    )

    reconciled = await refresh_pending(
        context=RecommendationContext(observation_enabled=True),
        root=tmp_path,
        version="0.1.0",
    )

    assert reconciled.pending == ()


@pytest.mark.anyio
async def test_refresh_rereads_decisions_under_lock_before_writing(tmp_path: Path) -> None:
    await refresh_pending(
        context=RecommendationContext(observation_enabled=False),
        root=tmp_path,
        version="0.1.0",
    )

    async def concurrent_decline() -> RecommendationContext:
        record_recommendation_decision(
            "observation-enabled",
            "declined",
            root=tmp_path,
            version="0.1.0",
            now=_NOW,
        )
        return RecommendationContext(observation_enabled=False)

    refreshed = await refresh_pending(
        context_factory=concurrent_decline,
        root=tmp_path,
        version="0.1.0",
        force=True,
    )

    assert refreshed.pending == ()
    assert refreshed.decisions["observation-enabled"].decision == "declined"


def test_corrupt_or_oversized_state_is_not_replaced(tmp_path: Path) -> None:
    store = tmp_path / "recommendations.json"
    store.write_text('{"schema":"wrong"}', encoding="utf-8")
    store.chmod(0o600)
    original = store.read_bytes()

    with pytest.raises(RecommendationStoreError, match="recommendation_store_corrupt"):
        load_recommendation_state(root=tmp_path)
    assert store.read_bytes() == original

    store.write_bytes(b"x" * (32 * 1024 + 1))
    store.chmod(0o600)
    with pytest.raises(RecommendationStoreError, match="recommendation_store_corrupt"):
        load_recommendation_state(root=tmp_path)


def test_store_parser_rejects_unknown_fields(tmp_path: Path) -> None:
    document: dict[str, object] = {
        "schema": "yoetz.recommendations/1",
        "last_evaluated_version": "0.1.0",
        "decisions": {},
        "pending": [],
        "unexpected": True,
    }
    store = tmp_path / "recommendations.json"
    store.write_text(json.dumps(document), encoding="utf-8")
    store.chmod(0o600)

    with pytest.raises(RecommendationStoreError, match="recommendation_store_corrupt"):
        load_recommendation_state(root=tmp_path)


def test_store_rejects_world_readable_or_symlink_leaf(tmp_path: Path) -> None:
    store = tmp_path / "recommendations.json"
    store.write_text("{}", encoding="utf-8")
    store.chmod(0o644)
    with pytest.raises(RecommendationStoreError, match="recommendation_store_unsafe"):
        load_recommendation_state(root=tmp_path)

    store.unlink()
    target = tmp_path / "foreign.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    os.symlink(target, store)
    with pytest.raises(RecommendationStoreError, match="recommendation_store_unsafe"):
        load_recommendation_state(root=tmp_path)


def _skipped_policy() -> PackageUpdateAdvisory:
    return build_package_update_advisory(
        installed_version="0.1.0",
        latest_version=None,
        source="none",
        outcome="skipped_policy",
    )


@pytest.mark.anyio
async def test_policy_skipped_advisory_is_unknown_and_retains_pending(tmp_path: Path) -> None:
    established = await refresh_pending(
        context=RecommendationContext(package_update=_newer()),
        root=tmp_path,
        version="0.1.0",
    )
    assert "package-update" in established.pending

    retained = await refresh_pending(
        context=RecommendationContext(package_update=_skipped_policy()),
        root=tmp_path,
        version="0.1.0",
        force=True,
    )

    assert "package-update" in retained.pending


@pytest.mark.anyio
async def test_policy_skipped_advisory_never_creates_pending(tmp_path: Path) -> None:
    state = await refresh_pending(
        context=RecommendationContext(package_update=_skipped_policy()),
        root=tmp_path,
        version="0.1.0",
    )

    assert "package-update" not in state.pending


@pytest.mark.anyio
async def test_performed_up_to_date_advisory_clears_pending(tmp_path: Path) -> None:
    await refresh_pending(
        context=RecommendationContext(package_update=_newer()),
        root=tmp_path,
        version="0.1.0",
    )

    up_to_date = build_package_update_advisory(
        installed_version="0.2.0", latest_version="0.2.0", source="network"
    )
    cleared = await refresh_pending(
        context=RecommendationContext(package_update=up_to_date),
        root=tmp_path,
        version="0.2.0",
    )

    assert up_to_date.outcome == "up_to_date"
    assert "package-update" not in cleared.pending


@pytest.mark.anyio
async def test_rebuilt_advisory_keeps_the_transitional_yoetz_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A transitional-yoetz install (ADR-048) has only ``yoetz`` on PATH: an advisory rebuilt for a
    # newer pending release must keep naming that package and its upgrade command.
    await refresh_pending(
        context=RecommendationContext(
            package_update=build_package_update_advisory(
                installed_version="0.1.0", latest_version="0.3.0", source="cache", package="yoetz"
            )
        ),
        root=tmp_path,
        version="0.1.0",
    )
    rebuilt: list[PackageUpdateAdvisory] = []

    def spy(**kwargs: Any) -> PackageUpdateAdvisory:
        advisory = build_package_update_advisory(**kwargs)
        rebuilt.append(advisory)
        return advisory

    monkeypatch.setattr(recommendations, "build_package_update_advisory", spy)
    state = await refresh_pending(
        context=RecommendationContext(
            package_update=build_package_update_advisory(
                installed_version="0.1.0", latest_version="0.2.0", source="network", package="yoetz"
            )
        ),
        root=tmp_path,
        version="0.1.0",
        force=True,
    )

    assert state.pending_package_version == "0.3.0"
    assert [(item.latest_version, item.package) for item in rebuilt] == [("0.3.0", "yoetz")]
    assert rebuilt[0].upgrade_command == "yoetz upgrade"


@pytest.mark.anyio
async def test_decline_cached_declines_pending_without_context(tmp_path: Path) -> None:
    await refresh_pending(
        context=RecommendationContext(package_update=_newer()),
        root=tmp_path,
        version="0.1.0",
    )

    declined = decline_cached_recommendation(
        "package-update", root=tmp_path, version="0.1.0", now=_NOW
    )

    assert "package-update" not in declined.pending
    assert declined.decisions["package-update"].decision == "declined"


def test_decline_cached_requires_cached_pending(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="recommendation_not_pending"):
        decline_cached_recommendation("package-update", root=tmp_path, version="0.1.0", now=_NOW)

    with pytest.raises(ValueError, match="recommendation_unknown"):
        decline_cached_recommendation("not-real", root=tmp_path, version="0.1.0", now=_NOW)


@pytest.mark.anyio
async def test_context_resolution_reuses_package_update_advisory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    async def fake_resolve(**kwargs: object) -> PackageUpdateAdvisory:
        calls.append(kwargs)
        return _newer()

    monkeypatch.setattr(
        "finishup.application.recommendations.resolve_package_update_advisory", fake_resolve
    )

    context = await evaluate_recommendation_context(
        observation_enabled=False,
        codex_activation_state="active",
        network_egress_permitted=True,
        update_checks_enabled=True,
        allow_network=False,
    )

    assert context.package_update == _newer()
    assert calls == [
        {
            "policy": None,
            "network_egress_permitted": True,
            "update_checks_enabled": True,
            "allow_network": False,
        }
    ]


@pytest.mark.anyio
async def test_new_release_is_discovered_without_installed_version_change(tmp_path: Path) -> None:
    def context(latest: str) -> RecommendationContext:
        return RecommendationContext(
            package_update=build_package_update_advisory(
                installed_version="0.2.0", latest_version=latest, source="cache"
            )
        )

    assert not (
        await refresh_pending(context=context("0.2.0"), root=tmp_path, version="0.2.0")
    ).pending
    discovered = await refresh_pending(context=context("0.3.0"), root=tmp_path, version="0.2.0")
    assert discovered.pending == ("package-update",)
    assert discovered.pending_package_version == "0.3.0"
    assert cached_pending_recommendations(root=tmp_path)[0].release_version == "0.3.0"


@pytest.mark.anyio
@pytest.mark.parametrize("decision", ["accepted", "declined"])
async def test_package_decision_only_suppresses_advertised_release(
    tmp_path: Path, decision: str
) -> None:
    context = RecommendationContext(package_update=_newer())
    await refresh_pending(context=context, root=tmp_path, version="0.1.0")
    if decision == "declined":
        decline_cached_recommendation("package-update", root=tmp_path, release_version="0.2.0")
    else:
        record_recommendation_decision(
            "package-update", "accepted", root=tmp_path, release_version="0.2.0"
        )
    assert not (await refresh_pending(context=context, root=tmp_path, version="0.1.0")).pending
    later = RecommendationContext(
        package_update=build_package_update_advisory(
            installed_version="0.1.0", latest_version="0.3.0", source="cache"
        )
    )
    assert (await refresh_pending(context=later, root=tmp_path, version="0.1.0")).pending == (
        "package-update",
    )
    with pytest.raises(ValueError, match="recommendation_release_changed"):
        decline_cached_recommendation("package-update", root=tmp_path, release_version="0.2.0")
    assert load_recommendation_state(root=tmp_path).pending_package_version == "0.3.0"


@pytest.mark.anyio
@pytest.mark.parametrize("schema", ["yoetz.recommendations/1", "yoetz.recommendations/2"])
async def test_legacy_permanent_package_opt_out_is_preserved(tmp_path: Path, schema: str) -> None:
    decision: dict[str, object] = {
        "decision": "declined",
        "decided_at": "2026-08-12T09:30:00Z",
        "version": "0.1.0",
    }
    document: dict[str, object] = {
        "schema": schema,
        "last_evaluated_version": "0.1.0",
        "decisions": {"package-update": decision},
        "pending": [],
    }
    if schema.endswith("/2"):
        document["pending_targets"] = {}
        decision.update(recommendation_id="package-update", target=None)
    path = tmp_path / "recommendations.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    result = await refresh_pending(
        context=RecommendationContext(package_update=_newer()), root=tmp_path, version="0.2.0"
    )
    assert not result.pending
    assert json.loads(path.read_text())["schema"] == "yoetz.recommendations/3"


@pytest.mark.anyio
@pytest.mark.parametrize("older_latest", ["0.1.0", "0.2.0"])
@pytest.mark.parametrize("decision", ["pending", "accepted", "declined"])
async def test_slow_older_refresh_cannot_regress_newer_release(
    tmp_path: Path, older_latest: str, decision: str
) -> None:
    import asyncio

    resolving = asyncio.Event()
    release = asyncio.Event()

    def context(latest: str) -> RecommendationContext:
        return RecommendationContext(
            package_update=build_package_update_advisory(
                installed_version="0.1.0", latest_version=latest, source="cache"
            )
        )

    async def slow_context() -> RecommendationContext:
        resolving.set()
        await release.wait()
        return context(older_latest)

    slow = asyncio.create_task(
        refresh_pending(context_factory=slow_context, root=tmp_path, version="0.1.0", force=True)
    )
    try:
        await asyncio.wait_for(resolving.wait(), timeout=1)
        await refresh_pending(context=context("0.3.0"), root=tmp_path, version="0.1.0")
        if decision == "accepted":
            record_recommendation_decision(
                "package-update", "accepted", root=tmp_path, release_version="0.3.0"
            )
        elif decision == "declined":
            decline_cached_recommendation("package-update", root=tmp_path, release_version="0.3.0")
        release.set()
        result = await asyncio.wait_for(slow, timeout=1)
        if decision == "pending":
            assert result.pending_package_version == "0.3.0"
            assert result.pending == ("package-update",)
        else:
            assert result.pending == ()
            assert result.decisions["package-update"].release_version == "0.3.0"
    finally:
        release.set()
        if not slow.done():
            slow.cancel()
        await asyncio.gather(slow, return_exceptions=True)
