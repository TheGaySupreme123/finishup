from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.cursor_integration import (
    CursorPluginTarget,
    apply_cursor_plugin,
    preview_cursor_plugin,
    render_cursor_plugin,
    status_cursor_plugin,
)
from finishup.adapters.integrations.cursor_mcp_runtime import (
    CursorMcpProcessSnapshot,
    FixedCursorMcpProcesses,
    classify_cursor_semantic_ceiling,
    classify_serve_suffix,
    observe_cursor_mcp_runtime,
)
from finishup.domain.values import request_id
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    PluginArtifactAction,
    PluginFormatProfile,
    PluginProofFacet,
)
from finishup.protocol.canonical import canonical_encode
from finishup.version import read_verified_resource

_REQUEST = request_id("req_10000000-0000-4000-8000-000000000021")
_REVIEW_ID = "a" * 64


class _AcceptingReview:
    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        return None

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        return None


def test_serve_suffix_classifies_exact_policy_and_strict_argv() -> None:
    assert classify_serve_suffix(("/opt/finishup/bin/finishup", "mcp", "serve")) == "policy"
    assert classify_serve_suffix(("finishup", "mcp", "serve", "--host", "cursor")) == "policy"
    assert (
        classify_serve_suffix(
            (
                "finishup",
                "mcp",
                "serve",
                "--host",
                "cursor",
                "--project-root",
                "/srv/projects/example",
            )
        )
        == "policy"
    )
    assert classify_serve_suffix(("finishup", "mcp", "serve", "--semantic", "off")) == "strict"
    assert (
        classify_serve_suffix(("finishup", "mcp", "serve", "--host", "cursor", "--semantic", "off"))
        == "strict"
    )
    assert (
        classify_serve_suffix(
            (
                "finishup",
                "mcp",
                "serve",
                "--host",
                "cursor",
                "--project-root",
                "/srv/projects/example",
                "--semantic",
                "off",
            )
        )
        == "strict"
    )
    assert (
        classify_serve_suffix(
            ("finishup", "mcp", "serve", "--host", "cursor", "--project-root", "relative")
        )
        == "foreign"
    )
    assert (
        classify_serve_suffix(
            ("finishup", "mcp", "serve", "--host", "cursor", "--project-root", "/")
        )
        == "foreign"
    )
    assert (
        classify_serve_suffix(
            ("finishup", "mcp", "serve", "--host", "cursor", "--project-root", "/srv/../project")
        )
        == "foreign"
    )
    assert classify_serve_suffix(("/secret/finishup", "mcp", "serve", "--extra")) == "foreign"
    assert classify_serve_suffix(("/secret/not-finishup", "mcp", "serve")) is None
    assert classify_serve_suffix(("python", "worker.py", "mcp", "serve")) is None
    assert classify_serve_suffix(("unrelated",)) is None


def test_cursor_helper_comm_accepts_macos_paths_without_retaining_them() -> None:
    import finishup.adapters.integrations.cursor_mcp_runtime as module

    assert module._cursor_helper_comm(  # pyright: ignore[reportPrivateUsage]
        "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin)"
    )
    assert module._cursor_helper_comm("cursor")  # pyright: ignore[reportPrivateUsage]
    assert not module._cursor_helper_comm(  # pyright: ignore[reportPrivateUsage]
        "/Applications/Other.app/Contents/MacOS/Other"
    )


def test_installed_policy_plus_live_strict_helper_requires_full_restart() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (
                CursorMcpProcessSnapshot("cursor_helper", "strict"),
                CursorMcpProcessSnapshot("cursor_helper", "policy"),
            )
        ),
    )
    assert runtime.activation == "full_restart_required"
    assert runtime.live_route_profile is None
    assert runtime.strict_process_count == 1
    assert runtime.policy_process_count == 1
    assert (
        classify_cursor_semantic_ceiling(
            semantic_status="blocked_by_policy",
            semantic_reason="route_semantic_ceiling",
            installed_route="policy",
            runtime=runtime,
        )
        == "activation_mismatch"
    )


def test_installed_and_live_strict_is_a_genuine_ceiling() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="strict",
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("cursor_helper", "strict"),)),
    )
    assert runtime.activation == "matched"
    assert runtime.live_route_profile == "strict"
    assert (
        classify_cursor_semantic_ceiling(
            semantic_status="blocked_by_policy",
            semantic_reason="route_semantic_ceiling",
            installed_route="strict",
            runtime=runtime,
        )
        == "genuine_route_ceiling"
    )


def test_non_helper_processes_do_not_prove_cursor_activation() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("other", "strict"),)),
    )
    assert runtime.activation == "unobserved"
    assert runtime.strict_process_count == 1
    assert runtime.live_route_profile is None


def test_truncated_process_inventory_never_reports_a_route_match() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            tuple(CursorMcpProcessSnapshot("cursor_helper", "policy") for _ in range(65))
        ),
    )

    assert runtime.observed is True
    assert runtime.activation == "unobserved"
    assert runtime.live_route_profile is None


def test_status_binds_installed_policy_to_stale_strict_runtime(tmp_path: Path) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
    )
    preview = preview_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
    )
    apply_cursor_plugin(
        preview.request_id,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=ArtifactAuthority("review_only", preview.preview_digest, _REVIEW_ID),
        review=_AcceptingReview(),
    )
    status = status_cursor_plugin(
        target,
        artifact,
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("cursor_helper", "strict"),)),
    )
    assert status.mcp_observation.route_profile == "policy"
    assert status.mcp_observation.ownership_state.value == "plugin"
    assert status.runtime.activation == "full_restart_required"
    assert status.runtime.live_route_profile == "strict"
    proof = {item.facet: item.status for item in status.proof}
    assert proof[PluginProofFacet.INSTALLED_BYTES] == "proven"
    assert proof[PluginProofFacet.HOST_ACTIVATION] == "not_observed"
    encoded = canonical_encode(
        {
            "activation": status.runtime.activation,
            "route": status.mcp_observation.route_profile,
        }
    )
    assert b"full_restart_required" in encoded
    assert b"/secret/" not in encoded
    assert "reload_window_does_not_replace_mcp_runtime" in preview.warnings


def test_runtime_status_never_echoes_foreign_argv() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("cursor_helper", None),)),
    )
    payload = json.dumps(
        {
            "activation": runtime.activation,
            "foreign_process_count": runtime.foreign_process_count,
            "live_route_profile": runtime.live_route_profile,
        }
    )
    assert runtime.foreign_process_count == 1
    assert runtime.activation == "full_restart_required"
    assert "secret" not in payload
    assert runtime.live_route_profile is None


def test_dogfood_fixture_names_the_activation_mismatch_case() -> None:
    fixture = json.loads(
        read_verified_resource("fixtures/agent-plugins/cursor-stale-shared-mcp-runtime.case.json")
    )
    runtime = observe_cursor_mcp_runtime(
        installed_route=fixture["installed_route_profile"],
        processes=FixedCursorMcpProcesses(
            (CursorMcpProcessSnapshot("cursor_helper", fixture["live_runtime_route_profile"]),)
        ),
    )
    assert runtime.activation == fixture["expected_activation"]
    assert (
        classify_cursor_semantic_ceiling(
            semantic_status="blocked_by_policy",
            semantic_reason="route_semantic_ceiling",
            installed_route=fixture["installed_route_profile"],
            runtime=runtime,
        )
        == fixture["expected_ceiling_class"]
    )


def test_serve_argv_compares_the_tokens_before_serve_with_the_bound_launcher() -> None:
    """Issue #468: a live helper child must be attributable to the exact bound executable."""

    from finishup.adapters.integrations.cursor_mcp_runtime import classify_serve_argv

    console = ("/opt/current/bin/finishup",)
    module = ("/opt/current/bin/python3.14", "-m", "finishup")
    serve = ("mcp", "serve", "--host", "cursor")

    assert classify_serve_argv((*console, *serve), console) == ("policy", "matched")
    # A shebang console script shows the interpreter first; the script token still matches.
    assert classify_serve_argv(("/opt/current/bin/python3.14", *console, *serve), console) == (
        "policy",
        "matched",
    )
    assert classify_serve_argv((*module, *serve, "--semantic", "off"), module) == (
        "strict",
        "matched",
    )
    # Another explicit executable answered the spawn: an ambient or neighbouring channel.
    assert classify_serve_argv(("/opt/older/bin/finishup", *serve), console) == (
        "policy",
        "different",
    )
    assert classify_serve_argv(("/usr/bin/python3", "-m", "finishup", *serve), module) == (
        "policy",
        "different",
    )
    # A bare name cannot be attributed either way.
    assert classify_serve_argv(("finishup", *serve), console) == ("policy", "unresolved")
    # Without an expected launcher nothing is compared.
    assert classify_serve_argv((*console, *serve), None) == ("policy", None)
    assert classify_serve_argv(("unrelated",), console) == (None, None)


def test_helper_child_on_a_different_executable_requires_full_restart() -> None:
    installed_policy_other_executable = FixedCursorMcpProcesses(
        (CursorMcpProcessSnapshot("cursor_helper", "policy", "different"),)
    )
    observation = observe_cursor_mcp_runtime(
        installed_route="policy", processes=installed_policy_other_executable
    )
    assert observation.activation == "full_restart_required"
    assert observation.executable_activation == "executable_mismatch"
    assert observation.live_route_profile == "policy"

    matched = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (CursorMcpProcessSnapshot("cursor_helper", "policy", "matched"),)
        ),
    )
    assert matched.activation == "matched"
    assert matched.executable_activation == "matched"

    unresolved = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (CursorMcpProcessSnapshot("cursor_helper", "policy", "unresolved"),)
        ),
    )
    assert unresolved.activation == "matched"
    assert unresolved.executable_activation == "unproven"

    # A non-helper process on another executable is counted but never drives activation.
    bystander = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (
                CursorMcpProcessSnapshot("cursor_helper", "policy", "matched"),
                CursorMcpProcessSnapshot("other", "policy", "different"),
            )
        ),
    )
    assert bystander.activation == "matched"
    assert bystander.executable_activation == "matched"
    assert bystander.policy_process_count == 2


def test_macos_ps_text_matches_a_launcher_path_that_contains_whitespace() -> None:
    """``ps`` joins argv with spaces; a bound path with whitespace must still match exactly."""

    from finishup.adapters.integrations.cursor_mcp_runtime import launcher_precedes_serve_in_text

    spaced = ("/opt/FinishUP Tools/bin/finishup",)
    module = ("/opt/FinishUP Tools/venv/bin/python3.14", "-m", "finishup")

    assert launcher_precedes_serve_in_text(
        "/opt/FinishUP Tools/bin/finishup mcp serve --host cursor", spaced
    )
    # Shebang expansion puts the interpreter first; the script token still sits before serve.
    assert launcher_precedes_serve_in_text(
        "/opt/FinishUP Tools/bin/python3.14 /opt/FinishUP Tools/bin/finishup mcp serve --host cursor",
        spaced,
    )
    assert launcher_precedes_serve_in_text(
        "/opt/FinishUP Tools/venv/bin/python3.14 -m finishup mcp serve", module
    )
    # A longer path that merely ends with the same suffix is another executable.
    assert not launcher_precedes_serve_in_text(
        "/opt/other/opt/FinishUP Tools/bin/finishup mcp serve --host cursor", spaced
    )
    assert not launcher_precedes_serve_in_text("/opt/older/bin/finishup mcp serve", spaced)
    assert not launcher_precedes_serve_in_text("", spaced)

    # The split-token path alone would call the spaced launcher ``different``; the text check
    # is what the macOS scanner consults before reporting an executable mismatch.
    from finishup.adapters.integrations.cursor_mcp_runtime import classify_serve_argv

    text = "/opt/FinishUP Tools/bin/finishup mcp serve --host cursor"
    assert classify_serve_argv(tuple(text.split()), spaced) == ("policy", "different")


def test_darwin_scanner_uses_the_text_match_for_whitespace_launchers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    import finishup.adapters.integrations.cursor_mcp_runtime as module

    spaced = ("/opt/FinishUP Tools/bin/finishup",)
    comm_table = b"10 1 Cursor\n11 10 mcp-process\n12 11 /opt/FinishUP\n"
    arg_table = (
        b"10 1 /Applications/Cursor.app/Contents/MacOS/Cursor\n"
        b"11 10 mcp-process\n"
        b"12 11 /opt/FinishUP Tools/bin/finishup mcp serve --host cursor\n"
    )

    class _Completed:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 0
            self.stdout = stdout

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> _Completed:
        del kwargs
        calls.append(argv)
        return _Completed(comm_table if "comm=" in argv else arg_table)

    monkeypatch.setattr(subprocess, "run", fake_run)
    snapshot = module._darwin_snapshots(spaced)  # pyright: ignore[reportPrivateUsage]
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", "policy", "matched"),)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "launcher",
    ["yoetz", "/opt/yoetz/bin/yoetz", "C:\\tools\\yoetz.exe", "finishup", "/opt/x/finishup.exe"],
)
def test_either_launcher_spelling_is_a_finishup_child(launcher: str) -> None:
    # A helper keeps the ``yoetz mcp serve`` child an older registration spawned (ADR-048).
    assert classify_serve_suffix((launcher, "mcp", "serve", "--host", "cursor")) == "policy"


def test_other_launcher_names_are_not_finishup_children() -> None:
    assert classify_serve_suffix(("/opt/yoetz-tools/bin/yoetzd", "mcp", "serve")) is None
