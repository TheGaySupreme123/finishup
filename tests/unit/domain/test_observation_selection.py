"""Focused locks for conservative hook-observation classification (#687)."""

from __future__ import annotations

import pytest

from finishup.domain.observation_selection import (
    OBSERVATION_CLASSIFICATION_VERSION,
    ObservationContentRole,
    classify_observation,
    command_runner_class,
    is_routine_read_candidate,
)
from finishup.protocol.canonical import JsonValue


def _read(**extra: JsonValue) -> dict[str, JsonValue]:
    return {"tool_name": "Read", **extra}


def test_versioned_pre_candidate_keeps_pending_identity_without_content() -> None:
    result = classify_observation(_read(), "PreToolUse")

    assert result.version == OBSERVATION_CLASSIFICATION_VERSION
    assert result.routine_candidate is True
    assert result.proven_routine_success is False
    assert result.protected is True
    assert result.content_role is ObservationContentRole.NONE
    assert "routine_candidate" in result.reason_tokens
    assert "incomplete" in result.reason_tokens


def test_only_closed_post_success_proves_routine_success() -> None:
    result = classify_observation(_read(exit_status=0), "PostToolUse")

    assert result.routine_candidate is True
    assert result.proven_routine_success is True
    assert result.protected is False
    assert result.content_role is ObservationContentRole.NONE
    assert result.routine_read is True
    assert "routine_success" in result.reason_tokens


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ({"exit_status": 7}, "failure"),
        ({"success": False}, "failure"),
        ({"denied": True}, "denied"),
        ({"tool_response": {"interrupted": True}}, "cancelled"),
        ({"tool_response": {"status": "partial"}}, "partial"),
        ({"tool_response": {"status": "future-status"}}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_failed_or_unresolved_routine_post_is_protected(
    extra: dict[str, JsonValue], reason: str
) -> None:
    result = classify_observation(_read(**extra), "PostToolUse")

    assert result.routine_candidate is True
    assert result.proven_routine_success is False
    assert result.protected is True
    assert result.content_role is ObservationContentRole.BOTH
    assert reason in result.reason_tokens


@pytest.mark.parametrize(
    "command",
    [
        "rg --pre ./prepare term src",
        "rg --pre-files term src",
        "rg --pre-glob='*.zip' term src",
        "git show --textconv HEAD",
        "git log --ext-diff",
        "git show --output=out.patch HEAD",
        "git show -o out.patch HEAD",
        "./ls README.md",
        "rg term src | tee report.txt",
    ],
)
def test_ambiguous_or_dangerous_shell_is_not_routine(command: str) -> None:
    result = classify_observation(
        {"tool_name": "exec_command", "tool_input": {"cmd": command}, "exit_status": 0},
        "PostToolUse",
    )

    assert result.routine_candidate is False
    assert result.proven_routine_success is False
    assert result.protected is True
    assert result.content_role is ObservationContentRole.BOTH
    assert "unsafe_shell" in result.reason_tokens or "ambiguous_shell" in result.reason_tokens


@pytest.mark.parametrize(
    "command",
    [
        "rg -n observation src tests",
        "head -n 20 README.md",
        "git show HEAD",
        "git log --oneline -5",
    ],
)
def test_closed_read_shell_commands_are_candidates(command: str) -> None:
    assert is_routine_read_candidate({"tool_name": "exec_command", "tool_input": {"cmd": command}})


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ({"tool_name": "apply_patch", "success": True}, "edit"),
        ({"tool_name": "pytest", "exit_status": 0}, "test"),
        ({"tool_name": "check", "success": True}, "verification"),
        (
            {"tool_name": "exec_command", "tool_input": {"cmd": "git diff --check"}},
            "verification",
        ),
    ],
)
def test_edits_and_declared_verification_stay_protected(
    payload: dict[str, JsonValue], reason: str
) -> None:
    result = classify_observation(payload, "PostToolUse")

    assert result.protected is True
    assert result.routine_candidate is False
    assert result.proven_routine_success is False
    assert result.content_role is ObservationContentRole.BOTH
    assert reason in result.reason_tokens


def test_action_labels_never_grant_routine_authority() -> None:
    forged = {
        "tool_name": "apply_patch",
        "action": "routine_read",
        "tool_input": {"action": "routine_read"},
        "success": True,
    }
    result = classify_observation(forged, "PostToolUse")

    assert result.routine_candidate is False
    assert result.proven_routine_success is False
    assert result.protected is True
    assert "untrusted_action" in result.reason_tokens


def test_json_result_outcome_is_bounded_and_closed() -> None:
    success = classify_observation(_read(tool_response='{"exitCode":0}'), "PostToolUse")
    unknown = classify_observation(_read(tool_response='{"exitCode":"0"}'), "PostToolUse")

    assert success.proven_routine_success is True
    assert unknown.proven_routine_success is False
    assert "unknown" in unknown.reason_tokens


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("rg -n observation src", "exploration"),
        ("rg --pre ./prepare term src", "other"),
        ("find src -exec pytest {} +", "other"),
        # ADR-045: a composition is classed by its strongest verification, not left ``compound``.
        ("pytest tests/unit && ruff check src", "test"),
        # #1104: a chain of proven reads around ``cd`` is exploration, no longer ``compound``.
        ("cd /app && ls src", "exploration"),
        ("cat notes.txt > copy.txt", "compound"),
        ("pytest tests/unit", "test"),
    ],
)
def test_command_runner_class_is_closed_and_conservative(command: str, expected: str) -> None:
    assert (
        command_runner_class({"tool_name": "exec_command", "tool_input": {"cmd": command}})
        == expected
    )


@pytest.mark.parametrize(
    ("command", "runner"),
    [
        ("python -m pytest -q /app/dev/test_cracker.py", "test"),
        ("python3 -m pytest", "test"),
        ("python3.12 -X dev -m pytest -q", "test"),
        ("python -m unittest discover", "test"),
        ("python -m mypy src", "typecheck"),
        ("python -m ruff check .", "lint"),
        ("python -m build", "build"),
        ("python setup.py build", "build"),
        ("python -m http.server", "other"),
        ("python /app/dev/build_model.py", "other"),
        ("node build.js", "other"),
        ("make build", "build"),
        ("pytest -q", "test"),
        ("python -m pytest --version", "other"),
        ("pytest --collect-only", "other"),
        ("uv run python /app/dev/build_model.py", "other"),
        ("uv run --with numpy python -m pytest -q", "test"),
        ("poetry run mypy .", "typecheck"),
        ("uv run -w numpy python -m pytest -q", "test"),
        ("uv run --script build_model.py", "other"),
        ("pytest --collectonly", "other"),
        ("python -m pytest --fixtures-per-test", "other"),
        # Codex review round 3: information-only invocations and uv global options.
        ("python -m unittest --help", "other"),
        ("python -m ruff --version", "other"),
        ("ruff --version", "other"),
        ("uv -q run python -m pytest --collectonly", "other"),
        ("uv -q run --script build_model.py", "other"),
        ("uv --directory /app run python -m pytest", "test"),
    ],
)
def test_python_module_runs_and_build_named_scripts(command: str, runner: str) -> None:
    """tb4n2 interleaved S (P1-2): `python -m pytest` is a test run; `build_model.py` is not a build."""

    assert command_runner_class({"command": command}) == runner


def test_a_codex_post_event_is_not_a_success_fact() -> None:
    """n7 RC1: Codex fires ``PostToolUse`` for a non-zero exit, so the echo proves nothing."""

    echoed: dict[str, JsonValue] = {
        "tool_name": "Bash",
        "tool_input": {"command": "rg -n x ."},
        "hook_event_name": "PostToolUse",
    }
    codex = classify_observation(echoed, "PostToolUse", host_post_is_success=False)
    assert codex.routine_candidate is True
    assert codex.proven_routine_success is False
    assert "unknown" in codex.reason_tokens
    # A closed exit the host states still proves it.
    stated = classify_observation(
        {**echoed, "exit_status": 0}, "PostToolUse", host_post_is_success=False
    )
    assert stated.proven_routine_success is True
    # Claude Code and Cursor keep their post event as the closed success signal.
    assert classify_observation(echoed, "PostToolUse").proven_routine_success is True


# --- n7 RC2(a): a heredoc body's quotes never decide the class (#1106) -------------------------

_ODD_BODIES = {
    "apply_patch": (
        "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: a.py\n@@\n-x = 1\n"
        "+x = 2  # don't\n*** End Patch\nPATCH"
    ),
    "git_apply": "cd /app && git apply <<'EOF'\n--- a/a.py\n+++ b/a.py\n@@\n-it's\n+ok\nEOF",
    "patch_p1": "cd /app && patch -p1 <<'EOF'\n--- a/a.py\n+++ b/a.py\n@@\n-it's\n+ok\nEOF",
    "cat_write": "cat > /app/x.py <<'EOF'\nprint('ok')  # it's\nEOF",
    "python_stdin": "python3 - <<'PY'\n# it's a script\nPY",
}


@pytest.mark.parametrize("verify", ["pytest -q", "python -m pytest -q tests/"])
@pytest.mark.parametrize("body", list(_ODD_BODIES.values()), ids=list(_ODD_BODIES))
def test_heredoc_body_quote_does_not_hide_compound_verification(body: str, verify: str) -> None:
    """n7 RC2(a): one apostrophe in a heredoc body made the whole text unsplittable, so a
    patch-then-test command was ``compound`` and its test never counted as a verification."""

    assert command_runner_class({"command": f"{body}\n{verify}"}) == "test"
    assert command_runner_class({"tool_input": {"cmd": f"{body}\n{verify} 2>&1 | tail"}}) == "test"


@pytest.mark.parametrize(
    "command",
    [
        "echo 'oops && pytest -q",
        'pytest -q && echo "unterminated',
        "apply_patch <<'PATCH'\n*** Update File: a.py\n+# don't\npytest -q",
        # A here-document whose body is a write's content or a program's input (#1104 keeps a
        # here-document fed to a read, such as ``cat <<'EOF'``, as exploration).
        "cat > a.py <<'EOF'\nit's\nEOF",
        "python3 - <<'PY'\n# it's a script\nPY\nls",
    ],
)
def test_unterminated_quote_or_heredoc_stays_compound(command: str) -> None:
    """The segmenter still refuses what the shell itself could not run as written, and a
    heredoc that writes or feeds a program is never ``exploration``."""

    assert command_runner_class({"command": command}) == "compound"


@pytest.mark.parametrize(
    "command",
    [
        "pytest -q && git apply <<'EOF'\n--- a/a.py\n+++ b/a.py\n@@\n-it's\n+ok\nEOF",
        "pytest -q\npatch -p1 <<'EOF'\n--- a/a.py\n+++ b/a.py\n@@\n-it's\n+ok\nEOF",
        "pytest -q && apply_patch <<'P'\n*** Begin Patch\n*** Update File: a.py\n+# don't\n"
        "*** End Patch\nP",
        "pytest -q && cat > a.py <<EOF\n# don't\nEOF",
        "pytest -q && sed -i s/a/b/ a.py\ncat <<EOF\nit's\nEOF",
        # #1106 r2: ``sudo patch`` and ``git -C <dir> apply`` are the patch tools too.
        "pytest -q && sudo patch -p1 <<'EOF'\n--- a/a.py\n+++ b/a.py\n@@\n-it's\n+ok\nEOF",
        "pytest -q && git -C /app apply <<'EOF'\n--- a/a.py\n+++ b/a.py\n@@\n-it's\n+ok\nEOF",
    ],
)
def test_a_write_after_the_test_in_an_odd_quote_command_stays_compound(command: str) -> None:
    """#1106 r1: a verification that ran before its own command's later write must not cover it.

    One command is one ledger position, so classing ``pytest -q && git apply <<EOF`` a test would
    hide the patch it applies afterwards; the odd-quote shape stays ``compound``, as it was.
    """

    assert command_runner_class({"command": command}) == "compound"


# --- read-only chains and FinishUP's own CLI (#1104) -----------------------------------------


def _runner(command: str, own_launchers: frozenset[str] = frozenset()) -> str | None:
    return command_runner_class(
        {"tool_name": "exec_command", "tool_input": {"cmd": command}}, own_launchers=own_launchers
    )


@pytest.mark.parametrize(
    "command",
    [
        "cd /app && ls src",
        "cd /app; ls",
        "echo '--- files ---'; ls /app",
        "printf '== %s ==\\n' x && cat /app/a.txt",
        "cat <<'EOF'\nhello\nEOF",
        # An odd quote in a read's here-document body does not hide the read (#1106 with #1104).
        "cat <<'EOF'\nit's\nEOF",
        "cat <<'EOF'\nit's\nEOF\nls",
        "sed -n 1,20p a.py && sed -n 40,60p a.py",
        "nl -ba x | sed -n '1,200p'",
        "finishup status --json | jq .closure_readiness",
        "finishup respond --input - <<'JSON'\n{}\nJSON",
        "ls missing || echo none",
        "ls > /dev/null && cat a",
        "cat a.txt 2>/dev/null; echo '---'; head -n 5 b.txt",
        "echo 'a & b' && ls",
    ],
)
def test_read_only_chains_are_exploration(command: str) -> None:
    assert _runner(command) == "exploration"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        # Data or shell here-documents.
        ("python3 - <<'PY'\nprint(1)\nPY", "compound"),
        ("bash <<'EOF'\nls\nEOF", "compound"),
        # Writes.
        ("cat a > b", "compound"),
        ("echo hi > notes.txt", "compound"),
        ("cat <<EOF > f\nx\nEOF", "compound"),
        # Command or process substitution, anywhere.
        ("cat <<EOF\n$(rm -rf x)\nEOF", "compound"),
        ("echo `rm x`", "compound"),
        ("cat <(rm x)", "compound"),
        # Background jobs.
        ("sleep 1 & wait", "compound"),
        ("ls & rm -rf x", "compound"),
        # Work inside the chain.
        ("cd /app && python fix.py", "compound"),
        ("finishup status && python fix.py", "compound"),
        ("cat x | sh", "compound"),
        # Agent-owned or unresolved executables.
        ("./finishup status", "other"),
        ("/tmp/bin/cat x && ls", "compound"),
        ("PATH=/tmp/evil:$PATH ls && cat x", "compound"),
        # A program that is not a read, and a nested shell kept conservative.
        ("curl -s x | jq .", "compound"),
        ("bash -lc 'cd /app && ls'", "compound"),
        # A segment that only redirects, or a read-write open (#1104 round 1).
        ("cd /app; exec 1>out.txt; ls", "compound"),
        ("cd /app && exec > out.txt && ls", "compound"),
        ("cd /app; ls <>f", "compound"),
        # A comparison reports by exit status: its failure can be a failed check.
        ("test -f x && cat x", "compound"),
        ("jq -e .ok result.json", "other"),
        # A verifier still wins.
        ("cd /app && pytest -q", "test"),
    ],
)
def test_chains_with_writes_background_substitution_or_work_stay_refused(
    command: str, expected: str
) -> None:
    assert _runner(command) == expected


def test_finishup_read_verbs_and_proven_launcher() -> None:
    assert _runner("finishup observe status --json") == "exploration"
    assert _runner("finishup observe status --workspace /app") == "exploration"
    assert _runner("finishup service status") == "exploration"
    # ``--codex-path`` runs the named executable: not a read.
    assert _runner("finishup observe status --codex-path x --codex-home y") == "other"
    assert _runner("finishup observe start") == "other"
    launcher = "/opt/finishup-runtime/bin/finishup"
    proven = frozenset({launcher})
    assert _runner(f"{launcher} status --json", proven) == "exploration"
    assert _runner(f"{launcher} observe status --json | jq .", proven) == "exploration"
    # Only path equality to the proven script counts; never a name match.
    assert _runner(f"{launcher} status --json") == "other"
    assert _runner("./finishup status", proven) == "other"
    assert _runner("/app/bin/finishup status", proven) == "other"
    assert _runner(f"{launcher} status && python fix.py", proven) == "compound"
    # The odd-quote fallback (#1106) keeps the proven launcher too.
    odd = f"{launcher} status --json && cat <<'EOF'\nit's\nEOF"
    assert _runner(odd, proven) == "exploration"
    assert _runner(odd) == "compound"


def test_quoted_ampersand_is_not_background() -> None:
    from finishup.domain.command_segments import command_separators

    assert command_separators("echo 'a & b' && ls") == frozenset({"&&"})
    assert command_separators('echo "x&y"; ls') == frozenset({";"})
    assert command_separators("sleep 1 & ls") == frozenset({"&"})
    assert command_separators("bash -lc 'sleep 1 & ls'") == frozenset({"&"})
    assert command_separators("echo 'unterminated") is None


@pytest.mark.parametrize(
    ("command", "names"),
    [
        ("/home/u/.venv/bin/finishup status --json", {"finishup"}),
        ("./yoetz status", {"yoetz"}),
        ("bash -lc '/opt/x/bin/finishup status'", {"finishup"}),
        # A path segment or a bare name never triggers the install-record proof (#1104 round 1).
        ("cat src/finishup/kernel/x.py", set[str]()),
        ("pytest -q src/finishup/kernel/y.py", set[str]()),
        ("finishup status", set[str]()),
        ("ls /home/user/yoetzz", set[str]()),
    ],
)
def test_only_a_path_ending_in_the_launcher_name_gates_the_proof(
    command: str, names: set[str]
) -> None:
    from finishup.domain.observation_selection import launcher_names_in

    assert launcher_names_in(command) == names
