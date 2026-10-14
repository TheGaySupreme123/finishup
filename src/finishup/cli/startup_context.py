"""Static host startup guidance, independent of observation and the service."""

from __future__ import annotations

from importlib import resources
from typing import BinaryIO, Literal

from finishup.cli.hook_io import claude_context_output, cursor_context_output, stdout_json


def handle_startup_context(
    *, host: Literal["claude", "cursor"], stdout: BinaryIO | None = None
) -> int:
    """Emit a cue without reading stdin, host identity, settings, vault, or ledger.

    This is a separate SessionStart command so observation consent, contention,
    or a failed observation process cannot suppress the cooperative workflow cue.
    It makes no activation or readiness assertion and never returns a decision.
    """

    if host not in {"claude", "cursor"}:
        raise ValueError("startup_context_host_invalid")
    # The shared guidance owns the materiality trigger. Read only a bounded
    # packaged prefix; the rest of the workflow remains an on-demand MCP read.
    try:
        node = resources.files("finishup.resources").joinpath("guidance/agent-instructions.md")
        with node.open("rb") as stream:
            prefix = stream.read(1_024).decode("utf-8", errors="ignore")
        cue = prefix.split("\n\n", 2)[1].strip()
        if "finishup://guidance/workflow.md" not in cue:
            raise ValueError("startup_context_guidance_incomplete")
    except OSError, UnicodeError, IndexError, ValueError:
        cue = (
            "For material work, read finishup://guidance/workflow.md with read_guidance, "
            "then follow its current startup and recovery procedure before substantive work. "
            "Skip trivial questions or edits."
        )
    context = (
        cue + " Load deferred FinishUP tool schemas when needed. A hook mapping is not an accepted "
        "current-scope plan. In a new session, use a mapped session_id from the session context "
        "for start mode=attach; otherwise follow the workflow's task identity rules. After "
        "resume or compaction of already-started work, use held current session/writer ids for "
        "status instead of creating a sibling. Before substantive work, publish the current "
        "plan with its effective obligations. This cue does not activate FinishUP or grant "
        "observation, credentials, permissions, or semantic disclosure."
    )
    output = (
        claude_context_output("SessionStart", context)
        if host == "claude"
        else cursor_context_output("sessionStart", context)
    )
    stdout_json(output, stdout)
    return 0
