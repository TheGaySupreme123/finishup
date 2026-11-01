"""The agent install guide names the platform boundary and the no-question-tool rule (issue #709).

Two first-time users hit the same two holes: an agent on Cursor, which has no structured question
tool, asked nothing and chose for them; and an agent on native Windows watched every command fail
as ``internal_error`` before working out that FinishUP is POSIX-only. The guide, the shipped install
page, and the CLI refusal must keep telling the same story.
"""

from __future__ import annotations

import re
from pathlib import Path

from finishup.cli.entry import UNSUPPORTED_PLATFORM_MESSAGE

_ROOT = Path(__file__).resolve().parents[3]


def _text(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def _collapsed(path: str) -> str:
    return " ".join(_text(path).split())


def test_agent_start_checks_the_platform_before_installing() -> None:
    guide = _collapsed("docs/usage/agent-start.md")

    assert "## 0. Check the platform first" in guide
    assert "FinishUP runs on macOS and Linux" in guide
    assert "Native Windows is not supported" in guide
    assert "WSL 2" in guide
    assert "wsl --install" in guide
    assert 'wsl -e bash -lc "<command>"' in guide
    assert "PowerShell as administrator" in guide
    assert "curl -LsSf https://astral.sh/uv/install.sh | sh" in guide
    assert "uv tool update-shell" in guide
    # Section 0 precedes the install section, so the platform is known before anything installs.
    assert guide.index("## 0. Check the platform first") < guide.index("## 1. Install")
    # The WSL host cell is untested, and the guide says so rather than implying support.
    assert "untested and not claimed" in guide


def test_agent_start_tells_an_agent_without_a_question_tool_to_ask_in_chat() -> None:
    guide = _collapsed("docs/usage/agent-start.md")

    assert "### Ask in chat when you have no question tool" in guide
    assert "Cursor's agent among them" in guide
    assert "One decision per message" in guide
    assert "end your turn and wait" in guide
    assert "Never use `finishup setup run --accept` or `--non-interactive`" in guide
    assert "### Hand over the terminal like it is their first" in guide
    assert "which application to open" in guide


def test_install_page_windows_section_matches_the_cli_refusal() -> None:
    page = _text("docs/usage/install-and-first-run.md")

    assert re.search(r"^## Windows$", page, flags=re.MULTILINE)
    collapsed = " ".join(page.split())
    assert "refuses with `unsupported_platform`" in collapsed
    assert "wsl --install" in collapsed
    assert "curl -LsSf https://astral.sh/uv/install.sh | sh" in collapsed
    # Shipped-product voice: no repository tooling or source paths on the usage page.
    assert "src/finishup" not in page
    assert "uv run" not in page

    # The CLI line points at exactly that heading's GitHub anchor.
    assert UNSUPPORTED_PLATFORM_MESSAGE.startswith("unsupported_platform: ")
    assert "docs/usage/install-and-first-run.md#windows" in UNSUPPORTED_PLATFORM_MESSAGE
    assert "WSL 2" in UNSUPPORTED_PLATFORM_MESSAGE

    readme = " ".join(_text("README.md").split())
    assert "docs/usage/install-and-first-run.md#windows" in readme


def test_agent_start_lists_the_questions_in_order_with_recommendations() -> None:
    guide = _collapsed("docs/usage/agent-start.md")

    assert "#### The questions, ready to ask" in guide
    for heading in (
        "1. **Agents.**",
        "2. **Review mode.**",
        "3. **The exact change.**",
        "4. **Secret storage**",
        "5. **AI reviewer**",
        "6. **Privacy policy**",
        "7. **Credential**, only on the API path: never ask for the key in chat",
    ):
        assert heading in guide, heading
    assert "No recommendation and no default" in guide
    # Issue #1119: storage is never asked, and the short procedure precedes the reference.
    assert "4. **Secret storage**: never a question" in guide
    assert guide.index("## The short version") < guide.index("## 0. Check the platform first")
    for line in (
        "uv tool install --managed-python --python 3.14 finishup",
        "finishup setup run --host all --route-profile policy --non-interactive --json",
        "finishup ai setup",
        "finishup setup vault && finishup ai off",
    ):
        assert line in guide, line
    assert "local only is a finished state, not a fallback" in guide

    decisions = guide.split("Guide these decisions in order:", 1)[1].split(
        "2. **Project trust**", 1
    )[0]
    questions = guide.split("#### The questions, ready to ask", 1)[1].split(
        "2. **Review mode.**", 1
    )[0]
    for section in (decisions, questions):
        for choice in ("Codex", "Claude Code", "Cursor", "decline integration"):
            assert choice in section
        assert "With no Codex" not in section


def test_agent_start_host_notes_cover_every_first_party_host_and_the_generic_route() -> None:
    guide = _collapsed("docs/usage/agent-start.md")

    assert "### Host notes" in guide
    for host in (
        "**Codex**",
        "**Claude Code**",
        "**Cursor**",
        "**Any other agent**",
    ):
        assert host in guide, host
    # The Cursor finding that started this: its question tool does not pause the agent.
    assert "it does not pause the agent" in guide
    # Each host's fetch blocker is named, and the guide is fetched as exact bytes on Claude Code.
    assert "the sandbox blocks network by default" in guide
    assert "`WebFetch` returns a small model's summary" in guide
    assert "run in a sandbox with no network" in guide
    # Cursor Cloud stays unsupported, matching the install page.
    assert "Cursor Cloud agents are not supported" in guide


def test_copied_setup_prompt_matches_between_readme_and_landing() -> None:
    # The README prompt is a blockquote; drop the `>` markers before comparing sentences.
    readme = " ".join(token for token in _text("README.md").split() if token != ">")
    landing = _collapsed("landing/src/pages/index.astro")
    for sentence in (
        "If your sandbox blocks that fetch, ask me to approve it or to paste the guide.",
        "ask me each one and wait",
        'follow "The short version" at the top',
        "Never ask me for a key or password in chat",
    ):
        assert sentence in readme, sentence
        assert sentence in landing, sentence


def test_linux_and_wsl_host_facts_are_stated_before_they_bite() -> None:
    """The Linux/WSL parity sweep (#720–#725): dependencies, keyring, state, and cells named."""

    page = _text("docs/usage/install-and-first-run.md")
    assert re.search(r"^## Linux$", page, flags=re.MULTILINE)
    collapsed = " ".join(page.split())
    assert "sudo apt install bubblewrap" in collapsed
    assert "`sandbox_unavailable`" in collapsed
    assert "AppArmor" in collapsed
    assert "Secret Service" in collapsed
    assert "`path_on_network_filesystem`" in collapsed
    assert "/mnt/c" in collapsed
    assert "`platform_cell_untested`" in collapsed
    assert "`human_authority_unavailable`" in collapsed
    assert "src/finishup" not in page and "uv run" not in page

    guide = _collapsed("docs/usage/agent-start.md")
    assert "`path_on_network_filesystem`" in guide
    assert "sudo apt install bubblewrap" in guide
    assert "`platform_cell_untested`" in guide
    # Both plugin hosts say the same thing about Linux and WSL as their runbooks do.
    assert guide.count("`human_authority_unavailable`") >= 2

    for runbook in (
        "docs/runbooks/claude-code-integration.md",
        "docs/runbooks/cursor-integration.md",
    ):
        text = _text(runbook)
        assert re.search(r"^## Linux and WSL$", text, flags=re.MULTILINE), runbook
        assert "human_authority_unavailable" in text, runbook
    facts = _collapsed("docs/runbooks/linux-and-wsl.md")
    assert "keyring.backends.SecretService.Keyring" in facts
    assert "keyring.backends.kwallet.DBusKeyring" in facts
    assert "virtiofs" in facts and "drvfs" in facts and "9p" in facts


def test_sandbox_readiness_is_recorded_as_a_client_surface_fact() -> None:
    """Issue #720's second acceptance branch: the revised contract, not a new status field."""

    facts = _collapsed("docs/runbooks/linux-and-wsl.md")
    assert "`finishup service status` does not report sandbox availability" in facts
    assert "`service-status-1.0.0`" in facts
    for surface in (
        "`finishup observe checks status --json`",
        "`finishup setup status --json`",
        "`/doctor`",
    ):
        assert surface in facts, surface

    interfaces = _collapsed("docs/INTERFACES.md")
    assert "carries no approved-check sandbox field" in interfaces

    page = _collapsed("docs/usage/install-and-first-run.md")
    assert "`finishup service status` reports the local service itself" in page
