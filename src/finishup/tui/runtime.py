"""The only bridge between the FinishUP terminal UI and the application services.

Everything the interface can do passes through this module, and this module does
nothing on its own authority. It discovers harnesses with the existing discovery
adapter, previews and applies integrations with ``HarnessMcpService`` and
``CodexPluginService``, reads readiness with ``provider_status_report``, and
runs the six canonical operations over the ordinary ``ServiceClient``. Secrets
are the sharpest case: this module never reads one. When a credential or
passphrase is required it hands the *real* terminal back to the existing
confidential ceremony in ``finishup.cli.unlock``, which opens ``/dev/tty``, checks
that it is the controlling terminal, and disables echo itself. No secret byte
ever reaches a widget, the transcript, a log line, or a snapshot.

Widgets therefore contain no security-relevant logic. If a rule matters — digest
staleness, foreign MCP entries, privacy widening, vault state — it is enforced
by the owning service and merely transcribed here.
"""

from __future__ import annotations

import shlex
import sys
from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from finishup.legacy_names import LAUNCHER_NAME, LEGACY_LAUNCHER_NAME, MCP_SERVER_NAME
from finishup.tui.models import (
    CheckMode,
    Detection,
    DoctorEntry,
    DoctorReport,
    HarnessOption,
    IntegrationOutcome,
    IntegrationPlan,
    LayerState,
    PrivacyPosture,
    PrivacyRecommendation,
    ProviderOption,
    ProviderPosture,
    ReadinessLayer,
    ReceiptSummary,
    StatusSnapshot,
    TaskStatusPage,
    VaultPosture,
    WorkDetail,
    WorkItem,
)

if TYPE_CHECKING:  # Runtime imports stay lazy; annotations still type-check.
    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.application.harness_mcp import HarnessMcpService
    from finishup.domain.observation_budget import CapacityRequest
    from finishup.domain.observation_settings import ObservationDetailProfile
    from finishup.ports.harness_mcp import HarnessBinary, McpRegistrationPreview
    from finishup.service.confidential_protocol import ProviderCredentialTarget

__all__ = [
    "ObservationCapacityUnavailable",
    "RuntimeError_",
    "FinishUpRuntime",
    "project_detection",
]

_MCP_SERVER_NAME: Final = MCP_SERVER_NAME
# Frozen legacy identifier (ADR-048): the released registration-state wire value for an owned
# MCP registration, whichever key (``finishup`` or the legacy ``yoetz``) holds it.
_OWNED: Final = "yoetz_owned"
_HARNESS: Final = "codex"
# What an entry or install under the pre-rename name means for the owner (ADR-048), keyed by the
# ``legacy_registration`` / ``legacy_installation`` vocabulary; ``none`` says nothing.
_LEGACY_REGISTRATION_TEXT: Final = {
    "legacy_only": "registered under the earlier name yoetz (connecting migrates it)",
    "duplicate": "also registered under the earlier name yoetz (connecting removes it)",
    "foreign": "the earlier name yoetz holds an entry FinishUP cannot prove is its own (kept)",
}
# An owned ``yoetz`` entry a project's Codex configuration still needs stays beside ``finishup``.
_KEPT_LEGACY_REGISTRATION_TEXT: Final = {
    "legacy_only": (
        "registered under the earlier name yoetz (kept beside finishup: a project's Codex "
        "settings still use it)"
    ),
    "duplicate": (
        "also registered under the earlier name yoetz (kept: a project's Codex settings still "
        "use it)"
    ),
}
_UNREAD_LEGACY_REGISTRATION_TEXT: Final = {
    "legacy_only": (
        "registered under the earlier name yoetz (kept: not every project of this Codex home "
        "could be read)"
    ),
    "duplicate": (
        "also registered under the earlier name yoetz (kept: not every project of this Codex "
        "home could be read)"
    ),
}
# A Cursor project registration whose earlier-name entry lives outside the project's own file,
# or beside another source: connect refuses rather than migrating it (ADR-048).
_PROJECT_MCP_REFUSED_STATES: Final = frozenset({"external_source", "multiple_sources"})
_LEGACY_REGISTRATION_REFUSED_TEXT: Final = (
    "the earlier name yoetz is registered where connecting will not edit it; FinishUP leaves it "
    "alone, so migrate or remove that entry yourself first"
)
# Both the FinishUP and the earlier Yoetz check policy exist (``policy_ambiguous``, ADR-048).
_POLICY_AMBIGUOUS_TEXT: Final = (
    "both .finishup/checks.toml and the earlier .yoetz/checks.toml exist; neither is used until "
    "you remove one"
)
_LEGACY_INSTALLATION_TEXT: Final = {
    "legacy_only": "installed under the earlier name yoetz (connecting migrates it)",
    "duplicate": "also installed under the earlier name yoetz (connecting removes it)",
    "foreign": "the earlier name yoetz holds an install FinishUP cannot prove is its own (kept)",
}


def _legacy_kept_plan_lines(
    preview: McpRegistrationPreview,
    *,
    executable: str,
    codex_home: Path,
    project: Path,
    route: str,
) -> tuple[str, ...]:
    """Why an approval keeps the owned ``yoetz`` entry, per project, and every way on (#1073).

    The same words `setup run` shows: the revoke only where it releases the entry, what makes an
    unreadable file readable, and the explicit removal under both names as the owner's choice.
    """

    if not (preview.legacy_kept_for or preview.legacy_kept_unchecked):
        return ()
    from finishup.cli.codex_connection import legacy_kept_disclosure, legacy_way_out
    from finishup.cli.host_connection import legacy_kept_lines

    return legacy_kept_lines(
        legacy_kept_disclosure(
            preview.legacy_kept_for,
            preview.legacy_kept_unread,
            codex_home=codex_home,
            way_out=legacy_way_out(executable, codex_home, project, route),
        )
    )


def _codex_legacy_registration_text(legacy: str) -> str | None:
    """Words for the ambient Codex ``yoetz`` key, matched to what connecting will do.

    Connecting keeps an owned entry while a project's Codex settings still need it (#1073), so
    the words promise the migration only when nothing holds it back.
    """

    if legacy in _KEPT_LEGACY_REGISTRATION_TEXT:
        from finishup.adapters.integrations.codex_mcp import legacy_registration_dependents

        use = legacy_registration_dependents(None)
        if use.needed_by:
            return _KEPT_LEGACY_REGISTRATION_TEXT[legacy]
        if use.keeps:
            # Nothing found to need it; only an incomplete read keeps it (round 3).
            return _UNREAD_LEGACY_REGISTRATION_TEXT[legacy]
    return _LEGACY_REGISTRATION_TEXT.get(legacy)


def _project_legacy_registration_text(project_mcp: Mapping[str, object]) -> str | None:
    """Words for a project MCP status's earlier-name entry, matched to what connect will do.

    An owned ``yoetz`` entry in the project's own file is migrated or removed on connect. When
    the status reads ``external_source`` or ``multiple_sources`` connect refuses instead, so the
    text must not promise a migration.
    """

    legacy = str(project_mcp.get("legacy_registration"))
    if legacy in {"legacy_only", "duplicate"} and (
        project_mcp.get("state") in _PROJECT_MCP_REFUSED_STATES
    ):
        return _LEGACY_REGISTRATION_REFUSED_TEXT
    return _LEGACY_REGISTRATION_TEXT.get(legacy)


def _conversation_review_token(
    policy_map: Mapping[str, object], llm_enabled: bool | None
) -> str | None:
    """The conversation setting a composed policy means (ADR-049).

    An explicit token is the owner's; a policy written before the field existed keeps the
    released reading: AI-powered review in every task where its inference channel is on, and
    local checks only where it is off.
    """

    explicit = policy_map.get("conversation_review")
    if explicit in {"local_only", "local_owner_approval", "local_agent_opt_in", "ai_powered"}:
        return cast(str, explicit)
    if explicit is not None or llm_enabled is None:
        return None
    return "ai_powered" if llm_enabled else "local_only"


def _agent_route_detail(provider: ProviderPosture) -> str:
    """Explain the agent-route verdict without restating installation readiness."""

    if provider.agent_route_semantic_ready is None:
        return "the Codex registration could not be read"
    if provider.agent_route_semantic_ready:
        return ""
    if provider.registered_route_profile == "strict":
        strict = (
            "registered on the strict route; 'finishup integrate codex mcp preview' to change it"
        )
        # The live route disagrees with what the last install applied (issue #537). That
        # disagreement is all this line claims; the owner decides whether it was intended.
        if provider.route_drift_since_install:
            return (
                f"{strict}; applied route differs since install — re-run the previewed "
                "policy install, then start a fresh Codex process"
            )
        return strict
    return "external review is off for this installation"


def _host_admission_layer_state(provider: ProviderPosture) -> LayerState:
    """Verified when at least one host admits and no host reads as drifted or unreadable."""

    states = {state for _host, state in provider.host_admission}
    if not states or "unknown" in states:
        return LayerState.UNKNOWN
    drifted = any(condition == "host_admission_drift" for condition, _state in provider.blockers)
    if drifted:
        return LayerState.NOT_CONFIGURED
    if "present" in states:
        return LayerState.VERIFIED
    return LayerState.NOT_CONFIGURED


def _host_admission_detail(provider: ProviderPosture) -> str:
    if not provider.host_admission:
        return "host admission could not be read"
    summary = ", ".join(f"{host} {state}" for host, state in provider.host_admission)
    drifted = any(condition == "host_admission_drift" for condition, _state in provider.blockers)
    if drifted:
        return f"{summary}; an admission outlives its grant or route, revoke it"
    if all(state == "absent" for _host, state in provider.host_admission):
        return f"{summary}; 'finishup integrate <host> admission preview' to admit the check"
    return summary


def _background_advice_detail(provider: ProviderPosture) -> str:
    from finishup.cli.provider_status import background_advice_human_line

    line = background_advice_human_line({"reason": provider.background_advice_reason})
    return "the configured setting could not be read" if line is None else line


def _review_recipe_outdated(policy_map: Mapping[str, object]) -> bool:
    """Whether the approved review selection is an earlier version of its named recipe.

    Such a policy stays valid and keeps its limits; the TUI only says a newer recipe exists and
    that approving it goes through the trusted terminal (issue #907). Anything unreadable, and
    Custom, reads as not outdated.
    """

    from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy

    raw_profile = policy_map.get("review_context_profile")
    selection = _mapping(policy_map.get("review_selection"))
    if not isinstance(raw_profile, str) or not selection:
        return False
    try:
        profile = ReviewContextProfile(raw_profile)
    except ValueError:
        return False
    if profile is ReviewContextProfile.CUSTOM:
        return False
    current = ReviewSelectionPolicy.for_profile(profile)
    for field in ReviewSelectionPolicy.__dataclass_fields__:
        expected: object = getattr(current, field)
        actual = selection.get(field)
        if isinstance(expected, tuple):
            wanted = sorted(str(item) for item in cast("tuple[object, ...]", expected))
            if not isinstance(actual, (list, tuple)) or (
                sorted(str(item) for item in cast("Sequence[object]", actual)) != wanted
            ):
                return True
        elif actual != expected:
            return True
    return False


def _mapping(value: object) -> Mapping[str, object]:
    """Narrow an untyped service payload to a string-keyed mapping, or nothing.

    Service results cross this boundary as loosely typed JSON-shaped objects.
    Reading them through one helper means a missing or misshapen block degrades
    to "unknown" everywhere rather than raising at whichever call site read it
    first.
    """

    if isinstance(value, Mapping):
        return {str(key): item for key, item in cast(Mapping[object, object], value).items()}
    return {}


def _credential_heuristic_pair(value: object) -> tuple[str, str] | None:
    """The setup read's filter pair (issue #982); ``None`` when absent or malformed."""

    pair = _mapping(value)
    if not pair:
        return None
    allowed = {"enforced", "disabled", "unknown"}
    repository = pair.get("repository")
    machine_default = pair.get("machine_default")
    return (
        repository if type(repository) is str and repository in allowed else "unknown",
        machine_default
        if type(machine_default) is str and machine_default in allowed
        else "unknown",
    )


def _task_statement_posture(policy_map: Mapping[str, object]) -> tuple[bool | None, str | None]:
    """Whether the composed policy sends the task statement, in ``privacy show`` words (#908).

    The same derivation ``finishup privacy show`` applies to the effective policy document, so the
    two surfaces cannot disagree. ``(None, None)`` when the document is not the expected shape:
    the interface says unknown rather than guessing.
    """

    from finishup.domain.task_statement import (
        TASK_STATEMENT_SECTION,
        task_statement_disclosure_text,
    )

    sections = _mapping(policy_map.get("review_selection")).get("sections")
    channels = policy_map.get("channel_policies")
    if not isinstance(sections, (list, tuple)) or not isinstance(channels, (list, tuple)):
        return None, None
    llm = next(
        (
            row
            for row in (_mapping(item) for item in cast("Sequence[object]", channels))
            if row.get("channel") == "llm_inference"
        ),
        None,
    )
    categories = None if llm is None else llm.get("allowed_categories")
    if llm is None or not isinstance(categories, (list, tuple)):
        return None, None
    selected = TASK_STATEMENT_SECTION in cast("Sequence[object]", sections)
    channel_sends = llm.get("enabled") is True and "task_description" in cast(
        "Sequence[object]", categories
    )
    text = task_statement_disclosure_text(
        section_selected=selected,
        channel_sends_task_description=channel_sends,
        # Read from the selection: the wire version also moves for other fields (#982).
        predates_section=not selected
        and policy_map.get("review_context_profile") in {"goal_aware", "assisted", "expanded"},
    )
    return selected and channel_sends, text


async def _shared_route_change(
    service: HarnessMcpService,
    binary: HarnessBinary,
    preview: McpRegistrationPreview,
    route: Literal["policy", "strict"],
    codex_home: Path,
    project: Path,
    *,
    before: Literal["policy", "strict"] | None = None,
) -> tuple[Literal["policy", "strict"] | None, tuple[str, ...], tuple[str, ...]]:
    """The review mode the home's shared registration has now, and who else it changes for.

    The user-level ``[mcp_servers.finishup]`` registration serves every project in the Codex home,
    so rewriting it on another review mode changes those projects' sessions too (#1058 review
    P2-3). Returns ``(before, verified others, possible others)``, or ``(None, (), ())`` when
    the registration is absent, not FinishUP's, already on ``route``, or serves nobody else.
    ``before`` is the mode the caller already derived for the same preview (the plan's own
    ``route_profile_before``, ADR-048); without it the registration is observed.
    """

    from finishup.adapters.integrations.codex_marketplace import other_members
    from finishup.ports.harness_mcp import McpRegistrationState
    from finishup.ports.integrations import IntegrationError

    if preview.state_before is not McpRegistrationState.FINISHUP_OWNED:
        return None, (), ()
    if before is None:
        before = (await service.observe(binary)).route_profile
    if before is None or before == route:
        return None, (), ()
    try:
        others, possible = other_members(codex_home, project)
    except IntegrationError as error:
        # Unknown membership is never "nobody else": stop before the shared mode changes
        # (#1058 review round 3); `setup` names the record and the way out.
        raise RuntimeError_(
            "source_invalid", "the projects using this Codex home could not be read"
        ) from error
    if not others and not possible:
        return None, (), ()
    return before, others, possible


class RuntimeError_(Exception):
    """A bounded operation failure carrying a code the interface may show."""

    def __init__(self, reason: str, message: str, *, details: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.details = tuple(details)


class ObservationCapacityUnavailable(RuntimeError_):
    """A requested capacity the structural queue cannot support; nothing was changed.

    ``lines`` is the owning explanation (the one human wording shared with the command
    line) and ``alternative_command`` the largest supported finite choice.
    """

    def __init__(self, lines: Sequence[str], alternative_command: str) -> None:
        super().__init__(
            "capacity_no_cap_unsupported",
            "No FinishUP cap is not available for this queue",
            details=tuple(lines),
        )
        self.lines = tuple(lines)
        self.alternative_command = alternative_command


# ---------------------------------------------------------------------------
# Detection (pure enough to test without a service)
# ---------------------------------------------------------------------------


def _git_root(start: Path) -> Path | None:
    """Find the repository root by walking up for a ``.git`` entry.

    Deliberately does not shell out to git: discovery must stay bounded and must
    not execute a repository-controlled hook or config on a folder the user has
    not yet said they trust.
    """

    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def project_detection(
    cwd: Path,
    *,
    harnesses: Sequence[HarnessOption] = (),
    secure_storage_available: bool = False,
    secure_storage_reason: str = "",
    already_connected: bool = False,
) -> Detection:
    """Describe the project the user is standing in, without changing anything."""

    resolved = cwd.resolve()
    root = _git_root(resolved)
    project_root = root if root is not None else resolved
    return Detection(
        project_root=str(project_root),
        project_name=project_root.name or None,
        is_git_repository=root is not None,
        launched_from_subdirectory=root is not None and root != resolved,
        harnesses=tuple(harnesses),
        secure_storage_available=secure_storage_available,
        secure_storage_reason=secure_storage_reason if not secure_storage_available else "",
        already_connected=already_connected,
        cwd=str(resolved),
    )


def _harness_option(binary: object, *, index: int, total: int) -> HarnessOption:
    """Label a discovered installation for humans before paths."""

    path = str(getattr(binary, "executable_path", ""))
    version = getattr(binary, "reported_version", None)
    version_text = version if isinstance(version, str) else None
    lowered = path.lower()
    # A bundled application install and a PATH shim are the same binary contract
    # but very different things to a person choosing between them. The tokens are
    # macOS and Windows on purpose: OpenAI publishes no Linux Codex App, so a Linux
    # path is a command-line installation by definition, not a missing case (#722).
    is_app = any(token in lowered for token in (".app/", "/applications/", "program files"))
    label = f"Codex Desktop {version_text}" if is_app else f"Codex CLI {version_text or ''}".strip()
    if version_text is None and is_app:
        label = "Codex Desktop"
    description = "Application installation" if is_app else "Command-line installation"
    recommended = index == 0 and total >= 1
    if recommended:
        description = f"{description} · recommended"
    return HarnessOption(
        executable_path=path,
        reported_version=version_text,
        label=label,
        description=description,
        recommended=recommended,
    )


def _secure_storage_probe() -> tuple[bool, str]:
    """Probe whether the OS credential store can hold the vault root, never storing anything.

    Uses the vault-root allowlist itself, so the interface never offers a store that
    initialization would then refuse, and names the reason when it is unusable (#721).
    """

    try:
        from finishup.adapters.keys.os_keyring import describe_vault_keyring_backend

        report = describe_vault_keyring_backend()
    except Exception:
        return False, "no credential store could be loaded"
    if report.approved:
        return True, ""
    if report.reason == "keyring_unavailable":
        return False, f"no credential store is loaded; FinishUP needs {report.requirement}"
    return (
        False,
        f"the loaded credential store is not approved for the vault ({report.backend_id}); "
        f"FinishUP needs {report.requirement}",
    )


def _host_entries() -> tuple[DoctorEntry, ...]:
    """Host facts that decide what this installation can do, named once (#720, #721, #724)."""

    from finishup.adapters.check_sandbox import probe_check_sandbox
    from finishup.version import platform_cell

    cell = platform_cell()
    if cell.certified:
        platform_entry = DoctorEntry(
            "platform_cell",
            "Platform",
            LayerState.VERIFIED,
            detail=f"{cell.os_name} {cell.machine} ({cell.cell})",
        )
    else:
        platform_entry = DoctorEntry(
            "platform_cell",
            "Platform",
            LayerState.UNPROVEN,
            detail=f"{cell.os_name} {cell.machine} is an untested platform cell",
            remediation=(
                "FinishUP is certified on macOS arm64 and Linux x86-64 (glibc 2.28+); it installed here "
                "but nothing has been proven on this cell, so expect no support claim"
            ),
        )
    sandbox = probe_check_sandbox()
    if sandbox.status.value == "ready":
        sandbox_entry = DoctorEntry(
            "check_sandbox",
            "Approved-check sandbox",
            LayerState.VERIFIED,
            detail=sandbox.mechanism,
        )
    else:
        sandbox_entry = DoctorEntry(
            "check_sandbox",
            "Approved-check sandbox",
            LayerState.NOT_CONFIGURED,
            detail=f"{sandbox.reason}; network-denied checks are rejected until this is fixed",
            remediation=sandbox.remediation,
        )
    available, reason = _secure_storage_probe()
    if available:
        storage_entry = DoctorEntry(
            "secure_storage", "System secure storage", LayerState.VERIFIED, detail="available"
        )
    else:
        storage_entry = DoctorEntry(
            "secure_storage",
            "System secure storage",
            LayerState.NOT_CONFIGURED,
            detail=reason,
            remediation=(
                "use a FinishUP passphrase instead (run /service, or "
                "'finishup service initialize-passphrase'); nothing to do if this installation "
                "already unlocks with one"
            ),
        )
    return (platform_entry, sandbox_entry, storage_entry)


def _path_refusal_entry(reason: str) -> DoctorEntry:
    """The blocked folders entry for a closed path-safety token, with its remedy."""

    from finishup.cli.exits import remediation_message

    return DoctorEntry(
        "installation_folders",
        "Installation folders",
        LayerState.BLOCKED,
        detail=reason,
        remediation=remediation_message(reason) or "",
    )


def _installation_folders_entry() -> DoctorEntry:
    """Which folders hold this installation's data, named so none is mistaken for a leftover.

    An installation first made as Yoetz is used in place (ADR-048); saying so keeps someone from
    deleting the folder that holds the vault after the rename.
    """

    from finishup.cli.exits import UPGRADING_FROM_YOETZ_GUIDE
    from finishup.cli.service_installation import installation_folders
    from finishup.config.paths import PathSafetyError

    label = "Installation folders"
    try:
        folders = installation_folders()
    except PathSafetyError as error:
        return _path_refusal_entry(error.reason_code)
    if folders == "legacy_yoetz":
        return DoctorEntry(
            "installation_folders",
            label,
            LayerState.VERIFIED,
            detail="Yoetz-era folders, used in place",
            remediation=(
                "nothing to do: this install still uses its Yoetz-era folders in place and nothing "
                "was moved. They hold your FinishUP data, so keep them. Read more: "
                + UPGRADING_FROM_YOETZ_GUIDE
            ),
        )
    detail = "isolated root" if folders == "isolated" else "FinishUP folders"
    return DoctorEntry("installation_folders", label, LayerState.VERIFIED, detail=detail)


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _WorkSession:
    """Identifiers returned by ``start``; reused for the task-scoped operations."""

    task_id: str
    session_id: str
    writer_id: str
    frontier: object


class FinishUpRuntime:
    """Async facade over the existing FinishUP services for one terminal session."""

    def __init__(self, *, cwd: Path | None = None) -> None:
        self._cwd = (cwd or Path.cwd()).resolve()
        self._sessions: dict[str, _WorkSession] = {}
        self._opened_titles: list[str] = []
        self._pending_checks: dict[str, object] = {}
        # The request id of the latest check per task, kept so its structural progress can be
        # read while it runs and recovered after a client wait ends (issue #571 A2).
        self._check_request_ids: dict[str, str] = {}
        # The evaluator runtime setup last offered as its default (see setup_codex_subscription).
        self._offered_codex_executable: Path | None = None

    # -- discovery ------------------------------------------------------

    @property
    def cwd(self) -> Path:
        return self._cwd

    @property
    def opened_titles(self) -> tuple[str, ...]:
        """Task titles opened in this session, newest first.

        This is a convenience for re-opening, not a task index: the control
        protocol has no task-listing operation and the interface must not invent
        one. Nothing here is persisted or treated as authoritative.
        """

        return tuple(reversed(self._opened_titles))

    def suggested_codex_home(self) -> Path | None:
        """``$CODEX_HOME`` or ``~/.codex`` when it exists, offered for confirmation."""

        from finishup.adapters.integrations.codex_discovery import default_codex_home

        return default_codex_home()

    def discover_harnesses(self) -> tuple[HarnessOption, ...]:
        from finishup.adapters.integrations.host_discovery import discover_hosts
        from finishup.ports.harness_mcp import HarnessBinary
        from finishup.ports.integrations import HarnessId

        installations = discover_hosts()
        return tuple(
            _harness_option(
                HarnessBinary(HarnessId.CODEX, str(item.executable), item.version, "untested"),
                index=index,
                total=len(installations),
            )
            if item.host == "codex"
            else HarnessOption(
                str(item.executable),
                item.version,
                item.label,
                "Installed agent",
                index == 0,
                item.host,
                str(item.config_root),
            )
            for index, item in enumerate(installations)
        )

    async def detect(self) -> Detection:
        """Everything the welcome screen shows, gathered without mutation."""

        harnesses = self.discover_harnesses()
        connected = False
        for harness in harnesses:
            try:
                if await self.mcp_state(harness) == _OWNED:
                    connected = True
                    break
            except RuntimeError_:
                continue
        secure_storage_available, secure_storage_reason = _secure_storage_probe()
        return project_detection(
            self._cwd,
            harnesses=harnesses,
            secure_storage_available=secure_storage_available,
            secure_storage_reason=secure_storage_reason,
            already_connected=connected,
        )

    def _binary_for(self, option: HarnessOption) -> HarnessBinary:
        from finishup.ports.harness_mcp import HarnessBinary
        from finishup.ports.integrations import HarnessId

        return HarnessBinary(
            harness_id=HarnessId.CODEX,
            executable_path=option.executable_path,
            reported_version=option.reported_version,
            compatibility="untested",
        )

    async def mcp_state(self, option: HarnessOption) -> str:
        if option.host != "codex":
            from finishup.cli.host_connection import CONNECTION_ERRORS

            try:
                status = await self._host_connection_status(option)
                ready = status.get("installed") is True and status.get("configured") is True
                if option.host == "claude":
                    ready = ready and status.get("enabled") is True
                return _OWNED if ready else "absent"
            except CONNECTION_ERRORS:
                return "unknown"
        from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter
        from finishup.application.harness_mcp import HarnessMcpService
        from finishup.ports.harness_mcp import McpRegistrationError

        service = HarnessMcpService(CodexMcpAdapter())
        try:
            state = await service.status(self._binary_for(option))
        except McpRegistrationError as error:
            raise RuntimeError_(error.reason.value, "the Codex registration could not be read")
        return str(state.value)

    async def mcp_registration(self, option: HarnessOption) -> tuple[str, str]:
        """The registration state and what the pre-rename ``yoetz`` key holds (ADR-048).

        Only Codex registrations carry a legacy key FinishUP reads here; another host's Yoetz-era
        install is reported with its plugin layer instead, so its legacy value is ``none``.
        """

        if option.host != "codex":
            return await self.mcp_state(option), "none"
        from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter
        from finishup.application.harness_mcp import HarnessMcpService
        from finishup.ports.harness_mcp import McpRegistrationError

        service = HarnessMcpService(CodexMcpAdapter())
        try:
            observation = await service.observe(self._binary_for(option))
        except McpRegistrationError as error:
            raise RuntimeError_(error.reason.value, "the Codex registration could not be read")
        return str(observation.state.value), str(observation.legacy_registration)

    async def _host_connection_status(self, option: HarnessOption) -> dict[str, object]:
        from anyio.to_thread import run_sync

        from finishup.cli.host_connection import prepare_selected, select_installation
        from finishup.cli.setup import configured_mcp_route_profile
        from finishup.protocol.ids import IdKind, new_id

        selected = await run_sync(
            lambda: select_installation(
                option.host,
                Path(option.executable_path),
                None if option.config_root is None else Path(option.config_root),
            )
        )
        plan = await run_sync(
            lambda: prepare_selected(
                selected,
                self.project_root(),
                action="connect",
                route=configured_mcp_route_profile(),
                request_value=new_id(IdKind.REQUEST),
            )
        )
        return dict(await run_sync(plan.status))

    async def _host_plugin_layers(self, option: HarnessOption) -> tuple[ReadinessLayer, ...]:
        from finishup.cli.host_connection import CONNECTION_ERRORS

        detail = option.label
        try:
            status = await self._host_connection_status(option)
        except CONNECTION_ERRORS:
            state = LayerState.UNKNOWN
        else:
            state = (
                LayerState.VERIFIED
                if status.get("installed") is True
                else LayerState.NOT_CONFIGURED
            )
            # A Yoetz-era install or project entry still present beside (or instead of) the
            # FinishUP one (ADR-048).
            project_mcp = _mapping(status.get("project_mcp"))
            legacy = [
                text
                for text in (
                    _LEGACY_INSTALLATION_TEXT.get(str(status.get("legacy_installation"))),
                    _project_legacy_registration_text(project_mcp),
                )
                if text is not None
            ]
            if legacy:
                detail = "; ".join((option.label, *legacy))
        return (
            ReadinessLayer("plugin_installed", "Guidance installed", state, detail),
            ReadinessLayer(
                "hooks_installed",
                "Structural hooks installed",
                LayerState.UNPROVEN if state is LayerState.VERIFIED else state,
                "Fresh host session required to verify hook activation"
                if state is LayerState.VERIFIED
                else option.label,
            ),
        )

    async def run_privacy_setup(
        self,
        recipe_hint: str | None,
        *,
        offer_recommended: bool = False,
        conversation_review: str | None = None,
        ai_review_add_on: bool = False,
    ) -> object:
        """Hand the trusted questionnaire to the CLI implementation.

        ``conversation_review`` is the owner's first-run answer (ADR-049), drafted into the
        policy instead of asked again. ``ai_review_add_on`` lists the AI-powered review recipes
        with their own recommendation (an answer that adds AI-powered review).
        """

        from finishup.cli.privacy_setup import run_privacy_setup
        from finishup.cli.unlock import HumanCeremonyCliError
        from finishup.domain.privacy import ConversationReview
        from finishup.ports.control import ControlError

        try:
            conversation = (
                None if conversation_review is None else ConversationReview(conversation_review)
            )
        except ValueError:
            raise RuntimeError_(
                "privacy_conversation_review_invalid", "the conversation setting is invalid"
            ) from None

        if recipe_hint is not None and recipe_hint not in {
            "private",
            "metadata_only",
            "assisted_review",
            "expanded_review",
            "custom",
        }:
            raise RuntimeError_("privacy_recipe_invalid", "the privacy recipe is invalid")
        try:
            return await run_privacy_setup(
                recipe_hint=cast(
                    Literal[
                        "private",
                        "metadata_only",
                        "assisted_review",
                        "expanded_review",
                        "custom",
                    ]
                    | None,
                    recipe_hint,
                ),
                offer_recommended=offer_recommended,
                workspace_locator=self._cwd,
                conversation_review=conversation,
                ai_review_add_on=ai_review_add_on,
            )
        except (ControlError, HumanCeremonyCliError, OSError, ValueError) as error:
            raise RuntimeError_(
                getattr(error, "reason", "privacy_setup_failed"),
                "the trusted privacy ceremony could not be completed",
            ) from error

    def privacy_recommendation(
        self, posture: PrivacyPosture | None = None
    ) -> PrivacyRecommendation:
        """The same recommendation rule the CLI uses, never a second opinion."""

        from finishup.cli.privacy_setup import recommended_privacy_recipe

        try:
            recipe = recommended_privacy_recipe()
        except Exception:
            # Reading the configured provider binding can fail on its own (an unrecognized
            # `FINISHUP_*` variable, an unreadable file). Recommend the closed posture rather
            # than propagating: never recommend enabling egress on the strength of a
            # configuration that could not be read.
            recipe = "private"
        if recipe == "assisted_review":
            grant_sentence = (
                " This repository already has the required grant."
                if posture is not None and posture.repository_grant_state == "granted"
                else " Approval creates the required grant only for this repository."
            )
            return PrivacyRecommendation(
                recipe,
                "This exact provider route has current reviewed no-training and retention evidence, "
                "so bounded Assisted review is available for this repository." + grant_sentence,
                "It may disclose selected problem-local ordinary user content; the trusted policy "
                "review shows the exact boundary and provider caveats before approval.",
            )
        if recipe == "metadata_only":
            return PrivacyRecommendation(
                recipe,
                "It enables AI-powered review while disclosing the least that still works, and "
                "asks before every provider request.",
                "In exchange, the reviewer sees structural metadata only, so it cannot judge "
                "whether a claim is actually supported.",
            )
        return PrivacyRecommendation(
            recipe,
            "No reviewer with current reviewed data-use evidence is set up, so FinishUP runs its "
            "local checks on every task and sends no work for AI-powered review.",
            "Add AI-powered review with /provider when you want it; your agent can then turn it "
            "on for a task when it helps.",
        )

    # -- integration ----------------------------------------------------

    async def integration_plan(
        self,
        option: HarnessOption,
        codex_home: Path,
        route_profile: Literal["policy", "strict"] | None = None,
    ) -> IntegrationPlan:
        """Build the exact proposed change, previewing through the owning services.

        ``route_profile`` is the answer the human just gave to "how should FinishUP review work?".
        Omit it only where nothing was asked -- post-setup ``/connect`` -- and the configured
        posture is then the authority.
        """

        from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter
        from finishup.application.codex_plugin import CodexPluginService
        from finishup.application.harness_mcp import HarnessMcpService
        from finishup.cli.runtime_refusal import connect_refusal
        from finishup.cli.setup import (
            check_policy_preview,
            codex_activation_preview,
            configured_mcp_route_profile,
            project_skill_preview,
        )
        from finishup.ports.harness_mcp import (
            MCP_SERVE_COMMAND,
            McpRegistrationAction,
            McpRegistrationError,
            McpRegistrationState,
        )
        from finishup.ports.integrations import (
            IntegrationError,
            IntegrationScope,
            IntegrationTarget,
        )

        refusal = connect_refusal()
        if refusal is not None:
            token, next_step = refusal
            raise RuntimeError_(
                token,
                "FinishUP cannot run from this installation for this account",
                details=tuple(line.strip() for line in next_step.splitlines() if line.strip()),
            )
        binary = self._binary_for(option)
        root = self.project_root()
        route = configured_mcp_route_profile() if route_profile is None else route_profile
        try:
            activation_preview = codex_activation_preview(binary, codex_home, root)
        except IntegrationError as error:
            raise RuntimeError_(error.reason.value, "the Codex activation could not be previewed")
        service = HarnessMcpService(
            CodexMcpAdapter(route_profile=route, codex_home=activation_preview.codex_home)
        )
        try:
            mcp_preview = await service.preview(binary)
        except McpRegistrationError as error:
            raise RuntimeError_(error.reason.value, "the Codex registration could not be previewed")
        reregister = (
            mcp_preview.state_before is McpRegistrationState.FINISHUP_OWNED
            and mcp_preview.action is McpRegistrationAction.REREGISTER
        )
        target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
        skill_preview = await project_skill_preview(root)
        plugin_preview = CodexPluginService().preview(
            target,
            codex_version=activation_preview.codex_version,
        )
        policy = check_policy_preview(root)
        digest = policy.get("policy_digest")
        checks = policy.get("check_ids")
        owned = mcp_preview.state_before is McpRegistrationState.FINISHUP_OWNED
        # The registration state in words: the route the owned entry serves now, when the adapter
        # observed it, and what the pre-rename ``yoetz`` key holds (ADR-048). A re-registration
        # can keep the route (a legacy key, launcher, or isolation change), so the action alone
        # never names the route before.
        state_words = [str(mcp_preview.state_before.value)]
        # Prefer the route the adapter observed in this preview (``finishup setup`` reads the same
        # registration). When it observed none, a re-registration is shown as a change to the
        # other route, so a possible review-mode change is never hidden from this approval.
        route_before: Literal["policy", "strict"] | None = None
        if owned:
            if mcp_preview.route_profile_before is not None:
                route_before = mcp_preview.route_profile_before
            elif mcp_preview.action is McpRegistrationAction.REREGISTER:
                route_before = "policy" if route == "strict" else "strict"
            else:
                route_before = route
        if route_before is not None and route_before != route:
            state_words.append(f"route {route_before} -> {route}")
        # The other projects of this Codex home whose sessions that review-mode change reaches
        # (#1058), judged from the same route before the plan shows.
        _shared_before, changes_for, changes_possible_for = await _shared_route_change(
            service,
            binary,
            mcp_preview,
            route,
            activation_preview.codex_home,
            root,
            before=route_before,
        )
        # Kept beside ``finishup`` because a project's Codex settings still use it, or because
        # not every project of the home could be read (#1073): the words say which.
        needed = set(mcp_preview.legacy_kept_for) - set(mcp_preview.legacy_kept_unreadable)
        legacy_text = (
            _KEPT_LEGACY_REGISTRATION_TEXT.get(mcp_preview.legacy_registration)
            if needed
            else _UNREAD_LEGACY_REGISTRATION_TEXT.get(mcp_preview.legacy_registration)
            if mcp_preview.legacy_kept_for or mcp_preview.legacy_kept_unchecked
            else _LEGACY_REGISTRATION_TEXT.get(mcp_preview.legacy_registration)
        )
        if legacy_text is not None:
            state_words.append(legacy_text)
        managed_paths = [
            str(root / ".agents" / "skills" / "finishup"),
            str(root / ".agents" / "plugins" / "finishup"),
        ]
        # Yoetz-era trees this same approval removes (ADR-048).
        legacy_skill_tree_planned = "legacy_skill_tree_owned" in skill_preview.warnings
        if legacy_skill_tree_planned:
            managed_paths.append(str(root / ".agents" / "skills" / "yoetz"))
        if activation_preview.legacy_plugin_tree_planned:
            managed_paths.append(str(root / ".agents" / "plugins" / "yoetz"))
        return IntegrationPlan(
            harness_label=option.label,
            executable_path=option.executable_path,
            codex_home=str(activation_preview.codex_home),
            reported_version=option.reported_version,
            project_root=str(root),
            route_profile=route,
            mcp_command=shlex.join(mcp_preview.serve_command),
            mcp_server_name=_MCP_SERVER_NAME,
            policy_digest=digest if isinstance(digest, str) else None,
            planned_check_ids=tuple(str(item) for item in checks)
            if isinstance(checks, (tuple, list))
            else (),
            planned_file_count=(
                int(getattr(plugin_preview, "planned_file_count", 0))
                + len(skill_preview.file_changes)
            ),
            managed_paths=tuple(managed_paths),
            state_before="; ".join(state_words),
            # Only an exact owned entry is verified and left alone; a re-registration (route,
            # launcher, isolation, or legacy key) replaces it under this approval.
            already_registered=owned and mcp_preview.action is McpRegistrationAction.NOOP,
            foreign_entry=mcp_preview.state_before is McpRegistrationState.FOREIGN_PRESENT,
            preview_digest=str(mcp_preview.preview_digest),
            skill_preview_digest=skill_preview.preview_digest,
            activation_preview_digest=activation_preview.preview_digest,
            activation_marketplace_path=str(root / ".agents" / "plugins" / "marketplace.json"),
            activation_config_path=str(activation_preview.codex_home / "config.toml"),
            activation_marketplace_text=activation_preview.marketplace_bytes.decode("utf-8"),
            activation_config_block=activation_preview.config_toml_block,
            activation_plugin_source_digest=activation_preview.plugin_source_digest,
            activation_inventory_verified=activation_preview.inspection.inventory_verified,
            activation_plugin_install_path=str(activation_preview.plugin_install_path),
            activation_plugin_install_digest=activation_preview.plugin_install_digest,
            activation_executable_digest=activation_preview.executable_digest,
            activation_codex_version=activation_preview.codex_version,
            activation_probe_command=activation_preview.probe_command,
            activation_inventory_command=activation_preview.inventory_command,
            activation_install_command=activation_preview.install_command,
            activation_probe_environment=activation_preview.probe_environment,
            activation_environment=activation_preview.activation_environment,
            activation_marketplace_preimage_digest=(activation_preview.marketplace_preimage_digest),
            activation_config_preimage_digest=activation_preview.config_preimage_digest,
            activation_cache_mutation_planned=activation_preview.cache_mutation_planned,
            activation_mcp_command=MCP_SERVE_COMMAND,
            mcp_isolated_root=mcp_preview.isolated_root,
            route_profile_before=route_before,
            legacy_registration=mcp_preview.legacy_registration,
            activation_legacy_removed_block=activation_preview.legacy_removed_block,
            activation_legacy_cache_versions=tuple(activation_preview.legacy_cache_versions),
            activation_legacy_plugin_tree_planned=activation_preview.legacy_plugin_tree_planned,
            legacy_skill_tree_planned=legacy_skill_tree_planned,
            policy_ambiguous=policy.get("outcome") == "ambiguous",
            mcp_reregister=reregister,
            route_changes_for=changes_for,
            route_changes_possible_for=changes_possible_for,
            legacy_registration_kept_for=mcp_preview.legacy_kept_for,
            legacy_registration_kept_unchecked=mcp_preview.legacy_kept_unchecked,
            legacy_registration_route_profile=mcp_preview.legacy_route_profile,
            legacy_registration_kept_unread=mcp_preview.legacy_kept_unread,
            legacy_registration_kept_lines=_legacy_kept_plan_lines(
                mcp_preview,
                executable=binary.executable_path,
                codex_home=activation_preview.codex_home,
                project=root,
                route=route,
            ),
        )

    async def apply_integration(
        self, option: HarnessOption, plan: IntegrationPlan
    ) -> IntegrationOutcome:
        """Apply exactly the plan the human approved, echoing back both digests.

        The digests are not decoration. ``apply_codex_integration`` re-previews
        and refuses when either has moved since the approval screen was drawn,
        which is the same staleness gate ``integrate mcp install
        --preview-digest`` already enforces.

        The route travels on the plan for the same reason: it is inside the preview digest, so
        resolving it a second time here could only ever disagree with what was approved.
        """

        from finishup.cli.setup import apply_codex_integration

        report = await apply_codex_integration(
            self._binary_for(option),
            route_profile=plan.route_profile,
            workspace=self.project_root(),
            approved_preview_digest=plan.preview_digest,
            approved_activation_mcp_command=plan.activation_mcp_command,
            approved_skill_preview_digest=plan.skill_preview_digest,
            approved_activation_digest=plan.activation_preview_digest,
            approved_policy_digest=plan.policy_digest,
            codex_home=Path(plan.codex_home),
        )
        return self._integration_outcome(report)

    def _integration_outcome(self, report: Mapping[str, object]) -> IntegrationOutcome:
        outcome = str(report.get("outcome") or "unknown")
        reason = report.get("reason")
        plugin_map = _mapping(report.get("plugin"))
        consent_map = _mapping(report.get("observation_consent"))
        policy_map = _mapping(report.get("check_policy"))

        # ``reregistered`` is a success too: a route change, or a Yoetz-era ``yoetz`` key moved
        # to ``finishup`` (ADR-048). The same set ``finishup setup`` reports as registered.
        registered = outcome in {"registered", "reregistered", "already_registered"}
        verified = registered and report.get("state") == _OWNED
        plugin_installed = plugin_map.get("presence") == "installed"
        consent_active = consent_map.get("outcome") == "granted"
        kept_profiles = consent_map.get("content_capture_profiles")
        consent_detail = (
            "native content profiles kept: "
            + ", ".join(str(profile) for profile in cast(list[object], kept_profiles))
            if consent_active and isinstance(kept_profiles, list) and kept_profiles
            else ""
        )
        policy_trusted = policy_map.get("outcome") == "trusted"
        policy_ambiguous = policy_map.get("outcome") == "ambiguous"
        policy_absent = policy_map.get("outcome") == "absent" or not policy_map
        if policy_trusted or policy_absent:
            policy_detail = ""
        elif policy_ambiguous:
            policy_detail = _POLICY_AMBIGUOUS_TEXT
        else:
            policy_detail = str(policy_map.get("outcome") or "")

        layers = (
            ReadinessLayer(
                "mcp_registered",
                "MCP registered",
                LayerState.VERIFIED if registered else LayerState.BLOCKED,
            ),
            ReadinessLayer(
                "mcp_verified",
                "MCP verified",
                LayerState.VERIFIED if verified else LayerState.UNPROVEN,
            ),
            ReadinessLayer(
                "plugin_installed",
                "Guidance installed",
                LayerState.VERIFIED if plugin_installed else LayerState.BLOCKED,
            ),
            ReadinessLayer(
                "hooks_installed",
                "Structural hooks installed",
                LayerState.VERIFIED
                if plugin_map.get("trust_observable") is True
                else LayerState.UNPROVEN,
            ),
            ReadinessLayer(
                "project_consent",
                "Project consent active",
                LayerState.VERIFIED if consent_active else LayerState.NOT_CONFIGURED,
                detail=consent_detail,
            ),
            ReadinessLayer(
                "policy_digest_trusted",
                "Approved-check policy trusted",
                LayerState.NOT_CONFIGURED
                if policy_absent or policy_ambiguous
                else (LayerState.VERIFIED if policy_trusted else LayerState.UNPROVEN),
                detail=policy_detail,
            ),
        )
        return IntegrationOutcome(
            outcome=outcome,
            reason=str(reason) if isinstance(reason, str) else None,
            layers=layers,
            foreign_entry=reason == "foreign_entry_present",
            existing_entry_detail=str(report.get("state") or ""),
        )

    async def foreign_entry_detail(self, option: HarnessOption) -> tuple[str, ...]:
        """Show what already owns the name, without offering to remove it."""

        binary = self._binary_for(option)
        executable = str(getattr(binary, "executable_path", ""))
        return (
            f'An MCP entry named "{_MCP_SERVER_NAME}" already exists for this Codex '
            "installation and was not created by FinishUP.",
            f"Codex executable: {executable}",
            "Inspect it with: codex mcp get finishup",
            "FinishUP will never replace or remove an entry it does not own.",
            "To keep this configuration, create a new owner-private Codex home (mode 0700) "
            "and select it in setup, or use setup run --host codex --host-config-root <new-home>.",
        )

    def project_root(self) -> Path:
        root = _git_root(self._cwd)
        return root if root is not None else self._cwd

    async def observation_selection_status(self) -> Mapping[str, object]:
        """Read owner-selected observation settings without touching the service.

        The projection contains commitments, bounded counters, and selected /
        effective modes only.  It never reads content or privacy policy.  A
        richer store projection is preferred when the running package exposes
        it; the CLI-shaped fallback keeps older services readable during an
        upgrade.
        """

        from finishup.adapters.integrations.observation_local import LocalObservationStore
        from finishup.cli.observe import selection_status_payload

        try:
            store = LocalObservationStore()
            commitment = store.workspace_commitment(self._selection_workspace_locator())
            raw = selection_status_payload(store, commitment)
            return cast(Mapping[str, object], raw)
        except (OSError, ValueError, RuntimeError) as error:
            raise RuntimeError_(
                "observation_status_unavailable", "observation status is unavailable"
            ) from error

    def _selection_workspace_locator(self) -> str:
        """Return the workspace locator the command line would resolve for this project.

        Selection reads and writes use the same canonicalization as
        ``finishup observe --workspace`` (the nearest safe Git root hooks use), so
        the terminal interface and the command line address one workspace.
        """

        from finishup.adapters.workspace_binding import canonical_workspace_locator

        locator = canonical_workspace_locator(str(self.project_root()))
        if locator is None:
            raise ValueError("workspace_locator_invalid")
        return locator

    def _workspace_selection_inputs(
        self,
    ) -> tuple[LocalObservationStore, str, ObservationDetailProfile]:
        """Open the local store and resolve the workspace selection's current detail.

        The terminal interface has no host session, so a capacity change here is the
        persisted workspace selection.  The current workspace detail is carried forward
        unchanged: this surface changes capacity only.
        """

        from finishup.adapters.integrations.observation_local import LocalObservationStore
        from finishup.domain.observation_settings import resolve_observation_selection

        store = LocalObservationStore()
        commitment = store.workspace_commitment(self._selection_workspace_locator())
        resolution = resolve_observation_selection(store.selection_settings_for(commitment))
        return store, commitment, resolution.selection.detail

    async def preview_observation_selection(
        self, capacity: CapacityRequest
    ) -> Mapping[str, object]:
        """Preview a workspace capacity change without changing local state.

        A request for no FinishUP cap raises :class:`ObservationCapacityUnavailable`
        carrying the owning explanation; nothing is changed in that case either.
        """

        try:
            from finishup.cli.observe import CapacityNoCapUnsupported, build_selection_preview
        except ImportError as error:
            raise RuntimeError_(
                "observation_selection_unavailable",
                "capacity changes are unavailable in this installation",
            ) from error
        from finishup.protocol.errors import PublicOperationError

        try:
            store, commitment, detail = self._workspace_selection_inputs()
            raw = build_selection_preview(
                store,
                commitment,
                detail=detail,
                capacity=capacity,
                scope="workspace",
                session_commitment=None,
                expires_at=None,
            )
        except CapacityNoCapUnsupported as error:
            raise ObservationCapacityUnavailable(
                tuple(error.lines), error.alternative_command
            ) from error
        except PublicOperationError as error:
            raise RuntimeError_(
                "observation_selection_preview_failed",
                "the capacity preview could not be built",
                details=(error.message,),
            ) from error
        except (OSError, ValueError, RuntimeError) as error:
            raise RuntimeError_(
                "observation_selection_preview_failed",
                "the capacity preview could not be built",
            ) from error
        return cast(Mapping[str, object], raw)

    async def apply_observation_selection(
        self, capacity: CapacityRequest, preview_digest: str
    ) -> Mapping[str, object]:
        """Apply exactly the previewed workspace capacity change.

        The owning path re-derives the preview and refuses a digest that no longer
        matches, so a setting changed elsewhere since the preview is never
        overwritten silently.
        """

        try:
            from finishup.cli.observe import CapacityNoCapUnsupported, apply_selection_preview
        except ImportError as error:
            raise RuntimeError_(
                "observation_selection_unavailable",
                "capacity changes are unavailable in this installation",
            ) from error
        from finishup.protocol.errors import PublicOperationError

        try:
            store, commitment, detail = self._workspace_selection_inputs()
            raw = apply_selection_preview(
                store,
                commitment,
                detail=detail,
                capacity=capacity,
                scope="workspace",
                session_commitment=None,
                expires_at=None,
                preview_digest=preview_digest,
                accept=True,
            )
        except CapacityNoCapUnsupported as error:
            raise ObservationCapacityUnavailable(
                tuple(error.lines), error.alternative_command
            ) from error
        except PublicOperationError as error:
            raise RuntimeError_(
                "observation_selection_apply_failed",
                "the capacity change was not applied",
                details=(error.message,),
            ) from error
        except (OSError, ValueError, RuntimeError) as error:
            raise RuntimeError_(
                "observation_selection_apply_failed",
                "the capacity change was not applied",
            ) from error
        return cast(Mapping[str, object], raw)

    # -- service --------------------------------------------------------

    @asynccontextmanager
    async def _client(self) -> AsyncGenerator[Any]:
        from finishup.cli.app import build_service_client
        from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator

        # Agent-facing like every client (ADR-009 round 3); the owner's full receipt is the
        # explicit, reauthenticated ``build_receipt(..., owner_view=True)`` path.
        try:
            client = await build_service_client(
                ControlClientKind.UI,
                workspace_locator=WorkspaceLocator(str(self._cwd.resolve(strict=True))),
            )
        except ControlError as error:
            raise _connect_failure(error) from error
        try:
            yield client
        finally:
            await client.close()

    async def vault_posture(self) -> VaultPosture:
        from finishup.ports.control import ControlError

        try:
            async with self._client() as client:
                status = await client.service_status()
        except RuntimeError_, ControlError:
            return VaultPosture(reachable=False, state=None, vault_mode=None)
        state = getattr(getattr(status, "state", None), "value", None)
        return VaultPosture(
            reachable=True,
            state=state if isinstance(state, str) else None,
            vault_mode=getattr(status, "vault_mode", None),
        )

    async def service_lock(self) -> str:
        async with self._client() as client:
            status = await client.lock()
        return str(getattr(getattr(status, "state", None), "value", "unknown"))

    async def service_stop(self) -> str:
        async with self._client() as client:
            result = await client.stop()
        return str(getattr(result, "state", "draining"))

    # -- privacy --------------------------------------------------------

    async def privacy_posture(self) -> PrivacyPosture:
        from finishup.domain.values import JsonObject
        from finishup.ports.control import ControlError

        try:
            async with self._client() as client:
                effective = await client.privacy_get_setup(JsonObject({"schema_version": "2.0.0"}))
        except RuntimeError_, ControlError:
            return PrivacyPosture(profile=None, llm_inference_enabled=None, readable=False)
        response = _mapping(effective)
        policy_map = _mapping(response.get("composed_policy"))
        if not policy_map:
            return PrivacyPosture(profile=None, llm_inference_enabled=None, readable=False)
        profile = policy_map.get("profile")
        enabled: list[str] = []
        llm_enabled: bool | None = None
        channels = policy_map.get("channel_policies")
        if isinstance(channels, (list, tuple)):
            for entry in cast("Sequence[object]", channels):
                row = _mapping(entry)
                if not row:
                    continue
                name = row.get("channel")
                if row.get("enabled") is True and isinstance(name, str):
                    enabled.append(name)
                if name == "llm_inference":
                    llm_enabled = row.get("enabled") is True
        never = policy_map.get("forbidden_data_kinds")
        never_send = (
            tuple(str(item) for item in cast("Sequence[object]", never))
            if isinstance(never, (list, tuple))
            else ()
        )
        network_raw = policy_map.get("network_egress_permitted")
        network_egress = network_raw if type(network_raw) is bool else None
        task_statement_sent, task_statement_disclosure = _task_statement_posture(policy_map)
        return PrivacyPosture(
            conversation_review=_conversation_review_token(policy_map, llm_enabled),
            conversation_review_explicit=policy_map.get("conversation_review") is not None,
            recipe_outdated=_review_recipe_outdated(policy_map),
            credential_heuristic=_credential_heuristic_pair(response.get("credential_heuristic")),
            profile=profile if isinstance(profile, str) else None,
            llm_inference_enabled=llm_enabled,
            readable=True,
            never_send=never_send,
            enabled_channels=tuple(enabled),
            network_egress_permitted=network_egress,
            task_statement_sent=task_statement_sent,
            task_statement_disclosure=task_statement_disclosure,
            repository_grant_state=cast(
                Literal["granted", "missing"] | None,
                response.get("grant_state")
                if response.get("grant_state") in {"granted", "missing"}
                else None,
            ),
            repository_migration_state=cast(
                str | None,
                response.get("migration_state")
                if response.get("migration_state")
                in {
                    "not_applicable",
                    "legacy_route_available",
                    "first_repository_available",
                    "consumed",
                }
                else None,
            ),
        )

    # -- provider -------------------------------------------------------

    def provider_options(self) -> tuple[ProviderOption, ...]:
        """The reviewed presets plus the owner-declared HTTPS escape hatch."""

        from finishup.config.write import PROVIDER_PRESETS

        labels = {
            "official_openai": "OpenAI",
            "fireworks": "Fireworks AI",
            "anthropic": "Anthropic",
            "google_gemini": "Google Gemini",
            "openrouter": "OpenRouter",
            "grok": "Grok (xAI)",
            "vercel_ai_gateway": "Vercel AI Gateway",
        }
        options = [
            ProviderOption(
                choice=preset.choice,
                label=labels.get(preset.choice, preset.provider_id),
                provider_id=preset.provider_id,
                host=preset.host,
                base_path_prefix=preset.base_path_prefix,
                default_model=preset.default_model,
                api_style=preset.api_style,
                endpoint_profile_id=preset.endpoint_profile_id,
                endpoint_profile_version=preset.endpoint_profile_version,
            )
            for key, preset in PROVIDER_PRESETS.items()
            if key in labels
        ]
        options.append(
            ProviderOption(
                choice="owner_declared",
                label="Custom OpenAI-compatible endpoint",
                provider_id="owner-declared",
                host="",
                base_path_prefix="",
                default_model="",
                api_style="responses",
                endpoint_profile_id="owner-declared-openai-responses",
                endpoint_profile_version="1.0.0",
                requires_origin=True,
            )
        )
        options.append(
            ProviderOption(
                choice="codex_subscription",
                label="Codex with ChatGPT subscription",
                provider_id="openai-codex",
                host="openai.com",
                base_path_prefix=" through Codex-managed login",
                default_model="gpt-6-luna",
                api_style="Codex app-server v2 (stdio)",
                endpoint_profile_id="codex-chatgpt-subscription",
                endpoint_profile_version="1.0.0",
            )
        )
        return tuple(options)

    def codex_subscription_defaults(self) -> tuple[str, str, str, str]:
        """Return eligible nonsecret defaults; setup still capability-checks the runtime.

        The executable default is the newest eligible evaluator runtime (a Codex release at or
        above the floor, FinishUP's retained copy first on equal releases), never a binary below the
        floor. An existing binding's model and reasoning effort are offered unchanged.
        """

        from finishup.cli.codex_subscription import (
            default_codex_evaluator_executable,
            default_codex_home,
            default_codex_subscription_model,
            default_codex_subscription_reasoning_effort,
        )

        selected = default_codex_evaluator_executable()
        # Remembered so accepting this default keeps newest-first discovery with fallback.
        self._offered_codex_executable = selected
        executable = "" if selected is None else str(selected)
        return (
            executable,
            str(default_codex_home()),
            default_codex_subscription_model(),
            default_codex_subscription_reasoning_effort(),
        )

    def codex_subscription_routine_default(self) -> str | None:
        """Routine effort setup applies by default; ``None`` keeps a legacy single effort."""

        from finishup.cli.codex_subscription import default_codex_subscription_routine_effort

        return default_codex_subscription_routine_effort()

    def preview_codex_subscription(
        self,
        executable: str,
        codex_home: str,
        model: str,
        reasoning_effort: str,
        routine_reasoning_effort: str | None = None,
    ) -> Mapping[str, object]:
        """Resolve and render the subscription binding without logging in or writing state."""

        from finishup.cli.codex_subscription import codex_subscription_preview

        try:
            return codex_subscription_preview(
                executable=Path(executable),
                codex_home=Path(codex_home),
                model=model,
                reasoning_effort=reasoning_effort,
                routine_reasoning_effort=routine_reasoning_effort,
            )
        except (OSError, ValueError) as error:
            raise _subscription_error(
                error, "that Codex is not a supported evaluator runtime"
            ) from None

    async def setup_codex_subscription(
        self,
        executable: str,
        codex_home: str,
        model: str,
        reasoning_effort: str,
        *,
        switch_account: bool = False,
        routine_reasoning_effort: str | None = None,
    ) -> Mapping[str, object]:
        """Run Codex-owned login, then recompose the service around the exact binding."""

        from finishup.cli.codex_subscription import (
            codex_subscription_setup,
            setup_executable_selection,
        )
        from finishup.cli.setup import restart_service_for_semantic_composition

        try:
            result = await codex_subscription_setup(
                # The offered default keeps newest-first discovery with fallback (ADR-006);
                # only a path the owner typed instead pins setup to that one runtime.
                executable=setup_executable_selection(executable, self._offered_codex_executable),
                codex_home=Path(codex_home),
                model=model,
                reasoning_effort=reasoning_effort,
                routine_reasoning_effort=routine_reasoning_effort,
                login_mode="browser",
                open_browser=True,
                switch_account=switch_account,
            )
            await restart_service_for_semantic_composition(report_startup_failure=False)
            return result
        except (OSError, TimeoutError, ValueError) as error:
            raise _subscription_error(error, "Codex subscription setup did not complete") from None

    async def codex_subscription_status(self) -> Mapping[str, object]:
        """Read structural Codex login/model state without sending a task case."""

        from finishup.cli.codex_subscription import codex_subscription_status

        try:
            return await codex_subscription_status()
        except (OSError, TimeoutError, ValueError) as error:
            raise _subscription_error(
                error, "Codex subscription status could not be read"
            ) from None

    async def disconnect_codex_subscription(self) -> Mapping[str, object]:
        """Log out the dedicated home, remove the binding, then recompose the service."""

        from finishup.cli.codex_subscription import codex_subscription_disconnect
        from finishup.cli.setup import restart_service_for_semantic_composition

        try:
            result = await codex_subscription_disconnect()
            await restart_service_for_semantic_composition(report_startup_failure=False)
            return result
        except (OSError, TimeoutError, ValueError) as error:
            raise _subscription_error(
                error, "Codex subscription disconnect did not complete"
            ) from None

    async def rollback_codex_subscription(self) -> Mapping[str, object]:
        """Remove only the FinishUP binding, then recompose so the old cell cannot dispatch."""

        from finishup.cli.codex_subscription import codex_subscription_rollback
        from finishup.cli.setup import restart_service_for_semantic_composition

        try:
            result = codex_subscription_rollback()
            await restart_service_for_semantic_composition(report_startup_failure=False)
            return result
        except (OSError, ValueError) as error:
            raise _subscription_error(
                error, "Codex subscription rollback did not complete"
            ) from None

    def codex_subscription_repair_plan(self) -> Mapping[str, object]:
        """What repair would change, without any store, home, config, or Codex side effect."""

        from finishup.cli.codex_subscription import codex_subscription_repair_plan

        try:
            return codex_subscription_repair_plan()
        except (OSError, ValueError) as error:
            raise _subscription_error(
                error, "The Codex evaluator binding cannot be repaired"
            ) from None

    async def repair_codex_subscription(self) -> Mapping[str, object]:
        """Rebind to the retained runtime keeping sign-in and choices, then recompose."""

        from finishup.cli.codex_subscription import codex_subscription_repair
        from finishup.cli.setup import restart_service_for_semantic_composition

        try:
            result = await codex_subscription_repair()
            await restart_service_for_semantic_composition(report_startup_failure=False)
            return result
        except (OSError, TimeoutError, ValueError) as error:
            raise _subscription_error(error, "Codex evaluator repair did not complete") from None

    def codex_evaluator_runtime_status(self) -> Mapping[str, object]:
        """Structural runtime and binding state; starts no Codex process."""

        from finishup.cli.codex_subscription import codex_evaluator_runtime_status

        try:
            return codex_evaluator_runtime_status()
        except (OSError, ValueError) as error:
            raise _subscription_error(
                error, "Codex evaluator runtime status could not be read"
            ) from None

    def save_provider_binding(
        self, option: ProviderOption, model: str, *, https_origin: str | None = None
    ) -> None:
        """Write only the nonsecret endpoint binding. Never a credential."""

        from finishup.cli.provider_binding import apply_provider_endpoint_choice
        from finishup.config.models import ConfigError

        try:
            apply_provider_endpoint_choice(
                cast(Any, option.choice), model=model, https_origin=https_origin
            )
        except (ConfigError, OSError, ValueError) as error:
            reason = getattr(error, "reason_code", "provider_binding_invalid")
            raise RuntimeError_(str(reason), "that provider binding is not valid")

    async def provider_posture(self) -> ProviderPosture:
        from finishup.cli.provider_status import provider_status_report

        # The repository root, not the launch directory: host admission files live at the
        # root, and a subdirectory launch must not report them absent (issue #478 review).
        report = await provider_status_report(workspace_locator=self.project_root())
        endpoint_map = _mapping(report.get("endpoint"))
        blockers: list[tuple[str, str]] = []
        raw_blockers = report.get("blockers")
        if isinstance(raw_blockers, (list, tuple)):
            for item in cast("Sequence[object]", raw_blockers):
                row = _mapping(item)
                if row:
                    blockers.append((str(row.get("condition")), str(row.get("state") or "unknown")))
        route_map = _mapping(report.get("mcp_route"))
        raw_agent_ready = report.get("agent_route_semantic_ready")
        admission_map = _mapping(report.get("host_admission"))
        host_admission = tuple(
            (host, str(_mapping(admission_map.get(host)).get("state") or "unknown"))
            for host in ("claude", "codex", "cursor")
            if host in admission_map
        )
        advice_map = _mapping(report.get("background_advice"))
        raw_advice_enabled = advice_map.get("enabled")
        raw_advice_reason = advice_map.get("reason")
        return ProviderPosture(
            agent_route_semantic_ready=(
                raw_agent_ready if isinstance(raw_agent_ready, bool) else None
            ),
            background_advice_enabled=(
                raw_advice_enabled if isinstance(raw_advice_enabled, bool) else None
            ),
            background_advice_reason=(
                raw_advice_reason if isinstance(raw_advice_reason, str) else None
            ),
            registered_route_profile=cast(str | None, route_map.get("registered_profile")),
            route_drift_since_install=route_map.get("drift_since_install") is True,
            endpoint_bound=report.get("endpoint_bound") is True,
            provider_id=cast(str | None, endpoint_map.get("provider_id")),
            model=cast(str | None, endpoint_map.get("model")),
            endpoint_profile_id=cast(str | None, endpoint_map.get("endpoint_profile_id")),
            credential_authority=cast(str | None, endpoint_map.get("credential_authority")),
            credential_connected=cast(bool | None, report.get("credential_connected")),
            llm_inference_enabled=cast(bool | None, report.get("llm_inference_enabled")),
            semantic_enabled=report.get("semantic_enabled") is True,
            semantic_ready=report.get("semantic_ready") is True,
            readiness_determinable=report.get("readiness_determinable") is True,
            blockers=tuple(blockers),
            host_admission=host_admission,
        )

    # -- confidential ceremonies ---------------------------------------

    def credential_target(
        self, repository_privacy_commitment: str | None = None
    ) -> ProviderCredentialTarget:
        """Build the nonsecret credential identifiers for the ceremony."""

        from finishup.config.load import load_config
        from finishup.service.confidential_protocol import ProviderCredentialTarget
        from finishup.service.vault import provider_credential_profile_binding

        provider = load_config({}, {}, None).provider
        if provider is None:
            raise RuntimeError_("provider_not_configured", "choose a provider and model first")
        binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        return ProviderCredentialTarget(
            action="set",
            provider_id=binding.provider_id,
            model_id=binding.model_id,
            endpoint_profile_id=binding.endpoint_profile_id,
            endpoint_profile_version=binding.endpoint_profile_version,
            purpose=binding.purpose,
            scope_digest=binding.authorization_scope_digest,
            purpose_digest=binding.purpose_digest,
            repository_privacy_commitment=repository_privacy_commitment,
        )

    async def store_provider_credential(self) -> str:
        """Run the existing confidential ceremony. No secret crosses this call."""

        from finishup.cli.privacy_setup import get_privacy_setup_snapshot
        from finishup.cli.unlock import (
            HumanCeremonyCliError,
            load_auto_unlock_reauthentication,
            set_provider_credential,
        )

        snapshot = await get_privacy_setup_snapshot(self._cwd)
        repository_commitment = snapshot.bound_scope.get("workspace_ref_commitment")
        if type(repository_commitment) is not str:
            raise RuntimeError_(
                "repository_privacy_scope_unavailable",
                "the current repository is not bound to privacy authority",
            )
        target = self.credential_target(repository_commitment)
        try:
            # A Keychain-provisioned vault has a passphrase the human never saw; supply it here
            # so the ceremony asks only for the provider key.
            result = await set_provider_credential(
                target, None, load_auto_unlock_reauthentication()
            )
        except HumanCeremonyCliError as error:
            raise RuntimeError_(error.reason, "the credential ceremony did not complete")
        return str(getattr(result, "activation_status", "unknown"))

    async def initialize_passphrase_vault(self) -> None:
        from finishup.cli.unlock import HumanCeremonyCliError, initialize_passphrase_vault

        try:
            await initialize_passphrase_vault()
        except HumanCeremonyCliError as error:
            raise RuntimeError_(error.reason, "the vault could not be initialized")

    async def rotate_vault_passphrase(self) -> None:
        from finishup.cli.unlock import HumanCeremonyCliError, rotate_vault_passphrase

        try:
            await rotate_vault_passphrase()
        except HumanCeremonyCliError as error:
            raise RuntimeError_(error.reason, "the passphrase could not be changed")

    async def initialize_system_keyring(self) -> None:
        from finishup.cli.unlock import HumanCeremonyCliError, retry_keyring

        try:
            await retry_keyring(expected_mode="uninitialized")
        except HumanCeremonyCliError as error:
            raise RuntimeError_(error.reason, "system secure storage could not be initialized")

    async def unlock_vault(self) -> None:
        from finishup.cli.unlock import HumanCeremonyCliError, retry_keyring, unlock_vault

        posture = await self.vault_posture()
        try:
            if posture.vault_mode == "os_keyring":
                await retry_keyring()
            elif posture.vault_mode == "passphrase":
                await unlock_vault()
            else:
                raise RuntimeError_(
                    "vault_uninitialized", "the vault has not been set up on this machine yet"
                )
        except HumanCeremonyCliError as error:
            raise RuntimeError_(error.reason, "the vault could not be unlocked")

    # -- readiness ------------------------------------------------------

    async def status_snapshot(self) -> StatusSnapshot:
        """Compose every readiness layer, keeping each one separately falsifiable."""

        from finishup.adapters.integrations.codex_plugin import inspect_plugin
        from finishup.ports.integrations import (
            IntegrationError,
            IntegrationScope,
            IntegrationTarget,
        )

        root = self.project_root()
        harnesses = self.discover_harnesses()
        layers: list[ReadinessLayer] = []

        detected = bool(harnesses)
        layers.append(
            ReadinessLayer(
                "harness_detected",
                "Harness detected",
                LayerState.VERIFIED if detected else LayerState.NOT_CONFIGURED,
                detail=harnesses[0].label if detected else "no supported agent installation found",
            )
        )

        mcp_state: str | None = None
        mcp_legacy = "none"
        if detected:
            try:
                mcp_state, mcp_legacy = await self.mcp_registration(harnesses[0])
            except RuntimeError_ as error:
                mcp_state = None
                layers.append(
                    ReadinessLayer(
                        "mcp_registered", "MCP registered", LayerState.UNKNOWN, error.reason
                    )
                )
        if mcp_state is not None:
            registered = mcp_state in {_OWNED, "foreign_present"}
            legacy_text = _codex_legacy_registration_text(mcp_legacy)
            layers.append(
                ReadinessLayer(
                    "mcp_registered",
                    "MCP registered",
                    LayerState.VERIFIED if registered else LayerState.NOT_CONFIGURED,
                    detail=mcp_state if legacy_text is None else f"{mcp_state}, {legacy_text}",
                )
            )
            layers.append(
                ReadinessLayer(
                    "mcp_verified",
                    "MCP verified",
                    LayerState.VERIFIED
                    if mcp_state == _OWNED
                    else (
                        LayerState.BLOCKED
                        if mcp_state == "foreign_present"
                        else LayerState.NOT_CONFIGURED
                    ),
                    detail="a connection FinishUP does not own holds this name"
                    if mcp_state == "foreign_present"
                    else "",
                )
            )
        elif not detected:
            layers.append(
                ReadinessLayer("mcp_registered", "MCP registered", LayerState.NOT_CONFIGURED)
            )
            layers.append(ReadinessLayer("mcp_verified", "MCP verified", LayerState.NOT_CONFIGURED))
        else:
            layers.append(ReadinessLayer("mcp_verified", "MCP verified", LayerState.UNKNOWN))

        if detected and harnesses[0].host != "codex":
            layers.extend(await self._host_plugin_layers(harnesses[0]))
        else:
            try:
                inspection = inspect_plugin(
                    IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root)),
                    codex_version=harnesses[0].reported_version if detected else None,
                )
                presence = str(inspection.presence.value)
                trust_observable = bool(inspection.trust_observable)
            except IntegrationError as error:
                presence = "unknown"
                trust_observable = False
                layers.append(
                    ReadinessLayer(
                        "plugin_installed",
                        "Guidance installed",
                        LayerState.UNKNOWN,
                        error.reason.value,
                    )
                )
            else:
                layers.append(
                    ReadinessLayer(
                        "plugin_installed",
                        "Guidance installed",
                        LayerState.VERIFIED
                        if presence == "installed"
                        else LayerState.NOT_CONFIGURED,
                    )
                )
            layers.append(
                ReadinessLayer(
                    "hooks_installed",
                    "Structural hooks installed",
                    LayerState.VERIFIED
                    if presence == "installed" and trust_observable
                    else (
                        LayerState.UNPROVEN
                        if presence == "installed"
                        else LayerState.NOT_CONFIGURED
                    ),
                )
            )

        consent_active = self._consent_active(root)
        layers.append(
            ReadinessLayer(
                "project_consent",
                "Project consent active",
                LayerState.VERIFIED if consent_active else LayerState.NOT_CONFIGURED,
            )
        )
        layers.append(self._policy_digest_layer(root))

        vault = await self.vault_posture()
        layers.append(
            ReadinessLayer(
                "service_reachable",
                "Local service reachable",
                LayerState.VERIFIED if vault.reachable else LayerState.BLOCKED,
                detail=vault.state or "not running",
            )
        )
        layers.append(
            ReadinessLayer(
                "vault_ready",
                "Vault ready",
                LayerState.VERIFIED
                if vault.ready
                else (LayerState.UNPROVEN if vault.reachable else LayerState.UNKNOWN),
                detail=vault.vault_mode or "",
            )
        )
        layers.append(
            ReadinessLayer(
                "local_checks",
                "Local checks",
                LayerState.VERIFIED if vault.ready else LayerState.UNPROVEN,
                detail="" if vault.ready else "the local service must be ready first",
            )
        )

        provider = await self.provider_posture()
        privacy = await self.privacy_posture()
        layers.extend(self._provider_layers(provider, privacy))

        # The control protocol has no task-listing operation. These values mean
        # work is unreadable here; they are not a claim that the task list is empty.
        open_work, open_findings, readable = 0, 0, False
        return StatusSnapshot(
            project_root=str(root),
            layers=tuple(layers),
            privacy=privacy,
            open_work=open_work,
            open_findings=open_findings,
            work_readable=readable,
        )

    def _consent_active(self, root: Path) -> bool:
        try:
            from finishup.adapters.integrations.observation_local import LocalObservationStore

            store = LocalObservationStore()
            consent = store.consent_for(store.workspace_commitment(str(root)))
        except Exception:
            return False
        return consent is not None and bool(consent.active)

    def _policy_digest_layer(self, root: Path) -> ReadinessLayer:
        from finishup.cli.setup import check_policy_preview

        preview = check_policy_preview(root)
        if preview.get("outcome") == "ambiguous":
            # Neither policy is proposed or trusted while both exist; "declares no approved
            # checks" would hide the one action that fixes it.
            return ReadinessLayer(
                "policy_digest_trusted",
                "Approved-check policy trusted",
                LayerState.NOT_CONFIGURED,
                detail=_POLICY_AMBIGUOUS_TEXT,
            )
        digest = preview.get("policy_digest")
        if not isinstance(digest, str):
            return ReadinessLayer(
                "policy_digest_trusted",
                "Approved-check policy trusted",
                LayerState.NOT_CONFIGURED,
                detail="this project declares no approved checks",
            )
        try:
            from finishup.adapters.integrations.observation_local import LocalObservationStore

            store = LocalObservationStore()
            commitment = store.workspace_commitment(str(root))
            trusted = store.policy_digest_is_trusted(commitment, digest)
        except Exception:
            return ReadinessLayer(
                "policy_digest_trusted", "Approved-check policy trusted", LayerState.UNKNOWN
            )
        return ReadinessLayer(
            "policy_digest_trusted",
            "Approved-check policy trusted",
            LayerState.VERIFIED if trusted else LayerState.UNPROVEN,
            detail="" if trusted else "the project policy bytes changed since approval",
        )

    def _provider_layers(
        self, provider: ProviderPosture, privacy: PrivacyPosture
    ) -> tuple[ReadinessLayer, ...]:
        return (
            ReadinessLayer(
                "provider_binding",
                "Provider binding saved",
                LayerState.VERIFIED if provider.endpoint_bound else LayerState.NOT_CONFIGURED,
                detail=f"{provider.provider_id or ''} {provider.model or ''}".strip(),
            ),
            ReadinessLayer(
                "credential_stored",
                "Credential stored",
                LayerState.VERIFIED
                if provider.credential_connected is True
                else (
                    LayerState.UNKNOWN
                    if provider.credential_connected is None
                    else LayerState.NOT_CONFIGURED
                ),
            ),
            # Deliberately never inferred from a stored credential.
            ReadinessLayer(
                "provider_transport_tested",
                "Provider connection tested",
                LayerState.VERIFIED if provider.transport_tested else LayerState.UNPROVEN,
                detail="" if provider.transport_tested else "no live probe has run",
            ),
            ReadinessLayer(
                "semantic_evaluator",
                "Deeper-review evaluator composed",
                LayerState.VERIFIED if provider.semantic_ready else LayerState.NOT_CONFIGURED,
            ),
            ReadinessLayer(
                "privacy_permission",
                "Privacy permits external review",
                LayerState.VERIFIED
                if privacy.llm_inference_enabled is True
                else (
                    LayerState.UNKNOWN
                    if privacy.llm_inference_enabled is None
                    else LayerState.NOT_CONFIGURED
                ),
                detail=privacy.summary,
            ),
            # What the reviewer may learn of the user's request (issue #908). Policy-level only:
            # which task holds a statement, and its source, is on that task's receipt.
            ReadinessLayer(
                "task_statement_review",
                "Privacy sends the task statement",
                LayerState.UNKNOWN
                if privacy.task_statement_sent is None
                else (
                    LayerState.VERIFIED
                    if privacy.task_statement_sent
                    else LayerState.NOT_CONFIGURED
                ),
                detail=privacy.task_statement_disclosure or "",
            ),
            ReadinessLayer(
                "semantic_review_ready",
                "Deeper review ready",
                LayerState.VERIFIED if provider.semantic_ready else LayerState.NOT_CONFIGURED,
                detail="" if provider.semantic_ready else "external review is off",
            ),
            # Deliberately its own layer rather than folded into the one above: the installation
            # can be ready while the registered agent route cannot dispatch, and reporting one
            # verdict for both would make a strict registration read as a broken installation.
            ReadinessLayer(
                "agent_route_review_ready",
                "Codex agent route permits deeper review",
                LayerState.UNKNOWN
                if provider.agent_route_semantic_ready is None
                else (
                    LayerState.VERIFIED
                    if provider.agent_route_semantic_ready
                    else LayerState.NOT_CONFIGURED
                ),
                detail=_agent_route_detail(provider),
            ),
            # Host admission is the owner's per-host, per-repository decision to let an
            # automatic reviewer admit the check (issue #467). Its own layer, because a ready
            # installation with no admission is exactly the state where a Claude auto-mode,
            # Codex auto_review, or Cursor Auto-review session holds every AI-powered check.
            ReadinessLayer(
                "host_admission",
                "Host auto-review admits the AI-powered check",
                _host_admission_layer_state(provider),
                detail=_host_admission_detail(provider),
            ),
            # The owner's background-advice switch (issue #888). Even when on it is only
            # unproven: the service schedules advice only while a provider is usable (#923).
            ReadinessLayer(
                "background_advice",
                "Background AI-powered advice",
                LayerState.UNKNOWN
                if provider.background_advice_enabled is None
                else (
                    LayerState.UNPROVEN
                    if provider.background_advice_enabled
                    else LayerState.NOT_CONFIGURED
                ),
                detail=_background_advice_detail(provider),
            ),
        )

    # -- the six canonical operations ----------------------------------

    async def open_task(self, title: str) -> WorkDetail:
        """Open an exact session selector, keeping display labels out of routing."""

        from finishup.protocol.ids import IdKind, validate_id
        from finishup.protocol.models import StartRequestModel

        prior = self._sessions.get(title)
        selector = title if prior is None else prior.session_id
        try:
            validate_id(IdKind.SESSION, selector)
        except ValueError as exc:
            raise RuntimeError_("session_selector_required", "enter the task's session ID") from exc
        request = StartRequestModel.model_validate(
            {
                **self._workflow_identity(),
                "mode": "attach",
                "session_id": selector,
                "task_title": "Terminal task view",
                "requested_view": "compact",
            }
        )
        async with self._client() as client:
            result = await client.start(request)
            success = self._unwrap(result, "that task could not be opened")
            session = _WorkSession(
                task_id=str(success.task_id),
                session_id=str(success.session_id),
                writer_id=str(success.writer_id),
                frontier=success.frontier,
            )
            self._sessions[title] = session
            if title not in self._opened_titles:
                self._opened_titles.append(title)
            compact = success.compact
            closure = await self._closure_readiness(client, session)
        return replace(self._work_detail(title, session, compact), **closure)

    async def _closure_readiness(self, client: Any, session: _WorkSession) -> dict[str, Any]:
        """Read the closure checklist for an opened task; never fabricate a clean answer.

        The panel renders the same service-derived lines as ``finishup status`` (issue #913). A read
        that fails leaves the panel saying readiness is unknown rather than implying it is done.
        """

        from finishup.cli.render import render_closure_readiness_lines
        from finishup.protocol.models import StatusRequestModel, StatusSuccessModel
        from finishup.protocol.readiness_text import readiness_directive

        request = StatusRequestModel.model_validate(
            {
                **self._workflow_identity(),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "compact",
                "limit": "1",
            }
        )
        unknown: dict[str, Any] = {
            "closure": ("Closure: unknown", readiness_directive("unknown")),
            "closure_state": "unknown",
        }
        try:
            result = await client.status(request)
        except Exception:  # noqa: BLE001 - a secondary read; the panel says unknown instead
            return unknown
        success = getattr(result, "root", None)
        if type(success) is not StatusSuccessModel or success.closure_readiness.state is None:
            return unknown
        return {
            "closure": render_closure_readiness_lines(success.closure_readiness),
            "closure_state": success.closure_readiness.state,
        }

    async def task_status(
        self,
        title: str,
        view: Literal["lineage", "project", "findings"],
        *,
        cursor: str | None = None,
    ) -> TaskStatusPage:
        """Render the same service projection used by MCP and the CLI.

        The ``findings`` view is the task's to-do list (issue #905): every item with its one
        state, verified rows included, rendered by the CLI's own checklist lines.
        """

        from finishup.cli.render import render_human_status
        from finishup.protocol.models import StatusRequestModel

        session = self._sessions.get(title)
        if session is None:
            raise RuntimeError_("task_not_open", "open the task first")
        request = StatusRequestModel.model_validate(
            {
                **self._workflow_identity(),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": view,
                "limit": "50",
                "cursor": cursor,
                **({"filter": {"include_resolved": True}} if view == "findings" else {}),
            }
        )
        async with self._client() as client:
            result = await client.status(request)
        success = self._unwrap(result, "the task view could not be read")
        session.frontier = success.head_frontier
        return TaskStatusPage(
            tuple(render_human_status(success).splitlines()), success.page.next_cursor
        )

    def _work_detail(self, title: str, session: _WorkSession, compact: object) -> WorkDetail:
        coverage = getattr(compact, "coverage", None)
        gaps = tuple(str(item) for item in getattr(coverage, "known_gaps", ()) or ())
        open_obligation_count = getattr(compact, "open_obligation_count", None)
        item = WorkItem(
            subject_id=session.task_id,
            title=title,
            state=str(getattr(compact, "ledger_freshness", "unknown")),
            open_findings=int(getattr(compact, "unanswered_finding_count", 0)),
            last_check="not run in this session",
            updated=str(getattr(session.frontier, "sequence", "")),
        )
        return WorkDetail(
            item=item,
            evidence_count=(None if open_obligation_count is None else int(open_obligation_count)),
            coverage=gaps or ("no gaps recorded",),
            limitations=tuple(str(code) for code in getattr(compact, "gaps", ()) or ()),
            receipt_available=False,
        )

    async def check_progress(self, title: str) -> TaskStatusPage:
        """Read the latest check's operation page, including structural review progress."""

        from finishup.cli.render import render_human_status
        from finishup.protocol.models import StatusRequestModel

        session = self._sessions.get(title)
        if session is None:
            raise RuntimeError_("task_not_open", "open the task first")
        request_id = self._check_request_ids.get(title)
        if request_id is None:
            raise RuntimeError_("check_not_started", "run a check for this task first")
        request = StatusRequestModel.model_validate(
            {
                **self._workflow_identity(),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": request_id},
            }
        )
        async with self._client() as client:
            result = await client.status(request)
        success = self._unwrap(result, "the check progress could not be read")
        return TaskStatusPage(tuple(render_human_status(success).splitlines()), None)

    async def run_check(self, title: str, mode: CheckMode) -> tuple[str, tuple[str, ...]]:
        """Run one check in the requested mode and report it without softening."""

        from finishup.protocol.models import CheckAwaitingHumanModel, CheckRequestModel

        session = self._sessions.get(title)
        if session is None:
            raise RuntimeError_("task_not_open", "open the task first")
        pending = self._pending_checks.get(title)
        request = (
            pending
            if isinstance(pending, CheckRequestModel)
            else CheckRequestModel.model_validate(
                {
                    **self._workflow_identity(),
                    "session_id": session.session_id,
                    "writer_id": session.writer_id,
                    "expected_frontier": self._frontier(session),
                    "mode": mode.value,
                }
            )
        )
        self._check_request_ids[title] = str(request.request_id)
        async with self._client() as client:
            result = await client.check(request)
        success = self._unwrap(result, "the check could not be completed")
        session.frontier = success.result_frontier
        from finishup.cli.render import render_human_awaiting_human, render_human_check

        if isinstance(success, CheckAwaitingHumanModel):
            self._pending_checks[title] = request
            return success.state, tuple(render_human_awaiting_human(success).splitlines())
        self._pending_checks.pop(title, None)
        return str(success.verdict), tuple(render_human_check(success).splitlines())

    async def build_receipt(
        self, title: str, output_format: str, *, owner_view: bool = False
    ) -> ReceiptSummary:
        """Build the agent-facing receipt, or with ``owner_view`` the owner's full one.

        The owner view runs the human-control reauthentication ceremony for this exact request
        on this client's own connection, so the caller must already have handed the terminal
        over (``hand_over_terminal``); the service, not this process, decides.
        """

        from finishup.cli.render import render_human_receipt
        from finishup.protocol.canonical import canonical_encode
        from finishup.protocol.coverage import CheckType
        from finishup.protocol.models import ReceiptRequestModel

        session = self._sessions.get(title)
        if session is None:
            raise RuntimeError_("task_not_open", "open the task first")
        request = ReceiptRequestModel.model_validate(
            {
                **self._workflow_identity(),
                "task_id": session.task_id,
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": self._frontier(session),
                "format": output_format,
                "include": "full" if owner_view else "standard",
                "redaction_profile": "full_local" if owner_view else "default_local_export",
            }
        )
        async with self._client() as client:
            if owner_view:
                await self._authorize_owner_receipt_view(client, request)
            result = await client.receipt(request)
        success = self._unwrap(result, "the receipt could not be built")
        session.frontier = success.result_frontier
        coverage = getattr(success, "coverage", None)
        gaps = tuple(str(item) for item in getattr(coverage, "known_gaps", ()) or ())
        semantic = CheckType.SEMANTIC_MODEL_DERIVED in success.coverage.check_types
        rendered = (
            canonical_encode(success.document).decode("utf-8")
            if success.document is not None
            else render_human_receipt(success)
        )
        return ReceiptSummary(
            subject_id=session.task_id,
            verdict=str(success.conclusion),
            coverage=gaps or ("no gaps recorded",),
            limitations=gaps,
            semantic_available=semantic,
            freshness=str(getattr(coverage, "ledger_freshness", "unknown")),
            rendered_lines=tuple(rendered.splitlines()),
            verified=("local checks recorded in this receipt",),
            not_verified=("external AI-powered review did not contribute to this receipt",),
        )

    async def _authorize_owner_receipt_view(self, client: Any, request: object) -> None:
        from finishup.cli.unlock import HumanCeremonyCliError, authorize_owner_receipt_view
        from finishup.service.confidential_client import ConfidentialClientError

        try:
            await authorize_owner_receipt_view(client.owner_receipt_view_target(request))
        except (ConfidentialClientError, HumanCeremonyCliError) as error:
            reason = error.reason
            if reason in {"presence_unavailable", "reauthentication_unavailable"}:
                raise RuntimeError_(
                    "owner_view_unavailable",
                    "FinishUP cannot confirm it is you on this installation (no vault passphrase, "
                    "and no Touch ID or login-password dialog could be shown), so the full "
                    "receipt stays closed; the ordinary receipt is unchanged",
                ) from error
            if reason in {"presence_refused", "presence_timeout"}:
                raise RuntimeError_(
                    "owner_view_refused",
                    "the system confirmation was cancelled, did not confirm it is you, or was "
                    "not answered in time; nothing was shown",
                ) from error
            if reason == "passphrase_in_credential_store":
                raise RuntimeError_(
                    "owner_view_unavailable",
                    "no system dialog can be shown here and this vault's passphrase may be kept "
                    "in the system credential store (or the store could not be read), so the "
                    "full receipt stays closed; if you chose "
                    "that passphrase yourself, run 'finishup receipt --owner-view --use-passphrase'",
                ) from error
            if reason == "ceremony_busy":
                raise RuntimeError_(
                    "owner_view_busy",
                    "another confirmation is already open, perhaps one an agent started; if a "
                    "system dialog is on screen it is not for this request, so cancel it; if "
                    "nothing is on screen, 'finishup service restart' ends it; then try again",
                ) from error
            if reason == "passphrase_rate_limited":
                raise RuntimeError_(
                    "owner_view_refused",
                    "too many wrong passphrases, so FinishUP waits up to five minutes before "
                    "accepting another; restarting the service does not clear this wait",
                ) from error
            if reason == "reauthentication_rate_limited":
                raise RuntimeError_(
                    "owner_view_refused",
                    "recent confirmations did not succeed, so FinishUP waits up to five minutes "
                    "before asking again; another program may have caused this, and 'finishup "
                    "service restart' clears the wait",
                ) from error
            raise RuntimeError_(reason, "the full receipt was not authorized") from error

    def _frontier(self, session: _WorkSession) -> object:
        frontier = session.frontier
        return {
            "sequence": str(getattr(frontier, "sequence")),
            "head_digest": getattr(frontier, "head_digest"),
        }

    def _workflow_identity(self) -> dict[str, object]:
        from finishup import __version__

        return {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": self._request_id(),
            # Frozen legacy identifier (ADR-048): a recorded actor id and a released client kind.
            "actor": {"actor_id": "yoetz:tui", "actor_type": "human"},
            "client": {"kind": "yoetz_cli", "version": __version__, "integration": "local_cli"},
        }

    def _request_id(self) -> str:
        from finishup.protocol.ids import IdKind, new_id

        return new_id(IdKind.REQUEST)

    def _unwrap(self, result: object, message: str) -> Any:
        payload = getattr(result, "root", getattr(result, "result", result))
        if getattr(payload, "ok", False) is not True:
            error = getattr(payload, "error", None)
            reason = str(getattr(error, "code", "operation_failed"))
            detail = str(getattr(error, "message", message))
            raise RuntimeError_(reason, detail)
        return payload

    # -- package update advisory ----------------------------------------

    async def package_update_advisory(self, *, allow_network: bool = True):
        """Best-effort structural package update advisory for interactive surfaces only.

        Fail closed when policy is unreadable or denies ``update_checks``. Network errors
        yield no tip (or a soft doctor note when the caller is ``doctor``).
        """

        from finishup.application.package_update import resolve_package_update_advisory

        posture = await self.privacy_posture()
        return await resolve_package_update_advisory(
            network_egress_permitted=posture.network_egress_permitted,
            update_checks_enabled="update_checks" in posture.enabled_channels,
            allow_network=allow_network and posture.update_checks_permitted,
        )

    # -- doctor ---------------------------------------------------------

    async def doctor(self) -> DoctorReport:
        """Bounded read-only diagnosis. Never mutates installation state."""

        from finishup import __version__
        from finishup.config.paths import PathSafetyError

        # First: when the installation's folders cannot be chosen (ADR-048), nothing that reads
        # configuration or the service can answer, so only the host facts are gathered.
        folders = _installation_folders_entry()
        folders_blocked = folders.state is LayerState.BLOCKED
        entries: list[DoctorEntry] = []
        supported = (3, 14) <= sys.version_info[:2] < (3, 15)
        entries.append(
            DoctorEntry(
                "runtime",
                "Python runtime",
                LayerState.VERIFIED if supported else LayerState.BLOCKED,
                detail=".".join(str(part) for part in sys.version_info[:3]),
                remediation=""
                if supported
                else "FinishUP requires Python 3.14; reinstall with 'uv tool install finishup'",
            )
        )
        package_detail = __version__
        package_state = LayerState.VERIFIED
        package_remediation = ""
        try:
            advisory = (
                None if folders_blocked else await self.package_update_advisory(allow_network=True)
            )
        except Exception:
            advisory = None
        if advisory is not None and advisory.is_newer and advisory.latest_version is not None:
            package_state = LayerState.UNPROVEN
            package_detail = f"{advisory.installed_version} (available {advisory.latest_version})"
            # Name the launcher this install has on PATH: the transitional ``yoetz``
            # distribution links only ``yoetz`` (ADR-048).
            launcher = (
                LEGACY_LAUNCHER_NAME if advisory.package == LEGACY_LAUNCHER_NAME else LAUNCHER_NAME
            )
            package_remediation = f"{advisory.upgrade_command}  # then re-run {launcher}"
        elif advisory is not None and advisory.outcome == "skipped_unavailable":
            package_state = LayerState.UNPROVEN
            package_detail = f"{__version__} (could not check for updates)"
        entries.append(
            DoctorEntry(
                "package",
                "FinishUP version",
                package_state,
                detail=package_detail,
                remediation=package_remediation,
            )
        )
        entries.extend(_host_entries())
        entries.append(folders)
        if folders_blocked:
            # The installation's folders cannot be chosen (ADR-048), so no readiness layer can
            # be read: report what is known and the one next step, instead of failing outright.
            return DoctorReport(entries=tuple(entries))
        try:
            snapshot = await self.status_snapshot()
        except PathSafetyError as error:
            # A folder failed a path-safety check while readiness was read; the folders entry
            # names it instead of the earlier verdict.
            entries[-1] = _path_refusal_entry(error.reason_code)
            return DoctorReport(entries=tuple(entries))
        remediation = {
            "harness_detected": "install Codex, or use FinishUP locally with /check",
            "mcp_verified": "run /connect to inspect or repair the integration",
            "plugin_installed": "run /connect and choose Repair",
            "service_reachable": "start the service with 'finishup service run'",
            "vault_ready": "run /service and choose Unlock",
            "provider_binding": "run /provider to choose a provider and model",
            "credential_stored": "run /provider to store an API key",
            "privacy_permission": "run /privacy if you want external review",
        }
        for layer in snapshot.layers:
            entries.append(
                DoctorEntry(
                    layer.key,
                    layer.label,
                    layer.state,
                    detail=layer.detail,
                    remediation=remediation.get(layer.key, "")
                    if layer.state in {LayerState.BLOCKED, LayerState.NOT_CONFIGURED}
                    else "",
                )
            )
        return DoctorReport(entries=tuple(entries))


def _connect_failure(error: BaseException) -> RuntimeError_:
    """The bounded TUI failure for a service connection that did not open.

    When the client refused because FinishUP's local folders cannot be used safely (for example
    data under both product names, ADR-048), the closed token and its remedy are the next step;
    an absent service is not, and starting one cannot help.
    """

    from finishup.cli.exits import remediation_message
    from finishup.service.client import path_refusal_reason

    path_reason = path_refusal_reason(error)
    if path_reason is not None:
        remedy = remediation_message(path_reason)
        return RuntimeError_(
            path_reason,
            "FinishUP's local folders cannot be used safely",
            details=() if remedy is None else (remedy,),
        )
    return RuntimeError_(
        str(getattr(error, "reason", "service_unavailable")),
        "the local FinishUP service is not reachable",
    )


def _subscription_error(error: BaseException, message: str) -> RuntimeError_:
    """One bounded subscription failure with its exact next step (#855); never native text."""

    from finishup.cli.codex_subscription import (
        subscription_failure_reason,
        subscription_remediation,
    )

    reason = subscription_failure_reason(error)
    remediation = subscription_remediation(reason)
    return RuntimeError_(reason, message, details=() if remediation is None else (remediation,))
