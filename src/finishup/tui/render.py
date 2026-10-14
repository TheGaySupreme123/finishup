"""Pure renderers for every FinishUP terminal surface.

Rendering is deliberately a function from value objects to lines of text, with
no Textual import anywhere in this module. That buys three things the project
already cares about: the exact wording of a safety-relevant screen can be
snapshot-tested byte for byte, narrow-terminal behaviour can be asserted at any
width without a terminal, and no widget can quietly invent a claim that the
owning service never made.

Wording rules enforced here:

* "verified" appears only for a layer the service reported as verified;
* a stored provider binding is never described as a working provider;
* an unavailable deeper review is rendered as a limitation, never as success.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from finishup.tui.models import (
    Detection,
    DoctorReport,
    HarnessOption,
    IntegrationPlan,
    LayerState,
    ProviderOption,
    ProviderPosture,
    ReadinessLayer,
    ReceiptSummary,
    StatusSnapshot,
    WorkDetail,
)
from finishup.tui.symbols import Level, symbol_for
from finishup.tui.text import middle_truncate, truncate, wrap

__all__ = [
    "MIN_ASCII_WIDTH",
    "render_detection",
    "render_doctor",
    "render_finish",
    "render_integration_preview",
    "render_integration_technical_details",
    "render_layers",
    "render_provider_stored",
    "render_receipt",
    "render_session_header",
    "render_status",
    "render_welcome",
    "closure_level",
    "render_work_detail",
    "finishup_mark",
]

_MIN_VALUE_COLUMN = 12
"""Below this the label/value listing stacks instead of shrinking the value."""

MIN_ASCII_WIDTH = 52
"""Below this width the wordmark is dropped rather than wrapped into noise."""

_MARK = (
    "  _   _  ___  ___ _____ ____",
    " | | | |/ _ \\| __|_   _|_  /",
    " | |_| | (_) | _|  | |  / /",
    "  \\__, |\\___/|___| |_| /___|",
    "  |___/",
)


def finishup_mark(width: int) -> tuple[str, ...]:
    """Return the wordmark when the terminal can hold it, otherwise nothing."""

    if width < MIN_ASCII_WIDTH:
        return ()
    return _MARK


def _bullet(level: Level, text: str) -> str:
    return f"{symbol_for(level)} {text}"


def _option_row(index: int, label: str, *, selected: bool, disabled: bool = False) -> str:
    marker = symbol_for(Level.SELECTED) if selected else " "
    suffix = "  (not available)" if disabled else ""
    return f"{marker} {index}. {label}{suffix}"


def _indent(lines: Iterable[str], *, width: int = 4) -> tuple[str, ...]:
    pad = " " * width
    return tuple(f"{pad}{line}" for line in lines)


def _describe(description: str, width: int) -> tuple[str, ...]:
    return _indent(wrap(description, max(width - 5, 12)), width=5)


def _labelled(
    rows: Sequence[tuple[str, str]],
    width: int,
    *,
    gap: int = 5,
    paths: Sequence[str] = (),
) -> tuple[str, ...]:
    """Align a label/value listing that is guaranteed to fit ``width``.

    The value column is sized from what is actually left after the labels, so a
    long project path is shortened to fit rather than pushing the line off the
    edge. Rows named in ``paths`` keep their head and tail; everything else is
    clipped from the right.

    When the labels leave too little room to say anything useful — a very narrow
    terminal — the listing stacks instead, putting each value on its own indented
    line rather than shrinking it to a stub.
    """

    if not rows:
        return ()
    label_width = max(len(label) for label, _ in rows)
    available = width - label_width - gap

    def shorten(label: str, value: str, room: int) -> str:
        return middle_truncate(value, room) if label in paths else truncate(value, room)

    if available < _MIN_VALUE_COLUMN:
        lines: list[str] = []
        for label, value in rows:
            lines.append(truncate(label, width))
            lines.append(f"  {shorten(label, value, max(width - 2, 4))}".rstrip())
        return tuple(lines)
    return tuple(
        f"{label.ljust(label_width)}{' ' * gap}{shorten(label, value, available)}".rstrip()
        for label, value in rows
    )


# ---------------------------------------------------------------------------
# First run
# ---------------------------------------------------------------------------


def render_welcome(width: int) -> tuple[str, ...]:
    """The opening lines: what FinishUP is, before it asks for anything."""

    body = max(width - 2, 24)
    lines: list[str] = []
    mark = finishup_mark(width)
    if mark:
        lines.extend(mark)
        lines.append("")
    lines.extend(wrap("Welcome to FinishUP, honest verification for agent work", body))
    lines.append("")
    lines.extend(
        wrap(
            "FinishUP records important claims, evidence, checks, and open questions. "
            "It tells you what was verified and what remains uncertain.",
            max(width - 2, 24),
        )
    )
    return tuple(lines)


def render_detection(detection: Detection, width: int) -> tuple[str, ...]:
    """What was found on this machine, before any change is proposed."""

    lines: list[str] = ["Detected:"]
    if detection.harnesses:
        for harness in detection.harnesses:
            # The label already names the version when one was reported; repeating it
            # printed "Codex CLI 0.153.4 0.153.4" (issue #766).
            text = harness.label
            if harness.reported_version is None:
                text = f"{text} ({harness.version_text})"
            lines.append(_bullet(Level.VERIFIED, text))
    else:
        lines.append(_bullet(Level.OPTIONAL, "No supported agent installation found"))
    if detection.project_name is not None:
        kind = "Git project" if detection.is_git_repository else "Project folder"
        lines.append(_bullet(Level.VERIFIED, f"{kind}: {detection.project_name}"))
    else:
        lines.append(_bullet(Level.OPTIONAL, "No project detected in this folder"))
    if detection.secure_storage_available:
        lines.append(_bullet(Level.VERIFIED, "System secure storage"))
    else:
        reason = detection.secure_storage_reason
        lines.append(
            _bullet(
                Level.OPTIONAL,
                "System secure storage is not available here" + (f" — {reason}" if reason else ""),
            )
        )
    if detection.already_connected:
        lines.append(_bullet(Level.VERIFIED, "FinishUP is connected to this project"))
    else:
        lines.append(_bullet(Level.OPTIONAL, "FinishUP is not connected yet"))
    return tuple(truncate(line, width) for line in lines)


def render_harness_choices(
    options: Sequence[HarnessOption], selected: int, width: int
) -> tuple[str, ...]:
    """Friendly labels first; the executable path stays behind the selection."""

    lines: list[str] = []
    for index, option in enumerate(options):
        is_selected = index == selected
        lines.append(_option_row(index + 1, option.label, selected=is_selected))
        lines.extend(_describe(option.description, width))
        if is_selected:
            lines.extend(
                _indent((middle_truncate(option.executable_path, max(width - 6, 16)),), width=5)
            )
    return tuple(lines)


def render_project_trust(detection: Detection, width: int) -> tuple[str, ...]:
    """Explain what trusting this project actually permits, then ask."""

    root = detection.project_root or detection.cwd
    prefix = f"{symbol_for(Level.ACTIVE)} You are in "
    lines = [prefix + middle_truncate(root, max(width - len(prefix), 8))]
    lines.append("")
    lines.extend(
        wrap(
            "Connecting FinishUP will allow project-local guidance and structural "
            "event hooks to load from this repository.",
            max(width - 2, 24),
        )
    )
    if detection.launched_from_subdirectory:
        lines.append("")
        lines.extend(
            wrap(
                "You started FinishUP in a subfolder. Trust applies to the whole "
                "repository root shown above, not just this folder.",
                max(width - 2, 24),
            )
        )
    lines.append("")
    lines.extend(wrap("Do you trust the contents of this project?", max(width - 2, 24)))
    return tuple(lines)


def render_integration_preview(plan: IntegrationPlan, width: int) -> tuple[str, ...]:
    """The exact proposed change, in words, before anything is applied."""

    body = max(width - 2, 24)
    lines: list[str] = [*wrap("Would you like to connect FinishUP to this project?", body), ""]
    lines.append("Codex installation")
    version = f" {plan.reported_version}" if plan.reported_version else ""
    lines.append(f"  {plan.harness_label}{version}")
    lines.append("")
    lines.append("Project changes")
    for change in plan.changes:
        lines.extend(_indent(wrap(f"+ {change}", body - 2), width=2))
    if plan.already_registered:
        lines.append("  · The MCP server is already registered; it will be verified, not replaced")
    lines.append("")
    lines.append("Safety")
    for note in (
        "No repository contents are uploaded during setup",
        "No API key is written to the project",
        "External LLM review remains off",
        "A foreign MCP entry will never be replaced",
    ):
        lines.extend(_indent(wrap(f"· {note}", body - 2), width=2))
    return tuple(lines)


def render_integration_technical_details(plan: IntegrationPlan, width: int) -> tuple[str, ...]:
    """Everything the friendly preview deliberately kept out of the way."""

    rows = [
        ("Codex executable", plan.executable_path),
        ("Explicit Codex home", plan.codex_home),
        ("Discovered Codex version", plan.reported_version or "unknown"),
        ("Probed activation version", plan.activation_codex_version),
        ("Project root", plan.project_root),
        ("MCP server name", plan.mcp_server_name),
        ("MCP command", plan.mcp_command),
        ("MCP isolation root", plan.mcp_isolated_root or "ambient"),
        ("MCP preview digest", plan.preview_digest),
        ("Skill preview digest", plan.skill_preview_digest),
        ("Activation preview digest", plan.activation_preview_digest),
        ("Plugin source-tree digest", plan.activation_plugin_source_digest),
        ("Marketplace target", plan.activation_marketplace_path),
        ("Selected Codex config", plan.activation_config_path),
        ("Policy digest", plan.policy_digest or "no project policy file"),
        ("Planned files", str(plan.planned_file_count)),
        ("Registration state", plan.state_before),
    ]
    lines = list(
        _labelled(
            rows,
            width,
            gap=2,
            paths=(
                "Codex executable",
                "Explicit Codex home",
                "Project root",
                "Marketplace target",
                "Selected Codex config",
            ),
        )
    )
    lines.append("")
    lines.append("Exact activation approval facts")

    def exact(label: str, value: str) -> None:
        lines.append(label)
        lines.extend(_indent(wrap(value, max(width - 2, 4)), width=2))

    for label, value in (
        ("Codex executable", plan.executable_path),
        ("Codex home", plan.codex_home),
        ("Marketplace", plan.activation_marketplace_path),
        ("Codex config", plan.activation_config_path),
        ("Plugin cache/install target", plan.activation_plugin_install_path),
        ("Probed Codex version", plan.activation_codex_version),
        ("Executable digest", plan.activation_executable_digest),
        ("Plugin source-tree digest", plan.activation_plugin_source_digest),
        ("Plugin install-tree digest", plan.activation_plugin_install_digest),
        ("Marketplace preimage digest", plan.activation_marketplace_preimage_digest),
        ("Config preimage digest", plan.activation_config_preimage_digest),
        (
            "Canonical installed inventory verified before approval",
            "yes" if plan.activation_inventory_verified else "no",
        ),
        (
            "Plugin cache mutation planned",
            "yes" if plan.activation_cache_mutation_planned else "no",
        ),
        ("Version probe environment", plan.activation_probe_environment),
    ):
        # Unlike the compact summary above, these approval-relevant identities are wrapped
        # without ellipsis: every character remains visible even on a narrow terminal.
        exact(label, value)
    lines.append("Forced activation environment")
    for name, value in plan.activation_environment:
        exact(name, value)
    lines.append("Exact activation command argv")
    for label, command in (
        ("Version probe", plan.activation_probe_command),
        ("Inventory", plan.activation_inventory_command),
        ("Install", plan.activation_install_command),
    ):
        exact(label, repr((plan.executable_path, *command)))
    lines.append("")
    lines.append("Exact activation bytes")
    # ``split("\n")`` rather than ``splitlines()``: these lines mirror the exact
    # digest-bound bytes, so a trailing newline must stay visible as a blank line.
    lines.extend(_indent(tuple(plan.activation_marketplace_text.split("\n")), width=2))
    if plan.activation_config_block:
        lines.extend(_indent(tuple(plan.activation_config_block.split("\n")), width=2))
    else:
        lines.extend(_indent(("(config already active; no byte change)",), width=2))
    lines.extend(
        _indent(
            (
                "Standing trust: this plugin remains enabled for future sessions using this "
                "Codex home until you disable or remove it.",
            ),
            width=2,
        )
    )
    if plan.planned_check_ids:
        lines.append("")
        lines.append("Proposed approved checks")
        lines.extend(_indent(plan.planned_check_ids, width=2))
    if plan.managed_paths:
        lines.append("")
        lines.append("Managed paths")
        lines.extend(
            _indent(
                tuple(middle_truncate(path, max(width - 4, 20)) for path in plan.managed_paths),
                width=2,
            )
        )
    return tuple(lines)


def render_foreign_entry(detail: str, width: int) -> tuple[str, ...]:
    """A safety block, stated as a block. There is no force-replace path."""

    body = max(width - 2, 24)
    lines = [_bullet(Level.BLOCKED, "Could not register FinishUP with Codex"), ""]
    lines.extend(
        wrap(
            'The name "finishup" is already used by a connection that this installation does not own.',
            body,
        )
    )
    lines.append("")
    lines.append("Nothing was replaced or removed.")
    if detail:
        lines.append("")
        lines.extend(wrap(detail, body))
    return tuple(lines)


def render_finish(snapshot: StatusSnapshot, width: int) -> tuple[str, ...]:
    """The closing summary. Only verified layers are allowed a green tick."""

    lines = [_bullet(Level.VERIFIED, "FinishUP is ready"), ""]
    rows: list[tuple[str, str]] = []
    for key, label in (
        ("mcp_verified", "Codex connection"),
        ("service_reachable", "Local service"),
        ("vault_ready", "Secure storage"),
        ("local_checks", "Local checks"),
        ("semantic_review_ready", "External review"),
    ):
        layer = snapshot.layer(key)
        if layer is not None:
            rows.append((label, _finish_word(layer)))
    rows.append(("Privacy", snapshot.privacy.summary))
    lines.extend(_labelled(rows, width))
    lines.append("")
    body = max(width - 2, 24)
    if snapshot.privacy.llm_inference_enabled is not True:
        lines.extend(wrap("Nothing is being sent to an external review model.", body))
    else:
        lines.extend(wrap("External review is permitted by your current privacy choice.", body))
    lines.append("")
    lines.extend(
        wrap(
            "To get started, ask Codex to use FinishUP on its next task or try one of these commands:",
            max(width - 2, 24),
        )
    )
    lines.extend(("/status", "/work", "/receipt", "/privacy", "/provider"))
    return tuple(lines)


def _finish_word(layer: ReadinessLayer) -> str:
    if layer.state is LayerState.VERIFIED:
        return "verified" if layer.key.endswith("verified") else "ready"
    if layer.state is LayerState.NOT_CONFIGURED:
        return "off" if layer.key == "semantic_review_ready" else "not configured"
    if layer.state is LayerState.BLOCKED:
        return "blocked"
    if layer.state is LayerState.UNKNOWN:
        return "unknown"
    return "not proven"


# ---------------------------------------------------------------------------
# Post-install surfaces
# ---------------------------------------------------------------------------


def render_session_header(
    *,
    version: str,
    project_root: str,
    harness_state: str,
    privacy_summary: str,
    width: int,
) -> tuple[str, ...]:
    """The compact session header. One of the few boxed surfaces."""

    inner = max(min(width, 78) - 4, 24)
    rows = _labelled(
        (
            ("project:", project_root),
            ("Codex:", harness_state),
            ("review:", f"{privacy_summary}   /privacy to change"),
        ),
        inner,
        gap=2,
        paths=("project:",),
    )
    return (f">_ FinishUP (v{version})", "", *rows)


def render_layers(layers: Sequence[ReadinessLayer], width: int) -> tuple[str, ...]:
    """One line per readiness layer, never merged into a single verdict."""

    label_width = max((len(layer.label) for layer in layers), default=0)
    lines: list[str] = []
    for layer in layers:
        word = _state_word(layer)
        text = f"{layer.label.ljust(label_width)}  {word}"
        if layer.detail:
            text = f"{text} — {layer.detail}"
        lines.append(truncate(f"{symbol_for(layer.level)} {text}", width))
    return tuple(lines)


def _state_word(layer: ReadinessLayer) -> str:
    return {
        LayerState.VERIFIED: "verified",
        LayerState.UNPROVEN: "not proven",
        LayerState.NOT_CONFIGURED: "not configured",
        LayerState.BLOCKED: "blocked",
        LayerState.UNKNOWN: "unknown",
    }[layer.state]


def render_status(snapshot: StatusSnapshot, width: int) -> tuple[str, ...]:
    """The ``/status`` transcript entry: readable first, exact underneath."""

    rows: list[tuple[str, str]] = [("Project", snapshot.project_root)]
    for key, label in (
        ("harness_detected", "Codex"),
        ("mcp_verified", "Project integration"),
        ("service_reachable", "Local service"),
        ("vault_ready", "Secure storage"),
        ("local_checks", "Local checks"),
        ("semantic_review_ready", "External review"),
    ):
        layer = snapshot.layer(key)
        if layer is not None:
            rows.append((label, _status_word(layer)))
    rows.append(("Privacy", snapshot.privacy.summary))
    if snapshot.work_readable:
        task_word = "task" if snapshot.open_work == 1 else "tasks"
        rows.append(("Open work", f"{snapshot.open_work} {task_word}"))
        rows.append(("Open findings", str(snapshot.open_findings)))
    else:
        rows.append(("Open work", "unavailable — the local service could not be read"))
    lines = list(_labelled(rows, width, paths=("Project",)))
    lines.append("")
    body = max(width - 2, 24)
    if snapshot.privacy.llm_inference_enabled is True:
        lines.extend(wrap("External review is permitted by your current privacy choice.", body))
    elif snapshot.privacy.readable:
        lines.extend(wrap("Nothing is leaving this computer.", body))
    else:
        lines.extend(wrap("The privacy policy could not be read, so no claim is made here.", body))
    return tuple(lines)


def _status_word(layer: ReadinessLayer) -> str:
    if layer.key == "harness_detected":
        return "connected" if layer.state is LayerState.VERIFIED else _state_word(layer)
    if layer.key == "vault_ready" and layer.state is LayerState.VERIFIED:
        return "unlocked"
    if layer.key == "semantic_review_ready" and layer.state is LayerState.NOT_CONFIGURED:
        return "off"
    if layer.key in {"service_reachable", "local_checks"} and layer.state is LayerState.VERIFIED:
        return "ready"
    return _state_word(layer)


# ---------------------------------------------------------------------------
# Provider and privacy
# ---------------------------------------------------------------------------


def render_provider_endpoint(option: ProviderOption, model: str, width: int) -> tuple[str, ...]:
    """The endpoint and posture shown before any credential is requested."""

    rows = [
        ("Provider", option.label),
        ("Model", model),
        ("Endpoint", option.endpoint_text),
        ("Request style", option.api_style),
        ("Endpoint profile", f"{option.endpoint_profile_id} {option.endpoint_profile_version}"),
    ]
    lines = list(_labelled(rows, width, gap=4))
    lines.append("")
    lines.extend(
        wrap(
            "Storing a key here does not switch external review on. "
            "Your privacy choice still decides what may leave this computer.",
            max(width - 2, 24),
        )
    )
    return tuple(lines)


def render_provider_stored(posture: ProviderPosture, width: int) -> tuple[str, ...]:
    """Separate what was saved from what was proven. They are not the same."""

    lines = [
        _bullet(Level.VERIFIED, "Provider binding saved"),
        _bullet(
            Level.VERIFIED,
            (
                "Codex-managed ChatGPT login is available"
                if posture.credential_authority == "external_runtime_oauth"
                else "API key stored securely"
            ),
        ),
    ]
    if posture.transport_tested:
        lines.append(_bullet(Level.VERIFIED, "Live provider connection responded"))
    else:
        lines.append(_bullet(Level.UNPROVEN, "Live provider connection has not been tested"))
    if posture.semantic_ready:
        lines.append(_bullet(Level.VERIFIED, "External AI-powered review is structurally ready"))
    else:
        lines.append(_bullet(Level.UNPROVEN, "External AI-powered review is not yet proven ready"))
    if posture.blockers:
        lines.append("")
        lines.append("Still required:")
        lines.extend(_indent(tuple(f"{name}: {detail}" for name, detail in posture.blockers)))
    return tuple(truncate(line, width) for line in lines)


def render_provider_failure(message: str, width: int) -> tuple[str, ...]:
    """A provider failure never downgrades local-check readiness."""

    body = max(width - 2, 24)
    lines = [_bullet(Level.BLOCKED, "Provider test failed"), ""]
    lines.append("Local FinishUP verification is still ready.")
    lines.append("Your API key remains stored securely.")
    lines.append("")
    lines.append("The provider returned:")
    lines.extend(_indent(wrap(message, body - 2), width=2))
    return tuple(lines)


# ---------------------------------------------------------------------------
# Work, receipts, diagnosis
# ---------------------------------------------------------------------------


def closure_level(state: str | None) -> Level:
    """The glyph for a closure-readiness state; never ``VERIFIED`` (issue #913).

    ``ready`` and ``ready_with_limitations`` mean nothing further to do, and an acknowledged item
    is carried as not done: none of them is an observed postcondition, so they read as limited.
    """

    return Level.ACTIVE if state == "action_required" else Level.UNPROVEN


def render_work_detail(detail: WorkDetail, width: int) -> tuple[str, ...]:
    """One task, expanded into the layers a receipt would report."""

    lines = [truncate(detail.item.title, width), ""]
    lines.extend(
        _labelled(
            (
                ("State", detail.item.state),
                (
                    "Evidence",
                    "unknown" if detail.evidence_count is None else str(detail.evidence_count),
                ),
                ("Open findings", str(detail.item.open_findings)),
                ("Last check", detail.item.last_check),
                ("Frontier sequence", detail.item.updated),
                ("Receipt", "available" if detail.receipt_available else "not available yet"),
            ),
            width,
            gap=4,
        )
    )
    if detail.closure:
        lines.append("")
        lines.append(
            truncate(_bullet(closure_level(detail.closure_state), detail.closure[0]), width)
        )
        lines.extend(
            _indent(
                tuple(line for item in detail.closure[1:] for line in wrap(item, width - 2)),
                width=2,
            )
        )
    for label, items in (
        ("Claims", detail.claims),
        ("Checks", detail.checks),
        ("Coverage", detail.coverage),
        ("Findings", detail.findings),
        ("Limitations", detail.limitations),
    ):
        lines.append("")
        lines.append(label)
        if items:
            lines.extend(_indent(tuple(truncate(item, width - 2) for item in items), width=2))
        else:
            lines.extend(_indent(("none recorded",), width=2))
    return tuple(lines)


def render_receipt(summary: ReceiptSummary, width: int) -> tuple[str, ...]:
    """The human view of a receipt: verdict, then everything qualifying it."""

    if summary.rendered_lines:
        return tuple(line for source in summary.rendered_lines for line in wrap(source, width))
    lines = [f"Verdict: {summary.verdict}", ""]
    lines.append("Coverage")
    lines.extend(_indent(summary.coverage or ("not recorded",), width=2))
    lines.append("")
    lines.append(f"Open findings: {summary.open_findings}")
    lines.append("")
    lines.append("Limitations")
    lines.extend(_indent(summary.limitations or ("none declared",), width=2))
    lines.append("")
    review = "available" if summary.semantic_available else "not available for this receipt"
    lines.append(f"Deeper review: {review}")
    lines.append(f"Freshness: {summary.freshness}")
    lines.append("")
    lines.append("What was verified")
    lines.extend(_indent(summary.verified or ("nothing recorded",), width=2))
    lines.append("")
    lines.append("What was not verified")
    lines.extend(_indent(summary.not_verified or ("nothing recorded",), width=2))
    return tuple(truncate(line, width) for line in lines)


def render_doctor(report: DoctorReport, width: int) -> tuple[str, ...]:
    """A read-only diagnosis with safe next steps and no automatic repair."""

    lines: list[str] = []
    label_width = max((len(entry.label) for entry in report.entries), default=0)
    for entry in report.entries:
        word = {
            LayerState.VERIFIED: "ok",
            LayerState.UNPROVEN: "not proven",
            LayerState.NOT_CONFIGURED: "not configured",
            LayerState.BLOCKED: "problem",
            LayerState.UNKNOWN: "unknown",
        }[entry.state]
        text = f"{entry.label.ljust(label_width)}  {word}"
        if entry.detail:
            text = f"{text} — {entry.detail}"
        lines.append(truncate(f"{symbol_for(entry.state.level)} {text}", width))
    remediations = tuple(entry for entry in report.entries if entry.remediation)
    if remediations:
        lines.append("")
        lines.append("Suggested next steps")
        for entry in remediations:
            lines.extend(_indent(wrap(f"· {entry.remediation}", max(width - 4, 20)), width=2))
        lines.append("")
        lines.extend(
            wrap(
                "Nothing above was changed. Diagnosis never repairs on its own.",
                max(width - 2, 24),
            )
        )
    return tuple(lines)
