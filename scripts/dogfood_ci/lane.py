#!/usr/bin/env python3
"""One unattended dogfood lane: provision, set up, connect one host, probe, drain, dispose.

Run from a checkout on a throwaway GitHub-hosted runner (Linux, macOS, or Ubuntu under WSL 2):

    uv run --no-project --python 3.14.6 python scripts/dogfood_ci/lane.py \\
        --host codex --evidence "$RUNNER_TEMP/evidence" --host-path "$(command -v codex)"

The lane walks the product's own path in order and records every step as bounded JSON under
``--evidence``: build the wheel and provision a pinned disposable instance
(``scripts/provision_test_instance.py``), start its service, initialize the passphrase vault,
bind the reviewed Fireworks Responses profile and store its credential, grant an assisted-review
repository privacy recipe, connect the selected host through ``yoetz setup run`` (or the
documented no-OS-presence substitutes where a runner cannot answer LocalAuthentication), grant
observation, run a deterministic ledger probe (start, publish, check with AI-powered review,
receipt, hook carrier probes, drain), run one tiny native agent session against the same
instance, drain again, restart and unlock the service, and dispose.

Verdict: the lane is *catastrophic* (exit 1) when an install, setup, connection, ledger, or
service-lifecycle step fails, or when observation reports a service or storage failure after
the agent ran. A native agent that never calls Yoetz, times out, or exits nonzero is recorded and
reported, not treated as catastrophic, unless ``--strict-agent`` is set: model compliance is not
what this lane certifies. A green lane means the product installed and its main paths did not
break; it is not evidence that Yoetz is correct, useful, or free of defects.

Secrets arrive only through the environment and are used once: ``DOGFOOD_VAULT_PASSPHRASE``
(generated when absent), ``FIREWORKS_API_KEY`` (AI-powered review and the Codex/Claude agent
model), ``CURSOR_API_KEY`` (the Cursor agent), ``DOGFOOD_OS_PASSWORD`` (the runner account's
password for the Linux PAM artifact review). Every saved file is redacted against those values
and against the runner's home, checkout, and instance paths. Nothing here touches an everyday
installation: the instance is pinned to its own root and disposed at the end.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import secrets as pysecrets
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, cast

_HERE: Final = Path(__file__).resolve().parent
_REPO_ROOT: Final = _HERE.parents[1]

_spec = importlib.util.spec_from_file_location("dogfood_ceremony", _HERE / "ceremony.py")
if _spec is None or _spec.loader is None:  # pragma: no cover - packaging error
    raise SystemExit("ceremony.py missing beside lane.py")
_ceremony = importlib.util.module_from_spec(_spec)
sys.modules["dogfood_ceremony"] = _ceremony
_spec.loader.exec_module(_ceremony)
Reply = _ceremony.Reply
run_ceremony = _ceremony.run_ceremony

HOSTS: Final = ("codex", "claude", "cursor")
CONNECTION_MODES: Final = ("auto", "setup-run", "plugin-dir", "mcp-only", "none")
SEMANTIC_MODEL_DEFAULT: Final = "accounts/fireworks/models/minimax-m3"
AGENT_MODEL_DEFAULT: Final = "accounts/fireworks/models/glm-5p3-flash"
CURSOR_MODEL_DEFAULT: Final = "gpt-5.6-luna-low"
FIREWORKS_OPENAI_BASE: Final = "https://api.fireworks.ai/inference/v1"
FIREWORKS_ANTHROPIC_BASE: Final = "https://api.fireworks.ai/inference"
_ACTOR: Final = {"actor_id": "harness:dogfood-ci", "actor_type": "harness"}
_CLIENT: Final = {
    "kind": "cooperative_agent",
    "version": "dogfood-ci/1",
    "integration": "cooperative_mcp",
}
_TAIL_BYTES: Final = 4000
# Lane secrets a native agent process must never inherit; the agent gets only the credential
# and settings its own command builder overlays.
_LANE_SECRET_ENV: Final = (
    "DOGFOOD_VAULT_PASSPHRASE",
    "DOGFOOD_OS_PASSWORD",
    "FIREWORKS_API_KEY",
    "CURSOR_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
)

# Prompt contract: every regex below names a product prompt this lane answers. The unit test
# renders the real prompts (typer/click and the trusted-console stems) and asserts each regex
# still matches, so a product wording change fails the test instead of the first CI run.
PROMPT_PASSPHRASE: Final = r"Passphrase \("
PROMPT_CONFIRM_PASSPHRASE: Final = r"Confirm passphrase"
PROMPT_PROVIDER_CREDENTIAL: Final = r"Provider credential: "
PROMPT_DECISION: Final = r"Decision \[approve/deny(?:/edit)?\]: "
PROMPT_PRIVACY_RECOMMENDED: Final = r"Use this recommended privacy policy\? \[Y/n\]: "
PROMPT_PRIVACY_CHOICE: Final = r"Choose a privacy option \[\d\]: "
PROMPT_PRIVACY_CREATE: Final = r"Create this exact privacy proposal .*\? \[y/N\]: "
PROMPT_PAM_PASSWORD: Final = r"Password for .*: "
_LEDGER_TASK_STATEMENT: Final = (
    "Exercise one isolated Yoetz workflow: attach to the host-mapped task or create the "
    "probe task, publish a plan and an obligation for one ledger round trip, run the "
    "configured check, retain its exact result and coverage limitations, and request a "
    "receipt. This is a mechanics probe; do not claim the obligation is satisfied or "
    "that the check proves product correctness."
)
_PROMPT_TEMPLATE: Final = (
    "You are a small integration probe. Use the MCP server/namespace containing '{tool_hint}': "
    "its functions include start, publish_work, and receipt. A function name may omit the "
    "server/namespace prefix; it need not itself contain '{tool_hint}'. Empty MCP resource "
    "or resource-template lists do not mean these callable tools are unavailable. "
    "You may use host tool discovery/search and execution wrappers solely "
    "to discover and invoke these tools. If they are deferred, discover them before deciding "
    "they are unavailable. Read and verify the packaged guidance required for each "
    "operation, recovering incomplete pages before continuing. Then do these steps. "
    "1) Call the start tool with protocol_version '0.1', schema_version '1.0.0', a fresh "
    "request_id of the form req_<random uuid4>, mode 'create', task_title 'dogfood native probe', "
    "workspace_ref '{workspace}', external_ref '{external_ref}', requested_view 'compact', "
    "task_statement set to this entire user message verbatim (not just its title), "
    "actor {{actor_id: 'harness:dogfood-native', actor_type: 'harness'}}, and client "
    "{{kind: 'cooperative_agent', version: '0.1.0', integration: 'cooperative_mcp'}}. "
    "2) Call publish_work once with the session_id, writer_id and frontier that start returned "
    "as expected_frontier, and one event draft: event_id evt_<uuid4>, schema "
    "{{name: 'plan_published', version: '1.0.0'}}, occurred_at the current UTC time with "
    "millisecond precision, causal_parents [], artifact_refs [], evidence_refs [], payload "
    "{{plan_version: 1, summary: 'native probe', obligation_refs: [], "
    "no_obligations_reason: 'single_atomic_change'}}. "
    "3) Call check with the same session_id and writer_id, the publish result frontier as "
    "expected_frontier, and mode 'semantic_required'. Preserve the returned coverage limits. "
    "A pending approval is not a completed check; follow its exact continuation. "
    "4) Read status view 'compact' to obtain the current frontier. Call receipt with "
    "task_id, session_id, writer_id, that status frontier "
    "as expected_frontier, format 'markdown', include 'standard', redaction_profile "
    "'default_local_export'. For Claude or Cursor only, before the final answer emit exactly one "
    "physical line with the prefix YOETZ_NATIVE_BINDING followed by one compact JSON object with "
    "exactly these keys: task_id, session_id, writer_id, frontier. Copy all four values from the "
    "start result, including frontier.sequence and frontier.head_digest; this line is only a "
    "locator and never replaces the MCP calls. Then answer with the single word DONE on its own "
    "line. Codex is checked from its structured JSONL and does not need this marker. Do not create "
    "or edit files."
)

_NATIVE_BINDING_PREFIX: Final = "YOETZ_NATIVE_BINDING "
_NATIVE_MAX_SEQUENCE: Final = 2**63 - 1
_NATIVE_ID_RE: Final = re.compile(
    r"^(?:tsk|ses|wri)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_NATIVE_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_NATIVE_ITEM_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def _native_final_response(host: str, output: str) -> str | None:
    """Return only the host's successful final response text."""

    final: str | None = None
    if host == "codex":
        completed = False
        for line in output.split("\n"):
            if not line.strip(" \t\r"):
                continue
            try:
                event = json.loads(line)
            except ValueError:
                return None
            if not isinstance(event, dict):
                return None
            event = cast(dict[str, Any], event)
            if event.get("type") in ("error", "turn.failed"):
                return None
            if event.get("type") == "turn.started":
                final = None
                completed = False
            if event.get("type") == "turn.completed":
                completed = True
            item = event.get("item")
            if (
                event.get("type") == "item.completed"
                and isinstance(item, dict)
                and cast(dict[str, Any], item).get("type") == "agent_message"
            ):
                value = cast(dict[str, Any], item).get("text")
                final = value if isinstance(value, str) else None
        return final if completed else None
    if host not in {"claude", "cursor"}:
        return None
    try:
        result = json.loads(output)
    except ValueError:
        return None
    if not isinstance(result, dict):
        return None
    result = cast(dict[str, Any], result)
    if (
        result.get("type") != "result"
        or result.get("subtype") != "success"
        or result.get("is_error") is not False
    ):
        return None
    value = result.get("result")
    return value if isinstance(value, str) else None


def _validated_native_binding(value: object, *, source: str) -> dict[str, Any] | None:
    """Validate a native locator regardless of whether it came from output or observation."""

    if not isinstance(value, dict):
        return None
    binding = cast(dict[str, Any], value)
    if set(binding) - {"task_id", "session_id", "writer_id", "frontier", "source"}:
        return None
    for key, prefix in (("task_id", "tsk_"), ("session_id", "ses_"), ("writer_id", "wri_")):
        item = binding.get(key)
        if (
            not isinstance(item, str)
            or _NATIVE_ID_RE.fullmatch(item) is None
            or not item.startswith(prefix)
        ):
            return None
    frontier_value = binding.get("frontier")
    if not isinstance(frontier_value, dict):
        return None
    frontier = cast(dict[str, Any], frontier_value)
    if set(frontier) != {"sequence", "head_digest"}:
        return None
    sequence = frontier.get("sequence")
    head_digest = frontier.get("head_digest")
    if (
        not isinstance(sequence, str)
        or not sequence.isdigit()
        or (sequence != "0" and sequence.startswith("0"))
        or int(sequence) > _NATIVE_MAX_SEQUENCE
        or not isinstance(head_digest, str)
        or (head_digest != "genesis" and _NATIVE_DIGEST_RE.fullmatch(head_digest) is None)
    ):
        return None
    return {
        "task_id": binding["task_id"],
        "session_id": binding["session_id"],
        "writer_id": binding["writer_id"],
        "frontier": {"sequence": sequence, "head_digest": head_digest},
        "source": source,
    }


def _native_binding_marker(host: str, output: str) -> dict[str, Any] | None:
    """Parse one strict Claude/Cursor locator marker from the successful final response."""

    final = _native_final_response(host, output)
    if final is None or host == "codex":
        return None
    markers = [line for line in final.splitlines() if line.startswith(_NATIVE_BINDING_PREFIX)]
    if len(markers) != 1:
        return None
    payload = markers[0][len(_NATIVE_BINDING_PREFIX) :]
    if not payload or payload.strip() != payload:
        return None

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_native_binding_key")
            result[key] = value
        return result

    try:
        parsed = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    parsed = cast(dict[str, Any], parsed)
    if set(parsed) != {
        "task_id",
        "session_id",
        "writer_id",
        "frontier",
    }:
        return None
    return _validated_native_binding(parsed, source="final_marker")


def _native_binding_from_observation(
    value: object,
    *,
    external_ref: str | None = None,
    workspace: str | None = None,
) -> dict[str, Any] | None:
    """Use an observation locator only when its native scope is explicit.

    Observation contains earlier ledger and hook probes, so a blind recursive search can bind a
    later native process to the wrong task. An adapter must carry the native external reference,
    or explicitly mark a native workspace scope, before its IDs are eligible here.
    """

    if external_ref is None and workspace is None:
        return None

    allowed_binding_keys = frozenset({"task_id", "session_id", "writer_id", "frontier", "source"})

    def visit(node: object, scoped: bool = False) -> dict[str, Any] | None:
        if isinstance(node, dict):
            mapping = cast(dict[str, Any], node)
            node_external = mapping.get("external_ref")
            if node_external is None:
                node_external = mapping.get("native_external_ref")
            node_workspace = mapping.get("workspace")
            if node_workspace is None:
                node_workspace = mapping.get("workspace_ref")
            if node_workspace is None:
                node_workspace = mapping.get("native_workspace")
            external_match = external_ref is not None and node_external == external_ref
            workspace_match = (
                workspace is not None
                and node_workspace == workspace
                and (
                    mapping.get("native") is True
                    or mapping.get("native_scope") is True
                    or "native_workspace" in mapping
                )
            )
            scoped_here = scoped or external_match or workspace_match
            binding_payload = {
                key: child for key, child in mapping.items() if key in allowed_binding_keys
            }
            scope_keys = {
                "external_ref",
                "native_external_ref",
                "workspace",
                "workspace_ref",
                "native_workspace",
                "native",
                "native_scope",
            }
            if scoped_here and not (set(mapping) - allowed_binding_keys - scope_keys):
                candidate = _validated_native_binding(binding_payload, source="observation")
                if candidate is not None:
                    return candidate
            for key, child in mapping.items():
                child_scoped = scoped_here or (
                    key in {"native_binding", "native_locator"}
                    and (external_match or workspace_match)
                )
                found = visit(child, child_scoped)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for child in cast(list[Any], node):
                found = visit(child, scoped)
                if found is not None:
                    return found
        return None

    return visit(value)


def _native_done(host: str, output: str) -> bool:
    """Accept DONE only in a successful host final response, never in tool output or echoes."""

    final: str | None = None
    if host == "codex":
        # Codex --json is JSONL. The last completed assistant message is authoritative;
        # a later refusal or turn failure must not inherit an earlier DONE.
        completed = False
        for line in output.split("\n"):
            if not line.strip(" \t\r"):
                continue
            try:
                event = json.loads(line)
            except ValueError:
                return False
            if not isinstance(event, dict):
                return False
            event = cast(dict[str, Any], event)
            if event.get("type") in ("error", "turn.failed"):
                return False
            if event.get("type") == "turn.started":
                final = None
                completed = False
            if event.get("type") == "turn.completed":
                completed = True
            item = event.get("item")
            if (
                event.get("type") == "item.completed"
                and isinstance(item, dict)
                and cast(dict[str, Any], item).get("type") == "agent_message"
            ):
                value = cast(dict[str, Any], item).get("text")
                final = value if isinstance(value, str) else None
        if not completed:
            return False
    elif host in {"claude", "cursor"}:
        try:
            result = json.loads(output)
        except ValueError:
            return False
        if not isinstance(result, dict):
            return False
        result = cast(dict[str, Any], result)
        if (
            result.get("type") != "result"
            or result.get("subtype") != "success"
            or result.get("is_error") is not False
        ):
            return False
        value = result.get("result")
        final = value if isinstance(value, str) else None
    # Stop hooks may require a disclosure after the completion marker. Accept a
    # standalone line or terminal DONE token in the final response, never tool output,
    # NOT_DONE, or a quoted marker in prose.
    lines = final.strip().splitlines() if final else []
    return any(line.strip() == "DONE" for line in lines) or bool(
        final and re.search(r"(?:^|\s)DONE\s*$", final)
    )


def _specification_manifest_matches(result: dict[str, Any], statement: str) -> bool:
    """Require the provider-bound statement identity, not just successful prompt delivery."""

    manifest = result.get("review_input_manifest")
    if not isinstance(manifest, dict):
        return False
    manifest = cast(dict[str, Any], manifest)
    if (
        manifest.get("schema") != "yoetz.review-input-manifest/1"
        or manifest.get("phase") != "provider_bound"
    ):
        return False
    specification = manifest.get("specification")
    if not isinstance(specification, dict):
        return False
    specification = cast(dict[str, Any], specification)
    content = statement.encode("utf-8")
    revision = specification.get("revision")
    selected = specification.get("item_ids")
    if not isinstance(selected, list):
        return False
    selected = cast(list[object], selected)
    if len(selected) > 64 or len(selected) != len(
        {item for item in selected if isinstance(item, str)}
    ):
        return False
    return bool(
        specification.get("status") == "complete"
        and specification.get("content_digest") == "sha256:" + hashlib.sha256(content).hexdigest()
        and specification.get("content_bytes") == len(content)
        and type(revision) is int
        and revision > 0
        and len(selected) > 0
        and all(
            type(item) is str
            and 1 <= len(item) <= 128
            and _NATIVE_ITEM_ID_RE.fullmatch(item) is not None
            for item in selected
        )
    )


def _history_provider_bound_manifest_matches(item: dict[str, Any], statement: str) -> bool:
    """Match one public history row's first provider-bound check to the exact statement."""

    if item.get("schema_name") != "check_recorded":
        return False
    manifest_value = item.get("review_input_manifest")
    if not isinstance(manifest_value, dict):
        return False
    manifest = cast(dict[str, Any], manifest_value)
    if manifest.get("phase") != "provider_bound":
        return False
    return _specification_manifest_matches({"review_input_manifest": manifest}, statement)


def _codex_workflow_completed(output: str, expected_statement: str | None = None) -> bool:
    """Correlate native MCP successes; later hook disclosures do not undo recorded work."""

    started: set[tuple[str, str, str]] = set()
    published: set[tuple[str, str, str]] = set()
    checked: set[tuple[str, str, str]] = set()
    receipted = False
    completed = False
    for line in output.split("\n"):
        if not line.strip(" \t\r"):
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            return False
        if not isinstance(raw, dict):
            return False
        event = cast(dict[str, Any], raw)
        if event.get("type") in ("error", "turn.failed"):
            return False
        if event.get("type") == "turn.started":
            completed = False
        elif event.get("type") == "turn.completed":
            completed = True
        item = event.get("item")
        if event.get("type") != "item.completed" or not isinstance(item, dict):
            continue
        item = cast(dict[str, Any], item)
        if (
            item.get("type") != "mcp_tool_call"
            or item.get("server") != "yoetz"
            or item.get("status") != "completed"
            or item.get("error") is not None
        ):
            continue
        result = item.get("result")
        args = item.get("arguments")
        if not isinstance(result, dict) or not isinstance(args, dict):
            continue
        result = cast(dict[str, Any], result).get("structured_content")
        args = cast(dict[str, Any], args)
        if not isinstance(result, dict):
            continue
        result = cast(dict[str, Any], result)
        if result.get("ok") is not True:
            continue
        tool = item.get("tool")
        ids = (
            result.get("task_id"),
            result.get("session_id"),
            result.get("writer_id") if tool == "start" else args.get("writer_id"),
        )
        if not all(isinstance(value, str) and value for value in ids):
            continue
        binding = cast(tuple[str, str, str], ids)
        if tool == "start":
            if expected_statement is None or args.get("task_statement") == expected_statement:
                started.add(binding)
        elif args.get("session_id") == binding[1]:
            if (
                tool == "publish_work"
                and binding in started
                and result.get("writer_id") == binding[2]
            ):
                accepted = result.get("accepted_events")
                if result.get("outcome") == "accepted" and isinstance(accepted, list):
                    for accepted_row in cast(list[object], accepted):
                        if isinstance(accepted_row, dict):
                            row = cast(dict[str, Any], accepted_row)
                            if (
                                row.get("schema_name") == "plan_published"
                                and row.get("projection_status") == "projected"
                            ):
                                published.add(binding)
            elif (
                tool == "check"
                and binding in published
                and result.get("semantic_status") != "awaiting_human"
                and result.get("outcome") != "awaiting_human"
                and (
                    expected_statement is None
                    or _specification_manifest_matches(result, expected_statement)
                )
            ):
                checked.add(binding)
            elif (
                tool == "receipt"
                and binding in checked
                and args.get("task_id") == binding[0]
                and isinstance(result.get("receipt_id"), str)
                and result["receipt_id"].startswith("rcp_")
            ):
                receipted = True
    return completed and receipted


class LaneAbort(Exception):
    """A catastrophic step already recorded; stop the lane and go to teardown."""


@dataclass(slots=True)
class Step:
    name: str
    phase: str
    status: str
    reason: str | None
    summary: dict[str, Any]
    output_file: str | None
    exit_code: int | None = None
    duration_ms: int = 0


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rid() -> str:
    return "req_" + str(uuid.uuid4())


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4()}"


def _find_key(value: object, key: str) -> object | None:
    """Depth-first search for the first mapping entry named ``key``."""

    if isinstance(value, dict):
        mapping = cast(dict[str, object], value)
        if key in mapping:
            return mapping[key]
        for item in mapping.values():
            found = _find_key(item, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in cast(list[object], value):
            found = _find_key(item, key)
            if found is not None:
                return found
    return None


def _semantic_provenance_provider(value: object) -> str | None:
    """Read the provider identity across the semantic-provenance wire versions."""

    provider_id = _find_key(value, "provider_id")
    if isinstance(provider_id, str) and provider_id:
        return provider_id
    if isinstance(value, dict):
        provider = cast(dict[str, object], value).get("provider")
        if isinstance(provider, str) and provider:
            return provider
    return None


def _find_frontier(value: object) -> dict[str, str] | None:
    """Return the first ``{sequence, head_digest}`` object found in a result."""

    if isinstance(value, dict):
        mapping = cast(dict[str, object], value)
        if {"sequence", "head_digest"} <= set(mapping) and isinstance(mapping["sequence"], str):
            return {
                "sequence": mapping["sequence"],
                "head_digest": cast(str, mapping["head_digest"]),
            }
        for name in ("result_frontier", "frontier", "subject_frontier"):
            if name in mapping:
                found = _find_frontier(mapping[name])
                if found is not None:
                    return found
        for item in mapping.values():
            found = _find_frontier(item)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in cast(list[object], value):
            found = _find_frontier(item)
            if found is not None:
                return found
    return None


def _parse_json(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
    except ValueError:
        # Some commands print a human line before the JSON; try the last JSON-looking line.
        for line in reversed(stripped.split("\n")):
            line = line.strip()
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                    break
                except ValueError:
                    continue
        else:
            return None
    return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else None


def _tail(text: str, limit: int = _TAIL_BYTES) -> str:
    return text if len(text) <= limit else "…" + text[-limit:]


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clean_env(
    extra: dict[str, str] | None = None, *, drop: tuple[str, ...] = ()
) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("YOETZ_") and k not in drop}
    if extra:
        env.update(extra)
    return env


def _os_cell() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    wsl = "microsoft" in platform.release().lower() or os.environ.get("WSL_DISTRO_NAME") is not None
    return f"{'wsl2-' if wsl else ''}{system}-{machine}"


class Lane:
    def __init__(self, args: argparse.Namespace) -> None:
        self.host: str = args.host
        self.checkout = Path(args.checkout).resolve()
        self.base = Path(args.base).expanduser().resolve()
        self.tag: str = args.tag
        self.evidence = Path(args.evidence).expanduser().resolve()
        self.python: str = args.python
        self.strict_agent: bool = args.strict_agent
        self.skip_agent: bool = args.skip_agent
        self.skip_restart: bool = args.skip_restart
        self.agent_timeout: float = args.agent_timeout
        self.semantic_model: str = args.semantic_model
        self.agent_model: str = args.agent_model or AGENT_MODEL_DEFAULT
        self.cursor_model: str = args.cursor_model
        self.allow_dirty: bool = args.allow_dirty
        self.host_path: str | None = args.host_path
        self.home = Path.home()
        default_roots = {"codex": ".codex", "claude": ".claude", "cursor": ".cursor"}
        self.host_config_root = (
            Path(args.host_config_root).expanduser().resolve()
            if args.host_config_root
            else self.home / default_roots[self.host]
        )
        self.project = (
            Path(args.project).expanduser().resolve()
            if args.project
            else self.home / f".yz-dogfood-{self.tag}" / "project"
        )
        self.stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.os_cell = _os_cell()
        self.is_darwin = platform.system() == "Darwin"
        self.passphrase = os.environ.get("DOGFOOD_VAULT_PASSPHRASE") or (
            "dogfood-" + pysecrets.token_urlsafe(24)
        )
        self.fireworks_key = os.environ.get("FIREWORKS_API_KEY", "")
        self.cursor_key = os.environ.get("CURSOR_API_KEY", "")
        self.os_password = os.environ.get("DOGFOOD_OS_PASSWORD", "")
        self.connection_mode = self._resolve_connection_mode(args.connection_mode)
        self.launcher: Path | None = None
        self.root: Path | None = None
        self.service_proc: subprocess.Popen[bytes] | None = None
        self.steps: list[Step] = []
        self.identity: dict[str, Any] = {}
        self.semantic: dict[str, Any] = {"configured": bool(self.fireworks_key)}
        self.agent: dict[str, Any] = {"ran": False}
        self.native_prompt: str | None = None
        self.native_provider_verification: dict[str, Any] = {}
        self.observation: dict[str, Any] = {}
        self.ledger: dict[str, Any] = {}
        self.plugin_dir: Path | None = None
        self.mcp_tool_hint = "yoetz"
        self._counter = 0
        secret_values = [
            self.passphrase,
            self.fireworks_key,
            self.cursor_key,
            self.os_password,
            os.environ.get("ANTHROPIC_API_KEY", ""),
            os.environ.get("ANTHROPIC_AUTH_TOKEN", ""),
            os.environ.get("CODEX_API_KEY", ""),
            os.environ.get("OPENAI_API_KEY", ""),
        ]
        self._secret_values = [value for value in secret_values if value]
        self._path_tokens: list[tuple[str, str]] = []
        for value, token in (
            (os.environ.get("RUNNER_TEMP", ""), "<runner-temp>"),
            (str(self.base), "<base>"),
            (str(self.checkout), "<checkout>"),
            (str(self.evidence), "<evidence>"),
            (str(self.home), "<home>"),
        ):
            if value:
                self._path_tokens.append((value, token))
        self._path_tokens.sort(key=lambda item: len(item[0]), reverse=True)

    # ------------------------------------------------------------------ plumbing

    def _resolve_connection_mode(self, requested: str) -> str:
        if requested != "auto":
            return requested
        if self.host == "codex":
            return "setup-run"
        if self.is_darwin or not self.os_password:
            return "plugin-dir" if self.host == "claude" else "mcp-only"
        return "setup-run"

    def redact(self, text: str) -> str:
        for value in sorted(set(self._secret_values), key=len, reverse=True):
            text = text.replace(value, "<secret>")
        for value, token in self._path_tokens:
            text = text.replace(value, token)
        return text

    def _save(self, name: str, text: str, suffix: str = ".txt") -> str:
        self._counter += 1
        path = self.evidence / f"{self._counter:02d}-{name}{suffix}"
        path.write_text(self.redact(text), encoding="utf-8")
        return path.name

    def _record(
        self,
        name: str,
        phase: str,
        *,
        status: str,
        exit_code: int | None = None,
        duration_ms: int = 0,
        reason: str | None = None,
        summary: dict[str, Any] | None = None,
        stdout: str = "",
        stderr: str = "",
        fatal: bool = False,
    ) -> Step:
        body = {
            "step": name,
            "phase": phase,
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "reason": reason,
            "stdout": _parse_json(stdout) or _tail(stdout),
            "stderr": _tail(stderr),
        }
        output_file = self._save(name, json.dumps(body, indent=2, sort_keys=True), ".json")
        step = Step(
            name=name,
            phase=phase,
            status=status,
            exit_code=exit_code,
            duration_ms=duration_ms,
            reason=reason,
            summary=self._redact_obj(summary or {}),
            output_file=output_file,
        )
        self.steps.append(step)
        marker = {"pass": "ok", "fail": "FAIL", "skip": "skip", "info": "info"}[status]
        sys.stdout.write(f"[{marker}] {phase}/{name}" + (f" ({reason})" if reason else "") + "\n")
        sys.stdout.flush()
        if fatal and status == "fail":
            raise LaneAbort(name)
        return step

    def _redact_obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {k: self._redact_obj(v) for k, v in cast(dict[str, Any], value).items()}
        if isinstance(value, list):
            return [self._redact_obj(v) for v in cast(list[Any], value)]
        return value

    def _run(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
        timeout: float = 300.0,
        drop: tuple[str, ...] = (),
    ) -> tuple[int, str, str, int]:
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - argv assembled from validated inputs
                argv,
                cwd=cwd,
                env=_clean_env(env, drop=drop),
                input=stdin.encode("utf-8") if stdin is not None else None,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"").decode("utf-8", errors="replace")
            err = (exc.stderr or b"").decode("utf-8", errors="replace")
            return 124, out, err + "\n<timeout>", int((time.monotonic() - started) * 1000)
        except FileNotFoundError as exc:
            return 127, "", str(exc), int((time.monotonic() - started) * 1000)
        return (
            completed.returncode,
            completed.stdout.decode("utf-8", errors="replace"),
            completed.stderr.decode("utf-8", errors="replace"),
            int((time.monotonic() - started) * 1000),
        )

    def _yoetz(
        self,
        name: str,
        phase: str,
        args: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
        fatal: bool = False,
        expect_zero: bool = True,
        summary: dict[str, Any] | None = None,
        timeout: float = 300.0,
    ) -> tuple[Step, dict[str, Any] | None]:
        assert self.launcher is not None
        # Repository-bound views (privacy grant, provider readiness, host admission) read the
        # working directory, so every product command runs from the probe project unless a
        # caller names another directory.
        rc, out, err, ms = self._run(
            [str(self.launcher), *args],
            cwd=self.project if cwd is None else cwd,
            env=env,
            stdin=stdin,
            timeout=timeout,
        )
        parsed = _parse_json(out)
        status = "pass" if (rc == 0 or not expect_zero) else "fail"
        reason = None if status == "pass" else f"exit_{rc}"
        step = self._record(
            name,
            phase,
            status=status,
            exit_code=rc,
            duration_ms=ms,
            reason=reason,
            summary=summary,
            stdout=out,
            stderr=err,
            fatal=fatal,
        )
        return step, parsed

    def _ceremony_step(
        self,
        name: str,
        phase: str,
        argv: list[str],
        replies: list[Any],
        *,
        cwd: Path | None = None,
        fatal: bool = False,
        timeout: float = 240.0,
    ) -> tuple[Step, dict[str, Any] | None]:
        started = time.monotonic()
        result = run_ceremony(
            argv,
            replies,
            cwd=self.project if cwd is None else cwd,
            env=_clean_env(),
            timeout=timeout,
        )
        ms = int((time.monotonic() - started) * 1000)
        parsed = _parse_json(result.transcript.replace("\r\n", "\n"))
        status = "pass" if result.exit_code == 0 else "fail"
        reason = (
            None
            if status == "pass"
            else ("timeout" if result.timed_out else f"exit_{result.exit_code}")
        )
        step = self._record(
            name,
            phase,
            status=status,
            exit_code=result.exit_code,
            duration_ms=ms,
            reason=reason,
            summary={"answered": result.answered},
            stdout=result.transcript,
            fatal=fatal,
        )
        return step, parsed

    def _wait_for_service(self, name: str, phase: str, *, timeout: float = 90.0) -> dict[str, Any]:
        """Poll ``service status`` until the service answers; a bounded wait on real state."""

        assert self.launcher is not None
        deadline = time.monotonic() + timeout
        last_err = ""
        started = time.monotonic()
        while True:
            rc, out, err, _ = self._run(
                [str(self.launcher), "service", "status", "--json"], cwd=self.project
            )
            parsed = _parse_json(out)
            if rc == 0 and parsed is not None:
                self._record(
                    name,
                    phase,
                    status="pass",
                    exit_code=rc,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    summary={
                        "state": parsed.get("state"),
                        "state_reason": parsed.get("state_reason"),
                        "vault_mode": parsed.get("vault_mode"),
                        "service_generation": parsed.get("service_generation"),
                    },
                    stdout=out,
                )
                return parsed
            last_err = err or out
            if time.monotonic() >= deadline:
                self._record(
                    name,
                    phase,
                    status="fail",
                    exit_code=rc,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    reason="service_not_ready",
                    stderr=last_err,
                    fatal=True,
                )
            time.sleep(1.0)

    # ------------------------------------------------------------------ phases

    def phase_install(self) -> None:
        phase = "install"
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.project.mkdir(parents=True, exist_ok=True)
        if not (self.project / ".git").exists():
            self._run(["git", "-C", str(self.project), "init", "-q"])
            self._run(
                [
                    "git",
                    "-C",
                    str(self.project),
                    "-c",
                    "user.name=dogfood",
                    "-c",
                    "user.email=dogfood@example.invalid",
                    "commit",
                    "-q",
                    "--allow-empty",
                    "-m",
                    "dogfood probe workspace",
                ]
            )
        self.host_config_root.mkdir(mode=0o700, parents=True, exist_ok=True)

        provision = [
            sys.executable,
            str(self.checkout / "scripts" / "provision_test_instance.py"),
            "create",
            "--base",
            str(self.base),
            "--tag",
            self.tag,
            "--checkout",
            str(self.checkout),
            "--lifecycle",
            "disposable",
            "--expires-in",
            "6",
            "--python",
            self.python,
            "--json",
        ]
        if self.allow_dirty:
            provision.append("--allow-dirty")
        rc, out, err, ms = self._run(provision, timeout=900.0)
        parsed = _parse_json(out)
        if rc != 0 or parsed is None:
            self._record(
                "provision",
                phase,
                status="fail",
                exit_code=rc,
                duration_ms=ms,
                reason="provision_failed",
                stdout=out,
                stderr=err,
                fatal=True,
            )
            return
        self.launcher = Path(cast(str, parsed["launcher"]))
        self.root = Path(cast(str, parsed["isolated_root"]))
        self.identity = {
            "source_ref": parsed.get("source_ref"),
            "source_state": parsed.get("source_state"),
            "package_version": parsed.get("package_version"),
            "package_digest": parsed.get("package_digest"),
            "installation_id": parsed.get("installation_id"),
            "lifecycle": parsed.get("lifecycle"),
        }
        self._record(
            "provision",
            phase,
            status="pass",
            exit_code=rc,
            duration_ms=ms,
            summary=self.identity,
            stdout=out,
            stderr=err,
        )

        _, isolation = self._yoetz(
            "isolation", phase, ["service", "isolation", "--json"], fatal=True
        )
        if isolation is None or isolation.get("mode") != "isolated":
            self._record(
                "isolation_mode",
                phase,
                status="fail",
                reason="isolation_unparseable" if isolation is None else "not_isolated",
                summary={
                    "mode": (isolation or {}).get("mode"),
                    "binding": (isolation or {}).get("binding"),
                },
                fatal=True,
            )
        self._yoetz("instance_status", phase, ["instance", "status", "--json"], fatal=True)
        _, version = self._yoetz("version", phase, ["version", "--json"], fatal=True)
        if version is not None:
            self.identity["version"] = version

        assert self.launcher is not None
        log_path = self.evidence / "service.log"
        self.service_proc = subprocess.Popen(  # noqa: S603 - fixed launcher argv
            [str(self.launcher), "service", "run"],
            cwd=self.home,
            env=_clean_env(),
            stdin=subprocess.DEVNULL,
            stdout=log_path.open("wb"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        status = self._wait_for_service("service_start", phase)
        if status.get("vault_mode") != "uninitialized":
            self._record(
                "vault_precondition",
                phase,
                status="fail",
                reason="vault_not_fresh",
                summary={"vault_mode": status.get("vault_mode")},
                fatal=True,
            )

        self._ceremony_step(
            "vault_initialize",
            phase,
            [str(self.launcher), "service", "initialize-passphrase", "--json"],
            [
                Reply(PROMPT_PASSPHRASE, self.passphrase),
                Reply(PROMPT_CONFIRM_PASSPHRASE, self.passphrase),
            ],
            fatal=True,
        )
        ready = self._wait_for_service("service_ready", phase)
        if ready.get("state") != "ready":
            self._record(
                "vault_ready",
                phase,
                status="fail",
                reason=str(ready.get("state_reason") or ready.get("state")),
                fatal=True,
            )

        self._yoetz(
            "provider_endpoint",
            phase,
            [
                "provider",
                "endpoint",
                "--provider",
                "fireworks",
                "--model",
                self.semantic_model,
                "--no-interactive",
                "--json",
            ],
            fatal=True,
        )
        if self.fireworks_key:
            self._ceremony_step(
                "provider_credential",
                phase,
                [str(self.launcher), "provider", "credential", "set", "--json"],
                [
                    Reply(PROMPT_PROVIDER_CREDENTIAL, self.fireworks_key),
                    Reply(PROMPT_PASSPHRASE, self.passphrase),
                    Reply(PROMPT_DECISION, "approve", secret=False),
                ],
                fatal=True,
            )
        else:
            self._record(
                "provider_credential",
                phase,
                status="skip",
                reason="FIREWORKS_API_KEY_unset",
            )

        if self.fireworks_key:
            # The running service composed provider readiness when the vault became ready,
            # before the endpoint and credential existed. Storing the credential verifies it
            # live but neither that nor a lock/unlock refreshes the composition (observed:
            # still not connected on the same generation); only a restart does. Restart before
            # the privacy grant so the grant's authorization and the later check share one
            # service generation and policy digest.
            self._restart_and_unlock(phase, "_after_credential")
        recipe = "3" if self.fireworks_key else "1"
        self._ceremony_step(
            "privacy_setup",
            phase,
            [str(self.launcher), "privacy", "setup"],
            [
                Reply(PROMPT_PRIVACY_RECOMMENDED, "n", secret=False),
                Reply(PROMPT_PRIVACY_CHOICE, recipe, secret=False),
                Reply(PROMPT_PRIVACY_CREATE, "y", secret=False),
                Reply(PROMPT_DECISION, "approve", secret=False),
                Reply(PROMPT_PASSPHRASE, self.passphrase),
            ],
            cwd=self.project,
            fatal=True,
        )

        _, provider_status = self._yoetz(
            "provider_status", phase, ["provider", "status", "--json"], expect_zero=False
        )
        if provider_status is not None:
            self.semantic["semantic_ready"] = provider_status.get("semantic_ready")
            self.semantic["blockers"] = [
                {"condition": b.get("condition"), "state": b.get("state")}
                for b in cast(list[dict[str, Any]], provider_status.get("blockers") or [])
            ]
            if self.fireworks_key and provider_status.get("semantic_ready") is not True:
                self._record(
                    "semantic_ready",
                    phase,
                    status="fail",
                    reason="semantic_not_ready_with_credential",
                    summary={"blockers": self.semantic["blockers"]},
                    fatal=True,
                )
        elif self.fireworks_key:
            self._record(
                "semantic_ready",
                phase,
                status="fail",
                reason="provider_status_unparseable",
                fatal=True,
            )
        _, setup_status = self._yoetz(
            "setup_status", phase, ["setup", "status", "--json"], expect_zero=False
        )
        if setup_status is not None:
            self.identity["platform"] = setup_status.get("platform")

    # ---- host connection

    def _host_flag(self) -> str:
        return "cursor-cli" if self.host == "cursor" else self.host

    def _write_codex_provider_config(self) -> None:
        config_path = self.host_config_root / "config.toml"
        existing = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
        if "[model_providers.fireworks]" in existing:
            return
        block = (
            f'model = "{self.agent_model}"\n'
            'model_provider = "fireworks"\n'
            'model_reasoning_effort = "low"\n'
            "\n"
            "[model_providers.fireworks]\n"
            'name = "Fireworks AI"\n'
            f'base_url = "{FIREWORKS_OPENAI_BASE}"\n'
            'env_key = "FIREWORKS_API_KEY"\n'
            'wire_api = "responses"\n'
        )
        config_path.write_text(block + ("\n" + existing if existing else ""), encoding="utf-8")

    def phase_connect(self) -> None:
        phase = "connect"
        assert self.launcher is not None
        if self.connection_mode == "none":
            self._record("host_connect", phase, status="skip", reason="connection_mode_none")
        elif self.connection_mode == "setup-run":
            self._connect_setup_run(phase)
        elif self.connection_mode == "plugin-dir":
            self._connect_plugin_dir(phase)
        elif self.connection_mode == "mcp-only":
            self._connect_mcp_only(phase)
        self._yoetz(
            "observe_grant",
            phase,
            ["observe", "grant", "--workspace", str(self.project)],
            fatal=True,
        )
        self._observe_status("observe_status_after_grant", phase)

    def _connect_setup_run(self, phase: str) -> None:
        assert self.launcher is not None
        if self.host == "codex" and self.fireworks_key:
            self._write_codex_provider_config()
        target = [
            "--host",
            self._host_flag(),
            "--host-config-root",
            str(self.host_config_root),
            "--project",
            str(self.project),
            "--route-profile",
            "policy",
        ]
        if self.host_path:
            target[2:2] = ["--host-path", self.host_path]
        _, preview = self._yoetz(
            "host_preview",
            phase,
            ["setup", "run", *target, "--non-interactive", "--json"],
            fatal=True,
        )
        plan = cast(dict[str, Any], (preview or {}).get("plan") or {})
        request_id = plan.get("request_id")
        digest = plan.get("preview_digest")
        if not isinstance(request_id, str) or not isinstance(digest, str):
            self._record(
                "host_preview_plan",
                phase,
                status="fail",
                reason="preview_without_plan",
                summary={"outcome": (preview or {}).get("outcome")},
                fatal=True,
            )
            return
        self.identity["host_version"] = plan.get("host_version")
        accept = [
            str(self.launcher),
            "setup",
            "run",
            *target,
            "--request-id",
            request_id,
            "--preview-digest",
            digest,
            "--accept",
            "--non-interactive",
            "--json",
        ]
        if plan.get("requires_os_presence") is False or self.host == "codex":
            _, report = self._yoetz("host_accept", phase, accept[1:], fatal=True)
        else:
            if not self.os_password:
                self._record(
                    "host_accept",
                    phase,
                    status="fail",
                    reason="os_presence_required_without_DOGFOOD_OS_PASSWORD",
                    fatal=True,
                )
                return
            _, report = self._ceremony_step(
                "host_accept",
                phase,
                accept,
                [Reply(PROMPT_PAM_PASSWORD, self.os_password)],
                fatal=True,
            )
        outcome = (report or {}).get("outcome")
        if outcome not in {"completed", "unchanged"}:
            self._record(
                "host_accept_outcome",
                phase,
                status="fail",
                reason=f"outcome_{outcome}",
                summary={"reason": (report or {}).get("reason")},
                fatal=True,
            )
        status_args = ["setup", "status", *target[:-2], "--json"]
        self._yoetz("host_status", phase, status_args, expect_zero=False)
        if self.host == "codex":
            mcp_status = [
                "integrate",
                "codex",
                "mcp",
                "status",
                "--codex-home",
                str(self.host_config_root),
                "--json",
            ]
            if self.host_path:
                mcp_status[4:4] = ["--codex-path", self.host_path]
            self._yoetz("codex_mcp_status", phase, mcp_status, expect_zero=False)
            if self.fireworks_key:
                self._grant_codex_check_admission(phase)
            else:
                self._record(
                    "codex_admission",
                    phase,
                    status="skip",
                    reason="FIREWORKS_API_KEY_unset",
                )
        elif self.host == "claude":
            status_argv = [
                "integrate",
                "claude",
                "plugin",
                "status",
                "--claude-config-root",
                str(self.host_config_root),
                "--project-root",
                str(self.project),
            ]
            for flag, key in (
                ("--cache-root", "cache_root"),
                ("--marketplace-root", "marketplace_root"),
            ):
                value = plan.get(key)
                if isinstance(value, str):
                    status_argv += [flag, value]
            self._yoetz("claude_plugin_status", phase, [*status_argv, "--json"], expect_zero=False)
            self.mcp_tool_hint = "yoetz"
        else:
            self._yoetz(
                "cursor_plugin_status",
                phase,
                [
                    "integrate",
                    "cursor",
                    "plugin",
                    "status",
                    "--cursor-config-root",
                    str(self.host_config_root),
                    "--json",
                ],
                expect_zero=False,
            )

    def _grant_codex_check_admission(self, phase: str) -> None:
        """Admit only the policy-route ``check`` in this disposable project.

        Codex's non-interactive process uses ``approval_policy = \"never\"`` in the evaluator
        home.  That is compatible with a per-tool ``approval_mode = \"approve\"`` entry, but it
        cannot answer a remaining MCP prompt.  Use Yoetz's previewed, digest-bound host-admission
        command so the privacy grant, observed route owner, and exact project file stay under the
        product's existing authority.  The subsequent native invocation is a fresh Codex process
        and is the final project-trust check.
        """

        project = str(self.project)
        _, preview = self._yoetz(
            "codex_admission_preview",
            phase,
            [
                "integrate",
                "codex",
                "admission",
                "preview",
                "--project-root",
                project,
                "--json",
            ],
            env={"CODEX_HOME": str(self.host_config_root)},
            fatal=True,
        )
        preview_body = preview if isinstance(preview, dict) else {}
        preview_digest = preview_body.get("preview_digest")
        route = preview_body.get("route")
        route_body = cast(dict[str, Any], route) if isinstance(route, dict) else {}
        if (
            not isinstance(preview_digest, str)
            or _NATIVE_DIGEST_RE.fullmatch(preview_digest) is None
            or route_body.get("observed") is not True
            or route_body.get("owner") != "external"
            or route_body.get("route_profile") != "policy"
        ):
            self._record(
                "codex_admission_preview_validation",
                phase,
                status="fail",
                reason="codex_admission_preview_unusable",
                summary={
                    "digest_valid": isinstance(preview_digest, str)
                    and _NATIVE_DIGEST_RE.fullmatch(preview_digest) is not None,
                    "route_observed": route_body.get("observed") is True,
                    "route_owner": route_body.get("owner"),
                    "route_profile": route_body.get("route_profile"),
                },
                fatal=True,
            )
            return

        self.identity["codex_admission_preview_digest"] = preview_digest
        _, grant = self._yoetz(
            "codex_admission_grant",
            phase,
            [
                "integrate",
                "codex",
                "admission",
                "grant",
                "--project-root",
                project,
                "--accept",
                "--preview-digest",
                preview_digest,
                "--json",
            ],
            env={"CODEX_HOME": str(self.host_config_root)},
            fatal=True,
        )
        grant_body = grant if isinstance(grant, dict) else {}
        if (
            grant_body.get("host") != "codex"
            or grant_body.get("state_after") != "present"
            or grant_body.get("action") not in {"grant", "noop"}
        ):
            self._record(
                "codex_admission_grant_validation",
                phase,
                status="fail",
                reason="codex_admission_grant_unconfirmed",
                summary={
                    "host": grant_body.get("host"),
                    "action": grant_body.get("action"),
                    "state_after": grant_body.get("state_after"),
                },
                fatal=True,
            )
            return

        _, status = self._yoetz(
            "codex_admission_status",
            phase,
            [
                "integrate",
                "codex",
                "admission",
                "status",
                "--project-root",
                project,
                "--json",
            ],
            env={"CODEX_HOME": str(self.host_config_root)},
            fatal=True,
        )
        status_body = status if isinstance(status, dict) else {}
        admission = status_body.get("admission")
        admission_body = cast(dict[str, Any], admission) if isinstance(admission, dict) else {}
        entries = admission_body.get("entries")
        details: set[str] = set()
        if isinstance(entries, list):
            for entry in cast(list[object], entries):
                if not isinstance(entry, dict):
                    continue
                detail = cast(dict[str, Any], entry).get("detail")
                if isinstance(detail, str):
                    details.add(detail)
        if admission_body.get("state") != "present" or "external" not in details:
            self._record(
                "codex_admission_status_validation",
                phase,
                status="fail",
                reason="codex_admission_status_unconfirmed",
                summary={
                    "state": admission_body.get("state"),
                    "external_entry_present": "external" in details,
                },
                fatal=True,
            )
            return
        self.identity["codex_admission"] = {
            "owner": "external",
            "route_profile": "policy",
            "state": "present",
            "tool": "check",
        }

    def _connect_plugin_dir(self, phase: str) -> None:
        if self.host != "claude":
            self._record(
                "host_connect", phase, status="fail", reason="plugin_dir_is_claude_only", fatal=True
            )
            return
        self.plugin_dir = self.base / f"{self.tag}-claude-plugin"
        if self.plugin_dir.exists():
            shutil.rmtree(self.plugin_dir)
        _, export = self._yoetz(
            "claude_plugin_export",
            phase,
            [
                "integrate",
                "claude",
                "plugin",
                "export",
                "--output-root",
                str(self.plugin_dir),
                "--development-enabled",
                "--project-root",
                str(self.project),
                "--mcp-ownership",
                "plugin-managed",
                "--route-profile",
                "policy",
                "--json",
            ],
            fatal=True,
        )
        self.mcp_tool_hint = "plugin_yoetz_yoetz"
        self._record(
            "host_connect",
            phase,
            status="info",
            reason="development_export_not_marketplace_activation",
            summary={"artifact_digest": (export or {}).get("artifact_digest")},
        )

    def _connect_mcp_only(self, phase: str) -> None:
        if self.host != "cursor":
            self._record(
                "host_connect", phase, status="fail", reason="mcp_only_is_cursor_only", fatal=True
            )
            return
        target = [
            "--project-root",
            str(self.project),
            "--cursor-config-root",
            str(self.host_config_root),
            "--route-profile",
            "policy",
            "--project-binding",
            "registered-project",
        ]
        _, preview = self._yoetz(
            "cursor_project_mcp_preview",
            phase,
            ["integrate", "cursor", "project-mcp", "preview", *target, "--json"],
            fatal=True,
        )
        digest = (preview or {}).get("preview_digest")
        if not isinstance(digest, str):
            self._record(
                "cursor_project_mcp_digest",
                phase,
                status="fail",
                reason="no_preview_digest",
                fatal=True,
            )
            return
        self._yoetz(
            "cursor_project_mcp_install",
            phase,
            [
                "integrate",
                "cursor",
                "project-mcp",
                "install",
                *target,
                "--preview-digest",
                digest,
                "--accept",
                "--json",
            ],
            fatal=True,
        )
        self._record(
            "host_connect",
            phase,
            status="info",
            reason="mcp_only_no_hooks_os_presence_unavailable",
        )

    # ---- observation helpers

    def _observe_status(self, name: str, phase: str) -> dict[str, Any] | None:
        _, status = self._yoetz(
            name,
            phase,
            ["observe", "status", "--workspace", str(self.project), "--json"],
            expect_zero=False,
        )
        if status is not None:
            diagnostics = cast(dict[str, Any], status.get("hook_diagnostics") or {})
            self.observation[name] = {
                "mapping_present": status.get("mapping_present"),
                "recent_count": status.get("recent_count"),
                "source_coverage": status.get("source_coverage"),
                "diagnostic_reasons": diagnostics.get("reasons"),
                # Per-(host, event, path) hook cost over every pass (#915), so each
                # host/OS lane reports what its hooks actually cost.
                "hook_pass_timings": diagnostics.get("pass_timings"),
                "quarantine_causes": status.get("quarantine_causes"),
                "delivery_causes": status.get("delivery_causes"),
                "pending_delivery_causes": status.get("pending_delivery_causes"),
            }
        return status

    def _observe_drain(self, name: str, phase: str, *, fatal: bool) -> dict[str, Any] | None:
        deadline = time.monotonic() + 60.0
        polls = 0
        drain: dict[str, Any] | None = None
        drain_step: Step | None = None
        while (remaining := deadline - time.monotonic()) > 0:
            polls += 1
            drain_step, drain = self._yoetz(
                name if polls == 1 else f"{name}_poll_{polls}",
                phase,
                ["observe", "drain", "--workspace", str(self.project), "--json"],
                expect_zero=False,
                timeout=min(remaining, 30.0),
            )
            if (
                drain_step.exit_code != 0
                or drain is None
                or drain.get("terminal")
                not in (
                    "retry_pending",
                    "pass_limit",
                )
            ):
                break
            # Observe real drain state after allowing the background worker to advance.
            # A delay alone never establishes success; the final result must be drained.
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        summary = {
            "polls": polls,
            "terminal": (drain or {}).get("terminal"),
            "pending_after": (drain or {}).get("pending_after"),
            "acknowledged": (drain or {}).get("acknowledged"),
            "quarantined": (drain or {}).get("quarantined"),
            "reasons": (drain or {}).get("reasons"),
        }
        self.observation[name] = summary
        ok = (
            drain_step is not None
            and drain_step.exit_code == 0
            and drain is not None
            and drain.get("terminal") == "drained"
            and drain.get("pending_after") == 0
        )
        self._record(
            f"{name}_verdict",
            phase,
            status="pass" if ok else "fail",
            reason=None if ok else "not_drained",
            summary=summary,
            fatal=fatal and not ok,
        )
        return drain

    @staticmethod
    def _catastrophic_diagnostics(status: dict[str, Any] | None) -> list[str]:
        if status is None:
            return ["observe_status_unavailable"]
        reasons = _find_key(status.get("hook_diagnostics"), "reasons")
        found: list[str] = []
        if isinstance(reasons, dict):
            for key in cast(dict[str, Any], reasons):
                if key.startswith(("service_unavailable", "storage_", "vault_locked")):
                    found.append(key)
        elif isinstance(reasons, list):
            for item in cast(list[Any], reasons):
                text = json.dumps(item) if not isinstance(item, str) else item
                if any(
                    token in text for token in ("service_unavailable", "storage_", "vault_locked")
                ):
                    found.append(text[:120])
        return found

    # ---- ledger probe

    def _request(self, extra: dict[str, Any]) -> str:
        body: dict[str, Any] = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _rid(),
            "actor": _ACTOR,
            "client": _CLIENT,
        }
        body.update(extra)
        return json.dumps(body)

    def phase_ledger_probe(self) -> None:
        phase = "ledger"
        assert self.launcher is not None
        # The product's own order: the host's SessionStart hook auto-attaches (creating the
        # workspace's task on first use) and hands the agent a session to attach to. A task
        # created ahead of the hook makes the hook's create_or_attach refuse with
        # workspace_task_exists, so the hook probe runs first and the CLI attaches to it.
        mapped = self._hook_session_start_probe(phase)
        if mapped is not None:
            start_body: dict[str, Any] = {
                "mode": "attach",
                "task_title": "dogfood ci deterministic probe",
                "session_id": mapped["session_id"],
                "requested_view": "compact",
            }
        else:
            start_body = {
                "mode": "create",
                "task_title": "dogfood ci deterministic probe",
                "workspace_ref": str(self.project),
                "external_ref": f"dogfood-ci-{self.host}-{self.stamp}",
                "requested_view": "compact",
            }
        start_body["task_statement"] = _LEDGER_TASK_STATEMENT
        _, started = self._yoetz(
            "ledger_start",
            phase,
            ["start", "--input", "-", "--json"],
            cwd=self.project,
            stdin=self._request(start_body),
            fatal=True,
        )
        if started is None:
            return
        session_id = started.get("session_id")
        writer_id = started.get("writer_id")
        task_id = started.get("task_id")
        frontier = _find_frontier(started)
        if (
            not all(isinstance(v, str) for v in (session_id, writer_id, task_id))
            or frontier is None
        ):
            self._record(
                "ledger_start_ids",
                phase,
                status="fail",
                reason="start_result_incomplete",
                fatal=True,
            )
            return
        self.ledger = {"session_id": session_id, "writer_id": writer_id, "task_id": task_id}
        ids = {"session_id": session_id, "writer_id": writer_id}
        obligation_id = _uid("obl")
        now = _now()
        drafts: list[dict[str, Any]] = [
            {
                "event_id": _uid("evt"),
                "schema": {"name": "plan_published", "version": "1.0.0"},
                "occurred_at": now,
                "causal_parents": [],
                "payload": {
                    "plan_version": 1,
                    "summary": "Deterministic dogfood probe: one bounded ledger round trip.",
                    "obligation_refs": [obligation_id],
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
            {
                "event_id": _uid("evt"),
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": now,
                "causal_parents": [],
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Record one probe round trip in the ledger.",
                    "acceptance_criteria": "The publish batch is accepted and a check runs.",
                    "evidence_expectation": "The check result recorded at the new frontier.",
                    "status": "open",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
        ]
        publish_rid = _rid()
        publish_body: dict[str, Any] = {
            **ids,
            "expected_frontier": frontier,
            "event_drafts": drafts,
        }
        dry = json.loads(self._request(publish_body))
        dry["request_id"] = publish_rid
        dry["dry_run"] = True
        self._yoetz(
            "ledger_publish_dry_run",
            phase,
            ["publish-work", "--input", "-", "--json"],
            cwd=self.project,
            stdin=json.dumps(dry),
            fatal=True,
        )
        real = dict(dry)
        real["dry_run"] = False
        _, published = self._yoetz(
            "ledger_publish",
            phase,
            ["publish-work", "--input", "-", "--json"],
            cwd=self.project,
            stdin=json.dumps(real),
            fatal=True,
        )
        _, status = self._yoetz(
            "ledger_status",
            phase,
            ["status", "--input", "-", "--json"],
            cwd=self.project,
            stdin=self._request({**ids, "view": "compact", "limit": "10"}),
            fatal=True,
        )
        frontier = _find_frontier(status) or _find_frontier(published) or frontier
        check_body: dict[str, Any] = {**ids, "expected_frontier": frontier, "max_findings": "10"}
        if self.fireworks_key:
            check_body["mode"] = "semantic_required"
        check_request = json.loads(self._request(check_body))
        check_request_id = cast(str, check_request["request_id"])
        _, checked = self._yoetz(
            "ledger_check",
            phase,
            ["check", "--input", "-", "--json"],
            cwd=self.project,
            stdin=json.dumps(check_request),
            fatal=True,
            timeout=420.0,
        )
        # Owner-only diagnostics explain a semantic outcome the public reason cannot name.
        self._yoetz(
            "service_diagnostics_for_check",
            phase,
            ["service", "diagnostics", "--request-id", check_request_id, "--json"],
            expect_zero=False,
        )
        for correlation_id in self._diagnostic_correlation_ids():
            self._yoetz(
                f"service_diagnostics_{correlation_id[4:12]}",
                phase,
                ["service", "diagnostics", "--correlation-id", correlation_id, "--json"],
                expect_zero=False,
            )
        if checked is not None:
            provenance = checked.get("semantic_provenance")
            self.semantic.update(
                {
                    "status": checked.get("semantic_status"),
                    "reason": checked.get("semantic_reason"),
                    "provenance_present": provenance is not None,
                    "provenance_provider": _semantic_provenance_provider(provenance),
                    "verdict": checked.get("verdict"),
                    "findings": len(cast(list[Any], checked.get("findings") or [])),
                }
            )
            frontier = _find_frontier(checked) or frontier
            # The egress receipt names why a case was or was not dispatched; keep it as evidence.
            self._yoetz(
                "privacy_receipts",
                phase,
                ["privacy", "receipts", "list", "--json"],
                expect_zero=False,
            )
            if self.fireworks_key:
                input_matches = _specification_manifest_matches(checked, _LEDGER_TASK_STATEMENT)
                self.semantic["specification_manifest_matches"] = input_matches
                self.semantic["review_input_manifest"] = checked.get("review_input_manifest")
                self._record(
                    "semantic_specification_input",
                    phase,
                    status="pass" if input_matches else "fail",
                    reason=None if input_matches else "provider_bound_specification_not_proven",
                    summary={
                        "expected_statement_digest": "sha256:"
                        + hashlib.sha256(_LEDGER_TASK_STATEMENT.encode("utf-8")).hexdigest()
                    },
                    fatal=False,
                )
                # docs/runbooks/semantic-dogfood.md §3: these rows prove a provider attempt was
                # made; every other status/reason pair is a pre-dispatch refusal or indeterminate.
                status = checked.get("semantic_status")
                reason = checked.get("semantic_reason")
                attempted = status in {
                    "succeeded",
                    "refused",
                    "timeout",
                    "invalid",
                    "late",
                    "stale",
                } or (
                    status == "unavailable"
                    and reason
                    in {
                        "transport_unavailable",
                        "provider_rate_limited",
                        "provider_quota_exhausted",
                        "outcome_unknown",
                    }
                )
                # Red for the lane, but not an abort: the connection, native, and lifecycle
                # phases still produce evidence that explains or narrows a dispatch refusal.
                self._record(
                    "semantic_attempt",
                    phase,
                    status="pass" if attempted else "fail",
                    reason=None if attempted else str(reason or status),
                    summary={
                        "semantic_status": status,
                        "semantic_reason": reason,
                        "provenance_present": provenance is not None,
                    },
                    fatal=False,
                )
        # The AI-powered result is recorded after the check returns, so the frontier the check
        # reported is usually stale by now; read the live one and honor one refresh continuation.
        _, before_receipt = self._yoetz(
            "ledger_status_before_receipt",
            phase,
            ["status", "--input", "-", "--json"],
            cwd=self.project,
            stdin=self._request({**ids, "view": "compact", "limit": "10"}),
            expect_zero=False,
        )
        frontier = _find_frontier(before_receipt) or frontier
        receipt_body = {
            **ids,
            "task_id": task_id,
            "format": "markdown",
            "include": "standard",
            "redaction_profile": "default_local_export",
        }
        _, receipt = self._yoetz(
            "ledger_receipt",
            phase,
            ["receipt", "--input", "-", "--json"],
            cwd=self.project,
            stdin=self._request({**receipt_body, "expected_frontier": frontier}),
            expect_zero=False,
        )
        refreshed = self._frontier_refresh(receipt)
        if refreshed is not None:
            _, receipt = self._yoetz(
                "ledger_receipt_retry",
                phase,
                ["receipt", "--input", "-", "--json"],
                cwd=self.project,
                stdin=self._request({**receipt_body, "expected_frontier": refreshed}),
                expect_zero=False,
            )
        if receipt is None or receipt.get("ok") is not True:
            self._record(
                "ledger_receipt_verdict",
                phase,
                status="fail",
                reason=str(_find_key(receipt, "code") or "receipt_failed"),
                fatal=True,
            )
        self._hook_post_probe(phase)
        self._observe_drain("observe_drain_after_probe", phase, fatal=True)
        self._observe_status("observe_status_after_probe", phase)

    @staticmethod
    def _frontier_refresh(result: dict[str, Any] | None) -> dict[str, str] | None:
        """Return the frontier a FRONTIER_CONFLICT continuation asks the caller to use."""

        if result is None or result.get("ok") is not False:
            return None
        error = result.get("error")
        if (
            not isinstance(error, dict)
            or cast(dict[str, Any], error).get("code") != "FRONTIER_CONFLICT"
        ):
            return None
        details = cast(dict[str, Any], error).get("safe_details")
        if not isinstance(details, dict):
            return None
        details_map = cast(dict[str, Any], details)
        sequence = details_map.get("sequence")
        head = details_map.get("head_digest")
        if not isinstance(head, str) or sequence is None:
            return None
        return {"sequence": str(sequence), "head_digest": head}

    def _hook_payloads(self) -> tuple[list[str], list[tuple[str, dict[str, Any]]]]:
        session = f"dogfood-{self.host}-{self.stamp}"
        payloads: list[tuple[str, dict[str, Any]]]
        if self.host == "codex":
            carrier = ["hooks", "observe", "--workspace", "."]
            payloads = [
                ("SessionStart", {"session_id": session, "hook_event_name": "SessionStart"}),
                (
                    "PostToolUse",
                    {
                        "session_id": session,
                        "hook_event_name": "PostToolUse",
                        "tool_name": "shell",
                        "exit_status": 0,
                    },
                ),
            ]
        elif self.host == "claude":
            carrier = ["hooks", "claude-observe", "--workspace", str(self.project)]
            payloads = [
                (
                    "SessionStart",
                    {
                        "cwd": str(self.project),
                        "hook_event_name": "SessionStart",
                        "session_id": session,
                        "transcript_path": str(self.project / "transcript.jsonl"),
                    },
                ),
                (
                    "PostToolUse",
                    {
                        "cwd": str(self.project),
                        "hook_event_name": "PostToolUse",
                        "session_id": session,
                        "tool_name": "Bash",
                        "tool_input": {},
                        "tool_response": {},
                        "tool_use_id": "tool-1",
                        "transcript_path": str(self.project / "transcript.jsonl"),
                    },
                ),
            ]
        else:
            carrier = ["hooks", "cursor-observe", "--workspace", str(self.project)]
            payloads = [
                (
                    "sessionStart",
                    {
                        "conversation_id": session,
                        "hook_event_name": "sessionStart",
                        "workspace_roots": [str(self.project)],
                    },
                ),
                (
                    "stop",
                    {
                        "conversation_id": session,
                        "hook_event_name": "stop",
                        "workspace_roots": [str(self.project)],
                    },
                ),
            ]
        return carrier, payloads

    def _hook_session_start_probe(self, phase: str) -> dict[str, str] | None:
        """Fire the session-start carrier and return the mapped ledger ids when it attached."""

        carrier, payloads = self._hook_payloads()
        event, payload = payloads[0]
        assert self.launcher is not None
        rc, out, err, ms = self._run(
            [str(self.launcher), *carrier, "--event", event],
            cwd=self.project,
            stdin=json.dumps(payload),
        )
        text = out + "\n" + err
        match = re.search(
            r"task (tsk_[0-9a-f-]{36}) is mapped .*? as session_id (ses_[0-9a-f-]{36}) and "
            r"writer_id (wri_[0-9a-f-]{36})",
            text,
            re.DOTALL,
        )
        mapped = (
            {"task_id": match.group(1), "session_id": match.group(2), "writer_id": match.group(3)}
            if match
            else None
        )
        self._record(
            f"hook_probe_{event}",
            phase,
            status="pass" if rc == 0 else "fail",
            exit_code=rc,
            duration_ms=ms,
            reason=None if rc == 0 else f"exit_{rc}",
            summary={
                "mapped": mapped is not None,
                "auto_attach": "mapped" if mapped else _tail(err, 200),
            },
            stdout=out,
            stderr=err,
        )
        return mapped

    def _hook_post_probe(self, phase: str) -> None:
        carrier, payloads = self._hook_payloads()
        event, payload = payloads[1]
        self._yoetz(
            f"hook_probe_{event}",
            phase,
            [*carrier, "--event", event],
            cwd=self.project,
            stdin=json.dumps(payload),
            fatal=False,
        )

    def _diagnostic_correlation_ids(self) -> list[str]:
        """Correlation ids from the instance's durable diagnostics ring, newest last."""

        if self.root is None:
            return []
        found: list[str] = []
        for path in self.root.rglob("service.diagnostics.jsonl"):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
            except OSError:
                continue
            for line in lines:
                match = re.search(r'"correlation_id":"(err_[0-9a-f-]{36})"', line)
                if match and match.group(1) not in found:
                    found.append(match.group(1))
        return found[-8:]

    # ---- native agent

    def _native_external_ref(self) -> str:
        """Return the exact pair used by the native prompt's start request."""

        return f"native-{self.host}-{self.stamp}"

    def _agent_command(self) -> tuple[list[str] | None, dict[str, str], str | None]:
        prompt = _PROMPT_TEMPLATE.format(
            tool_hint=self.mcp_tool_hint,
            workspace=str(self.project),
            external_ref=self._native_external_ref(),
        )
        self.native_prompt = prompt
        assert self.launcher is not None
        # setup run supplies this launch PATH because packaged hooks invoke bare yoetz.
        # The first executable is the disposable instance-pinned launcher (ADR-028).
        env: dict[str, str] = {
            "PATH": str(self.launcher.parent) + os.pathsep + os.environ.get("PATH", ""),
        }
        if self.host == "codex":
            exe = self.host_path or shutil.which("codex")
            if exe is None:
                return None, env, "codex_executable_missing"
            if self.fireworks_key:
                env["FIREWORKS_API_KEY"] = self.fireworks_key
            elif not (os.environ.get("CODEX_API_KEY") or os.environ.get("OPENAI_API_KEY")):
                return None, env, "no_model_credential"
            env["CODEX_HOME"] = str(self.host_config_root)
            argv = [
                exe,
                "exec",
                "--json",
                "--skip-git-repo-check",
                "-C",
                str(self.project),
                "--sandbox",
                "workspace-write",
                "--dangerously-bypass-hook-trust",
                "-o",
                str(self.evidence / "agent-last-message.md"),
                prompt,
            ]
            return argv, env, None
        if self.host == "claude":
            exe = self.host_path or shutil.which("claude")
            if exe is None:
                return None, env, "claude_executable_missing"
            if self.fireworks_key:
                env.update(
                    {
                        "ANTHROPIC_BASE_URL": FIREWORKS_ANTHROPIC_BASE,
                        "ANTHROPIC_AUTH_TOKEN": self.fireworks_key,
                        "ANTHROPIC_CUSTOM_HEADERS": f"X-Fireworks-Api-Key: {self.fireworks_key}",
                        "ANTHROPIC_MODEL": self.agent_model,
                        "ANTHROPIC_DEFAULT_SONNET_MODEL": self.agent_model,
                        "ANTHROPIC_DEFAULT_OPUS_MODEL": self.agent_model,
                        "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.agent_model,
                        "ANTHROPIC_SMALL_FAST_MODEL": self.agent_model,
                    }
                )
            elif not os.environ.get("ANTHROPIC_API_KEY"):
                return None, env, "no_model_credential"
            env.update(
                {
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "DISABLE_AUTOUPDATER": "1",
                    "DISABLE_TELEMETRY": "1",
                }
            )
            if self.host_config_root != self.home / ".claude":
                env["CLAUDE_CONFIG_DIR"] = str(self.host_config_root)
            argv = [
                exe,
                "-p",
                prompt,
                "--output-format",
                "json",
                "--dangerously-skip-permissions",
            ]
            if self.plugin_dir is not None:
                argv += ["--plugin-dir", str(self.plugin_dir)]
            return argv, env, None
        exe = self.host_path or shutil.which("cursor-agent") or shutil.which("agent")
        if exe is None:
            return None, env, "cursor_executable_missing"
        if not self.cursor_key:
            return None, env, "CURSOR_API_KEY_unset"
        env["CURSOR_API_KEY"] = self.cursor_key
        argv = [
            exe,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--force",
            "--trust",
            "--approve-mcps",
            "--model",
            self.cursor_model,
        ]
        return argv, env, None

    def _verify_native_provider_statement(
        self,
        phase: str,
        statement: str,
        binding: dict[str, Any] | None = None,
    ) -> bool:
        """Verify Claude/Cursor's native workflow through the session's public history.

        The host output supplies only a locator. It is never accepted as proof, and the verifier
        deliberately performs no post-run ``start mode=attach`` because that rotates the task
        session and hides the native rows from the session-scoped history view.
        """

        expected_digest = _digest(statement)
        expected_bytes = len(statement.encode("utf-8"))
        details: dict[str, Any] = {
            "host": self.host,
            "workspace": str(self.project),
            "external_ref": self._native_external_ref(),
            "statement_digest": expected_digest,
            "statement_bytes": expected_bytes,
            "operator_attach_mutation": False,
            "history_pages": 0,
            "history_items": 0,
            "provider_bound_checks": 0,
            "matched": False,
        }

        def fail(reason: str, **extra: Any) -> bool:
            details.update({"reason": reason, **extra})
            self.native_provider_verification = details
            self._record(
                "native_provider_input",
                phase,
                status="info",
                reason=reason,
                summary=details,
                fatal=False,
            )
            return False

        binding_source = "binding"
        if isinstance(binding, dict) and isinstance(binding.get("source"), str):
            binding_source = cast(str, binding["source"])
        checked_binding = _validated_native_binding(binding, source=binding_source)
        if checked_binding is None:
            return fail("native_binding_marker_missing")
        task_id = cast(str, checked_binding["task_id"])
        session_id = cast(str, checked_binding["session_id"])
        writer_id = cast(str, checked_binding["writer_id"])
        marker_frontier = cast(dict[str, str], checked_binding["frontier"])
        details.update(
            {
                "binding_source": checked_binding.get("source"),
                "task_id": task_id,
                "session_id": session_id,
                "writer_id": writer_id,
                "native_start_frontier": dict(marker_frontier),
            }
        )
        ids = {"task_id": task_id, "session_id": session_id, "writer_id": writer_id}

        def valid_frontier(value: object) -> dict[str, str] | None:
            if not isinstance(value, dict):
                return None
            frontier = cast(dict[str, Any], value)
            sequence = frontier.get("sequence")
            head_digest = frontier.get("head_digest")
            if (
                not isinstance(sequence, str)
                or not sequence.isdigit()
                or (sequence != "0" and sequence.startswith("0"))
                or int(sequence) > _NATIVE_MAX_SEQUENCE
                or not isinstance(head_digest, str)
                or (head_digest != "genesis" and _NATIVE_DIGEST_RE.fullmatch(head_digest) is None)
            ):
                return None
            return {"sequence": sequence, "head_digest": head_digest}

        def status_page(
            name: str, query: dict[str, Any]
        ) -> tuple[dict[str, str] | None, list[dict[str, Any]] | None, str | None]:
            _, status = self._yoetz(
                name,
                phase,
                ["status", "--input", "-", "--json"],
                cwd=self.project,
                stdin=self._request(query),
                expect_zero=False,
            )
            if not isinstance(status, dict) or status.get("ok") is not True:
                fail("native_history_unavailable")
                return None, None, None
            for key, expected in ids.items():
                if status.get(key) != expected:
                    fail("native_history_binding_mismatch")
                    return None, None, None
            requested = valid_frontier(status.get("requested_frontier"))
            if requested is None:
                fail("native_history_frontier_invalid")
                return None, None, None
            page_value = status.get("page")
            if not isinstance(page_value, dict):
                fail("native_history_page_invalid")
                return None, None, None
            page = cast(dict[str, Any], page_value)
            items_value = page.get("items")
            if "next_cursor" not in page or not isinstance(items_value, list):
                fail("native_history_page_invalid")
                return None, None, None
            raw_items = cast(list[Any], items_value)
            if any(not isinstance(item, dict) for item in raw_items):
                fail("native_history_item_invalid")
                return None, None, None
            next_cursor = page.get("next_cursor")
            if next_cursor is not None and not isinstance(next_cursor, str):
                fail("native_history_cursor_invalid")
                return None, None, None
            return (
                requested,
                [cast(dict[str, Any], item) for item in raw_items],
                next_cursor,
            )

        # The marker's frontier is checked through the same session/writer before reading the
        # later history. This proves that the locator names a real native route; it does not
        # claim that the marker itself proves any workflow event.
        marker_query = {
            **ids,
            "view": "history",
            "limit": "100",
            "at_frontier": marker_frontier["sequence"],
        }
        marker_requested, _, _ = status_page("native_history_marker_frontier", marker_query)
        if marker_requested is None:
            return False
        if marker_requested != marker_frontier:
            return fail("native_start_frontier_mismatch")

        cursor: str | None = None
        current_frontier: dict[str, str] | None = None
        history_items: list[dict[str, Any]] = []
        seen_sequences: set[int] = set()
        seen_events: set[str] = set()
        for page_number in range(1, 65):
            query: dict[str, Any] = {
                **ids,
                "view": "history",
                "limit": "100",
            }
            if cursor is not None:
                query["cursor"] = cursor
            requested, items, next_cursor_value = status_page(
                f"native_history_{page_number}", query
            )
            if requested is None or items is None:
                return False
            if current_frontier is None:
                current_frontier = requested
                if int(requested["sequence"]) < int(marker_frontier["sequence"]):
                    return fail("native_history_before_start_frontier")
                if (
                    requested["sequence"] == marker_frontier["sequence"]
                    and requested["head_digest"] != marker_frontier["head_digest"]
                ):
                    return fail("native_start_frontier_mismatch")
            elif requested != current_frontier:
                return fail("native_history_frontier_changed")
            for item in items:
                required = {
                    "event_id",
                    "schema_name",
                    "schema_version",
                    "publication_channel",
                    "ingestion_sequence",
                    "projection_status",
                    "summary_code",
                }
                if not required <= set(item):
                    return fail("native_history_item_invalid")
                event_id = item.get("event_id")
                if (
                    not isinstance(event_id, str)
                    or re.fullmatch(
                        r"evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        event_id,
                    )
                    is None
                ):
                    return fail("native_history_event_invalid")
                if event_id in seen_events:
                    return fail("native_history_duplicate")
                seen_events.add(event_id)
                sequence = item.get("ingestion_sequence")
                if (
                    not isinstance(sequence, str)
                    or not sequence.isdigit()
                    or (sequence != "0" and sequence.startswith("0"))
                    or int(sequence) <= 0
                    or int(sequence) > _NATIVE_MAX_SEQUENCE
                ):
                    return fail("native_history_sequence_invalid")
                sequence_number = int(sequence)
                if sequence_number > int(current_frontier["sequence"]):
                    return fail("native_history_not_pinned")
                if sequence_number in seen_sequences:
                    return fail("native_history_duplicate")
                seen_sequences.add(sequence_number)
                if item.get("summary_code") != item.get("schema_name"):
                    return fail("native_history_item_invalid")
                if item.get("projection_status") != "projected":
                    return fail("native_history_unprojected")
                if not isinstance(item.get("schema_name"), str) or not isinstance(
                    item.get("schema_version"), str
                ):
                    return fail("native_history_item_invalid")
                if item.get("schema_name") == "check_recorded":
                    manifest_value = item.get("review_input_manifest")
                    if manifest_value is not None and not isinstance(manifest_value, dict):
                        return fail("native_history_manifest_invalid")
                # The marker frontier is the native session's start boundary.  Public history
                # also includes earlier rows from the same task/session, so they must not be
                # allowed to satisfy this run's plan/check/receipt proof.
                if sequence_number <= int(marker_frontier["sequence"]):
                    continue
                history_items.append(item)
            if next_cursor_value is None:
                break
            if not next_cursor_value or next_cursor_value == cursor:
                return fail("native_history_cursor_invalid")
            cursor = next_cursor_value
        else:
            return fail("native_history_paging_exceeded")

        history_items.sort(key=lambda item: int(cast(str, item["ingestion_sequence"])))
        details["history_pages"] = page_number
        details["history_items"] = len(history_items)
        plans = [item for item in history_items if item.get("schema_name") == "plan_published"]
        checks = [item for item in history_items if item.get("schema_name") == "check_recorded"]
        receipts = [item for item in history_items if item.get("schema_name") == "receipt_recorded"]
        if not plans:
            return fail("native_plan_absent")
        plan = plans[0]
        if plan.get("publication_channel") != "cooperative_mcp":
            return fail("native_plan_channel_mismatch")
        if not checks:
            return fail("native_provider_bound_manifest_absent")
        check = checks[0]
        if check.get("publication_channel") != "engine_derived":
            return fail("native_check_channel_mismatch")
        if check.get("schema_version") != "1.3.0":
            return fail("native_provider_bound_schema_invalid")
        provider_bound = [
            item
            for item in checks
            if isinstance(item.get("review_input_manifest"), dict)
            and cast(dict[str, Any], item["review_input_manifest"]).get("phase") == "provider_bound"
        ]
        details["provider_bound_checks"] = len(provider_bound)
        details["first_provider_bound_event_id"] = check.get("event_id")
        details["first_provider_bound_sequence"] = check.get("ingestion_sequence")
        if not _history_provider_bound_manifest_matches(check, statement):
            return fail(
                "native_provider_bound_manifest_absent"
                if check.get("review_input_manifest") is None
                else "native_provider_bound_manifest_mismatch"
            )
        if not receipts:
            return fail("native_receipt_absent")
        receipt = receipts[0]
        if receipt.get("publication_channel") != "engine_derived":
            return fail("native_receipt_channel_mismatch")
        plan_sequence = int(cast(str, plan["ingestion_sequence"]))
        check_sequence = int(cast(str, check["ingestion_sequence"]))
        receipt_sequence = int(cast(str, receipt["ingestion_sequence"]))
        if not plan_sequence < check_sequence < receipt_sequence:
            return fail("native_workflow_order_invalid")
        details["plan_sequence"] = plan["ingestion_sequence"]
        details["receipt_sequence"] = receipt["ingestion_sequence"]
        details["matched"] = True
        details["reason"] = None
        self.native_provider_verification = details
        self._record(
            "native_provider_input",
            phase,
            status="pass",
            summary=details,
            fatal=False,
        )
        return True

    def phase_native_agent(self) -> None:
        phase = "native"
        if self.skip_agent:
            self._record("agent_run", phase, status="skip", reason="skip_agent")
            return
        argv, env, reason = self._agent_command()
        if argv is None:
            self._record("agent_run", phase, status="skip", reason=reason)
            self.agent = {"ran": False, "reason": reason}
            return
        rc, out, err, ms = self._run(
            argv, cwd=self.project, env=env, timeout=self.agent_timeout, drop=_LANE_SECRET_ENV
        )
        output_file = self._save("agent-output", out or "", ".txt")
        stderr_file = self._save("agent-stderr", err or "", ".txt")
        done = _native_done(self.host, out)
        native_binding = None
        if self.host != "codex":
            # The final response is the native process's own locator. An observation adapter is
            # only a fallback, and only when it carries the exact native external reference or an
            # explicit native workspace scope.
            native_binding = _native_binding_marker(self.host, out)
            if native_binding is None:
                native_binding = _native_binding_from_observation(
                    self.observation,
                    external_ref=self._native_external_ref(),
                    workspace=str(self.project),
                )
        # Freeze the native process evidence before the read-only public history verification.
        # A host's marker and DONE line are retained as metadata only; neither is workflow proof.
        self._record(
            "native_process_result",
            phase,
            status="pass" if rc == 0 else "info",
            exit_code=rc,
            duration_ms=ms,
            reason=None if rc == 0 else f"agent_exit_{rc}",
            summary={
                "done_marker": done,
                "output_digest": _digest(out),
                "output_bytes": len(out.encode("utf-8")),
                "output_file": output_file,
                "stderr_file": stderr_file,
                "receipt_or_frontier_proof": "host_output_not_authoritative",
                "binding_marker_present": native_binding is not None,
            },
            stderr=err,
        )
        native_mcp_completed = (
            _codex_workflow_completed(out, self.native_prompt)
            if self.host == "codex"
            else self._verify_native_provider_statement(
                phase, self.native_prompt or "", native_binding
            )
        )
        # Claude/Cursor require both a successful terminal response and the native session's
        # ordered public history. Codex keeps its direct structured MCP collector unchanged.
        completion_confirmed = (
            native_mcp_completed if self.host == "codex" else done and native_mcp_completed
        )
        self.agent = {
            "ran": True,
            "exit_code": rc,
            "timed_out": rc == 124,
            "duration_ms": ms,
            "output_digest": _digest(out),
            "output_bytes": len(out.encode("utf-8")),
            "done_marker": done,
            "native_mcp_completed": native_mcp_completed,
            "native_binding_source": None
            if native_binding is None
            else native_binding.get("source"),
            "native_provider_verification": self.native_provider_verification or None,
            "expected_statement_digest": _digest(self.native_prompt)
            if self.native_prompt is not None
            else None,
            "completion_confirmed": completion_confirmed,
            "output_file": output_file,
            "stderr_file": stderr_file,
        }
        ok = rc == 0 and completion_confirmed
        self._record(
            "agent_run",
            phase,
            status="pass" if ok else "fail",
            exit_code=rc,
            duration_ms=ms,
            reason=(
                None
                if ok
                else "agent_completion_missing"
                if rc == 0
                else "agent_timeout"
                if rc == 124
                else f"agent_exit_{rc}"
            ),
            summary={
                "done_marker": done,
                "native_mcp_completed": native_mcp_completed,
                "completion_confirmed": completion_confirmed,
                "output_bytes": len(out),
            },
            stderr=err,
        )
        status = self._observe_status("observe_status_after_agent", phase)
        self._observe_drain("observe_drain_after_agent", phase, fatal=False)
        status = self._observe_status("observe_status_after_drain", phase) or status
        catastrophic = self._catastrophic_diagnostics(status)
        mapped = bool((status or {}).get("mapping_present"))
        self.agent["mapping_present"] = mapped
        self.agent["catastrophic_diagnostics"] = catastrophic
        self._record(
            "agent_observation",
            phase,
            status="fail" if catastrophic else "pass",
            reason=",".join(catastrophic) if catastrophic else None,
            summary={"mapping_present": mapped, "catastrophic_diagnostics": catastrophic},
            fatal=bool(catastrophic),
        )
        self._yoetz(
            "service_status_after_agent", phase, ["service", "status", "--json"], fatal=True
        )

    # ---- lifecycle

    def _restart_and_unlock(self, phase: str, suffix: str) -> dict[str, Any]:
        """Restart the service and unlock it; the restarted service re-reads provider readiness."""

        assert self.launcher is not None
        self._yoetz(
            f"service_restart{suffix}",
            phase,
            ["service", "restart", "--json"],
            fatal=True,
            timeout=120.0,
        )
        status = self._wait_for_service(f"service_status_after_restart{suffix}", phase)
        if status.get("state") == "locked":
            self._ceremony_step(
                f"service_unlock{suffix}",
                phase,
                [str(self.launcher), "service", "unlock", "--json"],
                [Reply(PROMPT_PASSPHRASE, self.passphrase)],
                fatal=True,
            )
            status = self._wait_for_service(f"service_status_after_unlock{suffix}", phase)
        if status.get("state") != "ready":
            self._record(
                f"service_ready_after_restart{suffix}",
                phase,
                status="fail",
                reason=str(status.get("state_reason") or status.get("state")),
                fatal=True,
            )
        return status

    def _lock_and_unlock(self, phase: str, suffix: str) -> dict[str, Any]:
        """Lock and unlock the vault; the unlock recomposes the application in place."""

        assert self.launcher is not None
        self._yoetz(f"service_lock{suffix}", phase, ["service", "lock", "--json"], fatal=True)
        status = self._wait_for_service(f"service_status_after_lock{suffix}", phase)
        if status.get("state") == "locked":
            self._ceremony_step(
                f"service_unlock{suffix}",
                phase,
                [str(self.launcher), "service", "unlock", "--json"],
                [Reply(PROMPT_PASSPHRASE, self.passphrase)],
                fatal=True,
            )
            status = self._wait_for_service(f"service_status_after_unlock{suffix}", phase)
        if status.get("state") != "ready":
            self._record(
                f"service_ready_after_lock{suffix}",
                phase,
                status="fail",
                reason=str(status.get("state_reason") or status.get("state")),
                fatal=True,
            )
        return status

    def _check_after_restart(self, phase: str) -> None:
        """One more AI-review check on the probe session after a full restart (informational)."""

        session_id = self.ledger.get("session_id")
        writer_id = self.ledger.get("writer_id")
        if not (self.fireworks_key and isinstance(session_id, str) and isinstance(writer_id, str)):
            return
        ids = {"session_id": session_id, "writer_id": writer_id}
        _, status = self._yoetz(
            "ledger_status_after_restart",
            phase,
            ["status", "--input", "-", "--json"],
            stdin=self._request({**ids, "view": "compact", "limit": "10"}),
            expect_zero=False,
        )
        frontier = _find_frontier(status)
        if frontier is None:
            return
        _, checked = self._yoetz(
            "ledger_check_after_restart",
            phase,
            ["check", "--input", "-", "--json"],
            stdin=self._request(
                {
                    **ids,
                    "expected_frontier": frontier,
                    "max_findings": "10",
                    "mode": "semantic_required",
                }
            ),
            expect_zero=False,
            timeout=420.0,
        )
        if checked is not None:
            self.semantic["after_restart"] = {
                "status": checked.get("semantic_status"),
                "reason": checked.get("semantic_reason"),
                "provenance_present": checked.get("semantic_provenance") is not None,
            }

    def phase_lifecycle(self) -> None:
        phase = "lifecycle"
        if self.skip_restart:
            self._record("service_restart", phase, status="skip", reason="skip_restart")
            return
        self._restart_and_unlock(phase, "")
        self._check_after_restart(phase)
        after = self._observe_status("observe_status_after_restart", phase)
        consent_retained = after is not None and after.get("mapping_present") is not None
        self._record(
            "observation_retained",
            phase,
            status="pass" if consent_retained else "fail",
            reason=None if consent_retained else "observe_status_unreadable_after_restart",
        )

    # ---- teardown

    def phase_teardown(self) -> None:
        phase = "teardown"
        if self.launcher is None:
            self._record("dispose", phase, status="skip", reason="never_provisioned")
            return
        logs = self.evidence / "instance-logs"
        rc, out, err, ms = self._run(
            [
                sys.executable,
                str(self.checkout / "scripts" / "provision_test_instance.py"),
                "dispose",
                "--base",
                str(self.base),
                "--tag",
                self.tag,
                "--retain-logs",
                str(logs),
                "--json",
            ],
            timeout=300.0,
        )
        self._record(
            "dispose",
            phase,
            status="pass" if rc == 0 else "fail",
            exit_code=rc,
            duration_ms=ms,
            reason=None if rc == 0 else "dispose_failed",
            stdout=out,
            stderr=err,
        )
        proc = self.service_proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self.plugin_dir is not None and self.plugin_dir.exists():
            shutil.rmtree(self.plugin_dir, ignore_errors=True)
        direct = [self.evidence / "service.log", self.evidence / "agent-last-message.md"]
        for path in [*logs.rglob("*"), *direct]:
            if path.is_file():
                try:
                    path.write_text(
                        self.redact(path.read_text(encoding="utf-8", errors="replace")),
                        encoding="utf-8",
                    )
                except OSError:
                    pass

    # ---- report

    def report(self) -> dict[str, Any]:
        failed = [s.name for s in self.steps if s.status == "fail"]
        agent_ok: bool | None = None
        if self.agent.get("ran"):
            agent_ok = (
                self.agent.get("exit_code") == 0
                and self.agent.get("completion_confirmed") is True
                and self.agent.get("mapping_present") is True
            )
        agent_failures = {"agent_run"}
        catastrophic = [name for name in failed if name not in agent_failures]
        verdict = {
            "catastrophic": bool(catastrophic),
            "catastrophic_steps": catastrophic,
            "failed_steps": failed,
            "agent_ok": agent_ok,
            "strict_agent": self.strict_agent,
            # Strict mode passes only a successful agent; --skip-agent excuses an agent that
            # never ran, never one that ran and failed.
            "green": not catastrophic
            and (
                not self.strict_agent or agent_ok is True or (self.skip_agent and agent_ok is None)
            ),
        }
        body = {
            "schema": "yoetz.dogfood-lane/1",
            "generated_at": _now(),
            "host": self.host,
            "os_cell": self.os_cell,
            "connection_mode": self.connection_mode,
            "semantic_model": self.semantic_model,
            "agent_model": self.agent_model,
            "identity": self.identity,
            "semantic": self.semantic,
            "agent": self.agent,
            "observation": self.observation,
            "ledger": self.ledger,
            "steps": [asdict(step) for step in self.steps],
            "verdict": verdict,
        }
        return cast(dict[str, Any], self._redact_obj(body))

    def write_report(self) -> dict[str, Any]:
        body = self.report()
        (self.evidence / "lane-report.json").write_text(
            json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        lines = [
            f"## Dogfood lane: {self.host} on {self.os_cell} ({self.connection_mode})",
            "",
            f"verdict: {'GREEN' if body['verdict']['green'] else 'RED'}"
            f" · catastrophic={body['verdict']['catastrophic']} · agent_ok={body['verdict']['agent_ok']}",
            "",
            "| phase | step | status | reason |",
            "|---|---|---|---|",
        ]
        lines += [
            f"| {s.phase} | {s.name} | {s.status} | {self.redact(s.reason or '')} |"
            for s in self.steps
        ]
        text = "\n".join(lines) + "\n"
        (self.evidence / "lane-summary.md").write_text(text, encoding="utf-8")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as sink:
                sink.write(text)
        return body

    def run(self) -> int:
        try:
            self.phase_install()
            self.phase_connect()
            self.phase_ledger_probe()
            self.phase_native_agent()
            self.phase_lifecycle()
        except LaneAbort:
            pass
        finally:
            try:
                self.phase_teardown()
            finally:
                body = self.write_report()
        return 0 if body["verdict"]["green"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--host", choices=HOSTS, required=True)
    parser.add_argument("--checkout", default=str(_REPO_ROOT))
    parser.add_argument("--base", default=str(Path.home() / ".yz-instances"))
    parser.add_argument("--tag", default="df", help="Instance tag beneath --base (short).")
    parser.add_argument("--evidence", required=True, help="Directory for bounded evidence files.")
    parser.add_argument("--python", default="3.14.6", help="Interpreter for the instance runtime.")
    parser.add_argument("--host-path", default=None, help="Exact host executable.")
    parser.add_argument("--host-config-root", default=None, help="Host configuration root.")
    parser.add_argument("--project", default=None, help="Probe workspace (created if missing).")
    parser.add_argument("--connection-mode", choices=CONNECTION_MODES, default="auto")
    parser.add_argument("--semantic-model", default=SEMANTIC_MODEL_DEFAULT)
    parser.add_argument(
        "--agent-model",
        default=None,
        help="Fireworks model for the Codex and Claude agent sessions (default: glm-5p3-flash).",
    )
    parser.add_argument("--cursor-model", default=CURSOR_MODEL_DEFAULT)
    parser.add_argument("--agent-timeout", type=float, default=420.0)
    parser.add_argument("--strict-agent", action="store_true")
    parser.add_argument("--skip-agent", action="store_true")
    parser.add_argument("--skip-restart", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true", help="Build a modified tree.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    lane = Lane(args)
    return lane.run()


if __name__ == "__main__":
    raise SystemExit(main())
