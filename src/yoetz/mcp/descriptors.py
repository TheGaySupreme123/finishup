"""Frozen, honesty-bounded MCP tool descriptors and initialize instructions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from functools import cache
from types import MappingProxyType
from typing import Final, Literal, cast

from yoetz.mcp.resources import read_resource
from yoetz.mcp.semantic_destination import (
    MAX_DISCLOSURE_ENCODED_BYTES,
    SemanticDestinationDisclosure,
)
from yoetz.ports.control import McpHostProfile
from yoetz.ports.integrations import YOETZ_MCP_TOOL_NAMES
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.schemas import (
    SCHEMA_NAMESPACE,
    SCHEMA_VERSION_PATTERN,
    load_schema_catalog,
    schema_document_for,
)

__all__ = [
    "ADVERTISED_SURFACE_BUDGET",
    "CLAUDE_CODE_INITIALIZE_INSTRUCTIONS",
    "CLAUDE_CODE_INSTRUCTIONS_BUDGET",
    "COMPACT_INITIALIZE_INSTRUCTIONS",
    "COMPACT_INSTRUCTIONS_BUDGET",
    "COMPACT_INSTRUCTIONS_HOST_PROFILES",
    "INITIALIZE_GUIDANCE_URIS",
    "ORDINARY_MCP_PRESENTATION_SCHEMA_VERSIONS",
    "ORDINARY_MCP_PUBLISH_EVENT_FAMILIES",
    "PRESENTATION_INPUT_SCHEMA_BUDGETS",
    "SERVER_INSTRUCTIONS_BUDGET",
    "McpRouteProfile",
    "SemanticDestinationDisclosure",
    "TOOL_DESCRIPTOR_DIGESTS",
    "TOOL_DESCRIPTOR_SET_DIGEST",
    "TOOL_DESCRIPTORS",
    "ToolAnnotations",
    "ToolDescriptor",
    "advertised_surface_metrics",
    "descriptor_for",
    "ordinary_publish_families_in_presentation",
    "presentation_schema_metrics",
    "server_instructions",
]

type McpRouteProfile = Literal["policy", "strict"]
_HOST_PROFILES: Final[frozenset[str]] = frozenset({"generic", "codex", "claude", "cursor"})

_SCHEMA_VERSION: Final = "1.0.0"
_TOOL_INPUT_SCHEMA_VERSIONS: Final = MappingProxyType(
    {
        "start": "1.1.0",
        "publish_work": "1.2.0",
        "check": "1.1.0",
        "respond": "1.1.0",
        "status": "1.2.0",
        "closure_prepare": "1.0.0",
        "read_guidance": "1.1.0",
    }
)
_TOOL_OUTPUT_SCHEMA_VERSIONS: Final = MappingProxyType(
    {
        "start": "1.1.0",
        "check": "1.4.0",
        "respond": "1.1.0",
        "publish_work": "1.1.0",
        "status": "1.4.0",
        "receipt": "1.3.0",
        "closure_prepare": "1.0.0",
        "read_guidance": "1.1.0",
    }
)


def _tool_input_schema_version(name: str) -> str:
    return _TOOL_INPUT_SCHEMA_VERSIONS.get(name, _SCHEMA_VERSION)


def _tool_output_schema_version(name: str) -> str:
    return _TOOL_OUTPUT_SCHEMA_VERSIONS.get(name, _SCHEMA_VERSION)


# Exactly the entry document. Every other guidance document is fetched on demand: the catalog
# section of agent-instructions.md names the `resources/read` -> `read_guidance` -> installed
# `references/<name>.md` chain, and `read_guidance` (a plain tool call) survives the empty
# resource-read failure that motivated inlining workflow.md and coverage-and-receipts.md here.
# Keep this tuple at one entry; see ADVERTISED_SURFACE_BUDGET for why length is load-bearing.
INITIALIZE_GUIDANCE_URIS: Final[tuple[str, ...]] = ("yoetz://guidance/agent-instructions.md",)
_GUIDANCE_URI: Final = re.compile(r"yoetz://guidance/[a-z0-9.-]+\.md(?:#[a-z0-9-]+)?", re.ASCII)
_FORBIDDEN_CLAIMS: Final = re.compile(
    r"\b(?:authenticated|enforces?|gates?|observes?|proved|proves?|verified)\b",
    re.IGNORECASE | re.ASCII,
)
_BOUNDARY_TERMS: Final = re.compile(
    r"(?:/|\\|\b(?:claude|codex|cursor|gemini|host|model|openai|provider|version)\b)",
    re.IGNORECASE | re.ASCII,
)

# Mirrors application/publish_work ordinary cooperative_mcp|local_cli admission. Advertised
# publish_work schemas project to this set; catalog admission schemas remain authoritative.
# Presentation keeps ordinary families through schema 1.1.0. Additive ``evidence_recorded/1.2.0``
# (``observation_captured``) is authored only by the observation coordinator, not MCP/CLI publish.
ORDINARY_MCP_PRESENTATION_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1.0.0", "1.1.0"})
# Statement-bearing plans stay authorable through MCP so a parked review can receive its missing
# specification without replacing the session and writer that own the original check request.
ORDINARY_MCP_PUBLISH_EVENT_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "plan_published",
        "obligation_published",
        "assignment_recorded",
        "decision_recorded",
        "action_recorded",
        "result_recorded",
        "evidence_recorded",
        "claim_recorded",
        "plan_revised",
        "child_accepted",
        "child_rejected",
        "child_written_off",
        "delegation_cancelled",
        "work_closed",
        "work_cancelled",
        "work_written_off",
        "coordination_disposition_recorded",
        "coordination_obligation_declared",
    }
)

_COMMON_INLINE_SCHEMA_IDS: Final[frozenset[str]] = frozenset(
    {
        f"{SCHEMA_NAMESPACE}common/actor-assertion-1.0.0.schema.json",
        f"{SCHEMA_NAMESPACE}common/client-info-1.0.0.schema.json",
        f"{SCHEMA_NAMESPACE}common/frontier-1.0.0.schema.json",
    }
)
_EVENT_DRAFT_SCHEMA_ID: Final = f"{SCHEMA_NAMESPACE}events/event-draft-1.2.0.schema.json"
_OPAQUE_EVENT_DRAFT_SCHEMA_ID: Final = (
    f"{SCHEMA_NAMESPACE}events/opaque-unknown-event-draft-1.2.0.schema.json"
)

# Reviewed keyword budgets for tools/list presentation schemas (agent-usability guardrails).
PRESENTATION_INPUT_SCHEMA_BUDGETS: Final[Mapping[str, Mapping[str, int]]] = MappingProxyType(
    {
        "start-request": MappingProxyType(
            {
                "max_oneof_nodes": 0,
                "max_oneof_branches": 0,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 8,
                "max_defs_nest_depth": 1,
                "max_encoded_bytes": 5_000,
            }
        ),
        # obligation_published 1.1.0 (#1002) adds one draft branch, its payload definition and the
        # payload's evidence/result oneOf: +3 branches, +1 definition, and about 1.7 KB for that
        # payload (directory kind, item role, acknowledged_not_done status and its reason). The
        # branch cannot be shared with 1.0.0, which must keep refusing those additions.
        "publish-work-request": MappingProxyType(
            {
                "max_oneof_nodes": 8,
                "max_oneof_branches": 41,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 24,
                "max_defs_nest_depth": 1,
                # obligation_published 1.1.0 (#1002, #997) and blocker notices (#985).
                "max_encoded_bytes": 55_000,
            }
        ),
        "check-request": MappingProxyType(
            {
                "max_oneof_nodes": 0,
                "max_oneof_branches": 0,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 12,
                "max_defs_nest_depth": 1,
                "max_encoded_bytes": 8_000,
            }
        ),
        "respond-request": MappingProxyType(
            {
                "max_oneof_nodes": 0,
                "max_oneof_branches": 0,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 12,
                "max_defs_nest_depth": 1,
                "max_encoded_bytes": 8_000,
            }
        ),
        "status-request": MappingProxyType(
            {
                "max_oneof_nodes": 4,
                "max_oneof_branches": 8,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 20,
                "max_defs_nest_depth": 1,
                "max_encoded_bytes": 10_000,
            }
        ),
        "receipt-request": MappingProxyType(
            {
                "max_oneof_nodes": 0,
                "max_oneof_branches": 0,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 12,
                "max_defs_nest_depth": 1,
                "max_encoded_bytes": 6_000,
            }
        ),
        "read-guidance-request": MappingProxyType(
            {
                "max_oneof_nodes": 0,
                "max_oneof_branches": 0,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 4,
                "max_defs_nest_depth": 1,
                "max_encoded_bytes": 2_000,
            }
        ),
        "closure-prepare-request": MappingProxyType(
            {
                "max_oneof_nodes": 0,
                "max_oneof_branches": 0,
                "max_ref_nodes": 0,
                "max_conditional_nodes": 0,
                "max_defs_count": 4,
                "max_defs_nest_depth": 1,
                "max_encoded_bytes": 6_000,
            }
        ),
    }
)

# Reviewed budget for the initialize instructions block, per route profile.
#
# The MCP server sends `instructions` once, but a host is free to render it wherever it likes.
# Codex copies it verbatim into the `description` of every advertised tool, so this one string is
# charged once per tool on every turn of every session. Nothing bounded it before, and it grew to
# 41 KB (three inlined guidance documents) before a dogfood session noticed. The advertised input
# schemas have been bounded since #128; this is the same guardrail for the adjacent text.
# `packaged_max_encoded_bytes` bounds the packaged text alone (the #300 guard, unchanged).
# `max_encoded_bytes` adds the ceiling of the policy-route destination disclosure (#479), the one
# runtime-composed passage on this surface, so a budget review sees both numbers together.
SERVER_INSTRUCTIONS_BUDGET: Final[Mapping[str, int]] = MappingProxyType(
    {
        "packaged_max_encoded_bytes": 20_000,
        "max_encoded_bytes": 20_000 + MAX_DISCLOSURE_ENCODED_BYTES,
    }
)

# Observed host fact, not a documented Claude Code limit (issue #789): the Claude Code desktop app
# renders MCP initialize `instructions`, and each tool description it loads, into the model's
# context and keeps exactly the first 2,048 characters, then appends a literal "… [truncated]"
# marker. Measured 2026-09-21 on Claude Code desktop against the 0.2.1 bridge; every other MCP
# server on that machine stayed under the cap and Yoetz was the only block cut, mid-sentence,
# before the rule that says to call `start`. The packaged Claude text is bounded so that it, the
# policy route tail, and the longest admissible destination disclosure
# (`MAX_DISCLOSURE_ENCODED_BYTES`, issue #479) fit under the cap together: the privacy disclosure
# is never the part that gets cut. Codex and Cursor receive the compact body below (#918); the
# generic host keeps the full `agent-instructions.md` document.
# `packaged_max_chars` is derived: cap - len("\n\nRoute profile: policy. ") - len(policy tail)
# - 1 joiner - disclosure ceiling - 1 trailing newline = 2048 - 25 - 57 - 1 - 1000 - 1.
CLAUDE_CODE_INSTRUCTIONS_BUDGET: Final[Mapping[str, int]] = MappingProxyType(
    {
        "observed_host_cap_chars": 2_048,
        "packaged_max_chars": 964,
        "max_chars": 2_048,
    }
)
_POLICY_ROUTE_TAIL: Final = "External AI-powered review follows the configured policy."
_STRICT_ROUTE_TAIL: Final = (
    "This route will not request external AI-powered review for this process lifetime."
)
# The Claude-host initialize text. Its first two sentences are the trigger and the late-start
# rule, in imperative form, because those are the only lines guaranteed to survive a host that
# cuts the block; everything else is one `read_guidance` call away. Claude also renders this block
# into native subagents, which see no hook cue saying they are children (issue #509), so the
# scope sentences exempt a subagent whose assignment names neither child selector.
CLAUDE_CODE_INITIALIZE_INSTRUCTIONS: Final = (
    "# Yoetz: call start first\n"
    "\n"
    "If this session edits files, runs state-changing commands, or delegates, call `start` "
    "before work. If work began without a task, call `start` now, publish a plan, and disclose "
    "the uncovered prefix in the receipt. If only tool names show, load schema first (ToolSearch "
    "`select:mcp__yoetz__start` or plugin-prefixed name). Read-only questions skip it. "
    "Subagents whose assignment names no handle or parent session skip it.\n"
    "\n"
    "Before `start`, read `yoetz://guidance/agent-instructions.md`; if empty or clipped, page and "
    "verify. Do not list resources. After `start`, read workflow, publication, coverage, or "
    "request-template topics. Cadence: "
    "`publish_work` per transition, `check`, `receipt` last. Never claim active before `start`; "
    "never invent a task. If it fails, follow its continuation, then ask; do not work without a "
    "task.\n"
    "\n"
    "Yoetz records only what participants publish; a clean check does not mean the work "
    "is correct."
)

# Hosts that receive the compact initialize body instead of the full packaged document (#918).
COMPACT_INSTRUCTIONS_HOST_PROFILES: Final[frozenset[str]] = frozenset({"codex", "cursor"})
# Reviewed byte cap for the compact body (issue #918). Codex code mode builds every advertised
# tool's description from these instructions, the tool description and a generated declaration,
# so the body is charged once per tool (eight copies) on every turn. The full
# `agent-instructions.md` document cost 19,835 bytes per copy there. `packaged_max_encoded_bytes`
# bounds the packaged body alone. `max_encoded_bytes` is derived: that bound plus
# len("\n\nRoute profile: policy. ") + len(policy tail) + 1 joiner + the disclosure ceiling (#479)
# + 1 trailing newline = 2048 + 25 + 57 + 1 + 1000 + 1. The strict rendering is shorter. The
# disclosure is never trimmed to fit.
COMPACT_INSTRUCTIONS_BUDGET: Final[Mapping[str, int]] = MappingProxyType(
    {
        "packaged_max_encoded_bytes": 2_048,
        "max_encoded_bytes": 2_048
        + len("\n\nRoute profile: policy. ")
        + len(_POLICY_ROUTE_TAIL)
        + 1
        + MAX_DISCLOSURE_ENCODED_BYTES
        + 1,
    }
)
# The compact initialize text for the Codex and Cursor hosts. It keeps the rules an agent needs
# before its first guidance read: when to call `start`, the late-start and no-false-activation
# rules, where every guidance document is and when to read it, the cadence, the consent,
# disclosure and recovery boundaries, and coverage-honest wording. The full
# `agent-instructions.md` safety floor it summarizes is one `read_guidance` call away, and the
# text says to read it before the first `start`. It names no host, so one body serves both.
COMPACT_INITIALIZE_INSTRUCTIONS: Final = (
    "# Yoetz: call start first\n"
    "\n"
    "If this session will edit files, run state-changing commands, or delegate, call `start` "
    "before that work. If material work already began without a task, call `start` now, publish "
    "it as a plan, and disclose the uncovered prefix in the receipt. If the tool list shows only "
    "names, load the `start` schema first. Read-only questions skip it.\n"
    "\n"
    "Before the first `start`, call `read_guidance` on `yoetz://guidance/agent-instructions.md`; "
    "page and verify empty or clipped guidance. After `start`, read workflow "
    "`yoetz://guidance/workflow.md` for recovery or delegation, `yoetz://guidance/publication-policy.md` "
    "before `publish_work`, `yoetz://guidance/coverage-and-receipts.md` before `check`, and "
    "`yoetz://guidance/request-templates.md` for missing schemas or setup.\n"
    "\n"
    "Cadence: `start`, `publish_work`, `check`, `respond`, `receipt`. Never claim active before "
    "`start`; never invent a task, id, finding, verdict or receipt. If `start` fails, follow its "
    "typed continuation, then ask; do not work without a task.\n"
    "\n"
    "Publish only material, state-bound facts, never hidden reasoning, transcripts, credentials, "
    "secrets or whole files. Setup, privacy, credential and recommendation changes need user "
    "approval; never handle a vault secret. Recover through `status`, not Yoetz databases or source.\n"
    "\n"
    "Yoetz records only what participants publish; a clean check does not mean the work is correct."
)

# Reviewed budget for everything one host renders into the model's context to advertise Yoetz:
# the instructions block charged once per tool, plus every tool description, plus every advertised
# input schema. Per-item budgets cannot catch this — each item can sit inside its own bound while
# the total still doubles. `instructions_copies_per_tool` is descriptive, not a knob: it records the
# worst observed host behavior, one full copy of the instructions block charged to each of the
# eight advertised tools, which is what the total is computed against.
# The 0.3 surface retains the 18 ordinary lifecycle/coordination event families and the expanded
# current-main initialize guidance, including the #789 late-start rule carried from the 0.2 line.
# Statement-bearing plan variants add two branches and definitions for same-session input recovery
# (#951). The measured strict generic-host packaged surface is 252,168 bytes; the reviewed 253 KB
# ceiling retains every admitted family, example, and startup rule. Claude
# Code, Codex and Cursor receive compact initialize bodies instead, bounded separately above.
# The aggregate likewise carries the packaged bound plus one disclosure allowance per advertised
# tool, because the host that inlines the instructions inlines the disclosure with them.
ADVERTISED_SURFACE_BUDGET: Final[Mapping[str, int]] = MappingProxyType(
    {
        "instructions_copies_per_tool": 1,
        "packaged_max_encoded_bytes": 253_000,
        "max_encoded_bytes": 253_000 + len(YOETZ_MCP_TOOL_NAMES) * MAX_DISCLOSURE_ENCODED_BYTES,
    }
)


def advertised_surface_metrics(
    profile: McpRouteProfile = "policy",
    *,
    semantic_destination: SemanticDestinationDisclosure | None = None,
    host_profile: McpHostProfile = "generic",
) -> dict[str, int]:
    """Return the byte cost of one route profile's complete advertised MCP surface.

    ``replicated_encoded_bytes`` charges the instructions block once per advertised tool, which is
    what a host that inlines `instructions` into each tool description actually spends.
    ``semantic_destination`` is the policy-route disclosure the bridge appends (#479); pass the
    longest one to measure the worst case. ``host_profile`` selects the initialize body charged by
    the host, so Claude's compact surface can be measured separately from the generic surface.
    """

    if profile not in TOOL_DESCRIPTORS:
        raise ValueError("mcp_route_profile_invalid")
    descriptors = TOOL_DESCRIPTORS[profile]
    instructions_bytes = len(
        server_instructions(
            profile,
            semantic_destination=semantic_destination,
            host_profile=host_profile,
        ).encode("utf-8")
    )
    description_bytes = sum(len(item.description.encode("utf-8")) for item in descriptors)
    schema_bytes = sum(
        presentation_schema_metrics(item.input_schema)["encoded_bytes"] for item in descriptors
    )
    copies = len(descriptors) * ADVERTISED_SURFACE_BUDGET["instructions_copies_per_tool"]
    return {
        "tool_count": len(descriptors),
        "instructions_encoded_bytes": instructions_bytes,
        "description_encoded_bytes": description_bytes,
        "schema_encoded_bytes": schema_bytes,
        "replicated_encoded_bytes": instructions_bytes * copies + description_bytes + schema_bytes,
    }


def _example_id(kind: str, seed: int) -> str:
    prefixes = {
        "request": "req",
        "session": "ses",
        "writer": "wri",
        "event": "evt",
        "action": "act",
        "claim": "clm",
        "evidence": "evd",
        "finding": "fnd",
        "obligation": "obl",
        "result": "res",
        "task": "tsk",
    }
    return f"{prefixes[kind]}_00000000-0000-4000-8000-{seed:012d}"


# Illustrative only: do not copy into live drafts. Prefer the best real RFC 3339 ms UTC time.
_EXAMPLE_OCCURRED_AT: Final = "2026-01-01T00:00:00.000Z"


def _example_draft(
    seed: int,
    family: str,
    payload: dict[str, JsonValue],
    *,
    version: str = "1.0.0",
    evidence_refs: list[JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """One minimal valid draft envelope for a family, so agents copy shape rather than guess it.

    ``occurred_at`` is intentionally a fixed illustrative placeholder. Live drafts must use the
    best real caller-asserted event time; service acceptance time is stamped separately.
    """

    return {
        "event_id": _example_id("event", seed),
        "schema": {"name": family, "version": version},
        "occurred_at": _EXAMPLE_OCCURRED_AT,
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [] if evidence_refs is None else evidence_refs,
    }


_EXAMPLE_ACTOR: Final[dict[str, JsonValue]] = {
    "actor_id": "harness:mcp-example",
    "actor_type": "harness",
}
_EXAMPLE_CLIENT: Final[dict[str, JsonValue]] = {
    "kind": "cooperative_agent",
    "version": "0.1.0",
    "integration": "cooperative_mcp",
}
# A syntactically valid non-genesis head. Read the real one from status; never reuse this value.
_EXAMPLE_HEAD_DIGEST: Final = "sha256:" + "0" * 64


def _lifecycle_example(ordinal: int, family: str) -> dict[str, JsonValue]:
    """Separate requests keep mutually exclusive work transitions out of one example batch."""

    payload: dict[str, JsonValue] = (
        {"child_task_id": _example_id("task", 2)} if not family.startswith("work_") else {}
    )
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _example_id("request", ordinal),
        "session_id": _example_id("session", 1),
        "writer_id": _example_id("writer", 1),
        "expected_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
        "event_drafts": [_example_draft(ordinal, family, payload)],
        "actor": dict(_EXAMPLE_ACTOR),
        "client": dict(_EXAMPLE_CLIENT),
    }


_INPUT_SCHEMA_EXAMPLES: Final[Mapping[str, tuple[dict[str, JsonValue], ...]]] = MappingProxyType(
    {
        "start-request": (
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 1),
                "mode": "create",
                "task_title": "Example task",
                "requested_view": "compact",
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 30),
                "mode": "delegate",
                "session_id": _example_id("session", 1),
                "task_title": "Example child task",
                "requested_view": "compact",
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 31),
                "mode": "attach",
                "attach_handle": {
                    "handle": "illustrative-only-replace-with-returned-handle",
                    "child_task_id": _example_id("task", 2),
                    "expires_at": "2026-01-01T00:10:00.000Z",
                },
                "task_title": "Example child task",
                "requested_view": "compact",
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 32),
                "mode": "create_or_attach",
                "parent_session_id": _example_id("session", 1),
                "workspace_ref": "/workspace/project",
                "external_ref": "example-child-review",
                "task_title": "Example self-registered child",
                "requested_view": "compact",
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
        ),
        # check, respond, and receipt had no worked example at all. Every tool an agent must call
        # to reach a completion claim now shows one, so authoring never depends on reading source.
        "check-request": (
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 7),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
        ),
        "respond-request": (
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 8),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "finding_id": _example_id("finding", 1),
                "finding_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "disposition": "acknowledged",
                "reason": "The finding is accurate; the obligation stays open until it is fixed.",
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
        ),
        "receipt-request": (
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 9),
                "task_id": _example_id("task", 1),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "format": "markdown",
                "include": "standard",
                "redaction_profile": "default_local_export",
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
        ),
        "status-request": (
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 2),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "view": "compact",
                "limit": "10",
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
        ),
        "read-guidance-request": (
            {
                "uri": "yoetz://guidance/workflow.md",
            },
        ),
        # One worked draft per ordinary publishable family. The plan example alone left agents
        # hand-deriving action/result/evidence/claim shapes from a large oneOf, which is where
        # routine publication attempts actually fail.
        "publish-work-request": (
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 3),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
                "event_drafts": [
                    _example_draft(
                        1,
                        "plan_published",
                        {
                            "plan_version": 1,
                            "summary": "One atomic change with no independent obligation split.",
                            "obligation_refs": [],
                            "no_obligations_reason": "single_atomic_change",
                        },
                    )
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 4),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "event_drafts": [
                    _example_draft(
                        2,
                        "obligation_published",
                        {
                            "obligation_id": _example_id("obligation", 1),
                            "description": "State the outcome this work owes.",
                            "evidence_expectation": "A named test run or reviewed diff.",
                            "status": "open",
                        },
                    ),
                    _example_draft(
                        3,
                        "assignment_recorded",
                        {
                            "assignee_actor_id": "harness:mcp-example",
                            "obligation_ids": [
                                _example_id("obligation", 1),
                                _example_id("obligation", 2),
                            ],
                            "scope_description": "One independently reviewable work package.",
                        },
                    ),
                    _example_draft(
                        4,
                        "decision_recorded",
                        {
                            "statement": "Keep the existing adapter instead of adding one.",
                            "rationale": "The current path already covers the requested case.",
                            "authority": "harness:mcp-example",
                        },
                    ),
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 5),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "4", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "event_drafts": [
                    _example_draft(
                        5,
                        "action_recorded",
                        {
                            "action_id": _example_id("action", 1),
                            "action_kind": "command",
                            # action_kind "command" additionally requires command.
                            "command": "pytest -q",
                            "description": "Ran the focused test slice for the touched module.",
                            # Each entry copies one obligation requested_items value byte-for-byte;
                            # only action_recorded admits attempted_items (issue #264).
                            "attempted_items": ["pytest -q"],
                        },
                    ),
                    _example_draft(
                        6,
                        "result_recorded",
                        {
                            "result_id": _example_id("result", 1),
                            "action_id": _example_id("action", 1),
                            "outcome": "success",
                            "summary": "The focused slice passed.",
                        },
                    ),
                    _example_draft(
                        7,
                        "evidence_recorded",
                        {
                            "evidence_id": _example_id("evidence", 1),
                            "evidence_kind": "test_result",
                            # Each strength requires its own proof field; content_digest
                            # requires content_digest.
                            "strength": "content_digest",
                            "content_digest": _EXAMPLE_HEAD_DIGEST,
                            "digest_binding": {
                                "subject": "test_stdout",
                                "content_availability": "digest_only",
                                "byte_count": 4096,
                                "provenance": "caller_asserted",
                            },
                            "observed_at": "2026-01-01T00:00:00.000Z",
                            "description": "Focused test slice for the touched module.",
                        },
                        version="1.1.0",
                    ),
                    _example_draft(
                        8,
                        "claim_recorded",
                        {
                            "claim_id": _example_id("claim", 1),
                            "claim_kind": "completion",
                            "statement": "The requested change is implemented and covered.",
                            "supporting_refs": [_example_id("evidence", 1)],
                            "limitation_refs": [],
                            "supersedes_claim_refs": [],
                        },
                        version="1.1.0",
                    ),
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 6),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "8", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "event_drafts": [
                    _example_draft(
                        9,
                        "plan_revised",
                        {
                            "plan_version": 2,
                            "supersedes_plan_version": 1,
                            "reason": "The reviewed scope changed after inspecting the source.",
                            "summary": "Revised plan",
                            "obligation_changes": [
                                {
                                    "obligation_id": _example_id("obligation", 1),
                                    "change": "carried",
                                }
                            ],
                        },
                    )
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            # Obligation resolution: repeat meaning fields byte-for-byte; only status and
            # resolution_evidence_refs may change. See publication-policy.md#obligation-resolution.
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 10),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "2", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "event_drafts": [
                    _example_draft(
                        10,
                        "obligation_published",
                        {
                            "obligation_id": _example_id("obligation", 2),
                            "description": "State the outcome this work owes.",
                            "acceptance_criteria": "A focused test slice passes at the claimed state.",
                            "evidence_expectation": "A named test run or reviewed diff.",
                            "status": "open",
                            "requested_items": [{"item_kind": "command", "value": "pytest -q"}],
                        },
                    ),
                    _example_draft(
                        11,
                        "evidence_recorded",
                        {
                            "evidence_id": _example_id("evidence", 2),
                            "evidence_kind": "test_result",
                            "strength": "content_digest",
                            "content_digest": _EXAMPLE_HEAD_DIGEST,
                            "digest_binding": {
                                "subject": "test_stdout",
                                "content_availability": "digest_only",
                                "byte_count": 4096,
                                "provenance": "caller_asserted",
                            },
                            "observed_at": "2026-01-01T00:00:00.000Z",
                            "description": "Focused test slice for the claimed outcome.",
                        },
                        version="1.1.0",
                    ),
                    _example_draft(
                        12,
                        "obligation_published",
                        {
                            "obligation_id": _example_id("obligation", 2),
                            "description": "State the outcome this work owes.",
                            "acceptance_criteria": "A focused test slice passes at the claimed state.",
                            "evidence_expectation": "A named test run or reviewed diff.",
                            "status": "resolved",
                            "requested_items": [{"item_kind": "command", "value": "pytest -q"}],
                            "resolution_evidence_refs": [_example_id("evidence", 2)],
                        },
                    ),
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            # Issue #997 (ADR-032 slice C): the honest last resort for an obligation the agent
            # will not do, after repair: repeat the meaning fields, status acknowledged_not_done
            # with a reason, on obligation_published 1.1.0. A later open or resolved
            # publication of the same obligation takes it back.
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 13),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "2", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "event_drafts": [
                    _example_draft(
                        13,
                        "obligation_published",
                        {
                            "obligation_id": _example_id("obligation", 2),
                            "description": "State the outcome this work owes.",
                            "acceptance_criteria": "A focused test slice passes at the claimed state.",
                            "evidence_expectation": "A named test run or reviewed diff.",
                            "status": "acknowledged_not_done",
                            "requested_items": [{"item_kind": "command", "value": "pytest -q"}],
                            "acknowledged_not_done_reason": "Out of scope for this change; reported to the user.",
                        },
                        version="1.1.0",
                    ),
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            *(
                _lifecycle_example(40 + index, family)
                for index, family in enumerate(
                    (
                        "child_accepted",
                        "child_rejected",
                        "child_written_off",
                        "delegation_cancelled",
                        "work_closed",
                        "work_cancelled",
                        "work_written_off",
                    )
                )
            ),
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 50),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "event_drafts": [
                    _example_draft(
                        50,
                        "coordination_disposition_recorded",
                        {
                            "detection_id": _example_id("event", 49),
                            "project_id": "prj_00000000-0000-4000-8000-000000000001",
                            "membership_generation": "1",
                            "recipient_task_id": _example_id("task", 1),
                            "obligation_id": _example_id("obligation", 1),
                            "disposition": "shared_work",
                            "evidence_refs": [_example_id("evidence", 1)],
                        },
                        evidence_refs=[_example_id("evidence", 1)],
                    )
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _example_id("request", 51),
                "session_id": _example_id("session", 1),
                "writer_id": _example_id("writer", 1),
                "expected_frontier": {"sequence": "1", "head_digest": _EXAMPLE_HEAD_DIGEST},
                "event_drafts": [
                    _example_draft(
                        51,
                        "coordination_obligation_declared",
                        {
                            "detection_id": _example_id("event", 49),
                            "project_id": "prj_00000000-0000-4000-8000-000000000001",
                            "membership_generation": "1",
                            "recipient_task_id": _example_id("task", 1),
                            "obligation_id": _example_id("obligation", 1),
                        },
                    )
                ],
                "actor": dict(_EXAMPLE_ACTOR),
                "client": dict(_EXAMPLE_CLIENT),
            },
        ),
    }
)


def _mutable_json(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        source = cast(Mapping[str, JsonValue], value)
        return {key: _mutable_json(item) for key, item in source.items()}
    if isinstance(value, tuple | list):
        sequence = cast(tuple[JsonValue, ...] | list[JsonValue], value)
        return [_mutable_json(item) for item in sequence]
    return value


def _strip_schema_metadata(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        key: _mutable_json(item)
        for key, item in value.items()
        if key not in {"$id", "$schema", "title"}
    }


def _event_identity_from_payload_ref(branch: Mapping[str, JsonValue]) -> tuple[str, str] | None:
    properties = branch.get("properties")
    if not isinstance(properties, Mapping):
        return None
    payload = cast(Mapping[str, JsonValue], properties).get("payload")
    if not isinstance(payload, Mapping):
        return None
    ref = cast(Mapping[str, JsonValue], payload).get("$ref")
    if type(ref) is not str or not ref.startswith(SCHEMA_NAMESPACE):
        return None
    uri = ref.partition("#")[0]
    marker = "/events/"
    suffix = ".schema.json"
    if marker not in uri or not uri.endswith(suffix):
        return None
    stem = uri.rsplit(marker, 1)[1].removesuffix(suffix)
    for delimiter in (index for index, char in enumerate(stem) if char == "-"):
        slug = stem[:delimiter]
        version = stem[delimiter + 1 :]
        if slug and SCHEMA_VERSION_PATTERN.fullmatch(version) is not None:
            return slug.replace("-", "_"), version
    return None


def _event_identity_from_schema_consts(branch: Mapping[str, JsonValue]) -> tuple[str, str] | None:
    properties = branch.get("properties")
    if not isinstance(properties, Mapping):
        return None
    schema_node = cast(Mapping[str, JsonValue], properties).get("schema")
    if not isinstance(schema_node, Mapping):
        return None
    nested_props = cast(Mapping[str, JsonValue], schema_node).get("properties")
    if not isinstance(nested_props, Mapping):
        return None
    typed_props = cast(Mapping[str, JsonValue], nested_props)
    name_node = typed_props.get("name")
    version_node = typed_props.get("version")
    if not isinstance(name_node, Mapping) or not isinstance(version_node, Mapping):
        return None
    const_name = cast(Mapping[str, JsonValue], name_node).get("const")
    const_version = cast(Mapping[str, JsonValue], version_node).get("const")
    if type(const_name) is str and type(const_version) is str:
        return const_name, const_version
    return None


def _event_identity_from_draft_branch(branch: Mapping[str, JsonValue]) -> tuple[str, str] | None:
    return _event_identity_from_schema_consts(branch) or _event_identity_from_payload_ref(branch)


def _event_family_from_draft_branch(branch: Mapping[str, JsonValue]) -> str | None:
    identity = _event_identity_from_draft_branch(branch)
    return None if identity is None else identity[0]


def _project_event_draft_for_ordinary_mcp(
    event_draft: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    projected = _strip_schema_metadata(event_draft)
    one_of = projected.get("oneOf")
    if not isinstance(one_of, list):
        raise RuntimeError("mcp_event_draft_projection_invalid")
    kept: list[JsonValue] = []
    kept_families: set[str] = set()
    for branch in cast(list[JsonValue], one_of):
        if not isinstance(branch, Mapping):
            continue
        branch_map = cast(Mapping[str, JsonValue], branch)
        ref = branch_map.get("$ref")
        if type(ref) is str and ref.partition("#")[0] == _OPAQUE_EVENT_DRAFT_SCHEMA_ID:
            continue
        identity = _event_identity_from_draft_branch(branch_map)
        if identity is None:
            continue
        family, version = identity
        if (
            family in ORDINARY_MCP_PUBLISH_EVENT_FAMILIES
            and version in ORDINARY_MCP_PRESENTATION_SCHEMA_VERSIONS
        ):
            kept.append(_mutable_json(branch_map))
            kept_families.add(family)
    if kept_families != set(ORDINARY_MCP_PUBLISH_EVENT_FAMILIES):
        raise RuntimeError("mcp_event_draft_projection_incomplete")
    projected["oneOf"] = kept
    return projected


def _resolved_external_document(
    uri: str, *, project_ordinary_event_draft: bool
) -> Mapping[str, JsonValue]:
    catalog = load_schema_catalog()
    document = catalog.by_id.get(uri)
    if document is None:
        raise RuntimeError("mcp_schema_reference_unknown")
    if project_ordinary_event_draft and uri == _EVENT_DRAFT_SCHEMA_ID:
        return _project_event_draft_for_ordinary_mcp(document.json_schema)
    return document.json_schema


def _external_schema_documents(
    value: JsonValue, *, project_ordinary_event_draft: bool = False
) -> dict[str, Mapping[str, JsonValue]]:
    documents: dict[str, Mapping[str, JsonValue]] = {}

    def visit(candidate: JsonValue) -> None:
        if isinstance(candidate, Mapping):
            source = cast(Mapping[str, JsonValue], candidate)
            ref = source.get("$ref")
            if isinstance(ref, str) and ref.startswith(SCHEMA_NAMESPACE):
                uri = ref.partition("#")[0]
                if uri == _OPAQUE_EVENT_DRAFT_SCHEMA_ID and project_ordinary_event_draft:
                    return
                if uri not in documents:
                    nested = _resolved_external_document(
                        uri, project_ordinary_event_draft=project_ordinary_event_draft
                    )
                    documents[uri] = nested
                    visit(nested)
            for item in source.values():
                visit(item)
        elif isinstance(candidate, tuple | list):
            sequence = cast(tuple[JsonValue, ...] | list[JsonValue], candidate)
            for item in sequence:
                visit(item)

    visit(value)
    return documents


def _bundle_key(uri: str) -> str:
    return "__yoetz_" + hashlib.sha256(uri.encode("ascii")).hexdigest()[:16]


def _rewrite_schema_refs(
    value: JsonValue,
    *,
    current_uri: str,
    root_uri: str,
    inline_uris: frozenset[str] = frozenset(),
) -> JsonValue:
    if isinstance(value, Mapping):
        source = cast(Mapping[str, JsonValue], value)
        rewritten_ref = source.get("$ref")
        if isinstance(rewritten_ref, str):
            if rewritten_ref.startswith(SCHEMA_NAMESPACE):
                uri, separator, fragment = rewritten_ref.partition("#")
                if uri in inline_uris and not separator and set(source.keys()) == {"$ref"}:
                    catalog = load_schema_catalog()
                    document = catalog.by_id.get(uri)
                    if document is None:
                        raise RuntimeError("mcp_schema_reference_unknown")
                    return _rewrite_schema_refs(
                        _strip_schema_metadata(document.json_schema),
                        current_uri=uri,
                        root_uri=root_uri,
                        inline_uris=inline_uris,
                    )
                rewritten_ref = f"#/$defs/{_bundle_key(uri)}"
                if separator and fragment:
                    rewritten_ref += fragment
            elif rewritten_ref.startswith("#") and current_uri != root_uri:
                rewritten_ref = f"#/$defs/{_bundle_key(current_uri)}{rewritten_ref[1:]}"
        return {
            key: (
                rewritten_ref
                if key == "$ref" and isinstance(rewritten_ref, str)
                else _rewrite_schema_refs(
                    item,
                    current_uri=current_uri,
                    root_uri=root_uri,
                    inline_uris=inline_uris,
                )
            )
            for key, item in source.items()
            if key not in {"$id", "$schema"}
        }
    if isinstance(value, tuple | list):
        sequence = cast(tuple[JsonValue, ...] | list[JsonValue], value)
        return [
            _rewrite_schema_refs(
                item,
                current_uri=current_uri,
                root_uri=root_uri,
                inline_uris=inline_uris,
            )
            for item in sequence
        ]
    return value


def _inline_nested_local_defs(parent_key: str, body: JsonValue) -> JsonValue:
    """Inline ``#/$defs/<parent>/$defs/<child>`` targets and drop nested ``$defs``."""

    if not isinstance(body, Mapping):
        return body
    source = cast(Mapping[str, JsonValue], body)
    nested = source.get("$defs")
    if not isinstance(nested, Mapping):
        return _mutable_json(source)
    nested_defs = cast(Mapping[str, JsonValue], nested)
    prefix = f"#/$defs/{parent_key}/$defs/"

    def resolve(candidate: JsonValue) -> JsonValue:
        if isinstance(candidate, Mapping):
            mapping = cast(Mapping[str, JsonValue], candidate)
            ref = mapping.get("$ref")
            if type(ref) is str and ref.startswith(prefix) and "/" not in ref[len(prefix) :]:
                child_key = ref[len(prefix) :]
                target = nested_defs.get(child_key)
                if target is None:
                    raise RuntimeError("mcp_schema_nested_def_missing")
                resolved_target = resolve(_mutable_json(target))
                if not isinstance(resolved_target, Mapping):
                    raise RuntimeError("mcp_schema_nested_def_invalid")
                merged = dict(cast(Mapping[str, JsonValue], resolved_target))
                for key, item in mapping.items():
                    if key == "$ref":
                        continue
                    resolved_item = resolve(item)
                    if key in merged and merged[key] != resolved_item:
                        raise RuntimeError("mcp_schema_ref_sibling_conflict")
                    merged[key] = resolved_item
                return merged
            return {key: resolve(item) for key, item in mapping.items() if key != "$defs"}
        if isinstance(candidate, tuple | list):
            sequence = cast(tuple[JsonValue, ...] | list[JsonValue], candidate)
            return [resolve(item) for item in sequence]
        return candidate

    return resolve(source)


def _local_def_key(ref: JsonValue) -> str | None:
    if type(ref) is not str or not ref.startswith("#/$defs/"):
        return None
    remainder = ref[len("#/$defs/") :]
    if not remainder or "/" in remainder:
        return None
    return remainder


def _event_payload_definitions(
    definitions: Mapping[str, JsonValue],
) -> frozenset[str]:
    """Return event payload definitions and their shared definition dependencies."""

    event_body = definitions.get(_bundle_key(_EVENT_DRAFT_SCHEMA_ID))
    if not isinstance(event_body, Mapping):
        return frozenset()
    one_of = cast(Mapping[str, JsonValue], event_body).get("oneOf")
    if not isinstance(one_of, list):
        raise RuntimeError("mcp_event_draft_projection_invalid")
    roots: set[str] = set()
    for branch in cast(list[JsonValue], one_of):
        if not isinstance(branch, Mapping):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        properties = cast(Mapping[str, JsonValue], branch).get("properties")
        if not isinstance(properties, Mapping):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        payload = cast(Mapping[str, JsonValue], properties).get("payload")
        if not isinstance(payload, Mapping):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        key = _local_def_key(cast(Mapping[str, JsonValue], payload).get("$ref"))
        if key is None:
            raise RuntimeError("mcp_event_draft_projection_invalid")
        roots.add(key)

    retained = set(roots)
    pending = list(roots)
    while pending:
        key = pending.pop()
        body = definitions.get(key)
        if body is None:
            raise RuntimeError("mcp_schema_reference_unknown")
        for dependency in _referenced_top_level_defs(body):
            if dependency not in retained:
                retained.add(dependency)
                pending.append(dependency)
    return frozenset(retained)


def _inline_presentation_refs(schema: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Inline local presentation refs except the bounded event-payload definition graph."""

    raw_definitions = schema.get("$defs")
    if not isinstance(raw_definitions, Mapping):
        raise RuntimeError("mcp_schema_invalid")
    definitions = cast(Mapping[str, JsonValue], raw_definitions)
    retained = _event_payload_definitions(definitions)
    resolving: set[str] = set()

    def resolve(candidate: JsonValue) -> JsonValue:
        if isinstance(candidate, Mapping):
            mapping = cast(Mapping[str, JsonValue], candidate)
            key = _local_def_key(mapping.get("$ref"))
            if key is not None and key not in retained:
                if key in resolving:
                    raise RuntimeError("mcp_schema_reference_cycle")
                target = definitions.get(key)
                if target is None:
                    raise RuntimeError("mcp_schema_reference_unknown")
                resolving.add(key)
                try:
                    resolved_target = resolve(_mutable_json(target))
                finally:
                    resolving.remove(key)
                if not isinstance(resolved_target, Mapping):
                    raise RuntimeError("mcp_schema_def_invalid")
                merged = dict(cast(Mapping[str, JsonValue], resolved_target))
                for sibling_key, item in mapping.items():
                    if sibling_key == "$ref":
                        continue
                    resolved_item = resolve(item)
                    if sibling_key in merged and merged[sibling_key] != resolved_item:
                        raise RuntimeError("mcp_schema_ref_sibling_conflict")
                    merged[sibling_key] = resolved_item
                return merged
            return {
                item_key: resolve(item) for item_key, item in mapping.items() if item_key != "$defs"
            }
        if isinstance(candidate, tuple | list):
            sequence = cast(tuple[JsonValue, ...] | list[JsonValue], candidate)
            return [resolve(item) for item in sequence]
        return candidate

    resolved = resolve(schema)
    if not isinstance(resolved, dict):
        raise RuntimeError("mcp_schema_invalid")
    if retained:
        resolved["$defs"] = {
            key: _mutable_json(definitions[key]) for key in definitions if key in retained
        }
    return resolved


def _flatten_frontier_conditions(candidate: JsonValue) -> JsonValue:
    """Keep a host-authorable frontier shape while catalog admission retains exact coupling."""

    if isinstance(candidate, Mapping):
        mapping = {
            key: (_mutable_json(item) if key == "$defs" else _flatten_frontier_conditions(item))
            for key, item in cast(Mapping[str, JsonValue], candidate).items()
        }
        properties = mapping.get("properties")
        required = mapping.get("required")
        if (
            isinstance(properties, dict)
            and {"sequence", "head_digest"}.issubset(properties)
            and isinstance(required, list)
            and {"sequence", "head_digest"}.issubset(required)
            and "allOf" in mapping
        ):
            mapping.pop("allOf")
            head_digest = properties.get("head_digest")
            if not isinstance(head_digest, dict):
                raise RuntimeError("mcp_frontier_projection_invalid")
            head_digest["pattern"] = "^(genesis|sha256:[0-9a-f]{64})$"
            head_digest["description"] = "Genesis is valid only with sequence 0."
        return mapping
    if isinstance(candidate, tuple | list):
        sequence = cast(tuple[JsonValue, ...] | list[JsonValue], candidate)
        return [_flatten_frontier_conditions(item) for item in sequence]
    return candidate


def _describe_presentation_schema(name: str, schema: dict[str, JsonValue]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise RuntimeError("mcp_schema_invalid")

    request_id = properties.get("request_id")
    if isinstance(request_id, dict):
        request_id["description"] = "Use a fresh req_ prefixed random UUID for each request."

    expected_frontier = properties.get("expected_frontier")
    if isinstance(expected_frontier, dict):
        expected_frontier["description"] = (
            "Use the sequence and head digest returned by status. Genesis is valid only with "
            "sequence 0."
        )

    if name == "start-request":
        mode = properties.get("mode")
        if isinstance(mode, dict):
            mode["description"] = (
                "mode attach requires session_id, or both workspace_ref and external_ref with no "
                "session_id."
            )
    elif name == "publish-work-request":
        event_drafts = properties.get("event_drafts")
        if not isinstance(event_drafts, dict):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        event_drafts["description"] = (
            "Send one bounded batch per material transition. Each schema.name selects the "
            "payload shape. Every reference list in the envelope and payload must already be "
            "unique and in ascending ASCII order; a kernel rejection names unsorted_set_field "
            "at the owning field. A one-element dry_run subset cannot demonstrate that rule."
        )
        items = event_drafts.get("items")
        if not isinstance(items, dict):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        item_properties = items.get("properties")
        if not isinstance(item_properties, dict):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        schema_property = item_properties.get("schema")
        if not isinstance(schema_property, dict):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        schema_properties = schema_property.get("properties")
        if not isinstance(schema_properties, dict):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        family_name = schema_properties.get("name")
        if not isinstance(family_name, dict):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        family_name["enum"] = cast(list[JsonValue], sorted(ORDINARY_MCP_PUBLISH_EVENT_FAMILIES))
        family_name["description"] = "Selects the event family and its payload fields."
        payload = item_properties.get("payload")
        if not isinstance(payload, dict):
            raise RuntimeError("mcp_event_draft_projection_invalid")
        payload["type"] = "object"
        payload["description"] = (
            "Fields depend on schema.name; use the matching event family template. "
            "attempted_items is admitted only by action_recorded, authority is an actor id, and "
            "action_kind admits command, edit, research, review, and other."
        )
    elif name == "check-request":
        mode = properties.get("mode")
        if isinstance(mode, dict):
            mode["description"] = (
                "Omit to use the configured default. Select semantic_required for a known "
                "requirement, including final rechecks; semantic_if_configured only when review "
                "is known to be optional."
            )
        scope = properties.get("scope")
        if isinstance(scope, dict):
            scope["description"] = (
                "Omit for the whole case, or send both claim_ids and obligation_ids. Two empty "
                "arrays also mean the whole case."
            )
        final_review = properties.get("final_review")
        if isinstance(final_review, dict):
            final_review["description"] = (
                "Set true for the closing review, the last check before the receipt: the "
                "reviewer judges each stated requirement and requested output against the task, "
                "with or without a completion claim. Omit for in-progress checks."
            )
        await_observations = properties.get("await_observations")
        if isinstance(await_observations, dict):
            await_observations["description"] = (
                "Set true to wait up to about 3 seconds for this task's hook observations still "
                "being delivered before the check, instead of polling status. The result's "
                "observations_awaited reports complete or bounded_timeout; the check never fails "
                "because of the wait."
            )
    elif name == "respond-request":
        disposition = properties.get("disposition")
        if isinstance(disposition, dict):
            disposition["description"] = (
                "Acknowledged accepts no waiver fields and, on an AI-powered review finding, "
                "requires a reason the next review reads (for answer_question, the answer); on a "
                "limitation request (requested_next_step state_unresolved_limitation) one "
                "reasoned acknowledgement says the requirement may be met but cannot be confirmed "
                "here and needs no repair attempt. "
                "Self_verified means you repaired it, Yoetz's later check still cannot confirm it "
                "because of a Yoetz limit, and you checked it yourself: reason says how, and "
                "evidence_refs (at least one) cite your recorded evidence; it is final. "
                "Acknowledged_not_done means you will not or cannot do it and is the last resort "
                "(on a limitation request it says the requirement is NOT met); "
                "reopened (reason required) takes it back so the finding is open again, and a "
                "later check that finds the issue absent after your answer resolves it by "
                "itself. Duplicate_of is only for a restatement of the SAME issue (same origin "
                "and kind) as an earlier finding you answered: name it in duplicate_of_finding_id; "
                "reason and evidence are optional and it is not final. Linking never resolves the "
                "new finding (its own check must); a later check that raises its issue again "
                "breaks the link. Provenance_disputed contests the finding's authorship "
                "or provenance premise rather than its conclusion. It, rejected, reopened and "
                "acknowledged_not_done require reason and accept no waiver fields. Waived "
                "requires reason and waiver_scope."
            )
        duplicate_of = properties.get("duplicate_of_finding_id")
        if isinstance(duplicate_of, dict):
            duplicate_of["description"] = (
                "Only with duplicate_of: an earlier, readable finding of this task with the same "
                "origin and kind that names the same issue and is not itself linked."
            )
        finding_frontier = properties.get("finding_frontier")
        if isinstance(finding_frontier, dict):
            finding_frontier["description"] = (
                "Any frontier at or after the finding's own record: its status finding_frontier "
                "when listed, or the current status frontier. Not the finding's subject_frontier, "
                "which names the state the check tested and precedes that record."
            )
    elif name == "status-request":
        filter_property = properties.get("filter")
        if isinstance(filter_property, dict):
            filter_property["description"] = (
                "Fields must match the selected view; omit filter when that view accepts none."
            )


def _referenced_top_level_defs(value: JsonValue) -> set[str]:
    found: set[str] = set()

    def visit(candidate: JsonValue) -> None:
        if isinstance(candidate, Mapping):
            mapping = cast(Mapping[str, JsonValue], candidate)
            ref = mapping.get("$ref")
            if type(ref) is str and ref.startswith("#/$defs/"):
                remainder = ref[len("#/$defs/") :]
                found.add(remainder.split("/", 1)[0])
            for item in mapping.values():
                visit(item)
        elif isinstance(candidate, tuple | list):
            sequence = cast(tuple[JsonValue, ...] | list[JsonValue], candidate)
            for item in sequence:
                visit(item)

    visit(value)
    return found


@cache
def _mcp_schema(name: str, version: str) -> Mapping[str, JsonValue]:
    """Full catalog bundle used for dual-surface projection checks (not tools/list)."""

    document = schema_document_for(name, version)
    root = document.json_schema
    documents = _external_schema_documents(root)
    bundled = _rewrite_schema_refs(
        root,
        current_uri=document.schema_id,
        root_uri=document.schema_id,
    )
    if not isinstance(bundled, dict):
        raise RuntimeError("mcp_schema_invalid")
    bundled_dict = bundled
    existing_definitions = bundled_dict.get("$defs")
    if existing_definitions is None:
        definitions: dict[str, JsonValue] = {}
        bundled_dict["$defs"] = definitions
    elif isinstance(existing_definitions, Mapping):
        definitions = dict(cast(Mapping[str, JsonValue], existing_definitions))
        bundled_dict["$defs"] = definitions
    else:
        raise RuntimeError("mcp_schema_invalid")
    for uri, external in sorted(documents.items(), key=lambda item: item[0].encode("ascii")):
        definitions[_bundle_key(uri)] = _rewrite_schema_refs(
            external,
            current_uri=uri,
            root_uri=document.schema_id,
        )
    return MappingProxyType(bundled_dict)


@cache
def _mcp_output_presentation_schema(name: str, version: str) -> Mapping[str, JsonValue]:
    """MCP-compatible object-root projection of one catalogued result schema.

    MCP protocol versions through 2025-11-25 require ``outputSchema.type`` to be the
    literal ``"object"``. Yoetz result schemas express the success/error object union
    with a root ``oneOf``. Adding the shared object constraint preserves that union's
    accepted instances while keeping the immutable catalogue bytes unchanged.
    """

    bundled = _legacy_compatible_output_arrays(_mutable_json(_mcp_schema(name, version)))
    if not isinstance(bundled, dict):
        raise RuntimeError("mcp_output_schema_invalid")
    bundled_dict = bundled
    root_type = bundled_dict.get("type")
    if root_type not in (None, "object"):
        raise RuntimeError("mcp_output_schema_root_not_object")
    bundled_dict["type"] = "object"
    return MappingProxyType(bundled_dict)


def _legacy_compatible_output_arrays(candidate: JsonValue) -> JsonValue:
    """Project tuple arrays for hosts whose validator ignores 2020-12 ``prefixItems``.

    Cursor currently validates declared MCP output schemas with legacy ``items`` semantics: it
    ignores ``prefixItems`` and therefore treats the catalogue's companion ``items: false`` as a
    rejection of every returned tuple member. Result bytes have already passed the immutable
    catalogue schema, so this host-facing declaration may safely weaken tuple position constraints
    to one ``items.anyOf`` while preserving item count bounds and every member schema.
    """

    if isinstance(candidate, Mapping):
        mapping = {
            key: _legacy_compatible_output_arrays(item)
            for key, item in cast(Mapping[str, JsonValue], candidate).items()
        }
        prefix_items = mapping.pop("prefixItems", None)
        if not isinstance(prefix_items, list):
            return mapping
        if not prefix_items:
            return mapping
        raw_items = mapping.get("items")
        max_items = mapping.get("maxItems")
        fixed_prefix = type(max_items) is int and max_items == len(prefix_items)
        alternatives = list(cast(list[JsonValue], prefix_items))
        if not fixed_prefix and isinstance(raw_items, Mapping):
            alternatives.append(cast(JsonValue, raw_items))
        if fixed_prefix or raw_items is False or isinstance(raw_items, Mapping):
            mapping["items"] = (
                alternatives[0] if len(alternatives) == 1 else {"anyOf": alternatives}
            )
        else:
            # Later members are unconstrained, so the compatible declaration must be too.
            mapping["items"] = {}
        return mapping
    if isinstance(candidate, tuple | list):
        sequence = cast(tuple[JsonValue, ...] | list[JsonValue], candidate)
        return [_legacy_compatible_output_arrays(item) for item in sequence]
    return candidate


@cache
def _mcp_presentation_schema(name: str, version: str) -> Mapping[str, JsonValue]:
    """Agent-facing tools/list projection of a catalog request/result schema."""

    document = schema_document_for(name, version)
    root = _mutable_json(document.json_schema)
    project_ordinary = name == "publish-work-request"
    documents = _external_schema_documents(root, project_ordinary_event_draft=project_ordinary)
    bundled = _rewrite_schema_refs(
        root,
        current_uri=document.schema_id,
        root_uri=document.schema_id,
        inline_uris=_COMMON_INLINE_SCHEMA_IDS,
    )
    if not isinstance(bundled, dict):
        raise RuntimeError("mcp_schema_invalid")
    bundled_dict = bundled
    existing_definitions = bundled_dict.get("$defs")
    if existing_definitions is None:
        definitions: dict[str, JsonValue] = {}
        bundled_dict["$defs"] = definitions
    elif isinstance(existing_definitions, Mapping):
        definitions = dict(cast(Mapping[str, JsonValue], existing_definitions))
        bundled_dict["$defs"] = definitions
    else:
        raise RuntimeError("mcp_schema_invalid")
    for uri, external in sorted(documents.items(), key=lambda item: item[0].encode("ascii")):
        if uri in _COMMON_INLINE_SCHEMA_IDS or uri == _OPAQUE_EVENT_DRAFT_SCHEMA_ID:
            continue
        definitions[_bundle_key(uri)] = _rewrite_schema_refs(
            external,
            current_uri=uri,
            root_uri=document.schema_id,
            inline_uris=_COMMON_INLINE_SCHEMA_IDS,
        )
    for key, body in list(definitions.items()):
        definitions[key] = _inline_nested_local_defs(key, body)
    bundled_dict = _inline_presentation_refs(bundled_dict)
    if name in {"start-request", "respond-request", "status-request"}:
        bundled_dict.pop("allOf", None)
    flattened = _flatten_frontier_conditions(bundled_dict)
    if not isinstance(flattened, dict):
        raise RuntimeError("mcp_schema_invalid")
    bundled_dict = flattened
    _describe_presentation_schema(name, bundled_dict)
    examples = _INPUT_SCHEMA_EXAMPLES.get(name)
    if examples is not None:
        bundled_dict["examples"] = [_mutable_json(item) for item in examples]
    return MappingProxyType(bundled_dict)


def presentation_schema_metrics(schema: Mapping[str, JsonValue]) -> dict[str, int]:
    """Return keyword-budget metrics for one advertised MCP JSON Schema object."""

    oneof_nodes = 0
    oneof_branches = 0
    ref_nodes = 0
    conditional_nodes = 0
    top_level_definitions = schema.get("$defs")
    retained_payload_defs: frozenset[str]
    if isinstance(top_level_definitions, Mapping):
        retained_payload_defs = frozenset(
            cast(Mapping[str, JsonValue], top_level_definitions).keys()
        )
    else:
        retained_payload_defs = frozenset()

    def visit(candidate: JsonValue, *, inside_payload_defs: bool = False) -> int:
        nonlocal conditional_nodes, oneof_nodes, oneof_branches, ref_nodes
        nest = 0
        if isinstance(candidate, Mapping):
            mapping = cast(Mapping[str, JsonValue], candidate)
            ref_key = _local_def_key(mapping.get("$ref"))
            if (
                "$ref" in mapping
                and not inside_payload_defs
                and ref_key not in retained_payload_defs
            ):
                ref_nodes += 1
            if not inside_payload_defs:
                conditional_nodes += sum(
                    keyword in mapping for keyword in ("allOf", "if", "then", "else")
                )
            one_of = mapping.get("oneOf")
            if isinstance(one_of, list):
                oneof_nodes += 1
                oneof_branches += len(cast(list[JsonValue], one_of))
            defs = mapping.get("$defs")
            child_nest = 0
            if isinstance(defs, Mapping):
                child_nest = max(
                    visit(item, inside_payload_defs=True)
                    for item in cast(Mapping[str, JsonValue], defs).values()
                )
                nest = max(nest, child_nest + 1)
            for key, item in mapping.items():
                if key != "$defs":
                    nest = max(
                        nest,
                        visit(item, inside_payload_defs=inside_payload_defs),
                    )
            return nest
        if isinstance(candidate, tuple | list):
            sequence = cast(tuple[JsonValue, ...] | list[JsonValue], candidate)
            for item in sequence:
                nest = max(nest, visit(item, inside_payload_defs=inside_payload_defs))
            return nest
        return 0

    defs_nest_depth = visit(schema)
    definitions = schema.get("$defs")
    defs_count = len(definitions) if isinstance(definitions, Mapping) else 0
    encoded = json.dumps(_mutable_json(dict(schema)), ensure_ascii=True, separators=(",", ":"))
    return {
        "oneof_nodes": oneof_nodes,
        "oneof_branches": oneof_branches,
        "ref_nodes": ref_nodes,
        "conditional_nodes": conditional_nodes,
        "defs_count": defs_count,
        "defs_nest_depth": defs_nest_depth,
        "encoded_bytes": len(encoded.encode("utf-8")),
    }


def ordinary_publish_families_in_presentation(
    schema: Mapping[str, JsonValue],
) -> frozenset[str]:
    """Return event family names advertised in a publish_work presentation schema."""

    families: set[str] = set()

    def visit(candidate: JsonValue) -> None:
        if isinstance(candidate, Mapping):
            mapping = cast(Mapping[str, JsonValue], candidate)
            one_of = mapping.get("oneOf")
            if isinstance(one_of, list):
                for branch in cast(list[JsonValue], one_of):
                    if not isinstance(branch, Mapping):
                        continue
                    family = _event_family_from_draft_branch(cast(Mapping[str, JsonValue], branch))
                    if family is not None:
                        families.add(family)
            for item in mapping.values():
                visit(item)
        elif isinstance(candidate, tuple | list):
            for item in cast(tuple[JsonValue, ...] | list[JsonValue], candidate):
                visit(item)

    visit(schema)
    return frozenset(families)


@dataclass(frozen=True, slots=True)
class ToolAnnotations:
    """The exact MCP annotation hints for one public operation."""

    read_only: bool
    idempotent: bool
    destructive: bool = False
    open_world: bool = False

    def as_mcp_dict(self) -> dict[str, bool]:
        return {
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        }


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    """Static identity, text, schemas, and annotations for one MCP tool."""

    name: str
    title: str
    description: str
    input_schema_ref: str
    output_schema_ref: str
    annotations: ToolAnnotations

    @property
    def input_schema(self) -> Mapping[str, JsonValue]:
        return _mcp_presentation_schema(
            f"{self.name.replace('_', '-')}-request", _tool_input_schema_version(self.name)
        )

    @property
    def output_schema(self) -> Mapping[str, JsonValue]:
        return _mcp_output_presentation_schema(
            f"{self.name.replace('_', '-')}-result", _tool_output_schema_version(self.name)
        )

    @property
    def catalog_output_schema(self) -> Mapping[str, JsonValue]:
        """Full catalog-bundled output schema before MCP root-object projection."""

        return _mcp_schema(
            f"{self.name.replace('_', '-')}-result", _tool_output_schema_version(self.name)
        )

    @property
    def catalog_input_schema(self) -> Mapping[str, JsonValue]:
        """Full catalog-bundled input schema (admission dual-surface; not tools/list)."""

        return _mcp_schema(
            f"{self.name.replace('_', '-')}-request", _tool_input_schema_version(self.name)
        )


def _descriptor(
    name: str,
    title: str,
    description: str,
    *,
    read_only: bool,
    idempotent: bool,
    open_world: bool = False,
) -> ToolDescriptor:
    schema_name = name.replace("_", "-")
    input_schema_version = _tool_input_schema_version(name)
    output_schema_version = _tool_output_schema_version(name)
    return ToolDescriptor(
        name=name,
        title=title,
        description=description,
        input_schema_ref=(
            f"{SCHEMA_NAMESPACE}operations/{schema_name}-request-{input_schema_version}.schema.json"
        ),
        output_schema_ref=(
            f"{SCHEMA_NAMESPACE}operations/{schema_name}-result-{output_schema_version}.schema.json"
        ),
        annotations=ToolAnnotations(
            read_only=read_only,
            idempotent=idempotent,
            open_world=open_world,
        ),
    )


_POLICY_TOOL_DESCRIPTORS: Final = (
    _descriptor(
        "start",
        "Start or resume a work session",
        "First read yoetz://guidance/agent-instructions.md. Use current guidance and typed results for "
        "Yoetz procedure; preserve higher-priority instructions and user authorization. "
        "Call for material multi-step, delegated, resumable, or verification-heavy work before "
        "substantive work; skip trivial questions or edits. A new session's first workflow "
        "operation is this call, after the core read, tool and schema discovery, and necessary "
        "bootstrap clarification (including read_guidance and discovery commands). On failure, "
        "follow exact continuations and same-request recovery, including a named one-time repair, "
        "before asking the user for intro and guidance if startup remains blocked. Do not invent "
        "workflow or continue without a task outside the documented optional-service fallback. "
        "Records or resumes a cooperative work "
        "session and returns its compact record. It does not show that work outside the published "
        "record occurred. Each new operation uses a fresh req_ prefixed random UUID; recover an "
        "unknown write outcome with the same request_id before any sibling. "
        "workspace_ref and external_ref are admitted only as a pair. Call it once per "
        "task. task_title and requested_view are required; task_statement is the user's request "
        "verbatim. Attach selectors are exactly one of: "
        "(1) session_id for the session you hold, or "
        "(2) workspace_ref + external_ref as a pair with no session_id — mode=create_or_attach "
        "creates on first use and attaches on later conversations. task_id is not an accepted "
        "field. workspace_ref is the canonical absolute repository root (never a remote URL; "
        "the value hook observation auto-attaches with); external_ref is the stable task "
        "identity within that project (branch, issue, or plan slug). When the session-start "
        "context names a mapped task, use mode=attach with its session_id. A session-plus-new-pair "
        "recovery requires an active, non-quarantined root-task selector with matching workspace "
        "and repository binding; unrelated workspace tasks do not block it, while a pair bound to "
        "another task remains a conflict. Delegated child routes require an attach_handle or "
        "internal target selector. Both refs are "
        "redacted one-shot values; only HMAC commitments are persisted. mode=delegate takes the "
        "parent session_id and returns an attach_handle for the child; self-registration uses "
        "parent_session_id and remains pending until accepted. Do not self-censor into unstable "
        "refs. After resume or compaction, use status "
        "view=obligations to recover exact requested_items and unattempted_items rather than "
        "searching transcripts or source. Author the request from this input schema plus "
        "the guidance below, never from memory. Guidance: yoetz://guidance/agent-instructions.md.",
        read_only=False,
        idempotent=True,
    ),
    _descriptor(
        "publish_work",
        "Publish recorded work",
        "Before evidence or a completion claim, cite IDs you published; reuse only linked "
        "native captures. Put feedback and requested delivery in the effective "
        "plan via a revision. Accepted records are assertions, not repair proof. "
        "Previews or appends asserted work to the local Yoetz ledger. It does not publish to GitHub "
        "or run an AI-powered evaluation. Set-valued lists must be unique and already in "
        "ascending ASCII order; rejection names unsorted_set_field. attempted_items belongs only on the "
        "action_recorded payload; copy each requested_items value exactly and never place it on "
        "claim_recorded. decision_recorded.authority is a structural actor id, not approval prose; "
        "action_kind is one of command, edit, research, review, or other; command also requires "
        "command. claim_recorded at schema 1.1.0 separates supporting_refs from "
        "limitation_refs and corrections name exact prior effective claims in supersedes_claim_refs. "
        "Completion requires explicit obligation_refs; [] cannot carry obligation support. "
        "An accepted empty-scope target can be superseded with explicit empty or populated scope. "
        "Dry-run checks references, outcome, scope, replacement, and limitation linkage; author "
        "corrections from candidate_findings, history, and results. occurred_at is caller-asserted "
        "RFC 3339 UTC time with milliseconds; do not copy the illustrative example timestamp. Ledger order uses "
        "ingestion sequence. Service accepted_at is independent; receipt freshness is frontier-bound. "
        "Dry-run previews are not evidence. Read status "
        "view=obligations for exact unattempted_items before resolution; after publishing repair, "
        "claim and evidence, disposition older findings, call check, respond, then call receipt "
        "before claiming completion. Batch material transitions together, usually one to eight "
        "events and never one batch per file, tool call, or message; reading, searching, formatting, "
        "and unchanged state are not publishable. Lifecycle events record acceptance, cancellation, "
        "write-off, or explicit closure; receipts never close work. Coordination dispositions "
        "link an existing obligation and evidence; a later qualifying check resolves the finding. "
        "Guidance: yoetz://guidance/publication-policy.md.",
        read_only=False,
        idempotent=True,
    ),
    _descriptor(
        "check",
        "Check recorded work",
        "Runs the requested recorded-work checks and records the result; it returns at most "
        "max_findings findings plus a suppressed count, and status with view=findings reads the "
        "rest. A no_issue_detected verdict does not mean the work is correct. Choose mode "
        "deliberately: semantic_required when the user, effective policy or acceptance requires "
        "it, including subsequent final checks. Omit mode to preserve the configured default; "
        "use semantic_if_configured only when review is known to be optional. Reserve "
        "deterministic_only for explicitly local or structural checks or a user-authorized no-egress "
        "choice, disclose semantic_review_not_requested, and keep any required review unmet. "
        "Read status view=findings with filter.include_resolved=true after repair: "
        "not returned is not resolved. "
        "This call cannot widen privacy "
        "authority: an active AI-powered review route was selected by the owner during setup as a bounded "
        "standing policy, and check cannot change its route, workspace, scope, categories, "
        "retention ceiling, or credential authority. Whether a case is dispatched stays enforced "
        "by the installed route binding and privacy policy. A pre-invocation approval refusal or "
        "hold is an invocation-authorization event, not a Yoetz result: Yoetz did not run, so "
        "do not report an AI-powered review status or outbound dispatch. When AI-powered review was "
        "explicitly requested or mode is semantic_required, pause and present the manual approval "
        "request for the exact proposed check body and request_id. Approval authorizes that "
        "invocation only; it does not change Yoetz privacy policy, repository authority, "
        "disclosure decisions, credentials, or outbound-admission rules. Do not "
        "publish a completion claim, request a receipt, create a fresh AI-powered check, or switch "
        "to deterministic_only while approval is pending. An unambiguous, still-applicable "
        "first-party instruction for this exact AI-powered review action may present the manual approval "
        "request without redundant prose, but never bypasses that approval. After approval, "
        "invoke the exact same proposed check body and request_id; if Yoetz then returns "
        "awaiting_human, follow its separate continuation. After denial, cancellation, or expiry, "
        "continue without AI-powered review only after the user explicitly chooses that fallback. "
        "Omit scope for the whole case, "
        "or send both claim_ids and obligation_ids as arrays of unique ids; two empty arrays also "
        "mean the whole case, and sending only one of the two keys is rejected. Call it after "
        "publishing the completion claim and its evidence, and again after any material edit or "
        "new evidence; a check with no new events since the last one adds nothing. "
        "awaiting_human and awaiting_input are the nonterminal check results: each typed "
        "continuation identifies the exact next command. awaiting_human carries standing "
        "repository setup or a one-use decision; awaiting_input carries the same-task review-input "
        "amendment. Show that command, do not create a new "
        "check request, do not inspect live Yoetz storage or reconstruct consumer calls from source, "
        "and replay this same request with "
        "the same request_id after the decision. If Yoetz explicitly reports that the current "
        "repository grant is missing, direct the owner to run yoetz --privacy and complete the "
        "trusted local review there; assent in agent chat never authorizes that standing grant. "
        "It is distinct from a one-use decision; recover either handoff through operation status "
        "or replay this exact original request with the same request_id, never a fresh request. "
        "Denial, expiry, cancellation, stale authority, or incomplete review means no dispatch. "
        "AI-powered "
        "review that does not succeed is a coverage gap rather than a retry problem: "
        "not_configured, blocked_by_policy, and human_denied will not change without owner "
        "action; unavailable and timeout already spent that job's own attempt budget; "
        "response_content_invalid may spend exactly one in-job repair retry and has already done "
        "so by the time it is reported; refused, failed, and every other invalid reason are not "
        "retried inside the job at all. After one current-state recheck still lacks qualifying "
        "proof, stop unchanged rechecks, continue distinct authorized repairs, and disclose the "
        "exact gap. Do not downgrade required review to finish. Guidance: "
        "yoetz://guidance/coverage-and-receipts.md.",
        read_only=False,
        idempotent=True,
        open_world=True,
    ),
    _descriptor(
        "respond",
        "Respond to a finding",
        "Records an acknowledgement, self-verification, provenance dispute, or rejection for one "
        "finding at any frontier at or after its record, such as the current status frontier, "
        "not its subject_frontier. For an unresolved finding: repair it and check first. "
        "If you repaired it and Yoetz still cannot confirm it (a Yoetz limit), verify it yourself, "
        "record that evidence, and respond self_verified saying how you checked it, with the "
        "evidence ids; it is refused (finding_not_rechecked, finding_not_proof_limited) while "
        "no later check ran or Yoetz still sees the issue. A Yoetz limit is never a "
        "yoetz-blocker. Use acknowledged_not_done only if you truly will not or cannot do it, "
        "and reopened (with a reason) to take it back. A reviewer's limitation request "
        "(state_unresolved_limitation) is not repair work: respond acknowledged with the reason "
        "if the requirement may be met but cannot be confirmed here; acknowledged_not_done says it "
        "is not met. Only if a new finding restates the SAME issue as an earlier one you answered, respond "
        "duplicate_of with duplicate_of_finding_id; linking never resolves the new finding. "
        "This appends one "
        "finding-response record to the local Yoetz ledger; it does not publish to GitHub or run an "
        "AI-powered evaluation. It does not resolve other findings or establish that underlying work "
        "changed. A provenance_disputed response contests the finding's authorship or provenance "
        "premise rather than its conclusion, requires a reason, and never resolves the finding. "
        "Bounded waiver is reserved for an authorized local-CLI human and is not an agent option. "
        "A readable response removes that finding from unanswered_finding_count without reducing "
        "receipt_blocking_finding_count (except self_verified, which is disclosed and keeps the "
        "receipt from reading clean), erasing its historical record, or closing an independent "
        "coverage gap; only a later qualifying check of the repaired record resolves a finding. "
        "Disposition older findings before the final check. Call once per finding: a readable "
        "response to a finding returned by that check, or acknowledging a non-actionable "
        "observation-authored one, needs no recheck; another response to an older finding, a "
        "redacted or unreadable response or other material work does. Guidance: "
        "yoetz://guidance/publication-policy.md.",
        read_only=False,
        idempotent=True,
    ),
    _descriptor(
        "status",
        "Read recorded status",
        "Reads bounded, paginated state when uncertain what you already did or committed to, "
        "with advice naming recommended_next_action. Views are advice, assignment, "
        "candidate_findings, compact, evidence, findings, history, lineage, obligations, operation, "
        "project, results, and versions. Lineage is a live preview; parent receipts use recorded "
        "child manifests. Project shows generation-bound membership and coordination. "
        "History pairs caller-asserted occurred_at beside the service-stamped "
        "accepted_at; forward-skew classification compares clocks, not truth, and order follows "
        "ingestion sequence. view=operation with filter.operation_request_id recovers the stored "
        "outcome without resending the body; for a running or finished check it adds structural "
        "semantic_progress (phase, elapsed time, deadline). Before evidence or completion claims, "
        "cite IDs you published (view=evidence filter.author=mine); find native captures with "
        "filter.strength=immutable_snapshot and reuse IDs a results row's evidence_refs links. "
        "Omitted descriptions (privacy) and capture, selection or clipping limits "
        "are per item, not absence. Obligations expose exact requested_items, "
        "unattempted_items and command_attempts; the latter separates observed attempts, mismatch "
        "and unknown without establishing success. Results map res_ IDs to bounded structural facts "
        "without result prose. After repair, read view=findings with filter.include_resolved=true "
        "and resolved state: absent from a check but resolved=false means not returned but unproven. "
        "Finding detail explains qualification. Read closure_readiness before spending a check or "
        "receipt: unanswered_finding_count needs responses, while receipt_blocking_finding_count "
        "needs repair or a limited receipt; only a later qualifying check resolves one, never a "
        "response. Answer findings_unanswered; repair and recheck receipt_findings_unresolved once, "
        "then disclose if unchanged state still limits coverage. At state ready_with_limitations "
        "nothing is left to do: request the receipt; predicted_receipt names its conclusion. "
        "Call after resume, compaction, or "
        "delegate handoff and before a completion claim. Guidance: "
        "yoetz://guidance/workflow.md.",
        read_only=True,
        idempotent=True,
    ),
    _descriptor(
        "receipt",
        "Record and read a receipt",
        "Records and returns a receipt of the recorded conclusion and coverage limitations at one "
        "frontier. It does not establish correctness beyond that recorded coverage. Prefer format "
        "markdown or text; json is an owner-export format that stricter agent-context policies may "
        "block. Call it once at the end, and again only if material state changed since the "
        "previous receipt, after the last material deliverable covered by the claim. Final prose "
        "must state the actual actionable unresolved count, checked scope and frontier, AI-powered "
        "review status and reason and material coverage gaps. Distinguish unanswered findings, "
        "unresolved blockers and coverage-only gaps. A receipt is not a pass. Guidance: "
        "yoetz://guidance/coverage-and-receipts.md.",
        read_only=False,
        idempotent=True,
    ),
    _descriptor(
        "read_guidance",
        "Read guidance",
        "Reads one registered Yoetz guidance URI and returns its full markdown as tool text, or a "
        "bounded UTF-8-safe page when `page` or `page_size` is supplied. Catalogued heading topics "
        "return one bounded procedure; use only an anchor guidance names verbatim, never one "
        "derived from a heading, tool, or event name. An unknown anchor's rejection lists that "
        "document's registered anchors; the whole-document URI always works. "
        "`page_size` is a canonical "
        "UTF-8 byte budget from 4 through 16384 inclusive; use 4096 by default. An invalid size "
        "returns a field-local page_size correction with the permitted range and retry shape. "
        "Paged results carry stable "
        "document identity, source revision, total byte count, digest, page offsets and an exact "
        "continuation; consumers must reconstruct every page and verify the final digest before "
        "claiming guidance is loaded. A page marked complete means only that the service emitted "
        "the end page; delivery remains unconfirmed until the consumer reconstructs it. The text "
        "channel uses a bounded 4096-byte summary, while paged reads carry one marked page. The legacy "
        "URI-only route remains "
        "available on demand. This is not a ledger operation and does not write the ledger. Extra "
        "keys and unknown URIs are rejected without echoing the value. Guidance: "
        "yoetz://guidance/agent-instructions.md.",
        read_only=True,
        idempotent=True,
    ),
    _descriptor(
        "closure_prepare",
        "Prepare a closure request",
        "Reads a complete status inventory at one pinned frontier and returns it with the "
        "current closure readiness. A caller may select one explicit phase and existing IDs to "
        "draft at most one publish_work, respond, or receipt request. Publication drafts carry "
        "dry_run=true; this helper never writes the ledger, judges work, or claims completion. "
        "Use the emitted recovery request and keep its request identity when a later write "
        "times out. Select only IDs and requested-item indexes returned by the same inventory; "
        "a moving frontier or unavailable item is refused. The MCP response has a bounded frame: "
        "a draft phase echoes only the rows you selected, and an oversized inventory returns "
        "LIMIT_EXCEEDED without a partial success, so select ids from the status pages or use the "
        "CLI closure-prepare --output path for a larger local inventory. Guidance: "
        "yoetz://guidance/workflow.md.",
        read_only=True,
        idempotent=True,
    ),
)

_STRICT_CHECK_DESCRIPTION_SUFFIX: Final = (
    " Under the strict route profile, this route will not request external AI-powered review."
)
_STRICT_TOOL_DESCRIPTORS: Final = tuple(
    replace(
        descriptor,
        description=descriptor.description + _STRICT_CHECK_DESCRIPTION_SUFFIX,
        annotations=replace(descriptor.annotations, open_world=False),
    )
    if descriptor.name == "check"
    else descriptor
    for descriptor in _POLICY_TOOL_DESCRIPTORS
)
TOOL_DESCRIPTORS: Final[Mapping[McpRouteProfile, tuple[ToolDescriptor, ...]]] = MappingProxyType(
    {
        "policy": _POLICY_TOOL_DESCRIPTORS,
        "strict": _STRICT_TOOL_DESCRIPTORS,
    }
)


def _canonical_descriptor_bytes(descriptor: ToolDescriptor) -> bytes:
    return json.dumps(
        {
            "annotations": descriptor.annotations.as_mcp_dict(),
            "description": descriptor.description,
            "input_schema_ref": descriptor.input_schema_ref,
            "name": descriptor.name,
            "output_schema_ref": descriptor.output_schema_ref,
            "title": descriptor.title,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest_descriptor(descriptor: ToolDescriptor) -> str:
    return "sha256:" + hashlib.sha256(_canonical_descriptor_bytes(descriptor)).hexdigest()


# These are reviewed golden identities, not values supplied by a host or environment.
TOOL_DESCRIPTOR_DIGESTS: Final[Mapping[McpRouteProfile, Mapping[str, str]]] = MappingProxyType(
    {
        "policy": MappingProxyType(
            {
                "start": "sha256:d74368f4c375bd9f1f32bf6a99fa28c1cfd2f8366048e8dd617df54d9f606fe4",
                "publish_work": "sha256:7c11f3c51242386f32f69dd85fc787da2223df1e23b5fa0314887a73172ac574",
                "check": "sha256:f4e91ea5ae6138ca381d3a990340067b6e28a545340eec9c0ca4737a18f06166",
                "respond": "sha256:41dee68d3de5fa8d4d9d95a70f01660c1fab93bbf47c8a93ca0c7253abd11433",
                "status": "sha256:fcc6116a60b0b0938bebc5b327663fafeee1f28c6dffcd4a6ccb628711531551",
                "receipt": "sha256:c7676e1ca9afd96d9d7e74503edd5b31a758a05d7e7e1cf0d62c763611ffcecb",
                "read_guidance": "sha256:874876f601c5eb51d0b2059f71c4def9b59be842fbf4d59ac888146d6c8994b8",
                "closure_prepare": "sha256:fa7fa2e1aa2c64eae1ace9069b905dbe5c82c89e92d696434d0058a343393007",
            }
        ),
        "strict": MappingProxyType(
            {
                "start": "sha256:d74368f4c375bd9f1f32bf6a99fa28c1cfd2f8366048e8dd617df54d9f606fe4",
                "publish_work": "sha256:7c11f3c51242386f32f69dd85fc787da2223df1e23b5fa0314887a73172ac574",
                "check": "sha256:3cd2326917a550c0a24f3e94c6141f41b1549107030154c3e5b29f46bfaef78b",
                "respond": "sha256:41dee68d3de5fa8d4d9d95a70f01660c1fab93bbf47c8a93ca0c7253abd11433",
                "status": "sha256:fcc6116a60b0b0938bebc5b327663fafeee1f28c6dffcd4a6ccb628711531551",
                "receipt": "sha256:c7676e1ca9afd96d9d7e74503edd5b31a758a05d7e7e1cf0d62c763611ffcecb",
                "read_guidance": "sha256:874876f601c5eb51d0b2059f71c4def9b59be842fbf4d59ac888146d6c8994b8",
                "closure_prepare": "sha256:fa7fa2e1aa2c64eae1ace9069b905dbe5c82c89e92d696434d0058a343393007",
            }
        ),
    }
)
TOOL_DESCRIPTOR_SET_DIGEST: Final[Mapping[McpRouteProfile, str]] = MappingProxyType(
    {
        "policy": "sha256:9576c84c3b7476c7c3d9520ba18dec6ef7d852a1d96c5a29b4bc2348eafbb05d",
        "strict": "sha256:346964d57cf6c679a4b69d89c62172a1649d3d678922ae60a343dc85f4bca38f",
    }
)


def _presentation_description_strings(schema: Mapping[str, JsonValue]) -> tuple[str, ...]:
    found: list[str] = []

    def visit(candidate: JsonValue) -> None:
        if isinstance(candidate, Mapping):
            mapping = cast(Mapping[str, JsonValue], candidate)
            description = mapping.get("description")
            if type(description) is str:
                found.append(description)
            for item in mapping.values():
                visit(item)
        elif isinstance(candidate, tuple | list):
            for item in cast(tuple[JsonValue, ...] | list[JsonValue], candidate):
                visit(item)

    visit(schema)
    return tuple(found)


def _lint_descriptor_sets() -> None:
    for profile, descriptors in TOOL_DESCRIPTORS.items():
        names = tuple(descriptor.name for descriptor in descriptors)
        if names != YOETZ_MCP_TOOL_NAMES:
            raise RuntimeError("descriptor_registry_invalid")
        if len(set(names)) != len(names):
            raise RuntimeError("descriptor_registry_invalid")
        for descriptor in descriptors:
            if _FORBIDDEN_CLAIMS.search(descriptor.description) is not None:
                raise RuntimeError("descriptor_honesty_lint_failed")
            # Packaged guidance URIs are the one reviewed path exception; strip them before the
            # boundary scan so tool text can name the covering resource without looking like a
            # filesystem or host path.
            without_guidance = _GUIDANCE_URI.sub("yoetz-guidance-resource", descriptor.description)
            if _BOUNDARY_TERMS.search(without_guidance) is not None:
                raise RuntimeError("descriptor_boundary_lint_failed")
            for schema_description in _presentation_description_strings(descriptor.input_schema):
                if _FORBIDDEN_CLAIMS.search(schema_description) is not None:
                    raise RuntimeError("descriptor_honesty_lint_failed")
                without_guidance = _GUIDANCE_URI.sub("yoetz-guidance-resource", schema_description)
                if _BOUNDARY_TERMS.search(without_guidance) is not None:
                    raise RuntimeError("descriptor_boundary_lint_failed")
            if _digest_descriptor(descriptor) != TOOL_DESCRIPTOR_DIGESTS[profile][descriptor.name]:
                raise RuntimeError("descriptor_digest_mismatch")
        set_bytes = b"\n".join(_canonical_descriptor_bytes(item) for item in descriptors)
        if "sha256:" + hashlib.sha256(set_bytes).hexdigest() != TOOL_DESCRIPTOR_SET_DIGEST[profile]:
            raise RuntimeError("descriptor_set_digest_mismatch")


_DESCRIPTOR_BY_NAME: Final[Mapping[McpRouteProfile, Mapping[str, ToolDescriptor]]] = (
    MappingProxyType(
        {
            profile: MappingProxyType({descriptor.name: descriptor for descriptor in descriptors})
            for profile, descriptors in TOOL_DESCRIPTORS.items()
        }
    )
)


def descriptor_for(name: str, profile: McpRouteProfile = "policy") -> ToolDescriptor:
    """Return one exact registered descriptor or fail without echoing its input."""

    if type(name) is not str:
        raise TypeError("tool_descriptor_name_wrong_type")
    if profile not in TOOL_DESCRIPTORS:
        raise ValueError("mcp_route_profile_invalid")
    try:
        return _DESCRIPTOR_BY_NAME[profile][name]
    except KeyError:
        raise KeyError("unregistered_tool_descriptor") from None


def server_instructions(
    profile: McpRouteProfile = "policy",
    *,
    semantic_destination: SemanticDestinationDisclosure | None = None,
    host_profile: McpHostProfile = "generic",
) -> str:
    """Return the manifest-verified initialize instructions as strict UTF-8 text.

    ``semantic_destination`` is the one runtime-composed addition to this surface (issue #479):
    the bridge renders it from validated configuration through the closed catalog in
    ``mcp/semantic_destination.py`` and passes it here for the policy route only. It is typed,
    never a caller-authored string, and the strict route ignores it so strict instructions stay
    byte-identical whatever the configuration says.

    ``host_profile`` selects the packaged body (issue #789): the ``claude`` host receives
    ``CLAUDE_CODE_INITIALIZE_INSTRUCTIONS``, sized for that host's observed 2,048-character cap;
    the ``codex`` and ``cursor`` hosts receive ``COMPACT_INITIALIZE_INSTRUCTIONS`` (issue #918),
    bounded by ``COMPACT_INSTRUCTIONS_BUDGET`` because Codex charges it once per advertised tool;
    the ``generic`` host receives the ``INITIALIZE_GUIDANCE_URIS`` document unchanged. The route
    tail and the disclosure are composed identically for every body.
    """

    if profile not in TOOL_DESCRIPTORS:
        raise ValueError("mcp_route_profile_invalid")
    if host_profile not in _HOST_PROFILES:
        raise ValueError("mcp_host_profile_invalid")
    if semantic_destination is not None and (
        type(semantic_destination) is not SemanticDestinationDisclosure
    ):
        raise TypeError("semantic_destination_wrong_type")
    if host_profile == "claude":
        base = CLAUDE_CODE_INITIALIZE_INSTRUCTIONS
    elif host_profile in COMPACT_INSTRUCTIONS_HOST_PROFILES:
        base = COMPACT_INITIALIZE_INSTRUCTIONS
    else:
        base = "\n\n".join(
            read_resource(uri).decode("utf-8", errors="strict").rstrip()
            for uri in INITIALIZE_GUIDANCE_URIS
        )
    if profile != "policy":
        return f"{base}\n\nRoute profile: {profile}. {_STRICT_ROUTE_TAIL}\n"
    tail = _POLICY_ROUTE_TAIL
    if semantic_destination is not None:
        tail += " " + semantic_destination.sentence
    return f"{base}\n\nRoute profile: {profile}. {tail}\n"


def _lint_claude_code_instructions() -> None:
    """Fail import when the Claude-host text can no longer survive the observed cap (#789)."""

    text = CLAUDE_CODE_INITIALIZE_INSTRUCTIONS
    budget = CLAUDE_CODE_INSTRUCTIONS_BUDGET
    if not text.isascii() or len(text) > budget["packaged_max_chars"]:
        raise RuntimeError("claude_code_instructions_over_budget")
    if _FORBIDDEN_CLAIMS.search(text) is not None:
        raise RuntimeError("descriptor_honesty_lint_failed")
    if _BOUNDARY_TERMS.search(_GUIDANCE_URI.sub("yoetz-guidance-resource", text)) is not None:
        raise RuntimeError("descriptor_boundary_lint_failed")
    worst_case = (
        len(text)
        + len("\n\nRoute profile: policy. ")
        + len(_POLICY_ROUTE_TAIL)
        + 1
        + MAX_DISCLOSURE_ENCODED_BYTES
        + 1
    )
    if worst_case > budget["max_chars"] or budget["max_chars"] > budget["observed_host_cap_chars"]:
        raise RuntimeError("claude_code_instructions_over_budget")


def _lint_compact_initialize_instructions() -> None:
    """Fail import when the Codex and Cursor text outgrows its reviewed byte cap (#918)."""

    text = COMPACT_INITIALIZE_INSTRUCTIONS
    budget = COMPACT_INSTRUCTIONS_BUDGET
    encoded = len(text.encode("utf-8"))
    if not text.isascii() or encoded > budget["packaged_max_encoded_bytes"]:
        raise RuntimeError("compact_instructions_over_budget")
    if _FORBIDDEN_CLAIMS.search(text) is not None:
        raise RuntimeError("descriptor_honesty_lint_failed")
    if _BOUNDARY_TERMS.search(_GUIDANCE_URI.sub("yoetz-guidance-resource", text)) is not None:
        raise RuntimeError("descriptor_boundary_lint_failed")
    worst_case = (
        encoded
        + max(
            len(f"\n\nRoute profile: policy. {_POLICY_ROUTE_TAIL} ") + MAX_DISCLOSURE_ENCODED_BYTES,
            len(f"\n\nRoute profile: strict. {_STRICT_ROUTE_TAIL}"),
        )
        + 1
    )
    if worst_case > budget["max_encoded_bytes"]:
        raise RuntimeError("compact_instructions_over_budget")
    # The generic body stays the fallback, and Claude keeps its own capped body (#789).
    if not COMPACT_INSTRUCTIONS_HOST_PROFILES <= _HOST_PROFILES - {"generic", "claude"}:
        raise RuntimeError("compact_instructions_host_invalid")


_lint_descriptor_sets()
_lint_claude_code_instructions()
_lint_compact_initialize_instructions()

# Eagerly build presentation schemas so import fails closed on projection errors.
for descriptor_set in TOOL_DESCRIPTORS.values():
    for item in descriptor_set:
        _ = item.input_schema
