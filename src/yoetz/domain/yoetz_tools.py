"""Which host tool names are Yoetz's own MCP tools, in every spelling a host records.

The registry tuples are the one source for the host hook matchers, the hook-ingress sanitizers
and the MCP descriptor lint (re-exported by ``yoetz.ports.integrations``). The classifier below
is the one reading of an *observed* tool name that the delivery policy (#564), the observed-action
kind rule and the later-material rule (tb4n3 RC-6) share: a Yoetz tool call is never work under
test, whatever the host spelled it.
"""

from __future__ import annotations

from typing import Final, Literal

__all__ = [
    "YOETZ_MCP_TOOL_NAMES",
    "YOETZ_READ_TOOL_BASENAMES",
    "YOETZ_SUPPORT_TOOL_NAMES",
    "YOETZ_TOOL_SPELLING_RULES",
    "YOETZ_WORKFLOW_TOOL_NAMES",
    "YoetzToolSpelling",
    "yoetz_tool_spelling",
]

# The one exact Yoetz workflow tool-name set, in registry order. Renderers that
# scope host hook matchers to Yoetz tools and hook-ingress sanitizers that admit
# observed tool names must both derive from this tuple so the two allowlists
# cannot drift apart (the MCP descriptor registry lint pins the same order).
YOETZ_WORKFLOW_TOOL_NAMES: Final = (
    "start",
    "publish_work",
    "check",
    "respond",
    "status",
    "receipt",
    "read_guidance",
)

# Read-only support tools are advertised through MCP but do not enter the workflow hook
# allowlist: they prepare or inspect an existing workflow request and never append ledger state.
YOETZ_SUPPORT_TOOL_NAMES: Final = ("closure_prepare",)
YOETZ_MCP_TOOL_NAMES: Final = (*YOETZ_WORKFLOW_TOOL_NAMES, *YOETZ_SUPPORT_TOOL_NAMES)
# The tools that only read Yoetz's own state (the delivery policy of #564 keeps their successful
# post-events local).
YOETZ_READ_TOOL_BASENAMES: Final = ("status", "receipt", "read_guidance", "closure_prepare")

type YoetzToolSpelling = Literal[
    "server_scoped",  # mcp__yoetz__x, mcp__plugin_yoetz_yoetz__x, any mcp__<...yoetz...>__x
    "server_prefixed",  # yoetz:x, plugin-yoetz-yoetz:x (Cursor scoped spellings)
    "bare",  # x (the Codex session stream names an MCP item by its tool alone)
    "generic_mcp",  # MCP:x (Cursor's ordinary postToolUse names no server)
]
# Closed rule tokens, in the order the classifier tries them.
YOETZ_TOOL_SPELLING_RULES: Final[tuple[YoetzToolSpelling, ...]] = (
    "server_scoped",
    "server_prefixed",
    "bare",
    "generic_mcp",
)
_SERVER_PREFIXES: Final = ("yoetz:", "plugin-yoetz-yoetz:")
_GENERIC_MCP_PREFIX: Final = "mcp:"
_NAMES: Final = frozenset(YOETZ_MCP_TOOL_NAMES)


def yoetz_tool_spelling(tool: object) -> YoetzToolSpelling | None:
    """The spelling rule by which a host tool name is one of Yoetz's own MCP tools, or ``None``.

    * ``server_scoped``: ``mcp__<server>__<tool>`` where the server key is Yoetz's (``yoetz``,
      ``plugin_yoetz_yoetz``); any tool of that server qualifies, so a tool added later is
      recognised as Yoetz's own without a registry edit.
    * ``server_prefixed`` and ``bare``: a closed Yoetz tool basename, as the delivery policy
      (#564) already reads them.
    * ``generic_mcp``: Cursor's ordinary ``postToolUse`` spells every MCP call ``MCP:<tool>`` and
      names no server (tb4n1 B5), so a call cannot be attributed. The closed Yoetz basenames are
      read as Yoetz's: a foreign MCP tool with exactly one of these names is treated alike. That
      loses a later-material disclosure only for a state-changing foreign tool with such a name;
      a record the rule cannot attribute at all stays disclosed.

    Matching is case-insensitive and exact; nothing is parsed out of a longer name.
    """

    if type(tool) is not str or not tool:
        return None
    lowered = tool.casefold()
    if lowered.startswith("mcp__"):
        server, separator, name = lowered[len("mcp__") :].partition("__")
        if separator and name and "yoetz" in server.split("_"):
            return "server_scoped"
        return None
    for prefix in _SERVER_PREFIXES:
        if lowered.startswith(prefix):
            return "server_prefixed" if lowered[len(prefix) :] in _NAMES else None
    if lowered.startswith(_GENERIC_MCP_PREFIX):
        return "generic_mcp" if lowered[len(_GENERIC_MCP_PREFIX) :] in _NAMES else None
    return "bare" if lowered in _NAMES else None
