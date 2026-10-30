"""Serialized-size accounting and bounded, verified reconstruction of result pages."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final, cast

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

if TYPE_CHECKING:
    from finishup.protocol.models import StatusRequest, StatusResult

# Hosts read one channel each (ADR-043 result-delivery amendment). Codex 0.159 shows a model only
# ``serde_json(structuredContent)`` behind a ``Wall time`` header, cut to a 12,000-byte head/tail
# window for a slug missing from its bundled models.json (gpt-6.1-sol at that tag;
# tests/unit/mcp/test_codex_structured_head.py). Cursor reads the canonical JSON text copy and has
# no documented limit; Claude Code reads both channels and its MCP output limit is far above these
# sizes. Budget the larger channel plus a header allowance, never the sum of channels: Codex's
# "Wall time: N seconds\nOutput:\n" header is 35 bytes, and under 40 for any run below a day.
CODEX_FALLBACK_WINDOW_BYTES: Final = 12_000
HOST_FRAMING_BYTES: Final = 64
HOST_RESULT_BUDGET_BYTES: Final = CODEX_FALLBACK_WINDOW_BYTES


def mcp_delivery_bytes(wire: Mapping[str, JsonValue], *, text: str | None = None) -> int:
    """The larger MCP channel a host reads (structured JSON or the text) plus framing."""
    structured = len(canonical_encode(dict(wire)))
    channel = structured if text is None else max(structured, len(text.encode("utf-8")))
    return channel + HOST_FRAMING_BYTES


def reassemble_delivery(pages: Sequence[Mapping[str, Any]]) -> dict[str, JsonValue]:
    """Reconstruct typed containers and verify all scalar fragments and the source digest.

    Each page carries its own read's privacy projection; the result takes the final page's.
    """
    result: dict[str, Any] = {}
    fragments: dict[str, tuple[dict[str, Any], str]] = {}
    seen: set[str] = set()
    offset = 0
    if not pages:
        raise ValueError("result_delivery_invalid")
    identity = pages[0]

    def assign(path: str, value: Any) -> None:
        tokens = [part.replace("~1", "/").replace("~0", "~") for part in path.split("/")[1:]]
        parent: Any = result
        for token in tokens[:-1]:
            parent = (
                cast(list[Any], parent)[int(token)]
                if isinstance(parent, list)
                else cast(dict[str, Any], parent)[token]
            )
        last = tokens[-1]
        if isinstance(parent, list):
            array = cast(list[Any], parent)
            index = int(last)
            if index == len(array):
                array.append(value)
            elif 0 <= index < len(array):
                array[index] = value
            else:
                raise ValueError("result_delivery_invalid")
        else:
            parent[last] = value

    try:
        for page in pages:
            if page["offset"] != offset or any(
                page[key] != identity[key]
                for key in (
                    "source_request_id",
                    "source_operation",
                    "source_digest",
                    "total_items",
                    "task_id",
                    "session_id",
                    "writer_id",
                    "result_frontier",
                )
            ):
                raise ValueError("result_delivery_invalid")
            if page["privacy_projection"]["sink"] != identity["privacy_projection"]["sink"]:
                raise ValueError("result_delivery_invalid")
            for item in page["items"]:
                path, value = item["path"], item["value"]
                if (
                    not path.startswith("/")
                    or path in seen
                    # Outside the content digest, so never verifiable as items.
                    or path.split("/")[1] in {"privacy_projection", "review_delivery"}
                ):
                    raise ValueError("result_delivery_invalid")
                fragment = item.get("fragment")
                container = item.get("container")
                if container is not None:
                    if (
                        fragment is not None
                        or value is not None
                        or container not in {"object", "array"}
                    ):
                        raise ValueError("result_delivery_invalid")
                    value = (
                        cast(dict[str, Any], {}) if container == "object" else cast(list[Any], [])
                    )
                if fragment is not None:
                    first, text = fragments.get(path, (fragment, ""))
                    if (
                        not isinstance(value, str)
                        or fragment["unit"] != "unicode_scalar"
                        or fragment["offset"] != len(text)
                        or fragment["end"] != len(text) + len(value)
                        or fragment["length"] != first["length"]
                        or fragment["digest"] != first["digest"]
                    ):
                        raise ValueError("result_delivery_invalid")
                    text += value
                    fragments[path] = (first, text)
                    if not fragment["complete"]:
                        continue
                    if len(text) != first["length"] or canonical_digest(text) != first["digest"]:
                        raise ValueError("result_delivery_invalid")
                    del fragments[path]
                    value = text
                assign(path, value)
                seen.add(path)
            offset += len(page["items"])
        if (
            fragments
            or not pages[-1]["complete"]
            or pages[-1]["next_cursor"] is not None
            or offset != identity["total_items"]
            or canonical_digest(
                {
                    k: v
                    for k, v in result.items()
                    if k not in {"privacy_projection", "review_delivery"}
                }
            )
            != identity["source_digest"]
        ):
            raise ValueError("result_delivery_invalid")
        result["privacy_projection"] = dict(pages[-1]["privacy_projection"])
        return cast(dict[str, JsonValue], result)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ValueError("result_delivery_invalid") from exc


async def collect_status_delivery(
    fetch: Callable[[StatusRequest], Awaitable[StatusResult]],
    request: StatusRequest,
) -> StatusResult:
    """Bounded internal consumer for closure preparation; ordinary tools expose the pages."""
    from finishup.protocol.ids import IdKind, new_id
    from finishup.protocol.models import (
        DeliveryPageModel,
        StatusRequest,
        StatusResult,
        public_model_to_wire,
    )

    wrapped = await fetch(request)
    pages: list[dict[str, JsonValue]] = []
    size = 0
    offset = 0
    seen_cursors: set[str] = set()
    for _ in range(128):
        page = wrapped.root
        if not isinstance(page, DeliveryPageModel):
            if pages:
                raise ValueError("result_delivery_invalid")
            return wrapped
        if page.page_set_restarted is True and page.offset == 0 and pages:
            # #1244: a miss rebuilt the set with different content; it starts again at 0.
            pages, size, offset = [], 0, 0
        if (
            page.source_operation != "status"
            or page.session_id != request.session_id
            or page.writer_id != request.writer_id
            or page.offset != offset
        ):
            raise ValueError("result_delivery_invalid")
        wire = public_model_to_wire(wrapped)
        size += len(canonical_encode(wire))
        if size > 1_048_576:
            raise ValueError("result_delivery_limit")
        pages.append(wire)
        offset += len(page.items)
        if page.complete:
            return StatusResult.model_validate(reassemble_delivery(pages))
        if page.next_cursor is None or page.next_cursor in seen_cursors:
            raise ValueError("result_delivery_invalid")
        seen_cursors.add(page.next_cursor)
        wrapped = await fetch(
            StatusRequest.model_validate(
                {
                    **request.model_dump(
                        mode="json",
                        exclude_none=True,
                        include={
                            "protocol_version",
                            "schema_version",
                            "actor",
                            "client",
                            "session_id",
                            "writer_id",
                        },
                    ),
                    "request_id": new_id(IdKind.REQUEST),
                    "view": "compact",
                    "delivery_cursor": page.next_cursor,
                }
            )
        )
    raise ValueError("result_delivery_limit")
