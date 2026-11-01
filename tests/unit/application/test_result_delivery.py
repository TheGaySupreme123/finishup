"""#1139: the native MCP result fits, and continuation loses no actionable field."""

from __future__ import annotations

import copy
import json
from typing import Any, Literal, cast

import pytest

from finishup.application.result_delivery import (
    HOST_RESULT_BUDGET_BYTES,
    DeliveryPageSet,
    DeliveryPageStore,
    decode_handle,
    delivery_items,
    handle_check,
    invalid_cursor,
    mcp_delivery_bytes,
    page_result,
)
from finishup.domain.result_delivery import (
    CODEX_FALLBACK_WINDOW_BYTES,
    HOST_FRAMING_BYTES,
    collect_status_delivery,
    reassemble_delivery,
)
from finishup.domain.review_guidance import ReviewGuidance
from finishup.mcp.server import result_from_public_model
from finishup.ports.control import McpHostProfile
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import PublicOperationError
from finishup.protocol.models import CheckResultModel, StatusRequest

_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000002"
# What Codex 0.159 prefixes to the structured JSON it shows a model (test_codex_structured_head).
_CODEX_HEADER = "Wall time: 0.0000 seconds\nOutput:\n"


@pytest.mark.parametrize("with_findings", [False, True])
@pytest.mark.parametrize("host", ["codex", "claude", "cursor", "generic"])
def test_review_guidance_reaches_the_model_before_paged_summary(
    with_findings: bool, host: McpHostProfile
) -> None:
    source = _source()
    guidance = ReviewGuidance.MATERIAL_CONCERNS.value
    source["review_guidance"] = guidance
    if not with_findings:
        source["findings"] = []
    source["verified"] = [
        {"requirement_or_claim": f"criterion-{n}", "verdict": "supported", "snippet": "x" * 1000}
        for n in range(24)
    ]
    pages = _pages(source)
    assert len(pages) > 1
    first = pages[0]
    paths = [item["path"] for item in first["items"]]
    assert paths.index("/review_guidance") < paths.index("/review_summary")
    result = result_from_public_model(CheckResultModel.model_validate(first), host_profile=host)
    assert result.structuredContent is not None
    structured = canonical_encode(cast(Any, result.structuredContent))
    text = "".join(cast(Any, block).text for block in result.content).encode()
    # Actual channels read by Codex and text-only hosts, including framing and byte budget.
    assert guidance.encode() in structured and guidance.encode() in text
    assert len(_CODEX_HEADER.encode()) + len(structured) <= CODEX_FALLBACK_WINDOW_BYTES
    assert (
        mcp_delivery_bytes(cast(Any, result.structuredContent), text=text.decode())
        <= HOST_RESULT_BUDGET_BYTES
    )
    assert reassemble_delivery(pages)["review_guidance"] == guidance


def test_advisory_identities_are_paged_with_the_actionable_fields() -> None:
    """#1162 tracked advice: an oversized check never reports actionable_complete before its IDs."""

    source = _source()
    advisory_ids = [f"evt_00000000-0000-4000-8000-000000000042:{n}" for n in range(1, 11)]
    source["correctness_advisories"] = [
        {
            "advisory_id": advisory_id,
            "origin": "strongest_remaining_check",
            "subject_refs": ["obl_00000000-0000-4000-8000-000000000005"],
            "summary": "Decrypt a 32-character seed and compare with the reference. " * 6,
        }
        for advisory_id in advisory_ids
    ]
    source["verified"] = [
        {"requirement_or_claim": f"criterion-{n}", "verdict": "supported", "snippet": "x" * 1000}
        for n in range(24)
    ]
    pages = _pages(source)
    assert len(pages) > 1
    last_actionable = next(index for index, page in enumerate(pages) if page["actionable_complete"])
    actionable = canonical_encode(
        cast(Any, [item for page in pages[: last_actionable + 1] for item in page["items"]])
    )
    for advisory_id in advisory_ids:
        assert advisory_id.encode() in actionable
    assert reassemble_delivery(pages)["correctness_advisories"] == source["correctness_advisories"]
    # The verified rows stay optional provenance after the actionable fields.
    assert any(
        str(item["path"]).startswith("/verified")
        for page in pages[last_actionable + 1 :]
        for item in page["items"]
    )


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["optional", "disabled"])
async def test_guidance_originates_in_successful_review_projection_only(
    mode: Literal["optional", "disabled"],
) -> None:
    from builders.projection_workflow import run_projection_workflow
    from finishup.application.check import check_internal_json
    from finishup.ports.ledger import CheckCommitResult

    workflow = await run_projection_workflow(mode)
    internal = workflow.case("check").internal
    assert isinstance(internal, CheckCommitResult)
    wire = check_internal_json(internal)
    if mode == "optional":
        assert wire["review_guidance"] == ReviewGuidance.MATERIAL_CONCERNS.value
    else:
        assert "review_guidance" not in wire


def _projection(read: int = 1, omitted: tuple[str, ...] = ()) -> dict[str, Any]:
    """One read's local disclosure receipt; each continuation read gets a fresh one."""
    return {
        "sink": "agent_context",
        "local_disclosure_receipt_id": f"egr_00000000-0000-4000-8000-{read:012x}",
        "policy_id": "pvy_00000000-0000-4000-8000-000000000005",
        "policy_version": "1",
        "policy_digest": "sha256:" + "b" * 64,
        "included_categories": ["evidence_excerpt", "finding_summary"],
        "blocked_categories": ["repository_excerpt"],
        "omitted_pointers": sorted(set(omitted), key=str.encode),
        "projection_commitment": f"hmac-sha256:{read:064x}",
    }


def _source() -> dict[str, Any]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "ok": True,
        "state": "complete",
        "request_id": "req_00000000-0000-4000-8000-000000000003",
        "task_id": "tsk_00000000-0000-4000-8000-000000000004",
        "session_id": _SESSION,
        "result_frontier": {"sequence": "42", "head_digest": "sha256:" + "a" * 64},
        "verdict": "action_required",
        "agent_next": "Answer each question with its uncertainty.",
        "review_summary": "Advisory: compare both readings before changing the deliverable.",
        "findings": [
            {
                "finding_id": f"fnd_00000000-0000-4000-8000-{i:012x}",
                "kind": "decision_needed",
                "summary": f"Concern {i}: "
                + "Repeated poles need a discriminating measurement. " * 8,
                "detail": "Compare the measurement and preserve the owner-defined model. " * 8,
                "challenge": {
                    "discrepancy": "A pooled estimate can hide a mode shift. " * 10,
                    "requested_next_step": "answer_question",
                    "alternative_interpretation": "The supplied reference may intentionally pool the modes. "
                    * 10,
                    "uncertainty": "Do not replace it until the sensitivity diagnostic resolves the ambiguity. "
                    * 10,
                    "snippet": f"Supporting excerpt {i} " * 300,
                },
                "provenance": {"source": "model-derived", "refs": [f"ref_{i}"] * 100},
            }
            for i in range(1, 21)
        ],
        "privacy_projection": _projection(),
    }


def _pages(source: dict[str, Any]) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    position = 0
    while True:
        page: dict[str, Any] = page_result(
            source,
            method="check",
            selector={"request_id": source["request_id"]},
            writer_id=_WRITER,
            sink="agent_context",
            position=position,
        )
        pages.append(page)
        if page["complete"]:
            assert page["next_cursor"] is None
            return pages
        handle = decode_handle(page["next_cursor"])
        assert handle.position > position
        assert handle.digest_prefix == page["source_digest"].removeprefix("sha256:")[:8]
        position = handle.position


@pytest.fixture(scope="module")
def many_pages() -> list[dict[str, Any]]:
    return _pages(_source())


@pytest.mark.parametrize("host", ["codex", "claude", "cursor", "generic"])
def test_many_substantive_findings_are_whole_on_every_host(
    host: McpHostProfile, many_pages: list[dict[str, Any]]
) -> None:
    source = _source()
    assert len(canonical_encode(source)) > 120_000
    pages = many_pages
    atoms = [item for page in pages for item in page["items"]]
    assert atoms == delivery_items(source)
    assert all("fragment" not in atom for atom in atoms if "snippet" not in atom["path"])
    # Every complete action field, including fields well beyond the old 180-byte limit.
    for i, finding in enumerate(source["findings"]):
        for path, value in [
            (f"/findings/{i}/detail", finding["detail"]),
            *[
                (f"/findings/{i}/challenge/{key}", value)
                for key, value in finding["challenge"].items()
                if key != "snippet"
            ],
        ]:
            assert any(item["path"] == path and item["value"] == value for item in atoms)
    first_bulk = next(
        i
        for i, atom in enumerate(atoms)
        if "snippet" in atom["path"] or "provenance" in atom["path"]
    )
    assert all(
        "snippet" not in atom["path"] and "provenance" not in atom["path"]
        for atom in atoms[:first_bulk]
    )
    for page in pages:
        result = result_from_public_model(CheckResultModel.model_validate(page), host_profile=host)
        # Each channel a host reads fits: Codex reads only the structured JSON behind its header,
        # Cursor the canonical text copy, Claude Code both against a far larger limit.
        structured = canonical_encode(cast(Any, result.structuredContent))
        text = "".join(cast(Any, block).text for block in result.content).encode()
        assert len(structured) + HOST_FRAMING_BYTES <= HOST_RESULT_BUDGET_BYTES
        assert len(text) + HOST_FRAMING_BYTES <= HOST_RESULT_BUDGET_BYTES
        assert len(_CODEX_HEADER) + len(structured) <= CODEX_FALLBACK_WINDOW_BYTES
        assert mcp_delivery_bytes(page) <= HOST_RESULT_BUDGET_BYTES
        assert page["truncated"] is True
        assert "delivery_cursor=next_cursor" in page["required_next_step"]


def test_oversized_scalar_has_lossless_explicit_fragments_including_escaping() -> None:
    source = _source()
    original = '😀 עברית "quoted" \\ \n\t' * 1000
    source["findings"] = []
    source["review_summary"] = original
    atoms = [
        item
        for page in _pages(source)
        for item in page["items"]
        if item["path"] == "/review_summary"
    ]
    assert "".join(item["value"] for item in atoms) == original
    offset = 0
    for item in atoms:
        fragment = item["fragment"]
        assert fragment["unit"] == "unicode_scalar"
        assert fragment["offset"] == offset
        offset = fragment["end"]
        assert fragment["length"] == len(original)
        assert fragment["digest"] == canonical_digest(original)
    assert atoms[-1]["fragment"]["complete"] is True


def test_full_reconstruction_preserves_numeric_object_keys_and_rejects_incomplete_fields() -> None:
    source = _source()
    source["findings"] = []
    source["bulk"] = {"0": "numeric object key " * 200, "a/b~c": [{"": "nested " * 300}]}
    pages = _pages(source)
    assert reassemble_delivery(pages) == source
    with pytest.raises(ValueError, match="result_delivery_invalid"):
        reassemble_delivery(pages[:-1])
    altered = copy.deepcopy(pages)
    fragment = next(item for page in altered for item in page["items"] if "fragment" in item)
    fragment["value"] += "unrecorded tail"
    with pytest.raises(ValueError, match="result_delivery_invalid"):
        reassemble_delivery(altered)


def test_page_partition_is_independent_of_mapping_insertion_order() -> None:
    def reverse(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: reverse(v) for k, v in reversed(list(cast(dict[str, Any], value).items()))}
        if isinstance(value, list):
            return [reverse(v) for v in cast(list[Any], value)]
        return value

    source = _source()
    source["findings"] = source["findings"][:1]
    assert _pages(source) == _pages(reverse(source))


def test_handle_is_short_canonical_and_its_page_set_bound_to_session_and_writer(
    many_pages: list[dict[str, Any]],
) -> None:
    """#1244 (D12): a handle names its source; the kept page set binds session and writer."""
    source = _source()
    first = many_pages[0]
    cursor = cast(str, first["next_cursor"])
    assert len(cursor) <= 64 and next(iter(first)) == "next_cursor"
    handle = decode_handle(cursor)
    assert handle.method == "check"
    assert handle.source_request_id == source["request_id"]
    assert handle.frontier == 42 and handle.position == len(first["items"])
    for bad in (
        cursor + "0",
        cursor[:-1] + "G",
        cursor.replace(".", "..", 1),
        cursor.replace(f".{handle.position}.", ".0.", 1),
        cursor.replace(f".{handle.position}.", f".0{handle.position}.", 1),
        "x" + cursor[1:],
        "nonsense",
    ):
        with pytest.raises(PublicOperationError) as refused:
            decode_handle(bad)
        assert refused.value.safe_details["reason_code"] == "delivery_cursor_invalid"
    refusal = invalid_cursor()
    assert "copy next_cursor exactly" in refusal.message
    store = DeliveryPageStore(max_sets=2)
    entry = DeliveryPageSet(
        _SESSION, _WRITER, "agent_context", "check", {}, source, "sha256:" + "0" * 64, None, 10
    )
    store.put(handle.set_key, entry)
    assert store.get(handle.set_key, _SESSION, _WRITER) is entry
    assert store.get(handle.set_key, _SESSION, _WRITER[:-1] + "3") is None
    assert store.get(handle.set_key, _SESSION[:-1] + "9", _WRITER) is None
    store.put("a", entry)
    store.put("b", entry)
    assert len(store) == 2 and store.get(handle.set_key, _SESSION, _WRITER) is None


def _edits(cursor: str) -> dict[str, str]:
    """One plausible typo or deliberate edit per handle field, each still well formed."""

    body, check = cursor.rsplit(".", 1)
    kind_id, frontier, position, digest, *selector = body.split(".")

    def bump(number: str) -> str:
        return str(int(number) + 1)

    def flip(text: str, index: int) -> str:
        swapped = "0" if text[index] != "0" else "1"
        return text[:index] + swapped + text[index + 1 :]

    def join(*parts: str) -> str:
        return ".".join([*parts, *selector, check])

    edits = {
        "offset": join(kind_id, frontier, bump(position), digest),
        "offset_back": join(kind_id, frontier, str(max(1, int(position) - 1)), digest),
        "frontier": join(kind_id, bump(frontier), position, digest),
        "digest": join(kind_id, frontier, position, flip(digest, 3)),
        "source_id": join(flip(kind_id, 5), frontier, position, digest),
        "check": body + "." + flip(check, 0),
    }
    if selector:
        edits["selector"] = ".".join([kind_id, frontier, position, digest, "x", check])
    else:
        edits["selector"] = ".".join([kind_id, frontier, position, digest, "b", check])
    return {name: edited for name, edited in edits.items() if edited != cursor}


def test_an_edited_handle_field_is_refused_never_served_from_another_offset(
    many_pages: list[dict[str, Any]],
) -> None:
    """#1244: every handle field is under its check; ``.55.`` edited to ``.56.`` is refused.

    Before the check segment an edited offset was served from the edited item (skipping one),
    and an edited frontier or digest prefix silently rebuilt or restarted the set.
    """
    for page in many_pages[:-1]:
        cursor = cast(str, page["next_cursor"])
        assert len(cursor) <= 64
        handle = decode_handle(cursor)
        assert handle.position == page["offset"] + len(page["items"])
        edits = _edits(cursor)
        assert {"offset", "frontier", "digest", "source_id", "selector", "check"} <= set(edits)
        for name, edited in edits.items():
            with pytest.raises(PublicOperationError) as refused:
                decode_handle(edited)
            assert refused.value.safe_details["reason_code"] == "delivery_cursor_invalid", name
    # A deliberately recomputed check is accepted: it is typo detection, not authentication,
    # and only names a read the caller's own session and writer may already make.
    cursor = cast(str, many_pages[0]["next_cursor"])
    body = _edits(cursor)["offset"].rsplit(".", 1)[0]
    assert decode_handle(f"{body}.{handle_check(body)}").position == (
        decode_handle(cursor).position + 1
    )


@pytest.mark.parametrize("host", ["codex", "claude", "cursor", "generic"])
def test_the_text_channel_leads_with_the_continuation_handle(
    host: McpHostProfile, many_pages: list[dict[str, Any]]
) -> None:
    """#1244: the handle an agent copies leads the text, not ~7,700 bytes in after the items."""

    for page in (many_pages[0], many_pages[-1]):
        result = result_from_public_model(CheckResultModel.model_validate(page), host_profile=host)
        structured = cast(dict[str, Any], result.structuredContent)
        assert next(iter(structured)) == "next_cursor"
        (block,) = result.content
        text = cast(Any, block).text
        assert text.startswith('{"next_cursor":' + json.dumps(page["next_cursor"]))
        # Only that member moves: the text is the structured result, at the canonical length.
        assert json.loads(text) == structured
        assert len(text.encode()) == len(canonical_encode(cast(Any, structured)))
        assert mcp_delivery_bytes(structured, text=text) <= HOST_RESULT_BUDGET_BYTES
        if page["next_cursor"] is not None:
            assert text.index(page["next_cursor"]) < 64


def test_status_handle_carries_a_rebuildable_selector_and_preserves_inventory_cursor() -> None:
    source = _source()
    source.update(
        view="findings",
        head_frontier=source["result_frontier"],
        projection_lag="0",
        import_status={"active_count": "1", "terminal_count": "0"},
        page={"items": source.pop("findings"), "next_cursor": "original-inventory-cursor"},
    )
    selector: dict[str, Any] = {
        "request_id": source["request_id"],
        "view": "findings",
        "limit": "20",
        "detail": "full",
        "at_frontier": "42",
    }
    from finishup.application.result_delivery import (
        status_selector_code,
        status_selector_from_code,
    )

    code = status_selector_code(selector)
    assert code == "ff20"
    first = page_result(
        source,
        method="status",
        selector=selector,
        writer_id=_WRITER,
        sink="agent_context",
        selector_code=code,
    )
    inventory = first["inventory_read"]
    assert isinstance(inventory, dict)
    assert inventory == {
        **{k: v for k, v in selector.items() if k != "request_id"},
        "cursor": "original-inventory-cursor",
    }
    handle = decode_handle(cast(str, first["next_cursor"]))
    assert handle.method == "status" and handle.selector_code == code
    rebuilt = status_selector_from_code(handle.selector_code, handle)
    assert rebuilt == {**selector, "delivery": "paged"}
    # A selector the handle cannot carry (an inventory cursor) is marked, so a miss can say so.
    assert status_selector_code({**selector, "cursor": "abc"}) == "x"
    with pytest.raises(PublicOperationError) as expired:
        status_selector_from_code("x", handle)
    assert expired.value.safe_details["reason_code"] == "delivery_cursor_expired"
    continued = page_result(
        source,
        method="status",
        selector=selector,
        writer_id=_WRITER,
        sink="agent_context",
        position=handle.position,
        selector_code=code,
        ledger_moved_since={"sequence": "99", "head_digest": "sha256:" + "b" * 64},
    )
    assert continued["source_digest"] == first["source_digest"]
    assert continued["inventory_read"] == inventory
    assert cast(dict[str, Any], continued["ledger_moved_since"])["sequence"] == "99"
    # A notice never moves the partition: the same offsets hold with or without it.
    plain = page_result(
        source,
        method="status",
        selector=selector,
        writer_id=_WRITER,
        sink="agent_context",
        position=handle.position,
        selector_code=code,
    )
    assert plain["items"] == continued["items"] and plain["next_cursor"] == continued["next_cursor"]


def test_inventory_and_delivery_cursors_share_the_actual_envelope_budget() -> None:
    import base64
    import hashlib

    opaque = (
        base64.urlsafe_b64encode(
            b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(20))
        )
        .decode()
        .rstrip("=")
    )
    source = _source()
    source["findings"] = source["findings"][:1]
    source["page"] = {"items": source.pop("findings"), "next_cursor": opaque}
    selector: dict[str, Any] = {
        "view": "findings",
        "detail": "full",
        "limit": "20",
        "cursor": opaque,
        "at_frontier": "42",
    }
    pages: list[dict[str, Any]] = []
    position = 0
    while True:
        page = cast(
            dict[str, Any],
            page_result(
                source,
                method="status",
                selector=selector,
                writer_id=_WRITER,
                sink="agent_context",
                position=position,
                selector_code="x",
            ),
        )
        assert mcp_delivery_bytes(page) <= HOST_RESULT_BUDGET_BYTES
        pages.append(page)
        if page["complete"]:
            break
        position = decode_handle(page["next_cursor"]).position
    assert reassemble_delivery(pages) == source


def test_each_page_carries_its_own_read_disclosure_and_never_pages_it() -> None:
    """A projection too large for one atom is never split across reads with different receipts."""
    source = _source()
    omitted = tuple(f"/findings/{i}/provenance/refs/{j}" for i in range(20) for j in range(20))
    pages: list[dict[str, Any]] = []
    position = 0
    while True:
        # Every continuation reapplies disclosure: a fresh receipt and commitment per read.
        source["privacy_projection"] = _projection(len(pages) + 1, omitted)
        page: dict[str, Any] = page_result(
            source,
            method="check",
            selector={"request_id": source["request_id"]},
            writer_id=_WRITER,
            sink="agent_context",
            position=position,
        )
        CheckResultModel.model_validate(page)
        assert mcp_delivery_bytes(page) <= HOST_RESULT_BUDGET_BYTES
        assert not any(item["path"].startswith("/privacy_projection") for item in page["items"])
        carried = page["privacy_projection"]
        read = source["privacy_projection"]
        assert {k: v for k, v in carried.items() if k != "omitted_pointers"} == {
            k: v for k, v in read.items() if k != "omitted_pointers"
        }
        # Past the page's projection bound, pointers coalesce to containing fields (ADR-009).
        assert len(canonical_encode(carried)) < len(canonical_encode(read))
        for pointer in omitted:
            assert any(
                pointer == kept or pointer.startswith(kept + "/")
                for kept in carried["omitted_pointers"]
            )
        pages.append(page)
        if page["complete"]:
            break
        position = decode_handle(page["next_cursor"]).position
    assert len({page["privacy_projection"]["local_disclosure_receipt_id"] for page in pages}) > 1
    rebuilt = reassemble_delivery(pages)
    assert rebuilt["privacy_projection"] == pages[-1]["privacy_projection"]
    assert {k: v for k, v in rebuilt.items() if k != "privacy_projection"} == {
        k: v for k, v in source.items() if k != "privacy_projection"
    }
    mixed = copy.deepcopy(pages)
    mixed[0]["privacy_projection"]["sink"] = "local_human_view"
    with pytest.raises(ValueError, match="result_delivery_invalid"):
        reassemble_delivery(mixed)
    # Disclosure metadata assembled from items cannot stand in for the final read's receipt.
    paged_projection = {
        **pages[-1],
        "offset": 0,
        "total_items": 1,
        "source_digest": canonical_digest({}),
        "items": [{"path": "/privacy_projection", "value": _projection(99)}],
    }
    with pytest.raises(ValueError, match="result_delivery_invalid"):
        reassemble_delivery([paged_projection])
    # review_delivery is outside the content digest too: such an item could never be verified.
    unverified = {**paged_projection, "items": [{"path": "/review_delivery", "value": "advice"}]}
    with pytest.raises(ValueError, match="result_delivery_invalid"):
        reassemble_delivery([unverified])


@pytest.mark.parametrize("host", ["codex", "claude", "cursor", "generic"])
def test_small_check_text_also_contains_complete_action_fields(host: McpHostProfile) -> None:
    from tests.unit.protocol.test_models_and_schemas import (
        _check_result_wire,  # pyright: ignore[reportPrivateUsage]
    )

    wire = cast(dict[str, Any], _check_result_wire())
    wire["findings"][0]["detail"] = "Measure the second mode before changing the reference."
    wire["findings"][0].pop("challenge", None)
    result = result_from_public_model(CheckResultModel.model_validate(wire), host_profile=host)
    assert result.content[0].type == "text"
    assert wire["findings"][0]["detail"] in result.content[0].text
    assert mcp_delivery_bytes(wire, text=result.content[0].text) <= HOST_RESULT_BUDGET_BYTES


@pytest.mark.parametrize("host", ["codex", "claude", "generic"])
def test_canonical_text_fallback_never_enlarges_an_unpaged_result(host: McpHostProfile) -> None:
    """The service never pages publish results; a long structured body keeps its short prose."""
    from tests.unit.protocol.test_models_and_schemas import (
        _publish_result_wire,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.mcp.server import _result_text  # pyright: ignore[reportPrivateUsage]
    from finishup.protocol.models import PublishWorkResultModel

    wire = cast(dict[str, Any], _publish_result_wire())
    event = wire["accepted_events"][0]
    wire["accepted_events"] = [
        {
            **event,
            "event_id": f"evt_00000000-0000-4000-8000-{i:012x}",
            "writer_sequence": str(i + 1),
            "ingestion_sequence": str(i + 1),
        }
        for i in range(30)
    ]
    model = PublishWorkResultModel.model_validate(wire)
    prose = _result_text(wire, host_profile=host)
    canonical = canonical_encode(wire).decode()
    assert mcp_delivery_bytes(wire, text=prose) > HOST_RESULT_BUDGET_BYTES
    assert len(canonical.encode()) > len(prose.encode())
    result = result_from_public_model(model, host_profile=host)
    assert result.structuredContent == wire
    assert result.content[0].type == "text"
    assert result.content[0].text == prose
    assert mcp_delivery_bytes(wire, text=result.content[0].text) == mcp_delivery_bytes(
        wire, text=prose
    )


def test_delivery_read_is_an_explicit_unambiguous_status_selector(
    many_pages: list[dict[str, Any]],
) -> None:
    source = _source()
    cursor = many_pages[0]["next_cursor"]
    body = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": source["request_id"],
        "actor": {"actor_id": "test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "1", "integration": "local_cli"},
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "view": "compact",
        "delivery_cursor": cursor,
    }
    assert StatusRequest.model_validate(body).delivery_cursor == cursor
    with pytest.raises(ValueError):
        StatusRequest.model_validate(
            {**body, "filter": {"include_resolved": True}, "view": "findings"}
        )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("label", ["check", "status/findings", "receipt"])
async def test_real_disclosure_and_recorded_source_continuation_do_not_repeat_work(
    label: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from builders.projection_workflow import (
        ProjectionCase,
        project_case,
        request_base,
        run_projection_workflow,
    )
    from finishup.ports.control import ControlMethod

    # Reviewer provenance and four findings make each source genuinely oversize (#1139).
    workflow = await run_projection_workflow("optional", max_findings=10)
    disclosures = 0
    original_disclose = type(workflow.app.privacy).prepare_local_disclosure

    async def disclose(*args: Any, **kwargs: Any) -> Any:
        nonlocal disclosures
        disclosures += 1
        from finishup.protocol.canonical import strict_json_parse

        audit = args[1].projection_audit_context
        frame = strict_json_parse(audit.control_request_canonical)
        assert isinstance(frame, dict)
        assert audit.method == frame["method"]
        assert args[1].request_id == audit.original_request_id
        return await original_disclose(*args, **kwargs)

    monkeypatch.setattr(type(workflow.app.privacy), "prepare_local_disclosure", disclose)
    case = workflow.case(label)
    if label == "check":
        from dataclasses import replace

        from finishup.ports.ledger import CheckCommitResult, CheckObservationsAwaited

        # This call-local field is absent when the stored check is reloaded on continuation.
        assert isinstance(case.internal, CheckCommitResult)
        case = replace(
            case,
            internal=replace(
                case.internal,
                observations_awaited=CheckObservationsAwaited("bounded_timeout", 2),
            ),
        )
    if case.method is ControlMethod.STATUS:
        # The MCP status tool opts an agent's read into pages; internal reads stay complete.
        unpaged = dict(await project_case(workflow.app, case, 8990, paginate=True))
        assert "state" not in unpaged and unpaged["view"] == "findings"
        case = ProjectionCase(
            case.label, case.method, {**case.request_body, "delivery": "paged"}, case.internal
        )
    first: dict[str, Any] = dict(await project_case(workflow.app, case, 9000, paginate=True))
    assert first["state"] == "delivery_page"
    seen: list[Any] = list(first["items"])
    page = first
    pages = [first]
    seed = 9100

    async def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("delivery read must not repeat a workflow write")

    monkeypatch.setattr(type(workflow.app), "check", forbidden)
    monkeypatch.setattr(type(workflow.app), "receipt", forbidden)
    head_body = {
        **request_base("req_00000000-0000-4000-8000-000000008888"),
        "session_id": first["session_id"],
        "writer_id": first["writer_id"],
        "view": "compact",
    }
    before = await workflow.app.status(StatusRequest.model_validate(head_body))
    original_id = first["source_request_id"]
    while page["next_cursor"] is not None:
        body = {
            **request_base(f"req_00000000-0000-4000-8000-{seed:012x}"),
            "session_id": page["session_id"],
            "writer_id": page["writer_id"],
            "view": "compact",
            "delivery_cursor": page["next_cursor"],
        }
        internal = await workflow.app.read_result_delivery(StatusRequest.model_validate(body))
        next_case = ProjectionCase("delivery", ControlMethod.STATUS, body, internal)
        page = cast(
            dict[str, Any], dict(await project_case(workflow.app, next_case, seed, paginate=True))
        )
        assert page["source_request_id"] == original_id
        assert page["source_digest"] == first["source_digest"]
        assert page["result_frontier"] == first["result_frontier"]
        assert page["offset"] == len(seen)
        assert mcp_delivery_bytes(page) <= HOST_RESULT_BUDGET_BYTES
        seen.extend(page["items"])
        pages.append(page)
        seed += 2
    assert len(seen) == first["total_items"]
    # Each read is its own disclosure (counted below). A re-read that no longer matches the first
    # (the check's call-local observation wait, a status read's moved head) is served from the
    # kept copy (#1244, D12) with the receipt those items were disclosed under; an unchanged
    # re-read carries its own. The reconstruction carries the final page's receipt.
    receipts = {page["privacy_projection"]["local_disclosure_receipt_id"] for page in pages}
    assert 1 <= len(receipts) <= len(pages)
    reconstructed = reassemble_delivery(pages)
    assert reconstructed["privacy_projection"] == pages[-1]["privacy_projection"]
    expected = dict(await project_case(workflow.app, case, seed + 10))
    assert {k: v for k, v in reconstructed.items() if k != "privacy_projection"} == {
        k: v for k, v in expected.items() if k != "privacy_projection"
    }
    collected_reads = 0
    if label == "status/findings":
        from finishup.domain.closure import prepare_closure
        from finishup.protocol.models import (
            ClosureSelectionModel,
            StatusResultModel,
            public_model_to_wire,
        )

        frozen_initial = True

        async def fetch(request: StatusRequest) -> StatusResultModel:
            nonlocal collected_reads
            collected_reads += 1
            internal = (
                await workflow.app.read_result_delivery(request)
                if request.delivery_cursor is not None
                else case.internal
                if frozen_initial
                else await workflow.app.status(request)
            )
            read_case = ProjectionCase(
                "collect", ControlMethod.STATUS, public_model_to_wire(request), internal
            )
            return StatusResultModel.model_validate(
                await project_case(
                    workflow.app, read_case, seed + 100 + collected_reads, paginate=True
                )
            )

        collected = await collect_status_delivery(
            fetch, StatusRequest.model_validate(case.request_body)
        )
        actual = public_model_to_wire(collected)
        assert {k: v for k, v in actual.items() if k != "privacy_projection"} == {
            k: v for k, v in expected.items() if k != "privacy_projection"
        }
        frozen_initial = False
        prepared = await prepare_closure(
            fetch,
            first["session_id"],
            first["writer_id"],
            ClosureSelectionModel.model_validate({"phase": "inventory"}),
        )
        inventory = cast(dict[str, Any], prepared["inventory"])
        assert inventory["findings"]
        expected_page = cast(dict[str, Any], expected["page"])
        assert {row["finding_id"] for row in expected_page["items"]} <= {
            row["finding_id"] for row in inventory["findings"]
        }
    after = await workflow.app.status(
        StatusRequest.model_validate(
            {
                **head_body,
                "request_id": "req_00000000-0000-4000-8000-000000008889",
            }
        )
    )
    from finishup.application.status import StatusInternalResult

    assert isinstance(before, StatusInternalResult) and isinstance(after, StatusInternalResult)
    assert before.head_frontier == after.head_frontier
    unpaged_reads = 1 if label.startswith("status") else 0
    assert disclosures == 2 + unpaged_reads + (seed - 9100) // 2 + collected_reads


@pytest.mark.anyio
async def test_internal_collector_refuses_duplicate_pages_and_aggregate_overflow(
    many_pages: list[dict[str, Any]],
) -> None:
    from finishup.protocol.models import StatusResultModel

    source = _source()
    request = StatusRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": source["request_id"],
            "session_id": _SESSION,
            "writer_id": _WRITER,
            "actor": {"actor_id": "test", "actor_type": "harness"},
            "client": {"kind": "test_client", "version": "1", "integration": "local_cli"},
            "view": "compact",
        }
    )
    page = {**many_pages[0], "source_operation": "status"}
    calls = 0

    async def fetch(_request: StatusRequest) -> StatusResultModel:
        nonlocal calls
        calls += 1
        return StatusResultModel.model_validate(page)

    with pytest.raises(ValueError, match="result_delivery_invalid"):
        await collect_status_delivery(fetch, request)
    assert calls == 2
    page["items"] = [{"path": "/bulk", "value": "x" * 1_048_576}]
    with pytest.raises(ValueError, match="result_delivery_limit"):
        await collect_status_delivery(fetch, request)


@pytest.mark.anyio
async def test_service_routes_status_cursor_to_read_only_delivery_handler(
    monkeypatch: pytest.MonkeyPatch, many_pages: list[dict[str, Any]]
) -> None:
    from finishup.ports.control import ControlClientKind, ControlMethod
    from finishup.protocol.models import DeliveryPageModel, StatusResultModel
    from integration.service.test_daemon_clients import (
        _daemon,  # pyright: ignore[reportPrivateUsage]
        _request,  # pyright: ignore[reportPrivateUsage]
        _status_body,  # pyright: ignore[reportPrivateUsage]
    )

    daemon, application, _vault, _listener = _daemon()
    marker = object()
    body = _status_body().model_copy(update={"delivery_cursor": many_pages[0]["next_cursor"]})

    async def continuation(request: Any, **kwargs: Any) -> Any:
        assert request == body
        assert "repository_privacy_context" in kwargs
        return marker

    async def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a delivery cursor must not execute the ordinary status query")

    async def project(context: Any, binding: Any, result: Any) -> Any:
        assert binding.method is ControlMethod.STATUS
        assert result is marker
        return StatusResultModel.model_validate({**many_pages[0], "request_id": body.request_id})

    monkeypatch.setattr(application, "status", forbidden)
    monkeypatch.setattr(application, "read_result_delivery", continuation, raising=False)
    monkeypatch.setattr(application, "project_result_for_client", project)
    await daemon.start()
    try:
        result = await daemon.dispatch(
            ControlClientKind.MCP_BRIDGE, _request(daemon, ControlMethod.STATUS, body)
        )
        assert result.outcome == "ok"
        assert isinstance(result.body, StatusResultModel)
        assert isinstance(result.body.root, DeliveryPageModel)
    finally:
        await daemon.close()


@pytest.mark.parametrize("json_output", [True, False])
def test_cli_json_and_terminal_text_keep_the_explicit_cursor_page(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    many_pages: list[dict[str, Any]],
    json_output: bool,
) -> None:
    import json

    from typer.testing import CliRunner

    import finishup.cli.app as cli

    page = many_pages[0]
    result = CheckResultModel.model_validate(page)

    class Client:
        async def check(self, request: Any, *, deadline_ms: Any) -> Any:
            return result

        async def close(self) -> None:
            pass

    async def connect() -> Any:
        return Client()

    monkeypatch.setattr(cli, "build_service_client", connect)
    request_path = tmp_path / "check.json"
    request_path.write_text(
        json.dumps(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": page["source_request_id"],
                "session_id": _SESSION,
                "writer_id": _WRITER,
                "actor": {"actor_id": "test", "actor_type": "harness"},
                "client": {"kind": "test_client", "version": "1", "integration": "local_cli"},
                "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            }
        )
    )
    if json_output:
        output = CliRunner().invoke(cli.app, ["check", "--input", str(request_path), "--json"])
        assert output.exit_code == 0, output.output
        text = output.stdout
    else:
        from finishup.protocol.models import CheckRequest

        shown: list[str] = []
        monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)

        def show(value: str) -> None:
            shown.append(value)

        monkeypatch.setattr(cli.typer, "echo", show)
        code = cli.run_async(
            lambda: cli._call_workflow(  # pyright: ignore[reportPrivateUsage]
                "check",
                CheckRequest,
                str(request_path),
                None,
                False,
                None,
            )
        )
        assert code == 0
        text = shown[0]
    assert json.loads(text) == page
    assert len(text.encode()) <= HOST_RESULT_BUDGET_BYTES


def test_cli_and_tui_findings_keep_every_challenge_field() -> None:
    from types import SimpleNamespace

    from finishup.cli.render import render_human_findings

    source = _source()
    rows = [
        SimpleNamespace(**{**finding, "challenge": SimpleNamespace(**finding["challenge"])})
        for finding in source["findings"]
    ]
    text = render_human_findings(rows)
    for row in source["findings"]:
        assert row["summary"] in text
        assert row["detail"] in text
        for key in (
            "discrepancy",
            "requested_next_step",
            "alternative_interpretation",
            "uncertainty",
        ):
            assert row["challenge"][key] in text


@pytest.mark.parametrize(
    "operation,version", [("check", "1.7.0"), ("status", "1.5.0"), ("receipt", "1.4.0")]
)
def test_delivery_page_survives_catalog_and_control_boundaries(
    operation: str,
    version: str,
    many_pages: list[dict[str, Any]],
) -> None:
    from finishup.ports.control import ControlMethod, ControlResult
    from finishup.protocol.models import ReceiptResultModel, StatusResultModel
    from finishup.protocol.schemas import validate_schema_instance
    from finishup.service.control_protocol import (
        decode_control_frame,
        encode_control_frame,
        parse_control_result,
    )

    page = {**many_pages[0], "source_operation": operation}
    validate_schema_instance(f"{operation}-result", version, page)
    model = {"check": CheckResultModel, "status": StatusResultModel, "receipt": ReceiptResultModel}[
        operation
    ]
    result = ControlResult(
        protocol_version="1.0",
        rpc_id="rpc_00000000-0000-4000-8000-000000000001",
        service_instance_id="svc_00000000-0000-4000-8000-000000000002",
        service_generation="1",
        method=ControlMethod(operation),
        outcome="ok",
        body=model.model_validate(page),
    )
    decoded = parse_control_result(decode_control_frame(encode_control_frame(result)))
    assert decoded.body == result.body


@pytest.mark.parametrize(
    "operation,version", [("check", "1.7.0"), ("status", "1.5.0"), ("receipt", "1.4.0")]
)
@pytest.mark.parametrize(
    "field,malformed",
    [
        ("request_id", "req_not-a-request"),
        ("source_request_id", "tsk_00000000-0000-4000-8000-000000000004"),
        ("task_id", "tsk_x"),
        ("session_id", "ses_x"),
        ("writer_id", "wri_x"),
        ("source_digest", "sha256:short"),
        ("result_frontier", {"sequence": "-1", "head_digest": "sha256:short"}),
        ("fragment_digest", "sha256:short"),
        ("privacy_projection", {"sink": "agent_context"}),
    ],
)
def test_delivery_page_schema_keeps_the_model_wire_constraints(
    operation: str,
    version: str,
    field: str,
    malformed: Any,
) -> None:
    from pydantic import ValidationError

    from finishup.protocol.models import ReceiptResultModel, StatusResultModel
    from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

    source = _source()
    source["findings"] = []
    source["review_summary"] = "A long qualification. " * 400
    page: dict[str, Any] = {**_pages(source)[0], "source_operation": operation}
    validate_schema_instance(f"{operation}-result", version, page)
    fragment = next(item for item in page["items"] if "fragment" in item)
    bad: dict[str, Any] = copy.deepcopy(page)
    if field == "fragment_digest":
        next(item for item in bad["items"] if "fragment" in item)["fragment"]["digest"] = malformed
    else:
        bad[field] = malformed
    assert fragment["fragment"]["digest"] == canonical_digest(source["review_summary"])
    model = {"check": CheckResultModel, "status": StatusResultModel, "receipt": ReceiptResultModel}[
        operation
    ]
    with pytest.raises(ValidationError):
        model.model_validate(bad)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance(f"{operation}-result", version, bad)


def test_result_delivery_matches_owned_canonical_vector() -> None:
    import json
    from pathlib import Path

    from finishup.protocol.schemas import validate_schema_instance

    fixture = (
        Path(__file__).resolve().parents[3]
        / "fixtures/canonical/check-reviewer-record-1.6.0.case.json"
    )
    vector = json.loads(fixture.read_bytes())["input"]["result_delivery"]
    page = page_result(
        vector["source"],
        method="check",
        selector={"request_id": vector["source"]["request_id"]},
        writer_id="wri_00000000-0000-4000-8000-000000000004",
        sink="agent_context",
    )
    assert "cursor_normalization" not in vector
    assert page == vector["payload"]
    assert canonical_encode(page).hex() == vector["canonical_hex"]
    assert canonical_digest(page) == vector["digest"]
    validate_schema_instance("check-result", "1.7.0", page)


def _workflow_daemon(app: Any) -> Any:
    """The real ServiceDaemon dispatch path in front of a real projection-workflow application."""
    from finishup.service.daemon import ServiceComposition, ServiceDaemon
    from finishup.service.lifecycle import ServiceLifecycle
    from integration.service.test_daemon_clients import (
        _INSTANCE_ID,  # pyright: ignore[reportPrivateUsage]
        _Clock,  # pyright: ignore[reportPrivateUsage]
        _GenerationStore,  # pyright: ignore[reportPrivateUsage]
        _Listener,  # pyright: ignore[reportPrivateUsage]
        _Monitor,  # pyright: ignore[reportPrivateUsage]
        _Vault,  # pyright: ignore[reportPrivateUsage]
    )

    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "1" * 64,
        instance_id=_INSTANCE_ID,
    )
    return ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=cast(Any, _Listener()),
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=cast(Any, _Monitor()),
            vault=_Vault(),
            application=app,
        )
    )


@pytest.mark.anyio
async def test_ordinary_results_are_one_response_through_the_daemon() -> None:
    """Review of #1139: ordinary agent reads and the bridge's own probes stay single responses.

    Over MCP every status read is brief and opted into pages, as ``dispatch_status`` sends it.
    Only a genuinely oversize result (the JSON owner-export receipt here) becomes pages.
    """
    from builders.projection_workflow import run_projection_workflow
    from finishup.ports.control import ControlClientKind, ControlMethod
    from finishup.protocol.models import (
        CheckRequest,
        PublishWorkRequest,
        ReceiptRequest,
        public_model_to_wire,
    )
    from integration.service.test_daemon_clients import (
        _request,  # pyright: ignore[reportPrivateUsage]
    )

    workflow = await run_projection_workflow()
    daemon = _workflow_daemon(workflow.app)
    seed = iter(range(0x9100, 0x9200))

    def fresh() -> str:
        return f"req_00000000-0000-4000-8000-{next(seed):012x}"

    async def dispatch(method: ControlMethod, model: Any, body: Any) -> dict[str, Any]:
        result = await daemon.dispatch(
            ControlClientKind.MCP_BRIDGE, _request(daemon, method, model.model_validate(body))
        )
        assert result.outcome == "ok", (method, body.get("view"), result.body)
        return cast(dict[str, Any], public_model_to_wire(result.body))

    await daemon.start()
    try:
        for view in ("compact", "findings", "history", "obligations", "evidence", "operation"):
            case = workflow.case(f"status/{view}")
            for detail in ("brief", "full"):
                body = {**case.request_body, "request_id": fresh(), "detail": detail}
                wire = await dispatch(
                    ControlMethod.STATUS, StatusRequest, {**body, "delivery": "paged"}
                )
                assert wire.get("state") != "delivery_page", (view, detail)
                assert wire["view"] == view
        check = await dispatch(
            ControlMethod.CHECK, CheckRequest, workflow.case("check").request_body
        )
        assert check["state"] == "complete"
        receipt = workflow.case("receipt").request_body
        for fmt in ("markdown", "text"):
            wire = await dispatch(
                ControlMethod.RECEIPT,
                ReceiptRequest,
                {**receipt, "request_id": fresh(), "format": fmt},
            )
            assert wire.get("state") != "delivery_page" and wire["format"] == fmt
        publish = workflow.case("publish_work").request_body
        assert "state" not in await dispatch(
            ControlMethod.PUBLISH_WORK, PublishWorkRequest, publish
        )
        # The bridge's write-recovery probe (``_timeout_operation_state``) reads page.state.
        envelope = {
            k: publish[k]
            for k in ("protocol_version", "schema_version", "actor", "client", "session_id")
        }
        probe = await dispatch(
            ControlMethod.STATUS,
            StatusRequest,
            {
                **envelope,
                "writer_id": publish["writer_id"],
                "request_id": fresh(),
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": publish["request_id"]},
            },
        )
        assert probe["page"]["state"] == "complete"
        # A JSON owner-export receipt is past Codex's 12,000-byte window: pages, then whole.
        first = await dispatch(
            ControlMethod.RECEIPT, ReceiptRequest, {**receipt, "request_id": fresh()}
        )
        assert first["state"] == "delivery_page"
        pages = [first]
        while pages[-1]["next_cursor"] is not None:
            pages.append(
                await dispatch(
                    ControlMethod.STATUS,
                    StatusRequest,
                    {
                        **envelope,
                        "writer_id": publish["writer_id"],
                        "request_id": fresh(),
                        "view": "compact",
                        "delivery_cursor": pages[-1]["next_cursor"],
                    },
                )
            )
        # The action page, then the rest of the receipt document; its findings section states the
        # findings_suppressed way out once (#1234), which takes the document past one more page.
        assert len(pages) == 3
        assert reassemble_delivery(pages)["format"] == "json"
    finally:
        await daemon.close()


@pytest.mark.anyio
@pytest.mark.parametrize("view", ["compact", "findings", "history"])
async def test_oversized_brief_status_pages_and_reassembles(
    view: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A brief body omits requested_frontier; paging it pins result_frontier instead."""
    import finishup.application.result_delivery as delivery_module
    import finishup.application.service as service_module
    from builders.projection_workflow import (
        ProjectionCase,
        project_case,
        request_base,
        run_projection_workflow,
    )
    from finishup.ports.control import ControlMethod

    # A small budget makes these ordinary brief bodies oversize without a long ledger.
    monkeypatch.setattr(service_module, "HOST_RESULT_BUDGET_BYTES", 4_000)
    monkeypatch.setattr(delivery_module, "HOST_RESULT_BUDGET_BYTES", 4_000)
    workflow = await run_projection_workflow()
    source = workflow.case(f"status/{view}")
    body = {**source.request_body, "detail": "brief"}
    internal = await workflow.app.status(StatusRequest.model_validate(body))
    complete = dict(
        await project_case(
            workflow.app, ProjectionCase(view, ControlMethod.STATUS, body, internal), 9300
        )
    )
    assert "requested_frontier" not in complete
    paged_case = ProjectionCase(view, ControlMethod.STATUS, {**body, "delivery": "paged"}, internal)
    pages = [dict(await project_case(workflow.app, paged_case, 9310, paginate=True))]
    assert pages[0]["state"] == "delivery_page"
    seed = 9320
    while pages[-1]["next_cursor"] is not None:
        follow = {
            **request_base(f"req_00000000-0000-4000-8000-{seed:012x}"),
            "session_id": pages[0]["session_id"],
            "writer_id": pages[0]["writer_id"],
            "view": "compact",
            "delivery_cursor": pages[-1]["next_cursor"],
        }
        read = await workflow.app.read_result_delivery(StatusRequest.model_validate(follow))
        pages.append(
            dict(
                await project_case(
                    workflow.app,
                    ProjectionCase("delivery", ControlMethod.STATUS, follow, read),
                    seed,
                    paginate=True,
                )
            )
        )
        seed += 2
    assert len(pages) > 1
    rebuilt = reassemble_delivery(pages)
    assert {k: v for k, v in rebuilt.items() if k != "privacy_projection"} == {
        k: v for k, v in complete.items() if k != "privacy_projection"
    }


@pytest.mark.anyio
async def test_terminals_bridge_reads_and_live_operation_reads_are_never_paged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only an agent's MCP check, receipt or ``delivery=paged`` status read can become pages."""
    from builders.projection_workflow import ProjectionCase, project_case, run_projection_workflow
    from finishup.application.service import ClientProjectionContext, ProjectionRenderMode
    from finishup.ports.control import ControlClientKind, ControlMethod

    workflow = await run_projection_workflow("optional", max_findings=10)
    findings = workflow.case("status/findings")
    paged_findings = ProjectionCase(
        "findings",
        ControlMethod.STATUS,
        {**findings.request_body, "delivery": "paged"},
        findings.internal,
    )
    receipt = workflow.case("receipt")
    check = workflow.case("check")
    for case in (paged_findings, receipt, check):
        # Oversize for an agent's MCP read ...
        agent = dict(await project_case(workflow.app, case, 9400, paginate=True))
        assert agent["state"] == "delivery_page", case.label
        # ... but a terminal has no host clip and no flag to continue: complete, in both modes.
        for mode in (ProjectionRenderMode.HUMAN_READABLE, ProjectionRenderMode.MACHINE_READABLE):
            context = ClientProjectionContext(
                ControlClientKind.CLI, mode, mode is ProjectionRenderMode.HUMAN_READABLE
            )
            cli = dict(await project_case(workflow.app, case, 9410, context=context, paginate=True))
            assert cli.get("state") != "delivery_page", (case.label, mode)
    # The bridge's own closure inventory and recovery reads send no delivery=paged.
    internal: dict[str, Any] = dict(await project_case(workflow.app, findings, 9420, paginate=True))
    assert "state" not in internal and internal["view"] == "findings"
    assert len(internal["page"]["items"]) == 4
    operation = workflow.case("status/operation")
    live = ProjectionCase(
        "operation",
        ControlMethod.STATUS,
        {**operation.request_body, "delivery": "paged"},
        operation.internal,
    )
    import finishup.application.service as service_module

    monkeypatch.setattr(service_module, "HOST_RESULT_BUDGET_BYTES", 1_024)
    # Its elapsed time changes on every read, so a cursor could never continue it.
    assert "state" not in dict(await project_case(workflow.app, live, 9430, paginate=True))


@pytest.mark.anyio
async def test_bridge_opts_only_the_agents_status_reads_into_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``dispatch_status`` asks for pages unless the agent names a delivery; probes never do."""
    import finishup.mcp.server as server

    sent: list[dict[str, Any]] = []

    async def capture(arguments: Any, *_args: Any, **_kwargs: Any) -> Any:
        sent.append(dict(arguments))
        return None

    monkeypatch.setattr(server, "_dispatch", capture)
    await server.dispatch_status({"view": "compact"})
    await server.dispatch_status({"view": "compact", "delivery": "complete"})
    assert [arguments["delivery"] for arguments in sent] == ["paged", "complete"]

    probes: list[StatusRequest] = []

    async def invoke(_runtime: Any, request: Any, *_args: Any, **_kwargs: Any) -> Any:
        from finishup.ports.control import ControlError

        probes.append(request)
        # Both probes treat a control failure as an unknown outcome, recording no diagnostic.
        raise ControlError("frame_invalid")

    monkeypatch.setattr(server, "_invoke_with_reconnect", invoke)
    envelope = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000071",
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "actor": {"actor_id": "test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "1", "integration": "cooperative_mcp"},
    }
    runtime = server.BRIDGE_RUNTIME
    await server._timeout_operation_state(envelope, runtime, None)  # pyright: ignore[reportPrivateUsage]
    await server._publish_recovery_from_envelope(envelope, runtime, None)  # pyright: ignore[reportPrivateUsage]
    assert len(probes) == 2
    assert all(probe.view == "operation" and probe.delivery is None for probe in probes)


@pytest.mark.anyio
@pytest.mark.parametrize("view", ["evidence", "history"])
async def test_brief_status_pages_survive_an_append_between_reads(view: str) -> None:
    """Second review of #1139: the MCP default (brief, paged) continues after the agent publishes.

    A brief body omits live fields at their defaults; an append reveals them on the pinned
    re-read. The cursor freezes their presence too, so the continuation still reassembles to
    the first read's complete body. Natural sizes on the ~1,000-event #916 ledger.
    """
    from builders.projection_workflow import frontier_json, request_base
    from builders.start_application import protocol_id
    from builders.status_render_cost import build_codex_status_ledger
    from finishup.ports.control import ControlClientKind, ControlMethod
    from finishup.protocol.models import PublishWorkRequest, public_model_to_wire
    from integration.service.test_daemon_clients import (
        _request,  # pyright: ignore[reportPrivateUsage]
    )

    ledger = await build_codex_status_ledger()
    daemon = _workflow_daemon(ledger.app)
    seed = iter(range(0x7700, 0x7800))
    held = {"session_id": ledger.started.session_id, "writer_id": ledger.started.writer_id}

    async def dispatch(method: ControlMethod, model: Any, body: Any) -> dict[str, Any]:
        result = await daemon.dispatch(
            ControlClientKind.MCP_BRIDGE, _request(daemon, method, model.model_validate(body))
        )
        assert result.outcome == "ok", result.body
        wire = cast(dict[str, Any], public_model_to_wire(result.body))
        assert wire["ok"] is True, wire.get("error")
        return wire

    def status(**fields: Any) -> dict[str, Any]:
        rid = f"req_00000000-0000-4000-8000-{next(seed):012x}"
        return {**request_base(rid), **held, **fields}

    read = {"view": view, "limit": "25", "detail": "brief"}
    await daemon.start()
    try:
        complete = await dispatch(
            ControlMethod.STATUS, StatusRequest, status(**read, delivery="complete")
        )
        pages = [
            await dispatch(ControlMethod.STATUS, StatusRequest, status(**read, delivery="paged"))
        ]
        assert pages[0]["state"] == "delivery_page" and "head_frontier" not in complete
        # The agent's own publish advances the head before it asks for the next page.
        appended = await dispatch(
            ControlMethod.PUBLISH_WORK,
            PublishWorkRequest,
            status(
                expected_frontier=frontier_json(ledger.head),
                event_drafts=[
                    {
                        "event_id": protocol_id("evt_", 77002),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-28T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "obligation_id": protocol_id("obl_", 77001),
                            "description": "Appended between page reads.",
                            "evidence_expectation": "A linked result.",
                            "requested_items": [{"item_kind": "change", "value": "x"}],
                            "status": "open",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            ),
        )
        assert int(appended["result_frontier"]["sequence"]) > ledger.head.sequence
        while pages[-1]["next_cursor"] is not None:
            pages.append(
                await dispatch(
                    ControlMethod.STATUS,
                    StatusRequest,
                    status(view="compact", delivery_cursor=pages[-1]["next_cursor"]),
                )
            )
        assert len(pages) > 1
        rebuilt = reassemble_delivery(pages)
        assert {k: v for k, v in rebuilt.items() if k != "privacy_projection"} == {
            k: v for k, v in complete.items() if k not in {"privacy_projection", "request_id"}
        } | {"request_id": rebuilt["request_id"]}
    finally:
        await daemon.close()


_LEDGER_LINE = (
    "Ledger (records, not correctness): 7 obligations (5 resolved, 2 open); latest linked run: "
    "5 success, 1 failed or partial (obl_00000000-0000-4000-8000-000000000c04), 1 stale "
    "(obl_00000000-0000-4000-8000-000000000c02); 1 requested item unattempted "
    "(obl_00000000-0000-4000-8000-000000000c02); reviewer (current check): 1 not supported, "
    "2 not assessable; advice unanswered: 2; fix-or-decline: 2; per-obligation detail: status "
    "view=obligations."
)


@pytest.mark.parametrize("host", ["codex", "claude", "cursor", "generic"])
def test_ledger_line_readiness_and_totals_lead_the_first_page(host: McpHostProfile) -> None:
    """#1139: what the agent decides on precedes reviewer prose and stays on page one."""

    source = _source()
    source["agent_status_line"] = _LEDGER_LINE
    source["closure_readiness"] = {
        "state": "action_required",
        "evidence_basis_summary": _LEDGER_LINE,
        "fact_lineage": [{"code": f"gap_{n}", "rule": "deliverable_read"} for n in range(40)],
    }
    source["totals"] = {"obligations": {"declared": "7", "resolved": "5", "open": "2"}}
    source["correctness_advisories"] = [
        {
            "advisory_id": "evt_00000000-0000-4000-8000-000000000042:1",
            "origin": "strongest_remaining_check",
            "subject_refs": ["obl_00000000-0000-4000-8000-000000000c04"],
            "summary": "Run the discriminating probe. " * 30,
        }
    ]
    source["review_summary"] = "Reviewer prose. " * 400
    pages = _pages(source)
    assert len(pages) > 1
    first = pages[0]
    paths = [str(item["path"]) for item in first["items"]]

    def at(prefix: str) -> int:
        return next(index for index, path in enumerate(paths) if path.startswith(prefix))

    assert at("/agent_next") < at("/agent_status_line") < at("/totals")
    assert at("/totals") < at("/closure_readiness") < at("/correctness_advisories")
    assert "/review_summary" not in paths or at("/totals") < at("/review_summary")
    assert "optional" not in first["required_next_step"]
    result = result_from_public_model(CheckResultModel.model_validate(first), host_profile=host)
    structured = cast(dict[str, Any], result.structuredContent)
    text = "".join(cast(Any, block).text for block in result.content)
    codex = json.dumps(structured, separators=(",", ":"), ensure_ascii=False)
    # Within Codex's 6,000-byte head (the page itself fits its 12,000-byte window) and the text.
    assert json.dumps(_LEDGER_LINE) in (_CODEX_HEADER + codex)[:6_000]
    assert _LEDGER_LINE in text
    assert reassemble_delivery(pages)["agent_status_line"] == _LEDGER_LINE


def test_decision_fields_stay_on_page_one_beside_a_maximal_readiness() -> None:
    """#1139 (PR #1216 review): 64 resolved obligations each with all three acceptance-risk
    reasons push readiness past a page; the ledger line, totals and readiness's small fields stay
    on page one, and advisory ids still arrive by ``actionable_complete``."""

    source = _source()
    source["agent_status_line"] = _LEDGER_LINE
    reasons = [
        "requested_item_never_attempted",
        "evidence_not_linked_to_declared_items",
        "evidence_self_asserted_only",
    ]
    source["closure_readiness"] = {
        "state": "ready_with_limitations",
        "evidence_basis_summary": _LEDGER_LINE,
        "open_obligation_count": "0",
        "acceptance_risk": [
            {"obligation_id": f"obl_00000000-0000-4000-8000-{n:012x}", "reasons": reasons}
            for n in range(1, 65)
        ],
        "fix_or_decline": [
            {
                "code": "requested_output_unchanged",
                "obligation_id": f"obl_00000000-0000-4000-8000-{n:012x}",
            }
            for n in range(1, 65)
        ],
    }
    assert len(canonical_encode(cast(Any, source["closure_readiness"]))) > 12_000
    groups = ("obligations", "requested_items", "commands", "findings")
    source["totals"] = {group: {"declared": "64", "open": "0"} for group in groups}
    advisory_ids = [f"evt_00000000-0000-4000-8000-000000000042:{n}" for n in range(1, 11)]
    source["correctness_advisories"] = [
        {
            "advisory_id": advisory_id,
            "origin": "verified_not_supported",
            "subject_refs": ["obl_00000000-0000-4000-8000-000000000005"],
            "summary": "Run the discriminating probe. " * 6,
        }
        for advisory_id in advisory_ids
    ]
    pages = _pages(source)
    first = [str(item["path"]) for item in pages[0]["items"]]
    for path in (
        "/agent_status_line",
        "/totals",
        "/closure_readiness",
        "/closure_readiness/state",
        "/closure_readiness/evidence_basis_summary",
        "/closure_readiness/open_obligation_count",
    ):
        assert path in first, path
    assert first.index("/totals") < first.index("/closure_readiness")
    last_actionable = next(index for index, page in enumerate(pages) if page["actionable_complete"])
    assert last_actionable > 0  # the readiness list really spans pages
    actionable = canonical_encode(
        cast(Any, [item for page in pages[: last_actionable + 1] for item in page["items"]])
    )
    for advisory_id in advisory_ids:
        assert advisory_id.encode() in actionable
    rebuilt = reassemble_delivery(pages)
    assert rebuilt["closure_readiness"] == source["closure_readiness"]
    assert rebuilt["totals"] == source["totals"]


# -- #1234: the findings_suppressed re-run hint on every check-result surface ----------------


@pytest.mark.anyio
@pytest.mark.parametrize("suppressed", [0, 8])
async def test_a_suppressing_check_result_leads_with_the_findings_suppressed_hint(
    suppressed: int,
) -> None:
    """rv16 sol/terra closing check: ``suppressed_count`` 8 and no way out in ``agent_next``."""

    from dataclasses import replace

    from builders.projection_workflow import run_projection_workflow
    from finishup.application.check import check_internal_json
    from finishup.domain.review_input_render import MAX_AGENT_NEXT_BYTES
    from finishup.ports.ledger import CheckCommitResult
    from finishup.protocol.readiness_text import FINDINGS_SUPPRESSED_NEXT_STEP

    workflow = await run_projection_workflow("disabled")
    internal = workflow.case("check").internal
    assert isinstance(internal, CheckCommitResult) and internal.overall_next is not None
    wire = check_internal_json(replace(internal, suppressed_count=suppressed))
    lead = cast(str, wire["agent_next"])
    assert len(lead.encode("ascii")) <= MAX_AGENT_NEXT_BYTES
    # Once per result, in the bounded lead every host reads first.
    escaped = json.dumps(FINDINGS_SUPPRESSED_NEXT_STEP)[1:-1]  # the hint quotes "10"
    assert canonical_encode(cast(Any, wire)).decode().count(escaped) == (1 if suppressed else 0)
    assert (FINDINGS_SUPPRESSED_NEXT_STEP in lead) is bool(suppressed)


def _suppressing_check_wire(suppressed: int) -> dict[str, Any]:
    from tests.unit.protocol.test_models_and_schemas import (
        _check_result_wire,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.domain.review_input_render import render_agent_next

    wire = cast(dict[str, Any], _check_result_wire())
    wire["suppressed_count"] = str(suppressed)
    wire["agent_next"] = render_agent_next(
        {"action": "review_recorded_work", "status": "action_required", "target_refs": []},
        (),
        findings_suppressed=suppressed > 0,
    )
    return wire


@pytest.mark.parametrize("suppressed", [0, 8])
def test_claude_check_text_carries_the_findings_suppressed_hint(suppressed: int) -> None:
    from finishup.protocol.readiness_text import FINDINGS_SUPPRESSED_NEXT_STEP

    wire = _suppressing_check_wire(suppressed)
    result = result_from_public_model(CheckResultModel.model_validate(wire), host_profile="claude")
    text = "".join(cast(Any, block).text for block in result.content)
    # Once in the bounded prose summary, once in the complete JSON copy's ``agent_next``.
    assert text.count(FINDINGS_SUPPRESSED_NEXT_STEP) == (1 if suppressed else 0)
    assert text.count(json.dumps(FINDINGS_SUPPRESSED_NEXT_STEP)[1:-1]) == (1 if suppressed else 0)
    assert mcp_delivery_bytes(wire, text=text) <= HOST_RESULT_BUDGET_BYTES


@pytest.mark.parametrize("suppressed", [0, 8])
def test_codex_and_cursor_check_results_carry_the_hint_in_canonical_order(
    suppressed: int,
) -> None:
    from finishup.protocol.readiness_text import FINDINGS_SUPPRESSED_NEXT_STEP

    wire = _suppressing_check_wire(suppressed)
    model = CheckResultModel.model_validate(wire)
    codex = result_from_public_model(model, host_profile="codex")
    structured = cast(dict[str, Any], codex.structuredContent)
    assert (FINDINGS_SUPPRESSED_NEXT_STEP in structured["agent_next"]) is bool(suppressed)
    cursor = result_from_public_model(model, host_profile="cursor")
    text = "".join(cast(Any, block).text for block in cursor.content)
    # Cursor reads an exact canonical (sorted-key) copy; the hint adds no field and no reorder.
    assert text == canonical_encode(cast(Any, cursor.structuredContent)).decode()
    assert list(json.loads(text)) == sorted(json.loads(text), key=str.encode)
    escaped = json.dumps(FINDINGS_SUPPRESSED_NEXT_STEP)[1:-1]  # the hint quotes "10"
    assert text.count(escaped) == (1 if suppressed else 0)


# ------------------------------------------------------------------------------------------------
# #1244 (D12): short handles over a kept page set; continuations survive appends and restarts.
# ------------------------------------------------------------------------------------------------


class _Agent:
    """An agent's MCP calls through the daemon over the ~1,000-event #916 ledger."""

    def __init__(self, ledger: Any) -> None:
        from builders.projection_workflow import request_base

        self.ledger = ledger
        self.daemon = _workflow_daemon(ledger.app)
        self.head = ledger.head
        self._seed = iter(range(0x9900, 0xA000))
        self._base = request_base
        self.held = {"session_id": ledger.started.session_id, "writer_id": ledger.started.writer_id}

    def body(self, **fields: Any) -> dict[str, Any]:
        rid = f"req_00000000-0000-4000-8000-{next(self._seed):012x}"
        return {**self._base(rid), **self.held, **fields}

    async def call(self, method: Any, model: Any, body: Any) -> dict[str, Any]:
        from finishup.ports.control import ControlClientKind
        from finishup.protocol.models import public_model_to_wire
        from integration.service.test_daemon_clients import (
            _request,  # pyright: ignore[reportPrivateUsage]
        )

        result = await self.daemon.dispatch(
            ControlClientKind.MCP_BRIDGE, _request(self.daemon, method, model.model_validate(body))
        )
        assert result.outcome == "ok", result.body
        return cast(dict[str, Any], public_model_to_wire(result.body))

    async def refusal(self, cursor: str) -> str:
        """The reason code a refused continuation names."""
        from finishup.ports.control import ControlClientKind, ControlMethod
        from integration.service.test_daemon_clients import (
            _request,  # pyright: ignore[reportPrivateUsage]
        )

        body = self.body(view="compact", delivery_cursor=cursor)
        result = await self.daemon.dispatch(
            ControlClientKind.MCP_BRIDGE,
            _request(self.daemon, ControlMethod.STATUS, StatusRequest.model_validate(body)),
        )
        if result.outcome == "error":
            return cast(str, getattr(result.body, "reason", ""))
        error = cast(
            dict[str, Any], getattr(result.body, "root", result.body).model_dump(mode="json")
        )
        assert error["ok"] is False
        return cast(str, error["error"]["safe_details"]["reason_code"])

    async def check(self) -> dict[str, Any]:
        from builders.projection_workflow import frontier_json
        from finishup.domain.values import Frontier
        from finishup.ports.control import ControlMethod
        from finishup.protocol.models import CheckRequest

        wire = await self.call(
            ControlMethod.CHECK,
            CheckRequest,
            self.body(
                expected_frontier=frontier_json(self.head),
                mode="deterministic_only",
                max_findings="10",
            ),
        )
        frontier = wire["result_frontier"]
        self.head = Frontier(int(frontier["sequence"]), frontier["head_digest"])
        return wire

    async def publish_action(self, number: int) -> None:
        from builders.projection_workflow import frontier_json
        from builders.start_application import protocol_id
        from finishup.domain.values import Frontier
        from finishup.ports.control import ControlMethod
        from finishup.protocol.models import PublishWorkRequest

        wire = await self.call(
            ControlMethod.PUBLISH_WORK,
            PublishWorkRequest,
            self.body(
                expected_frontier=frontier_json(self.head),
                event_drafts=[
                    {
                        "event_id": protocol_id("evt_", 0x99000 + number),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-28T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": protocol_id("act_", 0x99800 + number),
                            "action_kind": "review",
                            "description": f"Paging between appends {number}.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            ),
        )
        frontier = wire["result_frontier"]
        self.head = Frontier(int(frontier["sequence"]), frontier["head_digest"])

    async def status(self, **fields: Any) -> dict[str, Any]:
        from finishup.ports.control import ControlMethod

        return await self.call(ControlMethod.STATUS, StatusRequest, self.body(**fields))

    async def follow(self, pages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        while pages[-1]["next_cursor"] is not None:
            page = await self.status(view="compact", delivery_cursor=pages[-1]["next_cursor"])
            assert page.get("ok") is True, page.get("error")
            if page.get("page_set_restarted") is True:
                pages = []
            pages.append(page)
        return pages


@pytest.mark.anyio
async def test_check_pages_continue_after_forty_appends_and_lead_with_a_short_handle() -> None:
    """TB4 biped a4: a check's fourth page was refused once 16 appends had landed (#1244).

    The replayed check view read only the adapter's 16-entry trusted history, dropped its
    checklist, and its digest changed. It now replays that prefix, and the kept page set serves
    the same copy; every handle is short and leads its page.
    """
    from builders.status_render_cost import build_codex_status_ledger

    agent = _Agent(await build_codex_status_ledger())
    await agent.daemon.start()
    try:
        first = await agent.check()
        assert first["state"] == "delivery_page"
        assert next(iter(first)) == "next_cursor"
        assert len(first["next_cursor"]) <= 64
        pages = [first]
        page = await agent.status(view="compact", delivery_cursor=first["next_cursor"])
        pages.append(page)
        for number in range(40):
            await agent.publish_action(number)
        pages = await agent.follow(pages)
        assert all(len(p["next_cursor"] or "") <= 64 for p in pages)
        assert {p["source_digest"] for p in pages} == {first["source_digest"]}
        rebuilt = reassemble_delivery(pages)
        assert rebuilt["finding_checklist"] and rebuilt["closure_readiness"]
        # A miss (as after a service restart) rebuilds the recorded check from the ledger. Its
        # prefix has since gained the agent's own records, which a pinned case may not absorb,
        # so the rebuilt set differs: it says so and starts again at offset 0, never a refusal.
        agent.ledger.app.delivery_pages.clear()
        again = await agent.status(view="compact", delivery_cursor=first["next_cursor"])
        assert again["page_set_restarted"] is True and again["offset"] == 0
        assert int(again["ledger_moved_since"]["sequence"]) == agent.head.sequence
        assert reassemble_delivery(await agent.follow([again]))["verdict"] == rebuilt["verdict"]
    finally:
        await agent.daemon.close()


@pytest.mark.anyio
async def test_a_restarted_service_rebuilds_a_check_page_set_past_sixteen_hook_batches() -> None:
    """A miss past the 16-entry trusted history replays the prefix and continues in place."""
    from builders.status_render_cost import (
        _append_hook_calls,  # pyright: ignore[reportPrivateUsage]
        build_codex_status_ledger,
    )
    from finishup.domain.values import Frontier

    agent = _Agent(await build_codex_status_ledger())
    await agent.daemon.start()
    try:
        first = await agent.check()
        ledger, objects = next(iter(agent.ledger.app.runtime.resources.values()))
        for call in range(20):
            frontier = await _append_hook_calls(
                ledger,
                objects,
                agent.ledger.started,
                agent.head,
                range(2_000 + call, 2_001 + call),
                now=agent.ledger.app.clock.now_utc(),
                request_seed=0x9A000 + call,
            )
            agent.head = Frontier(frontier.sequence, frontier.head_digest)
        agent.ledger.app.delivery_pages.clear()
        again = await agent.status(view="compact", delivery_cursor=first["next_cursor"])
        assert "page_set_restarted" not in again
        assert again["offset"] == len(first["items"])
        assert again["source_digest"] == first["source_digest"]
        rebuilt = reassemble_delivery(await agent.follow([first, again]))
        assert rebuilt["finding_checklist"] and rebuilt["closure_readiness"]
    finally:
        await agent.daemon.close()


@pytest.mark.anyio
async def test_status_pages_continue_after_the_agents_publish_with_frozen_live_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TB4 freecad a3: a status page was refused after the agent's own publish (#1244).

    ``check_in_flight`` (and ``leaf_authorship``) were read live on the first page and differ
    on the pinned re-read. The kept copy freezes them; the moved ledger is named, not refused.
    """
    import finishup.application.status as status_module
    from builders.status_render_cost import build_codex_status_ledger

    agent = _Agent(await build_codex_status_ledger())
    in_flight = {"value": True}

    async def check_in_flight(runtime: Any) -> bool:
        del runtime
        return in_flight["value"]

    monkeypatch.setattr(status_module, "_check_in_flight", check_in_flight)
    await agent.daemon.start()
    try:
        # The brief compact page now fits one reply (D13); the full one still pages.
        complete = await agent.status(view="compact", detail="full", delivery="complete")
        first = await agent.status(view="compact", detail="full", delivery="paged")
        assert first["state"] == "delivery_page"
        in_flight["value"] = False
        await agent.publish_action(1)
        pages = await agent.follow([first])
        assert len(pages) > 1 and pages[0] is first
        assert all(p["source_digest"] == first["source_digest"] for p in pages)
        moved = [p for p in pages[1:] if "ledger_moved_since" in p]
        assert moved and all(
            int(p["ledger_moved_since"]["sequence"]) == agent.head.sequence for p in moved
        )
        rebuilt = reassemble_delivery(pages)
        assert {
            k: v for k, v in rebuilt.items() if k not in {"privacy_projection", "request_id"}
        } == {k: v for k, v in complete.items() if k not in {"privacy_projection", "request_id"}}
        # After a restart the pinned read is rebuilt from the ledger; its content differs from
        # the first read (the check is no longer in flight), so the set starts again at 0.
        agent.ledger.app.delivery_pages.clear()
        restarted = await agent.status(view="compact", delivery_cursor=first["next_cursor"])
        assert restarted["page_set_restarted"] is True and restarted["offset"] == 0
        assert restarted["source_digest"] != first["source_digest"]
        assert reassemble_delivery(await agent.follow([restarted]))
    finally:
        await agent.daemon.close()


@pytest.mark.anyio
async def test_only_a_redaction_or_a_disclosure_change_refuses_a_continuation() -> None:
    """D12: the content refusal is kept for real redaction or disclosure changes and named."""
    from builders.start_application import protocol_id
    from builders.status_render_cost import build_codex_status_ledger
    from finishup.application.result_delivery import DeliveryPageSet

    agent = _Agent(await build_codex_status_ledger())
    await agent.daemon.start()
    try:
        first = await agent.check()
        handle = cast(str, first["next_cursor"])
        store = agent.ledger.app.delivery_pages
        key = handle.split(".")[0] + "." + handle.split(".")[1]
        kept = store.get(key, agent.held["session_id"], agent.held["writer_id"])
        assert kept is not None
        projection = dict(kept.source["privacy_projection"])
        projection["policy_version"] = str(int(projection["policy_version"]) + 1)
        changed = DeliveryPageSet(
            kept.session_id,
            kept.writer_id,
            kept.sink,
            kept.method,
            kept.selector,
            {**kept.source, "privacy_projection": projection},
            kept.digest,
            kept.selector_code,
            kept.size,
        )
        store.put(key, changed)
        assert await agent.refusal(handle) == "delivery_disclosure_changed"
        store.put(key, kept)
        assert (await agent.status(view="compact", delivery_cursor=handle))["ok"] is True
        await agent.publish_action(7)
        await _record_redaction(agent, protocol_id("evt_", 0x99000 + 7))
        assert await agent.refusal(handle) == "delivery_redaction_recorded"
        for bad in (handle + "x", "c" + handle[1:].replace(".", "_", 1), "nonsense"):
            assert await agent.refusal(bad) == "delivery_cursor_invalid"
    finally:
        await agent.daemon.close()


@pytest.mark.anyio
async def test_a_mistyped_status_handle_is_invalid_not_a_retryable_read_failure() -> None:
    """A status handle that names no valid request id or limit is ``delivery_cursor_invalid``.

    A miss rebuilds the status read from the handle alone. A typo that decodes to a non-v4 id,
    or a limit outside 1..100, used to fail that rebuild's request validation and come back as a
    retryable ``read_projection_failed``, so the agent retried the same handle.
    """
    import base64
    import uuid

    from builders.status_render_cost import build_codex_status_ledger

    agent = _Agent(await build_codex_status_ledger())
    await agent.daemon.start()
    try:
        complete = await agent.status(view="compact", detail="full", delivery="complete")
        frontier = complete["result_frontier"]["sequence"]
        raw = bytearray(uuid.UUID(complete["request_id"][4:]).bytes)
        valid = base64.urlsafe_b64encode(bytes(raw)).decode("ascii").rstrip("=")
        raw[6] = (raw[6] & 0x0F) | 0x10  # a version 1 UUID: no request id has one
        non_v4 = base64.urlsafe_b64encode(bytes(raw)).decode("ascii").rstrip("=")
        # Sealed with a valid check, so the rebuild itself (not the check) refuses them.
        for body in (
            f"s{non_v4}.{frontier}.1.0123abcd.cf20",
            f"s{valid}.{frontier}.1.0123abcd.cf200",
        ):
            assert await agent.refusal(f"{body}.{handle_check(body)}") == (
                "delivery_cursor_invalid"
            )
    finally:
        await agent.daemon.close()


@pytest.mark.anyio
async def test_an_edited_handle_is_refused_by_the_service_and_the_exact_one_still_serves() -> None:
    """#1244: offset, frontier and digest edits are refused whether the set is kept or rebuilt."""
    from builders.status_render_cost import build_codex_status_ledger

    agent = _Agent(await build_codex_status_ledger())
    await agent.daemon.start()
    try:
        first = await agent.check()
        handle = cast(str, first["next_cursor"])
        edits = _edits(handle)
        for kept in (True, False):
            if not kept:
                agent.ledger.app.delivery_pages.clear()  # as after a service restart
            for name in ("offset", "frontier", "digest"):
                assert await agent.refusal(edits[name]) == "delivery_cursor_invalid", name
        page = await agent.status(view="compact", delivery_cursor=handle)
        assert page["ok"] is True and "page_set_restarted" not in page
        assert page["offset"] == len(first["items"])
    finally:
        await agent.daemon.close()


async def _record_redaction(agent: _Agent, target: str) -> None:
    """Append one locally authenticated ``redaction_recorded`` after the page set's frontier."""
    from builders.start_application import protocol_id
    from finishup.domain.events import (
        EventDraft,
        EventSchema,
        RedactionMethod,
        RedactionReasonCategory,
        RedactionRecordedPayload,
        encode_payload,
        media_type_for,
    )
    from finishup.domain.values import (
        Actor,
        ActorType,
        Frontier,
        actor_id,
        event_id,
        timestamp_from_datetime,
    )
    from finishup.ports.ledger import AppendCommand, AppendEntry, OperationKind
    from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
    from finishup.protocol.coverage import (
        AuthorshipAssurance,
        PublicationChannel,
        coverage_for_channel,
    )

    app = agent.ledger.app
    started = agent.ledger.started
    ledger, objects = next(iter(app.runtime.resources.values()))
    now = app.clock.now_utc()
    payload = RedactionRecordedPayload(
        (event_id(target),),
        (),
        RedactionMethod.LOGICAL_REDACTION,
        RedactionReasonCategory.OTHER,
        actor_id("human.test.local"),
        "A test redaction after the delivered page set.",
    )
    encoded = canonical_encode(encode_payload(payload))
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD, media_type_for("redaction_recorded"), started.task_id, now
    )
    staged = await objects.stage(ObjectSource(data=encoded, declared_size=len(encoded)), metadata)
    ref = await objects.finalize(staged)
    channel = PublicationChannel.LOCAL_CLI
    result = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", 0x99FF1),
            OperationKind.PUBLISH_WORK,
            "sha256:" + "7" * 64,
            agent.head.sequence,
            (
                AppendEntry(
                    EventDraft(
                        event_id(protocol_id("evt_", 0x99FF2)),
                        EventSchema("redaction_recorded", "1.0.0"),
                        timestamp_from_datetime(now),
                        (),
                        payload,
                        (),
                        (),
                    ),
                    Actor(
                        actor_id("human.test.local"),
                        ActorType.HUMAN,
                        AuthorshipAssurance.LOCALLY_AUTHENTICATED,
                    ),
                    ref,
                    ref.commitment,
                    metadata.media_type,
                    ref.plaintext_size,
                    channel,
                    coverage_for_channel(channel),
                    "projected",
                ),
            ),
            None,
        )
    )
    agent.head = Frontier(result.result_frontier.sequence, result.result_frontier.head_digest)


@pytest.mark.anyio
async def test_the_mcp_check_tool_asks_for_a_brief_reply_unless_the_agent_names_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1244 (D13): like status (#1084), the agent's check reply is brief by default."""
    import finishup.mcp.server as server

    sent: list[dict[str, Any]] = []

    async def capture(arguments: Any, *_args: Any, **_kwargs: Any) -> Any:
        sent.append(dict(arguments))
        return None

    monkeypatch.setattr(server, "_dispatch", capture)
    await server.dispatch_check({"mode": "deterministic_only"})
    await server.dispatch_check({"mode": "deterministic_only", "detail": "full"})
    await server.dispatch_check({"mode": "inspect"})
    assert [arguments.get("detail") for arguments in sent] == ["brief", "full", None]


def test_a_brief_check_names_each_finding_and_carries_the_brief_readiness_subset() -> None:
    from finishup.application.result_delivery import brief_check_body
    from finishup.protocol.models import CHECK_BRIEF_FINDING_KEYS

    findings: list[dict[str, Any]] = [
        {
            "finding_id": f"fnd_00000000-0000-4000-8000-{i:012x}",
            "kind": "completion_with_open_obligations",
            "origin": "deterministic",
            "priority": 1,
            "summary": "A completion claim names an open obligation.",
            "detail": "Repair it. " * 200,
            "subject_refs": ["obl_00000000-0000-4000-8000-000000000009"],
            "policy_id": "work-integrity",
            "policy_version": "0.3.0",
            "subject_frontier": {"sequence": "42", "head_digest": "sha256:" + "a" * 64},
            "coverage": {"known_gaps": []},
            "provenance": None,
        }
        for i in range(1, 11)
    ]
    readiness = {
        "state": "action_required",
        "blocking_conditions": ["findings_unanswered"],
        "agent_actionable": ["findings_unanswered"],
        "limitation_refs_required": [f"res_{i}" for i in range(40)],
    }
    source: dict[str, Any] = {
        "state": "complete",
        "findings": findings,
        "closure_readiness": readiness,
    }
    brief = brief_check_body(source)
    assert brief["detail"] == "brief" and "closure_readiness" not in brief
    assert brief["closure_state"] == {
        "state": "action_required",
        "blocking_conditions": ["findings_unanswered"],
        "agent_actionable": ["findings_unanswered"],
    }
    rows = cast(list[dict[str, Any]], brief["findings"])
    assert all(set(row) <= set(CHECK_BRIEF_FINDING_KEYS) for row in rows)
    assert [row["finding_id"] for row in rows] == [row["finding_id"] for row in findings]
    assert len(canonical_encode(brief)) < len(canonical_encode(source)) // 4
    # Only omission: the source is unchanged and full rows stay full.
    assert cast(str, findings[0]["detail"]).startswith("Repair it.")


def test_a_brief_compact_page_names_unanswered_findings_without_their_detail() -> None:
    from finishup.application.status import (
        _brief_compact_page,  # pyright: ignore[reportPrivateUsage]
    )

    page: dict[str, Any] = {
        "items": [
            {
                "task_id": "tsk_00000000-0000-4000-8000-000000000004",
                "unanswered_findings": [
                    {
                        "finding_id": "fnd_00000000-0000-4000-8000-000000000001",
                        "kind": "failed_work_omitted",
                        "priority": 1,
                        "summary": "Recorded failed work is omitted.",
                        "detail": "Disclose it. " * 100,
                    }
                ],
            }
        ],
        "next_cursor": None,
    }
    brief = _brief_compact_page(page)
    (row,) = cast(list[Any], cast(list[Any], brief["items"])[0]["unanswered_findings"])
    assert row == {
        "finding_id": "fnd_00000000-0000-4000-8000-000000000001",
        "kind": "failed_work_omitted",
        "priority": 1,
        "summary": "Recorded failed work is omitted.",
    }
    assert "detail" in page["items"][0]["unanswered_findings"][0]
