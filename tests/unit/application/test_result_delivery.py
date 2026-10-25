"""#1139: the native MCP result fits, and continuation loses no actionable field."""

from __future__ import annotations

import copy
from typing import Any, Literal, cast

import pytest

from finishup.application.result_delivery import (
    HOST_RESULT_BUDGET_BYTES,
    decode_cursor,
    delivery_items,
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

_KEY = b"delivery-test-key" * 2
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
    digest = None
    while True:
        page: dict[str, Any] = page_result(
            source,
            key=_KEY,
            method="check",
            selector={"request_id": source["request_id"]},
            writer_id=_WRITER,
            sink="agent_context",
            position=position,
            expected_digest=digest,
        )
        pages.append(page)
        if page["complete"]:
            assert page["next_cursor"] is None
            return pages
        cursor = decode_cursor(_KEY, page["next_cursor"], _SESSION, _WRITER)
        assert cursor["position"] > position
        position, digest = cursor["position"], cursor["digest"]


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


def test_cursor_rejects_tamper_other_writer_and_changed_authorized_content(
    many_pages: list[dict[str, Any]],
) -> None:
    source = _source()
    first = many_pages[0]
    cursor = first["next_cursor"]
    with pytest.raises(PublicOperationError):
        decode_cursor(_KEY, cursor, _SESSION, _WRITER[:-1] + "3")
    # The session is bound by the signature only, not carried in the cursor body.
    with pytest.raises(PublicOperationError):
        decode_cursor(_KEY, cursor, _SESSION[:-1] + "9", _WRITER)
    assert decode_cursor(_KEY, cursor, _SESSION, _WRITER)["session_id"] == _SESSION
    with pytest.raises(PublicOperationError):
        decode_cursor(_KEY, cursor[:-2] + "AB", _SESSION, _WRITER)
    changed = copy.deepcopy(source)
    changed["review_summary"] = {"omitted": True, "reason": "withheld_by_policy"}
    with pytest.raises(PublicOperationError):
        page_result(
            changed,
            key=_KEY,
            method="check",
            selector={},
            writer_id=_WRITER,
            sink="agent_context",
            position=1,
            expected_digest=first["source_digest"],
        )


def test_status_continuation_freezes_watermarks_and_preserves_inventory_cursor() -> None:
    source = _source()
    source.update(
        view="findings",
        head_frontier=source["result_frontier"],
        projection_lag="0",
        import_status={"active_count": "1", "terminal_count": "0"},
        page={"items": source.pop("findings"), "next_cursor": "original-inventory-cursor"},
    )
    selector: dict[str, Any] = {
        "view": "findings",
        "limit": "20",
        "detail": "full",
        "at_frontier": "42",
    }
    first = page_result(
        source,
        key=_KEY,
        method="status",
        selector=selector,
        writer_id=_WRITER,
        sink="agent_context",
    )
    inventory = first["inventory_read"]
    assert isinstance(inventory, dict)
    assert inventory == {**selector, "cursor": "original-inventory-cursor"}
    cursor = decode_cursor(_KEY, cast(str, first["next_cursor"]), _SESSION, _WRITER)
    source["head_frontier"] = {"sequence": "99", "head_digest": "sha256:" + "b" * 64}
    source["projection_lag"] = "57"
    # Live fields a later read sees change: an import job finishing must not refuse the cursor.
    source["import_status"] = {"active_count": "0", "terminal_count": "1"}
    continued = page_result(
        source,
        key=_KEY,
        method="status",
        selector=cursor["selector"],
        writer_id=_WRITER,
        sink="agent_context",
        position=cursor["position"],
        expected_digest=cursor["digest"],
    )
    assert continued["source_digest"] == first["source_digest"]
    assert continued["inventory_read"] == inventory
    with pytest.raises(PublicOperationError):
        decode_cursor(
            b"another-service-generation-key-32", cast(str, first["next_cursor"]), _SESSION, _WRITER
        )


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
                key=_KEY,
                method="status",
                selector=selector,
                writer_id=_WRITER,
                sink="agent_context",
                position=position,
            ),
        )
        assert mcp_delivery_bytes(page) <= HOST_RESULT_BUDGET_BYTES
        pages.append(page)
        if page["complete"]:
            break
        cursor = decode_cursor(_KEY, page["next_cursor"], _SESSION, _WRITER)
        selector, position = cursor["selector"], cursor["position"]
    assert reassemble_delivery(pages) == source


def test_each_page_carries_its_own_read_disclosure_and_never_pages_it() -> None:
    """A projection too large for one atom is never split across reads with different receipts."""
    source = _source()
    omitted = tuple(f"/findings/{i}/provenance/refs/{j}" for i in range(20) for j in range(20))
    pages: list[dict[str, Any]] = []
    position, digest = 0, None
    while True:
        # Every continuation reapplies disclosure: a fresh receipt and commitment per read.
        source["privacy_projection"] = _projection(len(pages) + 1, omitted)
        page: dict[str, Any] = page_result(
            source,
            key=_KEY,
            method="check",
            selector={"request_id": source["request_id"]},
            writer_id=_WRITER,
            sink="agent_context",
            position=position,
            expected_digest=digest,
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
        cursor = decode_cursor(_KEY, page["next_cursor"], _SESSION, _WRITER)
        position, digest = cursor["position"], cursor["digest"]
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
    # Each read is its own disclosure; the reconstruction carries the final read's receipt.
    receipts = {page["privacy_projection"]["local_disclosure_receipt_id"] for page in pages}
    assert len(receipts) == len(pages)
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
        key=b"fixture-delivery-key-not-a-secret",
        method="check",
        selector={"request_id": vector["source"]["request_id"]},
        writer_id="wri_00000000-0000-4000-8000-000000000004",
        sink="agent_context",
    )
    page["next_cursor"] = vector["cursor_normalization"]
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
        assert len(pages) == 2  # the action page, then the rest of the receipt document
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
