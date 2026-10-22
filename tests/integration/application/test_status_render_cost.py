"""Status render-cost harness, pre-change golden, and CI regression bounds for issue #916.

The DeepSWE v2 run measured a 100-row ``status view=evidence`` page at ~2.1 s even on a cached
cursor page (~0.5 s fixed plus ~18 ms per returned row), and ``closure-prepare`` at 16-55 s. The
harness renders pages of a synthetic ~1,000-event Codex-shaped ledger
(``builders.status_render_cost``) through the exact path one MCP ``status`` response takes:

1. ``status`` itself (the cached projection query and the page-model validation);
2. the daemon's post-commit privacy projection (``project_result_for_client``: leaf walk and
   classification, the never-send scan, the audit encodings, the local-disclosure receipt write
   into the SQLite privacy catalog, and the public result model);
3. the control envelope: the daemon's success-body check, frame encode, client decode and parse;
4. the MCP bridge: wire dump, result-model revalidation and the tool result rendering.

``test_status_render_matches_pre_change_golden`` pins every rendered byte and every durable
receipt to ``tests/fixtures/status-render-cost/golden.json``, which was generated from the code
*before* the #916 optimizations. The optimizations change cost only: projected pages, MCP text,
receipts, audit subjects (field decisions and commitments) and the ``closure-prepare`` inventory
must stay byte-identical. Regenerate it only for an intended output change, from the owning
change, with::

    FINISHUP_STATUS_RENDER_GOLDEN=write uv run pytest \
        tests/integration/application/test_status_render_cost.py -k golden

The cost tests never compare wall-clock time with a fixed threshold. They count work that is
deterministic on any runner, and compare timings only as ratios against a baseline measured in
the same run, with generous bounds, so a slow or loaded CI runner cannot flip them. Run them with
``-s`` to print the stage profile.
"""

from __future__ import annotations

import cProfile
import hashlib
import json
import os
import pstats
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Final, Protocol, cast

import pytest
from mcp import types

from builders.start_application import protocol_id
from builders.status_render_cost import (
    CLOSURE_VIEWS,
    CodexStatusLedger,
    build_codex_status_ledger,
)
from finishup.cli.closure import Selection, prepare_closure
from finishup.mcp.server import result_from_public_model
from finishup.ports.control import ControlMethod, ControlResult
from finishup.protocol import models as models_module
from finishup.protocol import schemas as schemas_module
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import StatusRequest, StatusResult, public_model_to_wire
from finishup.service.control_protocol import (
    decode_control_frame,
    encode_control_frame,
    parse_control_result,
    validate_result,
)

pytestmark = pytest.mark.anyio


class _CacheInfo(Protocol):
    def cache_info(self) -> _CacheStats: ...


class _CacheStats(Protocol):
    @property
    def misses(self) -> int: ...


_GOLDEN: Final = Path(__file__).parents[2] / "fixtures" / "status-render-cost" / "golden.json"
_GOLDEN_SCHEMA: Final = "yoetz.test.status-render-golden/1"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _Processes:
    """Model the service and the MCP bridge (or CLI) as the two processes they are.

    Each process owns its schema verdict memory; sharing one in-process memory between the
    service and client halves would make the harness optimistic. Harmless before #916, when there
    was no memory to model.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        checker_type = getattr(schemas_module, "_ValidityChecker", None)
        self._checkers: dict[str, object] = {}
        self.current = "service"
        if checker_type is None:
            return
        state = schemas_module._load_catalog_state()  # pyright: ignore[reportPrivateUsage]
        build = cast(Callable[[object], object], getattr(checker_type, "build"))
        self._checkers = {"service": build(state), "client": build(state)}
        monkeypatch.setattr(
            schemas_module, "_validity_checker", lambda: self._checkers[self.current]
        )

    def enter(self, process: str) -> None:
        self.current = process


def _service_frame(model: StatusResult, seed: int) -> bytes:
    """The daemon's success-body check and the frame it writes to the control socket."""

    result = ControlResult(
        protocol_version="1.0",
        rpc_id=protocol_id("rpc_", seed),
        service_instance_id=protocol_id("svc_", seed + 1),
        service_generation="1",
        method=ControlMethod.STATUS,
        outcome="ok",
        body=model,
    )
    validate_result(result)
    return encode_control_frame(result)


def _client_parse(frame: bytes) -> StatusResult:
    """The client's frame decode and typed parse."""

    body = parse_control_result(decode_control_frame(frame)).body
    assert type(body) is StatusResult
    return body


def _bridge(model: StatusResult) -> tuple[dict[str, JsonValue], types.CallToolResult]:
    """What the MCP bridge does with a parsed status result before returning it to the host."""

    wire = public_model_to_wire(model)
    validated = StatusResult.model_validate(wire)
    return wire, result_from_public_model(validated, host_profile="codex")


async def _mcp_page(
    ledger: CodexStatusLedger,
    view: str,
    seed: int,
    cursor: str | None = None,
    processes: _Processes | None = None,
) -> tuple[dict[str, JsonValue], types.CallToolResult]:
    if processes is not None:
        processes.enter("service")
    model = await ledger.project_status(ledger.status_body(view, seed, cursor=cursor), seed + 1)
    frame = _service_frame(model, seed + 3)
    if processes is not None:
        processes.enter("client")
    return _bridge(_client_parse(frame))


def _omission_reasons(wire: dict[str, JsonValue]) -> tuple[tuple[str, str], ...]:
    """(pointer, reason) for every omitted pointer the projection names."""

    projection = cast(dict[str, JsonValue], wire["privacy_projection"])
    reasons: list[tuple[str, str]] = []
    for pointer in cast(list[str], projection["omitted_pointers"]):
        value: JsonValue = wire
        for segment in pointer.removeprefix("/").split("/"):
            if isinstance(value, list):
                value = cast(list[JsonValue], value)[int(segment)]
            else:
                assert isinstance(value, dict)
                value = value[segment]
        assert isinstance(value, dict)
        marker = value
        assert marker["omitted"] is True
        reasons.append((pointer, cast(str, marker["reason"])))
    return tuple(reasons)


def _closure_status(
    ledger: CodexStatusLedger, first_seed: int, processes: _Processes | None = None
) -> tuple[Callable[[StatusRequest], Awaitable[StatusResult]], list[str]]:
    """The CLI's ``client.status``: service projection, control frame, client parse.

    Returns the callable and the list of views it was asked for, in call order.
    """

    calls: list[str] = []

    async def status(request: StatusRequest) -> StatusResult:
        calls.append(request.view)
        seed = first_seed + len(calls) * 10
        if processes is not None:
            processes.enter("service")
        model = await ledger.project_status(public_model_to_wire(request), seed)
        frame = _service_frame(model, seed + 3)
        if processes is not None:
            processes.enter("client")
        return _client_parse(frame)

    return status, calls


async def _golden_record(ledger: CodexStatusLedger) -> dict[str, JsonValue]:
    pages: dict[str, JsonValue] = {}
    reasons: Counter[str] = Counter()
    never_send: list[str] = []
    seed = 700_000
    for view in ("compact", *CLOSURE_VIEWS):
        cursor: str | None = None
        index = 0
        while True:
            seed += 10
            wire, tool = await _mcp_page(ledger, view, seed, cursor)
            label = f"{view}/{index}"
            text = cast(types.TextContent, tool.content[0]).text
            pages[label] = {
                "rows": len(
                    cast(list[JsonValue], cast(dict[str, JsonValue], wire["page"])["items"])
                )
                if view != "compact"
                else None,
                "wire": _digest(canonical_encode(wire)),
                "mcp_text": _digest(text.encode("utf-8")),
            }
            for pointer, reason in _omission_reasons(wire):
                reasons[reason] += 1
                if reason == "never_send_redacted":
                    never_send.append(f"{label}{pointer}")
            cursor = cast(str | None, cast(dict[str, JsonValue], wire["page"]).get("next_cursor"))
            index += 1
            if cursor is None:
                break
    receipts: list[JsonValue] = [
        {"request_id": request, "audit_subject": _digest(subject), "receipt": _digest(receipt)}
        for request, subject, receipt in ledger.receipt_rows()
    ]
    inventory = await prepare_closure(
        _closure_status(ledger, 800_000)[0],
        ledger.started.session_id,
        ledger.started.writer_id,
        Selection(),
    )
    rows = cast(dict[str, list[JsonValue]], inventory["inventory"])
    return {
        "schema": _GOLDEN_SCHEMA,
        "ledger": {
            "head_sequence": ledger.head.sequence,
            "hook_calls": ledger.hook_calls,
            "agent_rows": ledger.agent_rows,
        },
        "pages": pages,
        "omission_reasons": dict(sorted(reasons.items())),
        "never_send_redacted": cast(list[JsonValue], never_send),
        "receipts": receipts,
        "closure_inventory": {
            "digest": _digest(canonical_encode(inventory)),
            "rows": {view: len(rows[view]) for view in CLOSURE_VIEWS},
        },
    }


async def test_status_render_matches_pre_change_golden() -> None:
    ledger = await build_codex_status_ledger()
    record = await _golden_record(ledger)
    # The fixed ledger must exercise both omission reasons, on another writer's row (the hook
    # evidence description) and on a self-authored row (the agent evidence reference), or the
    # golden would not pin the never-send distinction at all.
    assert set(cast(dict[str, int], record["omission_reasons"])) == {
        "local_disclosure_not_authorized",
        "never_send_redacted",
    }
    redacted = cast(list[str], record["never_send_redacted"])
    assert any(item.startswith("evidence/") and item.endswith("/description") for item in redacted)
    assert any(item.startswith("evidence/") and item.endswith("/reference") for item in redacted)
    if os.environ.get("FINISHUP_STATUS_RENDER_GOLDEN") == "write":
        _GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        _GOLDEN.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        pytest.skip("golden regenerated")
    expected = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    assert expected["schema"] == _GOLDEN_SCHEMA
    # Compare section by section so a failure names what diverged.
    for key in ("ledger", "omission_reasons", "never_send_redacted", "closure_inventory"):
        assert record[key] == expected[key], key
    assert sorted(cast(dict[str, JsonValue], record["pages"])) == sorted(expected["pages"])
    for label, page in cast(dict[str, JsonValue], record["pages"]).items():
        assert page == expected["pages"][label], label
    assert len(cast(list[JsonValue], record["receipts"])) == len(expected["receipts"])
    for index, receipt in enumerate(cast(list[JsonValue], record["receipts"])):
        assert receipt == expected["receipts"][index], f"receipt {index}"


# ------------------------------------------------------------------------------------------------
# Cost: stage attribution and regression bounds.
# ------------------------------------------------------------------------------------------------

_REPEATS: Final = 5
_STAGES: Final = (
    "status query and page model",
    "privacy projection, receipt, result model",
    "control envelope check and frame (service)",
    "control frame decode and parse (client)",
    "MCP bridge rendering",
)
# Functions whose cumulative time attributes the projection stage (issue #916, proposed direction
# item 1). They do not nest in one another on this path; ``validate_schema_instance`` spans every
# stage, so it is reported on its own and not summed.
_PROFILED: Final = (
    ("page-model validation", "status.py", "_page_model"),
    ("leaf walk", "service.py", "_leaves"),
    ("leaf classification", "models.py", "classify_result_leaf"),
    ("never-send scan", "local_enforcer.py", "scan_exact_bytes"),
    ("receipt reserve/complete write", "catalog.py", "complete_agent_projection"),
    ("public result model", "service.py", "_public_model"),
    ("JSON Schema validation (all stages)", "schemas.py", "validate_schema_instance"),
    ("canonical encoding (all stages)", "canonical.py", "canonical_encode"),
)


def _baseline_unit(wire: dict[str, JsonValue]) -> float:
    """CPU seconds to canonically encode one rendered page ten times: this run's unit of work.

    Canonical encoding is pure Python over the same bytes a page carries, so it slows down with a
    loaded or slower runner exactly as rendering does, and the #916 changes do not touch it.
    """

    samples: list[float] = []
    for _ in range(_REPEATS):
        started = time.process_time()
        for _ in range(10):
            canonical_encode(wire)
        samples.append(time.process_time() - started)
    return min(samples)


async def _cursor_page_stages(
    ledger: CodexStatusLedger, processes: _Processes, seed: int, *, cursor_page: bool = True
) -> tuple[dict[str, float], dict[str, JsonValue]]:
    """Min CPU seconds per stage over repeated renders of one cached 100-row evidence page.

    The first render warms the per-frontier projection query cache, as an agent's first page
    does; the measured renders are cached pages (the cursor page, or the first page again).
    """

    first, _ = await _mcp_page(ledger, "evidence", seed, processes=processes)
    cursor = (
        cast(str, cast(dict[str, JsonValue], first["page"])["next_cursor"]) if cursor_page else None
    )
    samples: dict[str, list[float]] = {stage: [] for stage in _STAGES}
    for repeat in range(_REPEATS):
        request_seed = seed + 10 * (repeat + 1)
        body = ledger.status_body("evidence", request_seed, cursor=cursor)
        processes.enter("service")
        marks = [time.process_time()]
        internal = await ledger.app.status(StatusRequest.model_validate(body))
        marks.append(time.process_time())
        model = await ledger.project(body, internal, request_seed + 1)
        marks.append(time.process_time())
        frame = _service_frame(model, request_seed + 3)
        marks.append(time.process_time())
        processes.enter("client")
        parsed = _client_parse(frame)
        marks.append(time.process_time())
        wire, _ = _bridge(parsed)
        marks.append(time.process_time())
        assert len(cast(list[JsonValue], cast(dict[str, JsonValue], wire["page"])["items"])) == 100
        for index, stage in enumerate(_STAGES):
            samples[stage].append(marks[index + 1] - marks[index])
    return {stage: min(values) for stage, values in samples.items()}, first


async def _profiled_page(
    ledger: CodexStatusLedger, processes: _Processes, cursor: str, seed: int
) -> dict[str, float]:
    profile = cProfile.Profile()
    profile.enable()
    await _mcp_page(ledger, "evidence", seed, cursor, processes)
    profile.disable()
    stats = cast(
        dict[tuple[str, int, str], tuple[int, int, float, float, object]],
        getattr(pstats.Stats(profile), "stats"),
    )
    attributed: dict[str, float] = {}
    for label, filename, function in _PROFILED:
        attributed[label] = sum(
            cumulative
            for (path, _, name), (_, _, _, cumulative, _) in stats.items()
            if name == function and path.endswith(filename)
        )
    return attributed


def _report(title: str, rows: dict[str, float], unit: str = "ms") -> None:
    print(f"\n#916 {title}")
    for label, seconds in rows.items():
        print(f"  {label:<48} {seconds * 1000:9.1f} {unit}")


async def test_cached_evidence_page_render_cost_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cached 100-row cursor page no longer pays ~18 ms per row (issue #916)."""

    ledger = await build_codex_status_ledger()
    processes = _Processes(monkeypatch)
    stages, first = await _cursor_page_stages(ledger, processes, 900_000)
    unit = _baseline_unit(first)
    total = sum(stages.values())
    cursor = cast(str, cast(dict[str, JsonValue], first["page"])["next_cursor"])

    # Deterministic work counts, independent of runner speed.
    stock_constructions = 0
    stock = schemas_module.Draft202012Validator

    def counted_stock(*args: object, **kwargs: object) -> object:
        nonlocal stock_constructions
        stock_constructions += 1
        return stock(*args, **kwargs)  # pyright: ignore[reportArgumentType]

    shape_cache = getattr(models_module, "_classify_leaf_shape", None)
    shape_misses_before = (
        None if shape_cache is None else cast(_CacheInfo, shape_cache).cache_info().misses
    )
    with monkeypatch.context() as patch:
        patch.setattr(schemas_module, "Draft202012Validator", counted_stock)
        await _mcp_page(ledger, "evidence", 950_000, cursor, processes)
    attributed = await _profiled_page(ledger, processes, cursor, 960_000)

    _report(
        "cached 100-row evidence cursor page, min CPU of "
        f"{_REPEATS} (ledger head {ledger.head.sequence})",
        {**stages, "total": total, "baseline unit (10 canonical encodes)": unit},
    )
    _report("profiled attribution of one page (cProfile cumulative, inflated)", attributed)
    print(
        f"  page/unit ratio {total / unit:.1f}; stock validator constructions {stock_constructions}"
    )

    # Every valid document is decided by the first-error checker; only a rejected one pays for
    # the stock validator's diagnostics. Before #916 each page built it about ten times.
    assert stock_constructions == 0
    # Leaf classification is decided once per pointer shape, not once per row.
    assert shape_cache is not None, "leaf classification is no longer memoized per shape"
    assert cast(_CacheInfo, shape_cache).cache_info().misses == shape_misses_before
    # Before #916 this ratio was ~130 (2.4 s of CPU per page); after it is ~15. The bound leaves a
    # 3x margin for runner noise while still failing on a return to per-row validation cost.
    assert total / unit < 45, f"page costs {total / unit:.1f} baseline units"


async def test_page_cost_does_not_grow_with_the_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 100-row page costs the same at ~400 and ~1,500 events (acceptance criterion 3)."""

    processes = _Processes(monkeypatch)
    small = await build_codex_status_ledger(hook_calls=100, agent_rows=34)
    large = await build_codex_status_ledger(hook_calls=400, agent_rows=100)
    assert small.head.sequence < 450 < 1_450 < large.head.sequence
    # The small ledger holds 134 evidence rows, so its only full page is the first one.
    small_stages, _ = await _cursor_page_stages(small, processes, 910_000, cursor_page=False)
    large_stages, _ = await _cursor_page_stages(large, processes, 920_000, cursor_page=False)
    small_total = sum(small_stages.values())
    large_total = sum(large_stages.values())
    _report(
        "100-row cursor page by ledger size, min CPU",
        {
            f"{small.head.sequence} events": small_total,
            f"{large.head.sequence} events": large_total,
        },
    )
    # The acceptance target is a p50 difference under 20%; min-of-N CPU on a shared runner gets a
    # wider band so only real growth with the ledger fails.
    assert large_total / small_total < 1.5


async def test_closure_inventory_reads_each_view_once_per_page(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``closure-prepare`` of a ~1,000-event ledger: one status call per page, saved whole."""

    ledger = await build_codex_status_ledger()
    processes = _Processes(monkeypatch)
    status, calls = _closure_status(ledger, 970_000, processes)
    started_wall = time.perf_counter()
    started_cpu = time.process_time()
    inventory = await prepare_closure(
        status, ledger.started.session_id, ledger.started.writer_id, Selection()
    )
    cpu = time.process_time() - started_cpu
    wall = time.perf_counter() - started_wall
    rows = cast(dict[str, list[JsonValue]], inventory["inventory"])
    expected_calls = ["compact"] + [
        view for view in CLOSURE_VIEWS for _ in range(max(1, -(-len(rows[view]) // 100)))
    ]
    assert calls == expected_calls
    assert {view: len(rows[view]) for view in CLOSURE_VIEWS} == {
        "obligations": 1,
        "results": 330,
        "evidence": 330,
        "findings": 3,
        "history": ledger.head.sequence,
    }
    # ``--output`` saves exactly the bytes the command prints, which are the pre-#916 inventory.
    # Imported here so the golden test still runs against a pre-#916 source tree (runbook).
    from finishup.cli.closure import write_prepared_output

    summary = write_prepared_output(inventory, tmp_path / "closure.json")
    saved = (tmp_path / "closure.json").read_bytes()
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))["closure_inventory"]["digest"]
    assert saved.endswith(b"\n") and _digest(saved[:-1]) == golden
    assert summary["inventory_rows"] == {view: len(rows[view]) for view in CLOSURE_VIEWS}
    unit = _baseline_unit({"inventory": inventory["inventory"]})
    _report(
        f"closure-prepare inventory, {len(calls)} status calls (ledger head {ledger.head.sequence})",
        {"wall": wall, "CPU": cpu, "baseline unit (10 encodes of the inventory)": unit},
    )
    # Before #916 this inventory took ~100 baseline units (~32 s of CPU on a loaded 4-core
    # machine, 16-55 s wall on the benchmark VMs); after it takes ~12. A 3x noise margin.
    assert cpu / unit < 40, f"closure inventory costs {cpu / unit:.1f} baseline units"


async def test_mcp_closure_prepare_is_never_paged_on_a_long_task() -> None:
    """#1139 review: the bridge's closure inventory reads one status call per inventory page.

    Its reads send no ``delivery=paged``, so the ~1,000-event ledger never turns into delivery
    pages, extra page reads or a disclosure audit row per page; the inventory stays whole.
    """

    from finishup.domain.closure import prepare_closure as prepare_mcp_closure
    from finishup.protocol.models import ClosureSelectionModel

    ledger = await build_codex_status_ledger()
    calls: list[str] = []

    async def status(request: StatusRequest) -> StatusResult:
        assert request.delivery is None and request.delivery_cursor is None
        calls.append(request.view)
        model = await ledger.project_status(
            public_model_to_wire(request), 990_000 + 10 * len(calls)
        )
        assert public_model_to_wire(model).get("state") != "delivery_page"
        return model

    prepared = await prepare_mcp_closure(
        status,
        ledger.started.session_id,
        ledger.started.writer_id,
        ClosureSelectionModel.model_validate({"phase": "inventory"}),
        client_kind="cooperative_agent",
        integration="cooperative_mcp",
        scope_to_selection=True,
        host="codex",
    )
    rows = cast(dict[str, list[JsonValue]], prepared["inventory"])
    assert calls == ["compact"] + [
        view for view in CLOSURE_VIEWS for _ in range(max(1, -(-len(rows[view]) // 100)))
    ]
    assert len(calls) == 21 and len(rows["history"]) == ledger.head.sequence


async def test_concurrent_compact_burst_is_no_worse_than_serial() -> None:
    """Sixteen concurrent compact reads cost what sixteen solo reads cost (criterion 5).

    One process cannot model two vCPUs, so this checks the part it can: concurrency adds no work
    (no lock contention, no repeated cache misses). With per-page cost ~7x lower, the benchmark's
    14.6 s burst shrinks in proportion.
    """

    import asyncio

    ledger = await build_codex_status_ledger()
    # One process holds both halves here: concurrent tasks interleave, so no per-process
    # verdict memory can be modeled, and solo and burst share the same accounting.
    await _mcp_page(ledger, "compact", 980_000)
    solo_samples: list[float] = []
    for repeat in range(_REPEATS):
        started = time.process_time()
        await _mcp_page(ledger, "compact", 981_000 + repeat * 10)
        solo_samples.append(time.process_time() - started)
    solo = min(solo_samples)

    async def one(seed: int) -> None:
        await _mcp_page(ledger, "compact", seed)

    burst_samples: list[float] = []
    for repeat in range(3):
        started = time.process_time()
        await asyncio.gather(*(one(990_000 + repeat * 1_000 + index * 10) for index in range(16)))
        burst_samples.append(time.process_time() - started)
    burst = min(burst_samples)
    _report("16-call concurrent compact burst, min CPU", {"solo": solo, "burst": burst})
    # The acceptance bound (3x solo p50 x 16 / 2) is 1.5x sixteen serial reads.
    assert burst < 1.5 * 16 * solo, f"burst costs {burst / solo:.1f} solo reads"
