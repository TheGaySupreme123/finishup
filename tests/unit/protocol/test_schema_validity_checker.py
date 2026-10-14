"""The first-error validity checker decides exactly what the stock validator decides (issue #916).

``validate_schema_instance`` answers most calls from ``_ValidityChecker``: lazy ``anyOf``/``oneOf``
that stop each failing branch at its first error, ``$ref`` resolved once per base URI, and a
bounded memory of (schema, canonical bytes) pairs already found valid. It only changes how much
work a *valid* instance costs; every rejection still goes through the stock ``Draft202012Validator``
for the exact diagnostic. These tests hold the checker to the stock verdict on real projected
results of every workflow method, every status view and the control envelope, plus systematic
mutations of each, and pin the two places where sharing a verdict would be wrong.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any, cast

import pytest

from builders.projection_workflow import project_case, run_projection_workflow
from builders.start_application import protocol_id
from finishup.ports.control import ControlMethod, ControlResult
from finishup.protocol import schemas
from finishup.protocol.canonical import (
    JsonValue,
    canonical_encode,
    canonical_fragment,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import StatusResult
from finishup.service.control_protocol import encode_control_frame

pytestmark = pytest.mark.anyio

_RESULT_SCHEMA = {
    ControlMethod.START: "start-result",
    ControlMethod.PUBLISH_WORK: "publish-work-result",
    ControlMethod.CHECK: "check-result",
    ControlMethod.RESPOND: "respond-result",
    ControlMethod.STATUS: "status-result",
    ControlMethod.RECEIPT: "receipt-result",
}
_MUTATIONS_PER_DOCUMENT = 24


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _schema_id(name: str) -> str:
    catalog = schemas.load_schema_catalog()
    version = schemas.request_result_schema_versions(catalog).get(name)
    if version is None:
        version = max(
            (
                document.schema_version
                for document in catalog.documents
                if document.schema_name == name
            ),
            key=lambda value: tuple(int(part) for part in value.split(".")),
        )
    return schemas.schema_document_for(name, version).schema_id


def _stock_accepts(schema_id: str, instance: JsonValue) -> bool:
    state = schemas._load_catalog_state()
    validator = schemas.Draft202012Validator(
        state.plain_by_id[schema_id],
        registry=state.registry,
        format_checker=schemas._FORMAT_CHECKER,
    )
    return next(cast(Any, validator).iter_errors(instance), None) is None


def _containers(
    value: JsonValue, path: tuple[str | int, ...] = ()
) -> Iterator[tuple[tuple[str | int, ...], JsonValue]]:
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _containers(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(cast(list[JsonValue], value)):
            yield from _containers(item, (*path, index))


def _replaced(document: JsonValue, path: tuple[str | int, ...], value: JsonValue) -> JsonValue:
    copy = strict_json_parse(canonical_encode(document))
    parent: Any = copy
    for step in path[:-1]:
        parent = parent[step]
    if value is _DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = value
    return copy


_DELETE: Any = object()


def _mutations(document: JsonValue) -> list[JsonValue]:
    """Deterministic, bounded mutations spread over the whole document."""

    candidates: list[tuple[tuple[str | int, ...], JsonValue]] = []
    for path, value in _containers(document):
        if not path:
            continue
        if isinstance(value, dict):
            candidates.append((path, {**value, "zz_unexpected": 1}))
            candidates.append((path, _DELETE))
        elif isinstance(value, list):
            items = cast(list[JsonValue], value)
            candidates.append((path, [*items, items[0]] if items else ["unexpected"]))
            candidates.append((path, []))
        elif isinstance(value, bool) or value is None:
            candidates.append((path, "not-a-boolean-or-null"))
        elif isinstance(value, int):
            candidates.append((path, str(value)))
            candidates.append((path, -1))
        elif isinstance(value, str):
            candidates.append((path, 7))
            candidates.append((path, ""))
            candidates.append((path, value + "é" * 300))
    step = max(1, len(candidates) // _MUTATIONS_PER_DOCUMENT)
    return [_replaced(document, path, value) for path, value in candidates[::step]]


async def _documents() -> list[tuple[str, str, JsonValue]]:
    workflow = await run_projection_workflow()
    documents: list[tuple[str, str, JsonValue]] = []
    envelope_id = _schema_id("control-result")
    for index, case in enumerate(workflow.cases):
        wire = cast(JsonValue, dict(await project_case(workflow.app, case, 5000 + index * 2)))
        documents.append((case.label, _schema_id(_RESULT_SCHEMA[case.method]), wire))
        if case.method is ControlMethod.STATUS:
            frame = encode_control_frame(
                ControlResult(
                    protocol_version="1.0",
                    rpc_id=protocol_id("rpc_", 6000 + index),
                    service_instance_id=protocol_id("svc_", 6100 + index),
                    service_generation="1",
                    method=ControlMethod.STATUS,
                    outcome="ok",
                    body=StatusResult.model_validate(wire),
                )
            )
            documents.append((f"{case.label}/envelope", envelope_id, strict_json_parse(frame[4:])))
    return documents


async def test_checker_agrees_with_stock_validator_on_results_and_mutations() -> None:
    checker = schemas._ValidityChecker.build(schemas._load_catalog_state())
    assert checker is not None
    compared = 0
    rejected = 0
    for label, schema_id, document in await _documents():
        assert _stock_accepts(schema_id, document), label
        for candidate in (document, *_mutations(document)):
            stock = _stock_accepts(schema_id, candidate)
            digest = hashlib.sha256(canonical_encode(candidate)).digest()
            # Twice: the second answer may come from the verdict memory and must not differ.
            assert checker.is_valid(schema_id, candidate, digest) is stock, label
            assert checker.is_valid(schema_id, candidate, digest) is stock, label
            assert checker.is_valid(schema_id, candidate, None) is stock, label
            compared += 1
            rejected += not stock
    # The mutations must actually exercise rejection, not only the happy path.
    assert compared > 400 and rejected > compared // 3


_COVERAGE: dict[str, JsonValue] = {
    "publication_channels": ["cooperative_mcp"],
    "authorship_assurance": "self_asserted",
    "artifact_observation": "published_only",
    "evidence_immutability": "content_digest",
    "ledger_freshness": "current",
    "check_types": ["none"],
    "known_gaps": [],
}


def _diagnostic(name: str, instance: JsonValue) -> tuple[object, ...]:
    with pytest.raises(schemas.SchemaInstanceInvalid) as invalid:
        schemas.validate_schema_instance(name, "1.0.0", instance)
    error = invalid.value
    return (
        error.reason_code,
        error.absolute_path,
        error.location_reasons,
        error.reason,
        error.family,
        error.unknown_count,
        error.misplaced_field,
        error.condition_field,
        error.condition_value,
    )


@pytest.mark.parametrize(
    "instance",
    [
        {**_COVERAGE, "extra": True},
        {key: value for key, value in _COVERAGE.items() if key != "known_gaps"},
        {**_COVERAGE, "publication_channels": []},
        {**_COVERAGE, "check_types": ["none", "none"]},
    ],
)
def test_rejection_keeps_the_stock_diagnostic(
    monkeypatch: pytest.MonkeyPatch, instance: JsonValue
) -> None:
    """A rejected instance is reported exactly as the stock validator alone reports it."""

    schemas.validate_schema_instance("coverage", "1.0.0", _COVERAGE)
    with_checker = _diagnostic("coverage", instance)
    monkeypatch.setattr(schemas, "_validity_checker", lambda: None)
    assert _diagnostic("coverage", instance) == with_checker


def test_a_spliced_fragment_never_shares_the_verdict_of_its_value() -> None:
    """A fragment has its value's canonical bytes but is not that value to the validator."""

    frontier: dict[str, JsonValue] = {"sequence": "3", "head_digest": "sha256:" + "a" * 64}
    schemas.validate_schema_instance("frontier", "1.0.0", frontier)
    spliced = cast(JsonValue, canonical_fragment(frontier))
    assert canonical_encode(spliced) == canonical_encode(frontier)
    with pytest.raises(ProtocolValueError):
        schemas.validate_schema_instance("frontier", "1.0.0", spliced)


def test_verdict_memory_is_bounded_and_never_holds_rejections() -> None:
    verdicts = schemas._ValidInstanceVerdicts(2)
    for index in range(3):
        verdicts.remember(("schema", bytes([index])))
    assert not verdicts.seen(("schema", bytes([0])))
    assert verdicts.seen(("schema", bytes([1]))) and verdicts.seen(("schema", bytes([2])))
    checker = schemas._ValidityChecker.build(schemas._load_catalog_state())
    assert checker is not None
    schema_id = _schema_id("frontier")
    invalid: JsonValue = {"sequence": "3"}
    digest = hashlib.sha256(canonical_encode(invalid)).digest()
    assert checker.is_valid(schema_id, invalid, digest) is False
    assert not checker.verdicts.seen((schema_id, digest))


async def test_a_checker_that_cannot_read_resolver_state_falls_back_to_stock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A jsonschema/referencing upgrade that renames the private resolver state the checker reads
    (``_resolver``, ``_base_uri``) costs speed only: every verdict still comes from the stock
    validator."""

    def unreadable(*_args: object) -> object:
        def keyword(*_keyword_args: object) -> Iterator[ProtocolValueError]:
            raise AttributeError("_base_uri")
            yield ProtocolValueError("unreachable")

        return keyword

    monkeypatch.setattr(schemas, "_ref_resolved_once", unreadable)
    monkeypatch.setattr(schemas, "_validity_checker_slot", [])
    by_id = {document.schema_id: document for document in schemas.load_schema_catalog().documents}
    checked = 0
    for label, schema_id, document in await _documents():
        checker = schemas._validity_checker()
        assert checker is not None
        # The broken ``$ref`` keyword is reached, so the checker cannot tell ...
        assert checker.is_valid(schema_id, document, None) is False, label
        # ... and the stock validator still accepts the valid result and rejects its mutation.
        identity = by_id[schema_id]
        schemas.validate_schema_instance(identity.schema_name, identity.schema_version, document)
        mutated = next(m for m in _mutations(document) if not _stock_accepts(schema_id, m))
        with pytest.raises(schemas.SchemaInstanceInvalid):
            schemas.validate_schema_instance(identity.schema_name, identity.schema_version, mutated)
        checked += 1
    assert checked > 5


async def test_the_pinned_dependencies_take_the_fast_path_for_valid_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard the ~8x speedup against a silent ``jsonschema``/``referencing`` regression.

    The checker reads private resolver state (``_resolver``, ``_base_uri``, ``resolved.resolver``)
    and falls back to the stock validator whenever it cannot, which keeps every verdict correct and
    would therefore pass every correctness test while losing the speedup. With the locked
    dependency versions, every valid workflow result, status page and control envelope must be
    decided by the checker alone: the checker exists, its ``$ref`` keyword really runs, and
    ``validate_schema_instance`` never builds a stock validator. An upgrade that breaks the private
    state fails here and must be adapted, or the fallback accepted on purpose.
    """

    from importlib.metadata import version

    installed = f"jsonschema {version('jsonschema')}, referencing {version('referencing')}"
    documents = await _documents()
    monkeypatch.setattr(schemas, "_validity_checker_slot", [])
    checker = schemas._validity_checker()
    assert checker is not None, f"no validity checker for the packaged catalog with {installed}"

    references = 0
    ref_keyword = checker.remembering_class.VALIDATORS["$ref"]

    def counted_ref(*args: object) -> Iterator[object]:
        nonlocal references
        references += 1
        return ref_keyword(*args)

    for validator_class in (checker.remembering_class, checker.forgetful_class):
        monkeypatch.setitem(validator_class.VALIDATORS, "$ref", counted_ref)

    stock_constructions = 0
    stock = schemas.Draft202012Validator

    def counted_stock(*args: object, **kwargs: object) -> object:
        nonlocal stock_constructions
        stock_constructions += 1
        return stock(*args, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(schemas, "Draft202012Validator", counted_stock)
    by_id = {document.schema_id: document for document in schemas.load_schema_catalog().documents}
    for label, schema_id, document in documents:
        identity = by_id[schema_id]
        assert checker.is_valid(schema_id, document, None) is True, (label, installed)
        schemas.validate_schema_instance(identity.schema_name, identity.schema_version, document)
    assert schemas._validity_checker() is checker
    assert references > len(documents), installed
    assert stock_constructions == 0, installed
