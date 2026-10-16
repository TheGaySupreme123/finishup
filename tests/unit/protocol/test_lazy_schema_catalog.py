"""Lazy schema loading decides exactly what the full catalog decides (issue #1083).

A hook is a fresh process per host callback. Until a process builds the full 232-schema catalog for
some other reason, ``validate_schema_instance`` parses only the requested schema and its transitive
``$ref`` closure. These tests hold that path to the full catalog for every packaged schema:

* each closure holds byte-for-byte the documents the full catalog holds, and every ``$ref`` in it
  resolves to the same contents from the same base URI as in the full catalog's checker;
* the lazy verdict equals the stock validator's verdict on real workflow documents, control
  envelopes, systematic mutations of them and generic probes, against every schema;
* a rejection carries the exact ``SchemaInstanceInvalid`` fields the full catalog reports;
* a tampered package fails with the full catalog's own reason;
* valid control frames never build the full catalog.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import hashlib
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast
from urllib.parse import urldefrag

import pytest

from builders.projection_workflow import project_case, run_projection_workflow
from builders.start_application import protocol_id
from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlMethod,
    ControlResult,
    ServiceState,
    ServiceStatus,
)
from finishup.protocol import models, schemas
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError
from finishup.service import control_protocol, daemon
from finishup.service.control_protocol import encode_control_frame

_CATALOG = schemas.load_schema_catalog()
_FULL_STATE = schemas._load_catalog_state()
_IDENTITIES = tuple(
    (document.schema_name, document.schema_version) for document in _CATALOG.documents
)
_RESULT_SCHEMA = {
    ControlMethod.START: "start-result",
    ControlMethod.PUBLISH_WORK: "publish-work-result",
    ControlMethod.CHECK: "check-result",
    ControlMethod.RESPOND: "respond-result",
    ControlMethod.STATUS: "status-result",
    ControlMethod.RECEIPT: "receipt-result",
}
_REQUEST_SCHEMA = {
    ControlMethod.START: "start-request",
    ControlMethod.PUBLISH_WORK: "publish-work-request",
    ControlMethod.CHECK: "check-request",
    ControlMethod.RESPOND: "respond-request",
    ControlMethod.STATUS: "status-request",
    ControlMethod.RECEIPT: "receipt-request",
}
_CONTROL_VERSION = "2.9.0"
_MUTATIONS_PER_DOCUMENT = 12
_PROBES: tuple[JsonValue, ...] = (
    {},
    [],
    "",
    "x",
    0,
    -1,
    None,
    True,
    {"zz_unexpected": 1},
    {"schema_version": "1.0.0"},
)

type _Corpus = tuple[tuple[str, str, JsonValue], ...]


def _schema_id(name: str, version: str | None = None) -> str:
    if version is None:
        version = schemas.request_result_schema_versions(_CATALOG)[name]
    return _CATALOG.by_name_version[(name, version)].schema_id


def _closure(plain_by_id: dict[str, dict[str, JsonValue]], schema_id: str) -> set[str]:
    closed = {schema_id}
    pending = [schema_id]
    while pending:
        for ref in schemas._walk_refs(plain_by_id[pending.pop()]):
            if ref.startswith("#"):
                continue
            base, _ = urldefrag(ref)
            if base not in closed:
                closed.add(base)
                pending.append(base)
    return closed


def _stock_accepts(schema_id: str, instance: JsonValue) -> bool:
    state = schemas._load_catalog_state()
    validator = schemas.Draft202012Validator(
        state.plain_by_id[schema_id],
        registry=state.registry,
        format_checker=schemas._FORMAT_CHECKER,
    )
    return next(cast(Any, validator).iter_errors(instance), None) is None


def _outcome(name: str, version: str, instance: JsonValue) -> tuple[object, ...]:
    """Everything ``validate_schema_instance`` tells its caller about one instance."""

    try:
        schemas.validate_schema_instance(name, version, instance)
    except schemas.SchemaInstanceInvalid as error:
        return (
            type(error).__name__,
            error.reason_code,
            error.absolute_path,
            error.location_reasons,
            error.reason,
            error.family,
            error.family_version,
            error.unknown_count,
            error.misplaced_field,
            error.missing_fields,
            error.condition_field,
            error.condition_value,
        )
    except ProtocolValueError as error:
        return (type(error).__name__, error.reason_code)
    return ("accepted",)


def _mutations(document: JsonValue) -> list[JsonValue]:
    """Deterministic, bounded mutations spread over the whole document."""

    candidates: list[tuple[tuple[str | int, ...], object]] = []

    def walk(value: JsonValue, path: tuple[str | int, ...]) -> None:
        if path:
            if isinstance(value, dict):
                candidates.append((path, {**value, "zz_unexpected": 1}))
                candidates.append((path, None))
            elif isinstance(value, list):
                candidates.append((path, []))
            elif isinstance(value, str):
                candidates.append((path, 7))
            elif isinstance(value, bool) or value is None:
                candidates.append((path, "not-a-boolean-or-null"))
            elif isinstance(value, int):
                candidates.append((path, str(value)))
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, (*path, key))
        elif isinstance(value, list):
            for index, item in enumerate(cast(list[JsonValue], value)):
                walk(item, (*path, index))

    walk(document, ())
    step = max(1, len(candidates) // _MUTATIONS_PER_DOCUMENT)
    mutated: list[JsonValue] = []
    for path, replacement in candidates[::step]:
        copy = strict_json_parse(canonical_encode(document))
        parent: Any = copy
        for segment in path[:-1]:
            parent = parent[segment]
        parent[path[-1]] = replacement
        mutated.append(copy)
    return mutated


def _without_nulls(value: JsonValue) -> JsonValue:
    """A model dump without the explicit nulls of unset optional fields, as a client sends it."""

    if isinstance(value, dict):
        return {key: _without_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_without_nulls(item) for item in cast(list[JsonValue], value)]
    return value


def _status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id=protocol_id("svc_", 9100),
        service_generation="1",
        state=ServiceState.READY,
        state_reason="none",
        vault_mode="passphrase",
        capabilities=("workflow",),
        session_monitor="unavailable",
    )


async def _workflow_corpus() -> _Corpus:
    """Real documents for request/result schemas and every control envelope the client uses."""

    workflow = await run_projection_workflow()
    corpus: list[tuple[str, str, JsonValue]] = []
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": ControlClientKind.CLI.value,
        "client_version": "0.3.0",
        "connection_nonce": "a" * 64,
        "schema_manifest_digest": schemas.schema_manifest_digest(),
        "workspace_locator": {"schema_version": "1.0.0", "path": "/work/space"},
        "presentation_context": {
            "render_mode": "machine_readable",
            "output_is_controlling_tty": False,
        },
    }
    corpus.append(("hello", _schema_id("control-hello", _CONTROL_VERSION), hello))
    hello_result = control_protocol._hello_result_wire(
        _status(), control_protocol._allowed_for(ControlClientKind.CLI)
    )
    corpus.append(
        (
            "hello-result",
            _schema_id("control-hello-result", _CONTROL_VERSION),
            strict_json_parse(canonical_encode(cast(JsonValue, hello_result))),
        )
    )
    for index, case in enumerate(workflow.cases):
        result = cast(JsonValue, dict(await project_case(workflow.app, case, 7000 + index * 2)))
        corpus.append((case.label, _schema_id(_RESULT_SCHEMA[case.method]), result))
        request = _without_nulls(cast(JsonValue, dict(case.request_body)))
        request_schema_id = _schema_id(_REQUEST_SCHEMA[case.method])
        if _stock_accepts(request_schema_id, request):
            corpus.append((f"{case.label}/request", request_schema_id, request))
        result_model = control_protocol._WORKFLOW_RESULT_MODELS[case.method]
        result_frame = encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=protocol_id("rpc_", 8000 + index),
                service_instance_id=protocol_id("svc_", 8100 + index),
                service_generation="1",
                method=case.method,
                outcome="ok",
                body=cast(Any, result_model.model_validate(result)),
            )
        )
        corpus.append(
            (
                f"{case.label}/result-envelope",
                _schema_id("control-result", _CONTROL_VERSION),
                strict_json_parse(result_frame[4:]),
            )
        )
        if not _stock_accepts(request_schema_id, request):
            continue
        request_model = control_protocol._WORKFLOW_REQUEST_MODELS[case.method]
        request_frame = encode_control_frame(
            ControlCallRequest(
                kind="call",
                protocol_version="1.0",
                rpc_id=protocol_id("rpc_", 8200 + index),
                service_instance_id=protocol_id("svc_", 8300 + index),
                service_generation="1",
                method=case.method,
                body=cast(Any, request_model.model_validate(request)),
            )
        )
        corpus.append(
            (
                f"{case.label}/request-envelope",
                _schema_id("control-request", _CONTROL_VERSION),
                strict_json_parse(request_frame[4:]),
            )
        )
    return tuple(corpus)


@pytest.fixture(scope="module")
def corpus() -> _Corpus:
    documents = asyncio.run(_workflow_corpus())
    for label, schema_id, document in documents:
        assert _stock_accepts(schema_id, document), label
    return documents


@pytest.fixture(scope="module")
def lazy_catalog() -> schemas._LazyCatalog:
    """A lazy catalog object, independent of this process's module-level caches."""

    return schemas._LazyCatalog(schemas._build_manifest_index())


@pytest.fixture(scope="module")
def eager_checker() -> schemas._ValidityChecker:
    checker = schemas._ValidityChecker.build(schemas._load_catalog_state())
    assert checker is not None
    return checker


@pytest.fixture
def lazy_process(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[], None]]:
    """Put this process in the state of a fresh hook process: no full catalog built yet.

    The returned callable resets it again, for a test that needs a rejection (which builds the
    full catalog) to be followed by another lazy decision.
    """

    def reset() -> None:
        schemas._load_catalog_state.cache_clear()
        monkeypatch.setattr(schemas, "_lazy_catalog_slot", [])
        monkeypatch.setattr(schemas, "_validity_checker_slot", [])

    reset()
    yield reset
    schemas._load_catalog_state.cache_clear()


def test_the_manifest_index_names_exactly_what_the_full_catalog_names() -> None:
    index = schemas._build_manifest_index()
    assert dict(index.id_by_identity) == {
        identity: document.schema_id for identity, document in _CATALOG.by_name_version.items()
    }
    assert index.known_ids == frozenset(_CATALOG.by_id)
    assert dict(index.request_result_versions) == dict(_CATALOG.request_result_versions)
    for document in _CATALOG.documents:
        assert index.member_bytes[document.schema_id] == document.schema_bytes


@pytest.mark.parametrize(
    ("name", "version"), _IDENTITIES, ids=[f"{name}@{version}" for name, version in _IDENTITIES]
)
def test_each_schema_closure_resolves_exactly_as_the_full_catalog(
    name: str,
    version: str,
    lazy_catalog: schemas._LazyCatalog,
    eager_checker: schemas._ValidityChecker,
) -> None:
    state = schemas._load_catalog_state()
    schema_id = _schema_id(name, version)
    checker = lazy_catalog._checker_for(schema_id)
    closure = _closure(dict(state.plain_by_id), schema_id)
    assert closure <= set(checker.plain_by_id)
    for document_id in sorted(closure):
        assert lazy_catalog._plain[document_id] == state.plain_by_id[document_id]
        assert checker.plain_by_id[document_id] == eager_checker.plain_by_id[document_id]
        lazy_resolver = checker.registry.resolver(document_id)
        full_resolver = eager_checker.registry.resolver(document_id)
        for ref in schemas._walk_refs(state.plain_by_id[document_id]):
            lazy_resolved = lazy_resolver.lookup(ref)
            full_resolved = full_resolver.lookup(ref)
            assert lazy_resolved.contents == full_resolved.contents, (document_id, ref)
            assert (
                cast(Any, lazy_resolved.resolver)._base_uri
                == cast(Any, full_resolved.resolver)._base_uri
            ), (document_id, ref)


def test_a_fresh_lazy_catalog_parses_only_the_closure_it_needs() -> None:
    lazy = schemas._LazyCatalog(schemas._build_manifest_index())
    state = schemas._load_catalog_state()
    expected: set[str] = set()
    for name in ("control-hello", "control-hello-result", "control-request", "control-result"):
        schema_id = _schema_id(name, _CONTROL_VERSION)
        lazy._checker_for(schema_id)
        expected |= _closure(dict(state.plain_by_id), schema_id)
        assert set(lazy._plain) == expected, name
    assert len(expected) < len(_CATALOG.documents)


@pytest.mark.parametrize(
    ("name", "version"), _IDENTITIES, ids=[f"{name}@{version}" for name, version in _IDENTITIES]
)
def test_each_schema_decides_like_the_stock_validator(
    name: str, version: str, lazy_catalog: schemas._LazyCatalog, corpus: _Corpus
) -> None:
    schema_id = _schema_id(name, version)
    candidates: list[JsonValue] = list(_PROBES)
    for _label, owner, document in corpus:
        candidates.append(document)
        if owner == schema_id:
            candidates.extend(_mutations(document))
    accepted = 0
    for candidate in candidates:
        stock = _stock_accepts(schema_id, candidate)
        digest = hashlib.sha256(canonical_encode(candidate)).digest()
        # Twice: the second answer may come from the verdict memory and must not differ.
        assert lazy_catalog.is_valid(schema_id, candidate, digest) is stock, candidate
        assert lazy_catalog.is_valid(schema_id, candidate, digest) is stock, candidate
        assert lazy_catalog.is_valid(schema_id, candidate, None) is stock, candidate
        accepted += stock
    if any(owner == schema_id for _label, owner, _document in corpus):
        assert accepted > 0, "the corpus must exercise acceptance for its own schemas"


def test_valid_control_frames_never_build_the_full_catalog(
    corpus: _Corpus, lazy_process: Callable[[], None]
) -> None:
    by_id = {document.schema_id: document for document in _CATALOG.documents}
    for label, schema_id, document in corpus:
        identity = by_id[schema_id]
        assert _outcome(identity.schema_name, identity.schema_version, document) == ("accepted",), (
            label
        )
    assert not schemas._full_catalog_loaded()


def _rejections(corpus: _Corpus) -> list[tuple[str, str, JsonValue]]:
    by_id = {document.schema_id: document for document in _CATALOG.documents}
    cases: list[tuple[str, str, JsonValue]] = [
        ("coverage", "1.0.0", {"publication_channels": []}),
        ("frontier", "1.0.0", {"sequence": "3"}),
        ("public-error", "1.0.0", {}),
        ("control-hello", _CONTROL_VERSION, {"protocol_version": "1.0"}),
    ]
    seen_schemas: set[str] = set()
    for _label, schema_id, document in corpus:
        if schema_id in seen_schemas:
            continue
        seen_schemas.add(schema_id)
        identity = by_id[schema_id]
        rejected = [
            mutation for mutation in _mutations(document) if not _stock_accepts(schema_id, mutation)
        ]
        cases.extend(
            (identity.schema_name, identity.schema_version, mutation) for mutation in rejected[:2]
        )
    return cases


def test_a_rejection_reports_exactly_what_the_full_catalog_reports(
    corpus: _Corpus, lazy_process: Callable[[], None]
) -> None:
    cases = _rejections(corpus)
    schemas.load_schema_catalog()
    eager = [_outcome(name, version, instance) for name, version, instance in cases]
    assert all(outcome[0] == "SchemaInstanceInvalid" for outcome in eager)
    for (name, version, instance), expected in zip(cases, eager, strict=True):
        lazy_process()
        assert schemas._lazy_catalog() is not None
        assert _outcome(name, version, instance) == expected, (name, version)


def test_lookup_failures_and_canonical_failures_are_unchanged(
    lazy_process: Callable[[], None],
) -> None:
    cases: list[tuple[object, object, JsonValue]] = [
        ("Not-A-Name", "1.0.0", {}),
        ("coverage", "1.0", {}),
        ("coverage", "9.9.9", {}),
        ("coverage", "1.0.0", cast(JsonValue, {"value": 1.0})),
    ]
    lazy = [_outcome(cast(str, name), cast(str, version), value) for name, version, value in cases]
    assert not schemas._full_catalog_loaded()
    schemas.load_schema_catalog()
    eager = [_outcome(cast(str, name), cast(str, version), value) for name, version, value in cases]
    assert lazy == eager
    assert [outcome[1] for outcome in lazy] == [
        "schema_name_invalid",
        "schema_name_invalid",
        "schema_not_found",
        "float_forbidden",
    ]


def test_request_result_versions_match_the_full_catalog(
    lazy_process: Callable[[], None],
) -> None:
    for name, version in _CATALOG.request_result_versions.items():
        assert schemas.request_result_schema_version(name) == version
    with pytest.raises(KeyError):
        schemas.request_result_schema_version("not-a-schema")
    assert not schemas._full_catalog_loaded()


def test_model_validation_uses_the_lazy_version_lookup(
    corpus: _Corpus, lazy_process: Callable[[], None]
) -> None:
    start_request = next(document for label, _id, document in corpus if label == "start/request")
    models.StartRequest.model_validate(start_request)
    assert not schemas._full_catalog_loaded()


def _copied_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "schemas"
    shutil.copytree(Path(cast(Any, schemas._schema_root())), tree)
    return tree


def _rewrite_member(
    tree: Path, relative_path: str, content: bytes, *, update_manifest: bool
) -> None:
    (tree / relative_path).write_bytes(content)
    if not update_manifest:
        return
    manifest = cast(dict[str, Any], strict_json_parse((tree / "manifest.json").read_bytes()))
    for member in manifest["members"]:
        if member["path"] == relative_path:
            member["byte_length"] = len(content)
            member["sha256"] = f"sha256:{hashlib.sha256(content).hexdigest()}"
    (tree / "manifest.json").write_bytes(canonical_encode(cast(JsonValue, manifest)))


def _reason_in_both_modes(
    tree: Path, monkeypatch: pytest.MonkeyPatch, reset: Callable[[], None]
) -> tuple[str, str]:
    monkeypatch.setattr(schemas, "_schema_root", lambda: tree)

    def attempt() -> str:
        with pytest.raises(ProtocolValueError) as failure:
            schemas.validate_schema_instance(
                "frontier", "1.0.0", {"sequence": "3", "head_digest": "sha256:" + "a" * 64}
            )
        return failure.value.reason_code

    reset()
    with pytest.raises(ProtocolValueError) as eager_failure:
        schemas.load_schema_catalog()
    reset()
    return eager_failure.value.reason_code, attempt()


@pytest.mark.parametrize("update_manifest", [False, True], ids=["digest-mismatch", "re-digested"])
def test_a_tampered_needed_member_fails_with_the_full_catalog_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lazy_process: Callable[[], None],
    update_manifest: bool,
) -> None:
    tree = _copied_tree(tmp_path)
    member = "common/frontier-1.0.0.schema.json"
    # Not canonical: a trailing space after otherwise identical bytes.
    _rewrite_member(
        tree, member, (tree / member).read_bytes() + b" ", update_manifest=update_manifest
    )
    eager_reason, lazy_reason = _reason_in_both_modes(tree, monkeypatch, lazy_process)
    assert lazy_reason == eager_reason
    assert eager_reason == (
        "schema_bytes_invalid" if update_manifest else "schema_manifest_member_mismatch"
    )


def test_a_tampered_unneeded_member_still_fails_its_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lazy_process: Callable[[], None]
) -> None:
    """Every member's bytes are held to the manifest even when the member is never parsed."""

    tree = _copied_tree(tmp_path)
    member = "receipts/receipt-document-1.0.0.schema.json"
    original = (tree / member).read_bytes()
    _rewrite_member(tree, member, original.replace(b'"', b"'", 1), update_manifest=False)
    eager_reason, lazy_reason = _reason_in_both_modes(tree, monkeypatch, lazy_process)
    assert lazy_reason == eager_reason == "schema_digest_mismatch"


class _RefusingStream:
    """Takes the hello's bytes, then fails the write as a closed socket would."""

    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        return b""

    async def send_all(self, data: bytes) -> None:
        self.sent.append(bytes(data))
        raise LocalControlTransportError("connection_failed")

    async def aclose(self) -> None:
        return None


def test_a_client_handshake_loads_its_envelopes_before_the_hello(
    lazy_process: Callable[[], None],
) -> None:
    """All schema work stays before the first frame, as when the hello built the whole catalog."""

    full_plain = dict(_FULL_STATE.plain_by_id)
    stream = _RefusingStream()
    with pytest.raises(LocalControlTransportError):
        asyncio.run(
            control_protocol.client_handshake(cast(Any, stream), ControlClientKind.CLI, "0.3.0")
        )
    assert len(stream.sent) == 1
    lazy = schemas._lazy_catalog()
    assert lazy is not None
    for name in ("control-hello", "control-hello-result", "control-request", "control-result"):
        assert _closure(full_plain, _schema_id(name, _CONTROL_VERSION)) <= set(lazy._plain), name
    assert not schemas._full_catalog_loaded()


def test_preparing_unknown_or_unloadable_schemas_never_raises(
    lazy_process: Callable[[], None],
) -> None:
    schemas.prepare_schemas(("not-a-schema", "1.0.0"), ("coverage", "1.0.0"))
    lazy = schemas._lazy_catalog()
    assert lazy is not None
    assert _schema_id("coverage", "1.0.0") in lazy._plain
    assert not schemas._full_catalog_loaded()


def test_a_process_that_keeps_the_full_catalog_never_builds_a_lazy_one(
    lazy_process: Callable[[], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(schemas, "_full_catalog_preferred", [False])
    schemas.use_full_schema_catalog()
    schemas.prepare_schemas(("control-hello", _CONTROL_VERSION))
    schemas.validate_schema_instance(
        "frontier", "1.0.0", {"sequence": "3", "head_digest": "sha256:" + "a" * 64}
    )
    assert (
        schemas.request_result_schema_version("status-result")
        == (_CATALOG.request_result_versions["status-result"])
    )
    assert schemas._full_catalog_loaded()
    assert schemas._lazy_catalog_slot == []


def test_the_service_keeps_the_full_catalog_before_anything_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Stopped(Exception):
        pass

    def stop_at_the_preference() -> None:
        raise _Stopped

    monkeypatch.setattr(daemon, "use_full_schema_catalog", stop_at_the_preference)
    with pytest.raises(_Stopped):
        asyncio.run(daemon.run_service())
