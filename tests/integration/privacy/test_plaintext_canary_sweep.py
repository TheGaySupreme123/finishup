"""Plaintext canary sweep across durable structural surfaces.

Proves user-controlled plaintext does not leak into the durable SQLite catalog (including its WAL/
SHM journal files), the encrypted object store's on-disk ciphertext, or the structured log/
diagnostic-manifest surfaces -- on both a normal approved-disclosure workflow and a workflow that
deliberately fails partway through.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import subprocess
from collections.abc import AsyncIterator, Buffer, Callable, Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import apsw
import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from yoetz.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from yoetz.adapters.privacy.catalog import CatalogPrivacyAudit, CatalogPrivacyPolicyStore
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.adapters.repository_identity import resolve_repository_privacy_context
from yoetz.adapters.sqlite.migrations import CATALOG_MIGRATIONS
from yoetz.application.egress import PrivacyCoordinator
from yoetz.config.models import LoggingConfig
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    LocalDisclosureApproved,
    LocalDisclosureBlocked,
    LocalDisclosureSink,
    PrivacyPolicy,
    PrivacyProfile,
    ReceiptSecretScanStage,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.values import parse_rfc3339_millis
from yoetz.observability.logging import LogMode, configure_logging, get_logger
from yoetz.observability.privacy import DiagnosticRedactionProfile as RedactionProfile
from yoetz.observability.privacy import (
    build_diagnostic_manifest,
    scan_for_sensitive_content,
)
from yoetz.ports.control import (
    ControlClientKind,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceLocator,
)
from yoetz.ports.keys import BundleKeys, WrappedDek
from yoetz.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
    StagedObject,
)
from yoetz.ports.secret_memory import SecretConsumer, SecretMemoryCapability, SecretPurpose
from yoetz.protocol.ids import IdKind
from yoetz.protocol.models import DataCategory
from yoetz.service.control_protocol import client_handshake, server_handshake

if TYPE_CHECKING:
    from yoetz.ports.secret_memory import SecretHandle

_INSTALLATION = "ins_50000000-0000-4000-8000-000000000001"
_TASK = "tsk_50000000-0000-4000-8000-000000000002"
_SESSION = "ses_50000000-0000-4000-8000-000000000003"
_POLICY = "pvy_50000000-0000-4000-8000-000000000004"
_REQUEST = "req_50000000-0000-4000-8000-000000000005"
_REQUEST_FAULT = "req_50000000-0000-4000-8000-000000000006"
_ROUTE_DIGEST = "sha256:" + "7" * 64
_DIGEST = "sha256:" + "3" * 64
_NOW = datetime(2026, 7, 19, tzinfo=UTC)
_SERVICE = "svc_50000000-0000-4000-8000-000000000007"


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


class _Key:
    """A deterministic ``MacKeyHandle``; never a raw key/bytes value to callers."""

    def __init__(self, seed: bytes) -> None:
        self._seed = seed

    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(self._seed, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


class _Secret:
    def __init__(self, value: bytes | bytearray) -> None:
        self._value = bytearray(value)
        self._consumed = False

    @property
    def purpose(self) -> SecretPurpose:
        return SecretPurpose.OBJECT_PAYLOAD

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if consumer is not SecretConsumer.OBJECT_CRYPTO or self._consumed:
            raise ValueError("secret_handle_invalid")
        self._consumed = True
        try:
            return fn(memoryview(self._value))
        finally:
            self._value[:] = b"\0" * len(self._value)


class _SecretMemory:
    def capability(self) -> SecretMemoryCapability:
        return SecretMemoryCapability("active", "unavailable", "unavailable", "active", "active")

    def capture(self, purpose: SecretPurpose, source: bytearray) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        result = _Secret(source)
        source[:] = b"\0" * len(source)
        return result

    def allocate(self, purpose: SecretPurpose, size: int) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        return _Secret(bytes(size))

    def close(self) -> None:
        return None


class _WrapKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def wrap_dek(self, dek: SecretHandle) -> WrappedDek:
        wrapped = dek.consume(
            SecretConsumer.OBJECT_CRYPTO, lambda value: aes_key_wrap(self._key, bytes(value))
        )
        return WrappedDek("aes-256-kw-rfc3394", wrapped)

    def unwrap_dek(self, wrapped: WrappedDek) -> _Secret:
        return _Secret(aes_key_unwrap(self._key, wrapped.wrapped))


class _Ids:
    def __init__(self) -> None:
        self._object_seq = 0
        self._proposal_seq = 0
        self._receipt_seq = 0

    def new(self, kind: IdKind) -> str:
        if kind is IdKind.OBJECT:
            self._object_seq += 1
            return f"obj_{self._object_seq:08x}-0000-4000-8000-000000000001"
        if kind is IdKind.PRIVACY_PROPOSAL:
            self._proposal_seq += 1
            return f"ppr_{self._proposal_seq:08x}-0000-4000-8000-000000000001"
        if kind is IdKind.EGRESS_RECEIPT:
            self._receipt_seq += 1
            return f"egr_{self._receipt_seq:08x}-0000-4000-8000-000000000001"
        raise AssertionError(f"unexpected id kind requested in canary sweep test: {kind}")


class _Roots:
    async def current(self) -> ObjectRootSnapshot:
        return ObjectRootSnapshot(
            _TASK, _ROUTE_DIGEST, 1, 1, 0, _DIGEST, _DIGEST, _DIGEST, _DIGEST, _NOW, ()
        )


class _Gateway:
    async def close(self) -> None:
        return None


def _database(path: Path) -> apsw.Connection:
    db = apsw.Connection(str(path))
    db.execute("PRAGMA journal_mode=WAL")
    for migration in CATALOG_MIGRATIONS:
        db.execute(migration.ddl.decode("utf-8"))
    db.execute(
        """INSERT INTO task_routes (
               task_id, workspace_ref_commitment, external_ref_commitment,
               active_session_id, bundle_relpath, route_generation,
               active_route_identity_digest, state, quarantine_code, created_at, updated_at
           ) VALUES (?, NULL, NULL, ?, ?, 1, ?, 'active', NULL, ?, ?)""",
        (
            _TASK,
            _SESSION,
            f"tasks/{_TASK}",
            _ROUTE_DIGEST,
            _NOW.isoformat().replace("+00:00", "Z"),
            _NOW.isoformat().replace("+00:00", "Z"),
        ),
    )
    return db


def _object_store(bundle_root: Path) -> EncryptedFilesObjectStore:
    bundle_root.mkdir(parents=True, exist_ok=True)
    bundle_root.chmod(0o700)
    keys = BundleKeys("privacy-canary-slot", _WrapKey(b"w" * 32), _Key(b"c" * 32))
    return EncryptedFilesObjectStore(
        bundle_root=bundle_root,
        bundle_keys=keys,
        secret_memory=_SecretMemory(),  # type: ignore[arg-type]
        id_port=_Ids(),
        current_root_snapshot=_Roots().current,
    )


def _disabled(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel, False, (), (), None, (), AuthorizationScopeKind.MACHINE, False, 0, 0, 0
    )


def _scope() -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK, _INSTALLATION, f"hmac-sha256:{'4' * 64}", _TASK
    )


def _policy(scope: AuthorizationScope | None = None) -> PrivacyPolicy:
    return PrivacyPolicy(
        _POLICY,
        1,
        _DIGEST,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        False,
        _scope() if scope is None else scope,
        tuple(_disabled(channel) for channel in sorted(EgressChannel, key=lambda item: item.value)),
        False,
        None,
        (),
        (),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (DataClass.PUBLIC_STRUCTURAL,),
        (DataCategory.TASK_DESCRIPTION,),
        (DataClass.ORDINARY_USER_CONTENT,),
        _NOW,
        None,
    )


def _coordinator(
    policies: CatalogPrivacyPolicyStore, audit: CatalogPrivacyAudit
) -> PrivacyCoordinator:
    return PrivacyCoordinator(
        policies,
        LocalPrivacyEnforcer(),
        audit,
        _Gateway(),  # type: ignore[arg-type]
        _Clock(),
        _Ids(),
    )


def _candidate(
    request_id: str,
    item_id: str,
    category: DataCategory,
    origin_ref: str,
    plaintext: bytes,
    *,
    scope: AuthorizationScope | None = None,
) -> CandidateContext:
    effective_scope = _scope() if scope is None else scope
    return CandidateContext(
        request_id,
        None,
        LocalDisclosureSink.TRUSTED_HUMAN_CONTROL,
        "trusted-preview",
        effective_scope,
        None,
        None,
        (CandidateContextItem(item_id, category, effective_scope, origin_ref, plaintext),),
    )


def _walk_bytes(root: Path) -> dict[Path, bytes]:
    collected: dict[Path, bytes] = {}
    if not root.exists():
        return collected
    for path in root.rglob("*"):
        if path.is_file():
            collected[path] = path.read_bytes()
    return collected


def _durable_surfaces(db_path: Path, bundle_root: Path) -> dict[str, bytes]:
    surfaces: dict[str, bytes] = {"catalog_db": db_path.read_bytes()}
    for suffix in ("-wal", "-shm"):
        sibling = db_path.with_name(db_path.name + suffix)
        if sibling.exists():
            surfaces[f"catalog_db{suffix}"] = sibling.read_bytes()
    for path, data in _walk_bytes(bundle_root).items():
        surfaces[f"object_store:{path.relative_to(bundle_root)}"] = data
    return surfaces


class _Env:
    def __init__(self, tmp_path: Path) -> None:
        self.db_path = tmp_path / "catalog.sqlite3"
        self.bundle_root = tmp_path / "bundle"
        self.db = _database(self.db_path)
        self.objects = _object_store(self.bundle_root)
        self.audit_key = _Key(b"a" * 32)
        self.audit = CatalogPrivacyAudit(self.db, self.objects, self.audit_key, _Clock())
        self.policies = CatalogPrivacyPolicyStore(self.db, _Clock())
        self.coordinator = _coordinator(self.policies, self.audit)

    def surfaces(self) -> dict[str, bytes]:
        self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return _durable_surfaces(self.db_path, self.bundle_root)


class _RecordingMemoryStream:
    """In-memory authenticated stream retaining frames only for the positive-control assertion."""

    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: _RecordingMemoryStream | None = None
        self.sent: list[bytes] = []
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue(maxsize=4)
        self._buffer = bytearray()

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            self._buffer.extend(await self._chunks.get())
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.other is not None
        frame = bytes(data)
        self.sent.append(frame)
        await self.other._chunks.put(frame)

    async def aclose(self) -> None:
        return None


def _control_stream_pair() -> tuple[_RecordingMemoryStream, _RecordingMemoryStream, object]:
    client_peer = object()
    service_peer = object()
    client = _RecordingMemoryStream(service_peer)
    server = _RecordingMemoryStream(client_peer)
    client.other = server
    server.other = client
    return client, server, client_peer


def _service_status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.1.0",
        service_instance_id=_SERVICE,
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="human_authority_unavailable",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )


def test_canaries_absent_from_structural_surfaces(tmp_path: Path) -> None:
    retained_root = os.environ.get("YOETZ_RUNTIME_CANARY_ROOT")
    canary_file = os.environ.get("YOETZ_RUNTIME_CANARY_FILE")
    assert bool(retained_root) is bool(canary_file), (
        "YOETZ_RUNTIME_CANARY_ROOT and YOETZ_RUNTIME_CANARY_FILE must be set together"
    )
    root = Path(retained_root) if retained_root else tmp_path
    root.mkdir(parents=True, exist_ok=not retained_root)
    env = _Env(root)
    canary = (
        Path(canary_file).read_bytes() if canary_file else f"CANARY-{os.urandom(8).hex()}".encode()
    )
    assert canary and len(canary) <= 4_096, "runtime canary must be nonempty and bounded"
    never_send_canary = f"NEVERSEND-{os.urandom(8).hex()}".encode()

    async def run() -> tuple[object, object]:
        await env.policies.seed_if_absent(_policy())
        approved = await env.coordinator.prepare_local_disclosure(
            _candidate(_REQUEST, "item-1", DataCategory.TASK_DESCRIPTION, "note:1", canary)
        )
        blocked = await env.coordinator.prepare_local_disclosure(
            _candidate(
                _REQUEST_FAULT,
                "item-2",
                DataCategory.TASK_DESCRIPTION,
                "credential:leak",
                never_send_canary,
            )
        )
        return approved, blocked

    approved, blocked = asyncio.run(run())

    assert type(approved) is LocalDisclosureApproved
    assert approved.approved_items[0].bounded_bytes == canary  # sanity: the canary really was used
    assert type(blocked) is LocalDisclosureBlocked

    # Positive control: prove the sweep mechanism itself actually detects an injected canary,
    # so an all-clean sweep below is meaningful rather than vacuous.
    poisoned = tmp_path / "poisoned-control.bin"
    poisoned.write_bytes(b"unrelated noise around " + canary)
    control_findings = scan_for_sensitive_content(poisoned.read_bytes(), canaries=(canary,))
    assert control_findings != ()
    poisoned.unlink()

    # The never-send canary must never have reached any structural surface at all: it was blocked
    # before any content object was written, so scanning for it must find nothing anywhere,
    # including inside the ciphertext (which legitimately holds only the *approved* canary).
    surfaces = env.surfaces()
    assert surfaces, "expected at least the catalog DB file to exist"
    for name, data in surfaces.items():
        findings = scan_for_sensitive_content(data, canaries=(never_send_canary,))
        assert findings == (), f"never-send canary leaked into {name!r}: {findings}"

    # The approved canary is legitimate ordinary content: it must never appear in the *structural*
    # catalog DB (only inside the AEAD-encrypted object payload), which is exactly what the
    # dedicated ciphertext test below verifies at the byte level.
    db_findings = scan_for_sensitive_content(surfaces["catalog_db"], canaries=(canary,))
    assert db_findings == (), f"approved canary leaked into catalog DB structure: {db_findings}"

    manifest = build_diagnostic_manifest(RedactionProfile.SUPPORT, {"message": canary.decode()})
    assert canary.decode() not in repr(manifest)


def test_local_policy_denial_records_candidate_scan_without_false_not_run(tmp_path: Path) -> None:
    """Classification runs before local policy denial, so the receipt names its candidate scan."""

    env = _Env(tmp_path)

    async def run() -> object:
        await env.policies.seed_if_absent(_policy())
        return await env.coordinator.prepare_local_disclosure(
            _candidate(
                _REQUEST,
                "item-denied",
                DataCategory.FINDING_SUMMARY,
                "note:ordinary",
                b"ordinary content",
            )
        )

    result = asyncio.run(run())
    assert type(result) is LocalDisclosureBlocked
    assert result.receipt.secret_scan.stage is ReceiptSecretScanStage.CANDIDATE
    assert result.receipt.secret_scan.passed is True
    assert result.receipt.secret_scan.match_count == 0
    assert result.receipt.secret_scan.not_run_reason is None


@pytest.mark.anyio
async def test_repository_locator_is_ephemeral_and_only_its_commitment_persists(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    common_root_marker = f"GIT-COMMON-ROOT-CANARY-{os.urandom(8).hex()}"
    locator_marker = f"RAW-WORKSPACE-LOCATOR-CANARY-{os.urandom(8).hex()}"
    repository = tmp_path / common_root_marker
    nested_locator = repository / locator_marker
    repository.mkdir()
    subprocess.run(
        ["git", "-C", os.fspath(repository), "init"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )
    nested_locator.mkdir()
    locator = WorkspaceLocator(os.fspath(nested_locator))
    raw_locator = locator.path.encode()
    marker_canaries = (common_root_marker.encode(), locator_marker.encode(), raw_locator)

    state_root = tmp_path / "state"
    state_root.mkdir()
    env = _Env(state_root)
    client, server, client_peer = _control_stream_pair()
    observed_locators: list[str] = []

    async def resolve(value: WorkspaceLocator) -> RepositoryPrivacyContext:
        observed_locators.append(value.path)
        return await resolve_repository_privacy_context(value, env.audit_key)

    client_session, server_session = await asyncio.gather(
        client_handshake(
            client,
            ControlClientKind.CLI,
            "0.1.0",
            workspace_locator=locator,
        ),
        server_handshake(
            server,
            client_peer,
            _service_status(),
            repository_context_resolver=resolve,
        ),
    )
    context = server_session.repository_privacy_context
    assert context is not None and context.identity_kind == "git_common_root"
    assert observed_locators == [locator.path]

    # Positive control: the exact client hello carries the raw locator into the trusted resolver,
    # while the server response and both retained session representations do not echo it.
    assert all(canary in client.sent[0] for canary in marker_canaries)
    assert all(canary not in b"".join(server.sent) for canary in marker_canaries)
    assert all(canary.decode() not in repr(client_session) for canary in marker_canaries)
    assert all(canary.decode() not in repr(server_session) for canary in marker_canaries)

    machine_scope = AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION)
    repository_scope = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE,
        _INSTALLATION,
        context.commitment,
    )
    task_scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
        context.commitment,
        _TASK,
    )
    machine_policy = replace(
        _policy(machine_scope),
        policy_id="pvy_50000000-0000-4000-8000-000000000008",
        policy_digest="sha256:" + "8" * 64,
    )
    repository_policy = replace(
        machine_policy,
        policy_id="pvy_50000000-0000-4000-8000-000000000009",
        policy_digest="sha256:" + "9" * 64,
        effective_scope=repository_scope,
    )
    env.db.execute(
        "UPDATE task_routes SET repository_privacy_commitment = ? WHERE task_id = ?",
        (context.commitment, _TASK),
    )
    await env.policies.seed_if_absent(machine_policy)
    await env.policies.seed_if_absent(repository_policy)
    authority = await env.policies.repository_authority(task_scope)
    approved = await env.coordinator.prepare_local_disclosure(
        _candidate(
            _REQUEST,
            "item-1",
            DataCategory.TASK_DESCRIPTION,
            "note:repository-bound",
            b"bounded content unrelated to the private locator",
            scope=task_scope,
        )
    )
    assert type(approved) is LocalDisclosureApproved
    assert authority.repository_privacy_commitment == context.commitment
    assert approved.receipt.scope.workspace_ref_commitment == context.commitment

    # Exercise the dedicated canonical policy and receipt columns in addition to scanning the
    # byte-level catalog/WAL/SHM and encrypted object corpus below.
    canonical_rows = env.db.execute(
        "SELECT policy_canonical FROM privacy_policy_versions "
        "UNION ALL SELECT subject_structural_canonical FROM privacy_audit_records "
        "UNION ALL SELECT receipt_canonical FROM privacy_audit_records "
        "WHERE receipt_canonical IS NOT NULL"
    ).fetchall()
    assert len(canonical_rows) >= 4
    for (canonical,) in canonical_rows:
        assert type(canonical) is bytes
        assert all(canary not in canonical for canary in marker_canaries)

    surfaces = env.surfaces()
    assert {"catalog_db", "catalog_db-wal", "catalog_db-shm"} <= surfaces.keys()
    for name, data in surfaces.items():
        findings = scan_for_sensitive_content(data, canaries=marker_canaries)
        assert findings == (), f"repository locator leaked into {name!r}: {findings}"

    retained_results = repr((authority, approved.receipt))
    assert all(canary.decode() not in retained_results for canary in marker_canaries)
    manifest = build_diagnostic_manifest(
        RedactionProfile.SUPPORT,
        {"workspace_locator": locator.path, "authority": retained_results},
    )
    assert all(canary.decode() not in repr(manifest) for canary in marker_canaries)

    configure_logging(LoggingConfig(level="debug"), LogMode.SERVICE, clock=_Clock())
    get_logger("repository_locator_canary_test").error(
        "simulated_fault",
        outcome=locator.path,
        correlation_id=locator.path,
    )
    captured = capsys.readouterr()
    assert all(canary.decode() not in captured.err for canary in marker_canaries)
    assert all(canary.decode() not in captured.out for canary in marker_canaries)


def test_ciphertext_matches_are_not_treated_as_plaintext(tmp_path: Path) -> None:
    env = _Env(tmp_path)
    canary = f"CIPHER-CANARY-{os.urandom(8).hex()}".encode()

    async def run() -> LocalDisclosureApproved:
        await env.policies.seed_if_absent(_policy())
        result = await env.coordinator.prepare_local_disclosure(
            _candidate(_REQUEST, "item-1", DataCategory.TASK_DESCRIPTION, "note:1", canary)
        )
        assert type(result) is LocalDisclosureApproved
        return result

    approved = asyncio.run(run())
    assert approved.approved_items[0].bounded_bytes == canary

    object_files = [
        path
        for path in env.bundle_root.rglob("*")
        if path.is_file() and ".staging" not in path.parts
    ]
    assert object_files, "the approved disclosure must have persisted an encrypted object"

    for path in object_files:
        raw = path.read_bytes()
        # The scanner never treats ciphertext-at-rest as a plaintext canary match: the AEAD
        # envelope's bytes on disk contain neither the raw canary nor its immediate codec form.
        assert scan_for_sensitive_content(raw, canaries=(canary,)) == ()
        assert canary not in raw

    # Prove this is a real, non-vacuous property: the *same* corpus, once genuinely decrypted
    # through the object store, really does recover the canary. The disclosure-proposal codec
    # base64-wraps a canonical JSON blob whose items are themselves base64-encoded, so recovering
    # the original bytes requires walking that exact two-layer envelope rather than a substring
    # search -- which is precisely why a raw byte scan of the ciphertext above is meaningful.
    ref = _reserved_content_ref(env, approved)

    async def decrypt() -> bytes:
        chunks = [chunk async for chunk in env.objects.open_verified(ref)]
        return b"".join(chunks)

    decrypted = asyncio.run(decrypt())
    envelope = json.loads(decrypted)
    inner = json.loads(base64.b64decode(envelope["prepared_bytes_base64"]))
    recovered = base64.b64decode(inner["items"][0]["content_base64"])
    assert recovered == canary


def _reserved_content_ref(env: _Env, approved: LocalDisclosureApproved) -> ObjectRef:
    row = env.db.execute(
        "SELECT content_object_id, content_plaintext_size, content_commitment, "
        "content_envelope_digest, content_encryption_format, content_key_slot, "
        "content_media_type, content_created_at, task_id "
        "FROM privacy_audit_records WHERE proposal_id = ?",
        (approved.privacy_proposal_id,),
    ).fetchone()
    assert row is not None
    return ObjectRef(
        row[0],
        row[1],
        row[2],
        row[3],
        row[4],
        row[5],
        ObjectMetadata(ObjectKind.PRIVACY_AUDIT, row[6], row[8], parse_rfc3339_millis(row[7])),
    )


def test_fault_paths_do_not_add_plaintext_leaks(tmp_path: Path) -> None:
    env = _Env(tmp_path)
    canary = f"FAULT-CANARY-{os.urandom(8).hex()}".encode()

    class _BrokenObjects:
        """Duck-typed ``ObjectStorePort`` whose staging step always fails."""

        def __init__(self, real: EncryptedFilesObjectStore) -> None:
            self._real = real

        async def stage(self, source: ObjectSource, metadata: ObjectMetadata) -> StagedObject:
            del source, metadata
            raise OSError("simulated_staging_failure")

        async def finalize(self, staged: StagedObject) -> ObjectRef:
            del staged
            raise AssertionError("unreachable: stage always fails first")

        async def commitment_for(self, data: bytes, kind: ObjectKind) -> str:
            return await self._real.commitment_for(data, kind)

        async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
            return await self._real.resolve_verified(object_id, envelope_digest)

        def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
            return self._real.open_verified(ref)

        async def sweep_orphans(self, root_snapshot: ObjectRootSnapshot, now: datetime) -> int:
            del root_snapshot, now
            return 0

    broken_audit = CatalogPrivacyAudit(
        env.db,
        _BrokenObjects(env.objects),  # type: ignore[arg-type]
        env.audit_key,
        _Clock(),
    )
    broken_coordinator = _coordinator(env.policies, broken_audit)

    async def run() -> object:
        await env.policies.seed_if_absent(_policy())
        with pytest.raises(OSError, match="simulated_staging_failure"):
            await broken_coordinator.prepare_local_disclosure(
                _candidate(_REQUEST, "item-1", DataCategory.TASK_DESCRIPTION, "note:1", canary)
            )
        # A second, unrelated request through the *working* coordinator must still function and
        # must not have inherited any partial state from the failed attempt.
        return await env.coordinator.prepare_local_disclosure(
            _candidate(
                _REQUEST_FAULT,
                "item-2",
                DataCategory.TASK_DESCRIPTION,
                "credential:leak",
                canary,
            )
        )

    result = asyncio.run(run())
    assert type(result) is LocalDisclosureBlocked

    surfaces = env.surfaces()
    for name, data in surfaces.items():
        findings = scan_for_sensitive_content(data, canaries=(canary,))
        assert findings == (), f"fault path leaked canary into {name!r}: {findings}"


@pytest.fixture(autouse=True)
def _restore_process_logging() -> Iterator[None]:  # pyright: ignore[reportUnusedFunction]
    """``configure_logging`` mutates process-global state; restore it for every other test."""

    root = logging.getLogger()
    root_handlers = tuple(root.handlers)
    root_level = root.level
    last_resort = logging.lastResort
    raise_exceptions = logging.raiseExceptions
    existing_loggers = {
        name: (tuple(logger.handlers), logger.propagate, logger.level)
        for name, logger in logging.root.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    yield
    root.handlers.clear()
    root.handlers.extend(root_handlers)
    root.setLevel(root_level)
    logging.lastResort = last_resort
    logging.raiseExceptions = raise_exceptions
    for name, state in existing_loggers.items():
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.handlers.extend(state[0])
        logger.propagate = state[1]
        logger.setLevel(state[2])


def test_fault_path_logging_and_manifest_surfaces_stay_canary_free(
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = f"LOG-CANARY-{os.urandom(8).hex()}"

    configure_logging(LoggingConfig(level="debug"), LogMode.SERVICE, clock=_Clock())
    logger = get_logger("privacy_canary_test")
    # Every field the logger accepts is validated/redacted; an out-of-shape value collapses to the
    # closed "unavailable" sentinel rather than ever echoing caller-supplied plaintext.
    logger.error("simulated_fault", outcome=canary, correlation_id=canary)

    captured = capsys.readouterr()
    assert canary not in captured.err
    assert canary not in captured.out

    manifest = build_diagnostic_manifest(RedactionProfile.RELEASE_PROBE, {"payload": canary})
    assert canary not in repr(manifest)
