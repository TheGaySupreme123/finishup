"""Network API keys and the shared wire codecs (ADR-051, server-native approach).

Keys are stored only as salted hashes in an owner-only canonical file, compared in constant time,
re-read by the service when the file changes, and every failure is a closed reason that never
carries the key. The shared module parses keys, claim headers and the API's small documents
strictly.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from builders.network_api import claim, service_status
from finishup.ports.control import ControlMethod, WorkspaceAgentDeclaration
from finishup.service.api_keys import API_KEYS_SCHEMA, ApiKeyError, ApiKeyStore
from finishup.service.network_protocol import (
    AgentRegistration,
    ServerInfo,
    agent_declaration_document,
    agent_registration_document,
    claim_principal_digest,
    encode_claim_header,
    method_allowed,
    mint_api_key,
    new_agent_id,
    parse_agent_declaration,
    parse_agent_registration,
    parse_api_key,
    parse_claim_header,
    parse_rest_error,
    parse_server_info,
    parse_wait_ms,
    rest_error_document,
    server_info_document,
)

_NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


@pytest.fixture
def store() -> Iterator[ApiKeyStore]:
    base = Path.home() / f".yz-keys-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        yield ApiKeyStore(base / "network")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_a_created_key_is_stored_hashed_owner_only_and_shown_once(store: ApiKeyStore) -> None:
    record, token = store.create("laptop", "agent", now=_NOW)
    assert parse_api_key(token) is not None
    data = store.path.read_bytes()
    assert token.encode() not in data
    assert parse_api_key(token).secret not in data  # type: ignore[union-attr]
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    assert API_KEYS_SCHEMA.encode() in data
    assert store.authenticate(token, now=_NOW) == record
    assert token not in repr(record) and record.hash not in repr(record)
    assert record.created_at == "2026-11-05T12:00:00.000Z"


def test_failures_are_closed_reasons_without_the_key(store: ApiKeyStore) -> None:
    record, token = store.create("laptop", "operator", now=_NOW)
    for candidate in ("", "fuk_short", token.replace(record.key_id, "f" * 12), "x" * 80):
        with pytest.raises(ApiKeyError) as raised:
            store.authenticate(candidate, now=_NOW)
        assert raised.value.reason == "api_key_invalid"
        assert token not in str(raised.value)
    assert store.revoke(record.key_id, now=_NOW) is True
    assert store.revoke(record.key_id, now=_NOW) is False
    with pytest.raises(ApiKeyError, match="api_key_revoked"):
        store.authenticate(token, now=_NOW)
    with pytest.raises(ApiKeyError, match="api_key_unknown"):
        store.revoke("0" * 12)


def test_expiry_and_rotation(store: ApiKeyStore) -> None:
    first, first_token = store.create("laptop", "agent", expires_in_days=1, now=_NOW)
    assert store.authenticate(first_token, now=_NOW + timedelta(hours=23)).key_id == first.key_id
    with pytest.raises(ApiKeyError, match="api_key_expired"):
        store.authenticate(first_token, now=_NOW + timedelta(days=1))
    second, _second_token = store.create("laptop-2", "operator", rotate=first.key_id, now=_NOW)
    third, _third_token = store.create("other", "agent", now=_NOW)
    assert second.principal == first.principal != third.principal
    assert not store.is_active(first.key_id, now=_NOW + timedelta(days=2))
    assert store.is_active(second.key_id, now=_NOW)
    with pytest.raises(ApiKeyError, match="api_key_unknown"):
        store.create("x", "agent", rotate="0" * 12)


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ({"label": "", "scope": "agent"}, "api_key_label_invalid"),
        ({"label": "bad\nlabel", "scope": "agent"}, "api_key_label_invalid"),
        ({"label": "ok", "scope": "root"}, "api_key_scope_invalid"),
        ({"label": "ok", "scope": "agent", "expires_in_days": 0}, "api_key_expiry_invalid"),
    ],
)
def test_creation_inputs_are_validated(
    store: ApiKeyStore, arguments: dict[str, object], reason: str
) -> None:
    with pytest.raises(ApiKeyError) as raised:
        store.create(**arguments)  # type: ignore[arg-type]
    assert raised.value.reason == reason
    assert not store.path.exists()


def test_the_service_rereads_the_file_when_it_changes(store: ApiKeyStore) -> None:
    other = ApiKeyStore(store.path.parent)
    record, token = store.create("laptop", "agent", now=_NOW)
    assert other.authenticate(token, now=_NOW).key_id == record.key_id
    store.revoke(record.key_id, now=_NOW)
    with pytest.raises(ApiKeyError, match="api_key_revoked"):
        other.authenticate(token, now=_NOW)


def test_an_unsafe_or_damaged_file_fails_closed(store: ApiKeyStore) -> None:
    _record, token = store.create("laptop", "agent", now=_NOW)
    store.path.chmod(0o644)
    with pytest.raises(ApiKeyError, match="api_keys_unsafe"):
        ApiKeyStore(store.path.parent).authenticate(token)
    store.path.chmod(0o600)
    store.path.write_bytes(b'{"keys":[],"schema":"other"}\n')
    with pytest.raises(ApiKeyError, match="api_keys_damaged"):
        ApiKeyStore(store.path.parent).records()


def test_api_key_tokens_have_one_spelling() -> None:
    token, text = mint_api_key()
    parsed = parse_api_key(text)
    assert parsed == token
    assert "<redacted>" in repr(parsed)
    # The last character carries two padding bits; only the zero-padded spelling is accepted.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    sibling = text[:-1] + alphabet[alphabet.index(text[-1]) ^ 1]
    assert parse_api_key(sibling) is None
    assert parse_api_key(text + "A") is None


def test_claim_headers_round_trip_and_refuse_paths() -> None:
    workspace = claim("x")
    assert parse_claim_header(encode_claim_header(workspace)) == workspace
    for raw in ("/home/me/repo", "git_common_root:" + "0" * 64, "repo:sha256:" + "0" * 64):
        with pytest.raises(ValueError):
            parse_claim_header(raw)
    first = claim_principal_digest(workspace, "p_" + "1" * 16)
    assert first == claim_principal_digest(workspace, "p_" + "1" * 16)
    assert first != claim_principal_digest(workspace, "p_" + "2" * 16)
    assert first.identity_kind == workspace.identity_kind and first.digest != workspace.digest


def test_documents_round_trip_strictly() -> None:
    info = ServerInfo(
        release="0.3.0",
        schema_manifest_digest="sha256:" + "a" * 64,
        status=service_status(),
        key_id="0123456789ab",
        scope="agent",
        transport="https",
        workspace_binding="client_claim",
        workspace_handle="client:" + "0" * 16,
    )
    assert parse_server_info(server_info_document(info)) == info
    with pytest.raises(ValueError):
        parse_server_info(server_info_document(info).replace(b'"agent"', b'"root"'))
    declaration = WorkspaceAgentDeclaration(("capture", "inspect"), 1024)
    assert parse_agent_declaration(agent_declaration_document(declaration)) == declaration
    registration = AgentRegistration(new_agent_id(), "client:" + "1" * 16, 60_000)
    assert parse_agent_registration(agent_registration_document(registration)) == registration
    assert parse_rest_error(rest_error_document("origin_forbidden")) == "origin_forbidden"
    assert parse_rest_error(b'{"reason":"free text","schema_version":"1.0.0"}') is None
    assert parse_wait_ms(None) == 25_000 and parse_wait_ms("0") == 0
    for raw in ("25001", "-1", "1.5", "x"):
        with pytest.raises(ValueError):
            parse_wait_ms(raw)


def test_scope_gate_is_per_method_and_claim() -> None:
    assert method_allowed("agent", ControlMethod.START, claim_bound=False)
    assert not method_allowed("agent", ControlMethod.PROJECT, claim_bound=False)
    assert method_allowed("operator", ControlMethod.PROJECT, claim_bound=False)
    assert not method_allowed("operator", ControlMethod.OBSERVATION_INGEST, claim_bound=False)
    assert method_allowed("agent", ControlMethod.OBSERVATION_INGEST, claim_bound=True)
    assert not method_allowed("operator", ControlMethod.BACKUP_EXECUTE, claim_bound=True)
