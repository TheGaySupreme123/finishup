"""Exact Codex app-server cell stays secret-free, context-free, and fail closed."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections import deque
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

import pytest

from yoetz.adapters.providers import codex_app_server as module
from yoetz.adapters.providers.codex_app_server import (
    CODEX_APP_SERVER_SCHEMA_SHA256,
    CODEX_EVALUATOR_CAPABILITY_CELL_SHA256,
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_CODE_MODE_HOST_SHA256,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    CODEX_EVALUATOR_LINUX_X64_CAPABILITY_CELL_SHA256,
    CODEX_EVALUATOR_LINUX_X64_CODE_MODE_HOST_SHA256,
    CODEX_EVALUATOR_LINUX_X64_EXECUTABLE_SHA256,
    CODEX_EVALUATOR_LINUX_X64_SOURCE_IDENTITY,
    CODEX_EVALUATOR_RUNTIME_VERSION,
    CodexAppServerEvaluator,
    CodexAppServerExternalFactory,
    CodexAppServerProfile,
    CodexReviewBudget,
    CodexRuntimeStatus,
)
from yoetz.adapters.providers.data_use_catalog import data_use_record_for_endpoint
from yoetz.adapters.providers.openai_responses import (
    JUDGMENT_JSON_SCHEMA,
    SEMANTIC_REVIEW_INSTRUCTION,
)
from yoetz.domain.findings import SemanticFailureClass
from yoetz.domain.privacy import (
    ApprovedOutboundCase,
    DataCategory,
    ProviderBinding,
    RequestCommitment,
)
from yoetz.ports.secret_memory import ProviderAttemptAuthBinding
from yoetz.ports.semantic import (
    Deadline,
    ExternalRuntimeAuthority,
    SemanticResultInvalid,
    SemanticResultRefused,
    SemanticResultSuccess,
    SemanticResultUnavailable,
)
from yoetz.ports.semantic_budget import semantic_budget_profile_scope
from yoetz.protocol.canonical import canonical_digest, canonical_encode

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "d" * 64
_COMMITMENT = "hmac-sha256:" + "a" * 64
_NOW = datetime(2026, 8, 30, tzinfo=UTC)


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


def _profile() -> CodexAppServerProfile:
    return CodexAppServerProfile(
        provider_id="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        endpoint_profile_version="1.0.0",
        executable_path=Path("/opt/codex/0.157.1/codex"),
        executable_sha256="sha256:27ceb5f9b957b43a519efe4eaa3816a0bffb0a531a2c89af18840c0a3c016a7d",
        runtime_version="0.157.1",
        source_identity="openai-codex-npm-darwin-arm64-0.157.1",
        app_server_schema_sha256=CODEX_APP_SERVER_SCHEMA_SHA256,
        capability_cell_sha256=CODEX_EVALUATOR_CAPABILITY_CELL_SHA256,
        capability_profile=CODEX_EVALUATOR_CAPABILITY_PROFILE,
        capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        codex_home=Path("/var/lib/yoetz/codex-0.150.1"),
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        model="gpt-5.6-sol",
        reasoning_effort="high",
        timeout_seconds=30,
        data_use_profile=data_use_record_for_endpoint("codex-chatgpt-subscription").profile,
    )


def test_committed_compatibility_cell_matches_runtime_constants() -> None:
    root = Path(__file__).resolve().parents[4]
    cell = json.loads((root / "support/codex-evaluator/0.157.1/cell.json").read_text("utf-8"))
    config = (root / "support/codex-evaluator/0.157.1/config.toml").read_bytes()

    assert cell["runtime_version"] == module.CODEX_EVALUATOR_RUNTIME_VERSION
    assert cell["app_server_schema_sha256"] == CODEX_APP_SERVER_SCHEMA_SHA256
    assert cell["capability_profile"] == CODEX_EVALUATOR_CAPABILITY_PROFILE
    assert cell["capability_cell_sha256"] == CODEX_EVALUATOR_CAPABILITY_CELL_SHA256
    assert cell["evidence_expires_at"] == CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT
    identity_keys = (
        "schema",
        "runtime_version",
        "distribution_kind",
        "distribution",
        "platform",
        "protocol",
        "executable_sha256",
        "app_server_schema_sha256",
        "isolated_config_sha256",
        "capability_profile",
        "credential_authority",
        "upstream_body_observability",
        "evidence_reviewed_at",
        "evidence_expires_at",
        "code_mode_host_sha256",
    )
    assert canonical_digest({key: cell[key] for key in identity_keys}) == (
        CODEX_EVALUATOR_CAPABILITY_CELL_SHA256
    )
    assert cell["isolated_config_sha256"] == CODEX_EVALUATOR_CONFIG_SHA256
    assert "sha256:" + hashlib.sha256(config).hexdigest() == CODEX_EVALUATOR_CONFIG_SHA256
    assert config.decode("utf-8") == module.CODEX_EVALUATOR_CONFIG
    assert cell["upstream_body_observability"] == "unavailable"
    assert cell["release_evidence"] == "pending"
    assert cell["code_mode_host_sha256"] == CODEX_EVALUATOR_CODE_MODE_HOST_SHA256
    assert cell["capability_profile"] == "codex-evaluator/0.157.1/v2"


def test_committed_linux_compatibility_cell_matches_runtime_constants() -> None:
    root = Path(__file__).resolve().parents[4]
    cell = json.loads(
        (root / "support/codex-evaluator/0.157.1/cell-linux-x64.json").read_text("utf-8")
    )
    identity_keys = (
        "schema",
        "runtime_version",
        "distribution_kind",
        "distribution",
        "platform",
        "protocol",
        "executable_sha256",
        "app_server_schema_sha256",
        "isolated_config_sha256",
        "capability_profile",
        "credential_authority",
        "upstream_body_observability",
        "evidence_reviewed_at",
        "evidence_expires_at",
        "code_mode_host_sha256",
    )

    assert cell["runtime_version"] == CODEX_EVALUATOR_RUNTIME_VERSION
    assert cell["app_server_schema_sha256"] == CODEX_APP_SERVER_SCHEMA_SHA256
    assert cell["capability_profile"] == CODEX_EVALUATOR_CAPABILITY_PROFILE
    assert cell["capability_cell_sha256"] == CODEX_EVALUATOR_LINUX_X64_CAPABILITY_CELL_SHA256
    assert cell["executable_sha256"] == CODEX_EVALUATOR_LINUX_X64_EXECUTABLE_SHA256
    assert cell["isolated_config_sha256"] == CODEX_EVALUATOR_CONFIG_SHA256
    assert canonical_digest({key: cell[key] for key in identity_keys}) == (
        CODEX_EVALUATOR_LINUX_X64_CAPABILITY_CELL_SHA256
    )
    assert cell["platform"] == {"architecture": "x86_64", "os": "linux"}
    assert cell["release_evidence"] == "pending"
    runtime_cell = module.codex_evaluator_cell_for_platform("linux", "x86_64")
    assert cell["code_mode_host_sha256"] == CODEX_EVALUATOR_LINUX_X64_CODE_MODE_HOST_SHA256
    assert runtime_cell.code_mode_host_sha256 == CODEX_EVALUATOR_LINUX_X64_CODE_MODE_HOST_SHA256
    assert (
        cell["code_mode_host_relative"]
        == (
            runtime_cell.native_executable_relative.parent / module.CODEX_CODE_MODE_HOST_NAME
        ).as_posix()
    )
    assert cell["native_package"] == f"@openai/{runtime_cell.native_package_directory}"
    assert cell["native_executable_relative"] == (
        runtime_cell.native_executable_relative.as_posix()
    )


def test_linux_cell_identity_binds_the_native_digest_and_package_alias() -> None:
    cell = module.codex_evaluator_cell_for_platform("linux", "x86_64")
    assert module.codex_evaluator_cell_for_platform("linux2", "amd64") is cell

    assert cell.source_identity == CODEX_EVALUATOR_LINUX_X64_SOURCE_IDENTITY
    assert cell.executable_sha256 == CODEX_EVALUATOR_LINUX_X64_EXECUTABLE_SHA256
    assert cell.capability_cell_sha256 == CODEX_EVALUATOR_LINUX_X64_CAPABILITY_CELL_SHA256
    assert cell.native_package_directory == "codex-linux-x64"
    assert cell.native_package_spec == "npm:@openai/codex@0.157.1-linux-x64"
    assert cell.native_executable_relative.as_posix() == (
        "vendor/x86_64-unknown-linux-musl/bin/codex"
    )


def test_linux_cell_rejects_mac_digest_or_source_identity() -> None:
    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        module.codex_evaluator_cell_for_binding(
            source_identity=CODEX_EVALUATOR_LINUX_X64_SOURCE_IDENTITY,
            executable_sha256="sha256:27ceb5f9b957b43a519efe4eaa3816a0bffb0a531a2c89af18840c0a3c016a7d",
            runtime_version="0.157.1",
            app_server_schema_sha256=CODEX_APP_SERVER_SCHEMA_SHA256,
            capability_cell_sha256=CODEX_EVALUATOR_LINUX_X64_CAPABILITY_CELL_SHA256,
            capability_profile=CODEX_EVALUATOR_CAPABILITY_PROFILE,
            capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
            isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        )

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        module.codex_evaluator_cell_for_binding(
            source_identity="openai-codex-npm-darwin-arm64-0.157.1",
            executable_sha256=CODEX_EVALUATOR_LINUX_X64_EXECUTABLE_SHA256,
            runtime_version="0.157.1",
            app_server_schema_sha256=CODEX_APP_SERVER_SCHEMA_SHA256,
            capability_cell_sha256=CODEX_EVALUATOR_LINUX_X64_CAPABILITY_CELL_SHA256,
            capability_profile=CODEX_EVALUATOR_CAPABILITY_PROFILE,
            capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
            isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        )


@pytest.mark.parametrize(
    ("source_identity", "executable_sha256", "capability_cell_sha256"),
    [
        (
            "openai-codex-npm-darwin-arm64-0.150.1",
            "sha256:a14f9a907c12c8812878b70e6b7d65f81c39ed795513e46a55817d7428c0ca6b",
            "sha256:c04d2dd111c85d323c3f96c7041bb598f047fff9f73b84f916d38b5321d32cfa",
        ),
        (
            "openai-codex-npm-linux-x64-0.150.1",
            "sha256:abf1bb1643a79f73aa78ee627e111e02d4f8c98f25813a0cf6ce277709664386",
            "sha256:3fac9e18eca7395b14166114ebf49eaaae5fe3061e86c0d5b76eb17b54488cab",
        ),
    ],
)
def test_the_superseded_0_150_1_cells_are_no_longer_admitted(
    source_identity: str, executable_sha256: str, capability_cell_sha256: str
) -> None:
    """A binding written under the replaced cell must go through repair, never launch."""

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        module.codex_evaluator_cell_for_binding(
            source_identity=source_identity,
            executable_sha256=executable_sha256,
            runtime_version="0.150.1",
            app_server_schema_sha256=(
                "sha256:8cdccfc35582696d7141e7f916e0d5a664ab5b5e90b732f104284d2507f369f8"
            ),
            capability_cell_sha256=capability_cell_sha256,
            capability_profile="codex-evaluator/0.150.1/v2",
            capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
            isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        )


def test_macos_cell_binds_the_exact_0_157_1_native_package() -> None:
    cell = module.codex_evaluator_cell_for_platform("darwin", "arm64")

    assert CODEX_EVALUATOR_RUNTIME_VERSION == "0.157.1"
    assert cell.source_identity == "openai-codex-npm-darwin-arm64-0.157.1"
    assert cell.executable_sha256 == (
        "sha256:27ceb5f9b957b43a519efe4eaa3816a0bffb0a531a2c89af18840c0a3c016a7d"
    )
    assert cell.capability_cell_sha256 == CODEX_EVALUATOR_CAPABILITY_CELL_SHA256
    assert cell.native_package_spec == "npm:@openai/codex@0.157.1-darwin-arm64"
    assert cell.code_mode_host_sha256 == (
        "sha256:80fdf166c3da068282d5692f67a852715a327ae7dc1913abb93b8c3d3030103f"
    )
    assert CODEX_EVALUATOR_LINUX_X64_CODE_MODE_HOST_SHA256 == (
        "sha256:67b86142bac5cead11b8420cf32d3a2bf88c8868d71733f351ed7c5d95a953e0"
    )
    assert CODEX_EVALUATOR_CAPABILITY_PROFILE == "codex-evaluator/0.157.1/v2"
    assert module.codex_code_mode_host_path(Path("/store/codex")) == Path(
        "/store/codex-code-mode-host"
    )
    assert cell.native_executable_relative.as_posix() == "vendor/aarch64-apple-darwin/bin/codex"


def test_local_binding_rejects_a_mac_cell_on_linux_before_file_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")

    with pytest.raises(ValueError, match="codex_runtime_platform_unsupported"):
        _profile().verify_local_binding()


def test_codex_output_schema_omits_provider_rejected_keywords() -> None:
    def keys(value: object) -> set[str]:
        if type(value) is dict:
            source = cast(dict[str, object], value)
            result = set(source)
            for item in source.values():
                result.update(keys(item))
            return result
        if type(value) is list:
            result: set[str] = set()
            for item in cast(list[object], value):
                result.update(keys(item))
            return result
        return set()

    assert "uniqueItems" in keys(JUDGMENT_JSON_SCHEMA)
    sent = keys(module._CODEX_JUDGMENT_JSON_SCHEMA)  # pyright: ignore[reportPrivateUsage]
    assert not {"allOf", "default", "if", "not", "then", "uniqueItems"} & sent


def _case() -> ApprovedOutboundCase:
    payload = canonical_encode({"schema": "yoetz.semantic-check-candidate/1", "items": []})
    return ApprovedOutboundCase(
        case_id="cas_64000000-0000-4000-8000-000000000001",
        request_id="req_64000000-0000-4000-8000-000000000001",
        payload=payload,
        media_type="application/json",
        schema_id="yoetz-semantic-case-1.0.0",
        included_item_ids=("case-packet",),
        approved_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        blocked_categories=(),
        byte_count=len(payload),
        token_count=8,
        provider_binding=ProviderBinding(
            "openai-codex",
            "gpt-5.6-sol",
            "codex-chatgpt-subscription",
            "1.0.0",
            "external",
        ),
        purpose="semantic-review",
        authorization_id="aut_64000000-0000-4000-8000-000000000001",
        policy_digest=_DIGEST,
        case_digest="sha256:" + "c" * 64,
    )


def _attempt(
    case: ApprovedOutboundCase,
) -> tuple[ProviderAttemptAuthBinding, ExternalRuntimeAuthority]:
    body_digest = module._sha256_bytes(  # pyright: ignore[reportPrivateUsage]
        case.payload
    )
    binding = ProviderAttemptAuthBinding(
        provider_id="openai-codex",
        model_id="gpt-5.6-sol",
        endpoint_profile_id="codex-chatgpt-subscription",
        endpoint_profile_version="1.0.0",
        purpose="semantic-review",
        authorization_scope_digest=_DIGEST,
        purpose_digest=canonical_digest({"purpose": "semantic-review"}),
        dispatch_id="dsp_64000000-0000-4000-8000-000000000001",
        request_body_digest=body_digest,
        service_generation=1,
        monotonic_deadline=30.0,
    )
    return binding, ExternalRuntimeAuthority(
        dispatch_id=binding.dispatch_id,
        request_body_digest=body_digest,
        request_commitment=_COMMITMENT,
        service_generation=1,
        monotonic_deadline=30.0,
    )


_THREAD_ID = "019a0000-0000-7000-8000-000000000001"
_TURN_ID = "019a0000-0000-7000-8000-000000000002"


def _token_usage_notice(
    *,
    thread_id: str = _THREAD_ID,
    turn_id: str = _TURN_ID,
    total_input: int = 100,
    total_cached: int = 40,
    total_cache_write: int = 0,
    total_output: int = 30,
    total_reasoning: int = 10,
    last_input: int = 100,
    last_cached: int = 40,
    last_cache_write: int = 0,
    last_output: int = 30,
    last_reasoning: int = 10,
) -> dict[str, object]:
    def breakdown(
        input_tokens: int,
        cached_input_tokens: int,
        cache_write_input_tokens: int,
        output_tokens: int,
        reasoning_output_tokens: int,
    ) -> dict[str, int]:
        return {
            "inputTokens": input_tokens,
            "cachedInputTokens": cached_input_tokens,
            "cacheWriteInputTokens": cache_write_input_tokens,
            "outputTokens": output_tokens,
            "reasoningOutputTokens": reasoning_output_tokens,
            "totalTokens": input_tokens + output_tokens,
        }

    return {
        "method": "thread/tokenUsage/updated",
        "params": {
            "threadId": thread_id,
            "turnId": turn_id,
            "tokenUsage": {
                "last": breakdown(
                    last_input,
                    last_cached,
                    last_cache_write,
                    last_output,
                    last_reasoning,
                ),
                "total": breakdown(
                    total_input,
                    total_cached,
                    total_cache_write,
                    total_output,
                    total_reasoning,
                ),
            },
        },
    }


class _Runtime:
    def __init__(
        self,
        profile: CodexAppServerProfile,
        *,
        model_available: bool = True,
        account: object = None,
        predisclosure_event: dict[str, object] | None = None,
    ) -> None:
        self.profile = profile
        self.workdir = Path("/private/empty-attempt")
        self.pending_notifications: deque[dict[str, object]] = deque()
        self.model_available = model_available
        self.account = (
            {"type": "chatgpt", "email": "discard@example", "planType": "plus"}
            if account is None
            else account
        )
        self.predisclosure_event = predisclosure_event
        self.supported_efforts: tuple[str, ...] = ("high",)
        self.params: dict[str, object] = {}
        self.sent: list[dict[str, object]] = []
        self.methods: list[str] = []
        self.events: list[dict[str, object]] = [
            {
                "method": "item/completed",
                "params": {
                    "item": {
                        "type": "agentMessage",
                        "text": (
                            '{"conclusion":"no_material_discrepancy",'
                            '"review_summary":"The supplied packet was reviewed.",'
                            '"verified":[],"reviewer_challenges":[],"prior_finding_verdicts":[]}'
                        ),
                    }
                },
            },
            {
                "method": "turn/completed",
                "params": {
                    "threadId": "019a0000-0000-7000-8000-000000000001",
                    "turn": {
                        "id": "019a0000-0000-7000-8000-000000000002",
                        "status": "completed",
                        "error": None,
                    },
                },
            },
        ]

    async def send(self, value: dict[str, object]) -> None:
        self.sent.append(value)

    async def request(
        self, request_id: int, method: str, params: object, timeout: float
    ) -> dict[str, object]:
        del request_id, timeout
        self.methods.append(method)
        self.params[method] = params
        if method == "initialize":
            return {
                "codexHome": str(self.profile.codex_home),
                "userAgent": "yoetz_semantic_evaluator/0.157.1",
            }
        if method == "account/read":
            return {"account": self.account}
        if method == "model/list":
            return {
                "data": (
                    [
                        {
                            "id": self.profile.model,
                            "supportedReasoningEfforts": [
                                {"reasoningEffort": effort} for effort in self.supported_efforts
                            ],
                        }
                    ]
                    if self.model_available
                    else []
                ),
                "nextCursor": None,
            }
        if method == "thread/start":
            if self.predisclosure_event is not None:
                self.pending_notifications.append(self.predisclosure_event)
            return {
                "thread": {
                    "id": "019a0000-0000-7000-8000-000000000001",
                    "ephemeral": True,
                    "path": None,
                    "cwd": str(self.workdir),
                },
                "cwd": str(self.workdir),
                "model": self.profile.model,
                "modelProvider": "openai",
                "sandbox": {"type": "readOnly", "networkAccess": False},
                "instructionSources": [],
            }
        if method == "turn/start":
            return {
                "turn": {
                    "id": "019a0000-0000-7000-8000-000000000002",
                    "status": "inProgress",
                }
            }
        raise AssertionError(method)

    async def read(self, timeout: float) -> dict[str, object]:
        del timeout
        return self.events.pop(0)


class _LoginRuntime:
    def __init__(
        self,
        profile: CodexAppServerProfile,
        events: list[object],
        *,
        account_results: list[Mapping[str, object]] | None = None,
        login_result: Mapping[str, object] | None = None,
        login_notifications: list[dict[str, object]] | None = None,
        cancel_error: BaseException | None = None,
        block_read: bool = False,
    ) -> None:
        self.profile = profile
        self.workdir = Path("/private/empty-login-attempt")
        self.events = list(events)
        self.account_results: list[Mapping[str, object]] = list(
            account_results or [{"account": {"type": "chatgpt", "planType": "plus"}}]
        )
        self.login_result = login_result
        self.login_notifications = list(login_notifications or [])
        self.cancel_error = cancel_error
        self.block_read = block_read
        self.pending_notifications: deque[dict[str, object]] = deque()
        self.methods: list[str] = []
        self.timeouts: list[float] = []
        self.read_timeouts: list[float] = []
        self.sent: list[dict[str, object]] = []
        self.read_started = asyncio.Event()
        self.release_read = asyncio.Event()

    async def send(self, value: dict[str, object]) -> None:
        self.sent.append(value)

    async def request(
        self, request_id: int, method: str, params: object, timeout: float
    ) -> Mapping[str, object]:
        del request_id
        self.methods.append(method)
        self.timeouts.append(timeout)
        if method == "initialize":
            return {
                "codexHome": str(self.profile.codex_home),
                "userAgent": "yoetz_semantic_evaluator/0.157.1",
            }
        if method == "account/login/start":
            assert isinstance(params, dict)
            self.pending_notifications.extend(self.login_notifications)
            if self.login_result is not None:
                return self.login_result
            if params["type"] == "chatgpt":
                return {
                    "type": "chatgpt",
                    "loginId": "login-1",
                    "authUrl": "https://chatgpt.com/auth",
                }
            return {
                "type": "chatgptDeviceCode",
                "loginId": "login-1",
                "verificationUrl": "https://auth.openai.com/codex/device",
                "userCode": "ABCD-1234",
            }
        if method == "account/login/cancel":
            if self.cancel_error is not None:
                raise self.cancel_error
            return {}
        if method == "account/read":
            result = self.account_results.pop(0)
            if self.account_results:
                self.pending_notifications.append({"method": "account/updated", "params": {}})
            return result
        if method == "model/list":
            return {
                "data": [
                    {
                        "id": self.profile.model,
                        "supportedReasoningEfforts": [
                            {"reasoningEffort": self.profile.reasoning_effort}
                        ],
                    }
                ],
                "nextCursor": None,
            }
        raise AssertionError(method)

    async def read(self, timeout: float) -> dict[str, object]:
        self.timeouts.append(timeout)
        self.read_timeouts.append(timeout)
        self.read_started.set()
        if self.block_read:
            await self.release_read.wait()
        if not self.events:
            raise TimeoutError
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        assert isinstance(event, dict)
        return cast(dict[str, object], event)


async def _evaluate(
    monkeypatch: pytest.MonkeyPatch,
    runtime: _Runtime,
    *,
    cleanup_outcome: str = "terminated",
    budget: CodexReviewBudget | None = None,
) -> SemanticResultSuccess | SemanticResultUnavailable | SemanticResultInvalid:
    async def launch(profile: CodexAppServerProfile) -> _Runtime:
        assert profile is runtime.profile
        return runtime

    async def cleanup(value: object) -> str:
        assert value is runtime
        return cleanup_outcome

    monkeypatch.setattr(module, "_launch", launch)
    monkeypatch.setattr(module, "_cleanup", cleanup)
    case = _case()
    binding, authority = _attempt(case)
    evaluator = CodexAppServerEvaluator(runtime.profile, binding, authority, _Clock(), budget)
    return cast(
        SemanticResultSuccess | SemanticResultUnavailable | SemanticResultInvalid,
        await evaluator.evaluate(case, Deadline(_NOW + timedelta(seconds=30), 30.0)),
    )


async def _login(
    monkeypatch: pytest.MonkeyPatch,
    runtime: _LoginRuntime,
    *,
    mode: str = "browser",
) -> CodexRuntimeStatus:
    async def launch(profile: CodexAppServerProfile) -> _LoginRuntime:
        assert profile is runtime.profile
        return runtime

    async def cleanup(value: object) -> str:
        assert value is runtime
        return "terminated"

    monkeypatch.setattr(module, "_launch", launch)
    monkeypatch.setattr(module, "_cleanup", cleanup)
    return await module.codex_login(
        runtime.profile,
        mode=cast("Literal['browser', 'device_code']", mode),
        present_challenge=lambda _challenge: None,
    )


@pytest.mark.parametrize(
    ("mode", "expected_timeout"),
    [("browser", 600.0), ("device_code", 900.0)],
)
async def test_login_uses_the_native_method_window(
    monkeypatch: pytest.MonkeyPatch, mode: str, expected_timeout: float
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [
            {
                "method": "account/login/completed",
                "params": {"loginId": "login-1", "success": True},
            }
        ],
    )

    result = await _login(monkeypatch, runtime, mode=mode)

    assert result.auth_mode == "chatgpt"
    assert result.model_available is True
    assert any(timeout >= expected_timeout - 0.1 for timeout in runtime.timeouts)
    assert runtime.methods.count("account/login/cancel") == 0


@pytest.mark.parametrize("mode", ["browser", "device_code"])
async def test_login_demultiplexes_exact_remote_control_notice_before_completion(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [
            {
                "method": "account/login/completed",
                "params": {"loginId": "login-1", "success": True},
            }
        ],
        # Codex 0.150.1 and 0.157.1 emit this notification while account/login/start is in
        # flight. The request buffers it before returning the login challenge, as the native
        # process does.
        login_notifications=[
            {
                "method": "remoteControl/status/changed",
                "params": {
                    "environmentId": None,
                    "installationId": "discard-installation-canary",
                    "serverName": "discard-server-canary",
                    "status": "disabled",
                },
            }
        ],
    )

    result = await _login(monkeypatch, runtime, mode=mode)

    assert result.auth_mode == "chatgpt"
    assert result.model_available is True
    assert runtime.methods.count("account/login/cancel") == 0
    assert not runtime.pending_notifications
    assert "discard-installation-canary" not in repr(result)
    assert "discard-server-canary" not in repr(result)


_RATE_LIMITS_NOTICE: dict[str, object] = {
    "method": "account/rateLimits/updated",
    "params": {
        "rateLimits": {
            "limitId": "codex",
            "limitName": None,
            "primary": {"usedPercent": 3, "windowDurationMins": 10080, "resetsAt": 1788698233},
            "secondary": None,
            "credits": {"hasCredits": False, "unlimited": False, "balance": "discard-balance"},
            "individualLimit": None,
            "spendControlReached": None,
            "planType": "prolite",
            "rateLimitReachedType": None,
        }
    },
}
_REMOTE_CONTROL_NOTICE: dict[str, object] = {
    "method": "remoteControl/status/changed",
    "params": {
        "environmentId": None,
        "installationId": "discard-installation-canary",
        "serverName": "discard-server-canary",
        "status": "disabled",
    },
}
_LOGIN_COMPLETED: dict[str, object] = {
    "method": "account/login/completed",
    "params": {"loginId": "login-1", "success": True},
}


@pytest.mark.parametrize(
    "snapshot",
    [
        {},
        {"limitId": "premium", "primary": None, "secondary": None},
        {"limitId": None, "credits": None, "individualLimit": None},
        {"limitId": "other-bucket", "primary": {"usedPercent": 100}},
        {"secondary": {"usedPercent": 0, "resetsAt": None, "windowDurationMins": None}},
        {"credits": {"hasCredits": True, "unlimited": False}},
        {"limitId": "codex", "normalModelSlug": "gpt-6-luna"},
        {"normalModelSlug": None},
        {
            "individualLimit": {
                "limit": "10.0",
                "remainingPercent": 0,
                "resetsAt": 1,
                "used": "10.0",
            }
        },
    ],
)
async def test_sparse_rate_limit_snapshots_do_not_prevent_a_valid_answer(
    monkeypatch: pytest.MonkeyPatch, snapshot: dict[str, object]
) -> None:
    runtime = _Runtime(_profile())
    notice: dict[str, object] = {
        "method": "account/rateLimits/updated",
        "params": {"rateLimits": snapshot},
    }
    # Exercise the strict pre-disclosure validator too; post-ack fallback must not mask
    # accidental rejection of a sparse shape the pinned app-server schema allows.
    module._discard_rate_limits_notification(notice)  # pyright: ignore[reportPrivateUsage]
    runtime.events.insert(0, notice)
    result = await _evaluate(monkeypatch, runtime)
    assert type(result) is SemanticResultSuccess
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage is None


@pytest.mark.parametrize(
    "snapshot",
    [
        {"limitId": "premium", "primary": None, "secondary": None},
        {"limitId": 42, "limitName": "private-account-canary"},
    ],
)
@pytest.mark.parametrize(
    ("native_error", "failure_class"),
    [
        ("usageLimitExceeded", SemanticFailureClass.QUOTA_EXHAUSTED),
        ("rateLimitExceeded", SemanticFailureClass.RATE_LIMITED),
        ({"httpConnectionFailed": {"httpStatusCode": 429}}, SemanticFailureClass.RATE_LIMITED),
    ],
)
async def test_rate_limit_bookkeeping_cannot_mask_authoritative_quota_or_rate_errors(
    monkeypatch: pytest.MonkeyPatch,
    snapshot: dict[str, object],
    native_error: object,
    failure_class: SemanticFailureClass,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events[:0] = [
        {"method": "account/rateLimits/updated", "params": {"rateLimits": snapshot}},
        {
            "method": "error",
            "params": {
                "error": {"codexErrorInfo": native_error, "message": "private-account-canary"}
            },
        },
    ]
    result = await _evaluate(monkeypatch, runtime)
    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is failure_class
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "turn_failed"
    assert result.provenance.runtime_evidence.turn_acknowledged is True
    assert result.provenance.runtime_evidence.process_cleanup == "terminated"
    assert "private-account-canary" not in repr(result)


@pytest.mark.parametrize(
    "snapshot",
    [
        None,
        [],
        {"unexpected": "private-account-canary"},
        {"limitId": 42},
        {"limitName": "x" * 129},
        {"normalModelSlug": 42},
        {"normalModelSlug": "x" * 129},
        {"planType": []},
        {"spendControlReached": 1},
        {"rateLimitReachedType": "unknown-canary"},
        {"primary": {}},
        {"primary": {"usedPercent": True}},
        {"primary": {"usedPercent": 1.5}},
        {"primary": {"usedPercent": 2**31}},
        {"secondary": {"usedPercent": 1, "resetsAt": 2**63}},
        {"secondary": {"usedPercent": 1, "windowDurationMins": "1"}},
        {"credits": {"hasCredits": 1, "unlimited": False}},
        {"credits": {"hasCredits": True, "unlimited": False, "balance": "x" * 65}},
        {"individualLimit": {"limit": None, "remainingPercent": 1, "resetsAt": 1, "used": "1"}},
    ],
)
async def test_malformed_rate_limit_snapshot_records_only_nonterminal_diagnostic(
    monkeypatch: pytest.MonkeyPatch, snapshot: object
) -> None:
    notice: dict[str, object] = {
        "method": "account/rateLimits/updated",
        "params": {"rateLimits": snapshot},
    }
    with pytest.raises(ValueError, match="^codex_app_server_rate_limits_invalid$"):
        module._discard_rate_limits_notification(notice)  # pyright: ignore[reportPrivateUsage]
    runtime = _Runtime(_profile())
    runtime.events.insert(0, notice)
    result = await _evaluate(monkeypatch, runtime)
    assert type(result) is SemanticResultSuccess
    assert result.provenance.failure_class is None
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "rate_limits_invalid"
    assert "canary" not in repr(result)


@pytest.mark.parametrize(
    "notice",
    [
        {"method": "unreviewed/method", "params": {}},
        {"method": "account/rateLimits/updated", "id": 99, "params": {}},
        {"method": "item/started", "params": {"item": {"type": "commandExecution"}}},
        # Codex 0.157.1 schema additions that were reviewed and deliberately not allowlisted.
        {"method": "item/completed", "params": {"item": {"type": "functionCallOutput"}}},
        {
            "method": "modelProvider/authRecoveryStarted",
            "params": {"message": "canary", "provider": "openai", "threadId": "t", "turnId": "u"},
        },
        {"method": "thread/attachment/updated", "params": {"threadId": "t"}},
        {"method": "account/gatewayOAuth/changed", "params": {}},
    ],
)
async def test_post_ack_isolation_failures_remain_terminal_without_answer_blame(
    monkeypatch: pytest.MonkeyPatch, notice: dict[str, object]
) -> None:
    runtime = _Runtime(_profile())
    runtime.events.insert(0, notice)
    result = await _evaluate(monkeypatch, runtime)
    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.UNSUPPORTED_PROFILE
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.final_output_sha256 is None
    assert result.provenance.runtime_evidence.process_cleanup == "terminated"


async def test_login_demultiplexes_every_reviewed_predisclosure_notice_in_the_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [_RATE_LIMITS_NOTICE, _REMOTE_CONTROL_NOTICE, _LOGIN_COMPLETED],
        login_notifications=[_REMOTE_CONTROL_NOTICE],
    )

    result = await _login(monkeypatch, runtime)

    assert result.auth_mode == "chatgpt"
    assert result.model_available is True
    assert runtime.methods.count("account/login/cancel") == 0
    assert "discard-balance" not in repr(result)
    assert "discard-installation-canary" not in repr(result)


async def test_login_tolerates_predisclosure_notices_around_the_account_projection_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [
            _LOGIN_COMPLETED,
            _RATE_LIMITS_NOTICE,
            {"method": "account/updated", "params": {"account": {"type": "chatgpt"}}},
        ],
        account_results=[
            {"account": None},
            {"account": {"type": "chatgpt", "planType": "plus"}},
        ],
    )

    result = await _login(monkeypatch, runtime)

    assert result.auth_mode == "chatgpt"
    assert runtime.methods.count("account/read") == 2
    assert runtime.methods.count("account/login/cancel") == 0


@pytest.mark.parametrize(
    "notice",
    [
        {"method": "warning", "params": {"message": "native-text-canary", "threadId": "t"}},
        {
            "method": "remoteControl/status/changed",
            "params": {
                "environmentId": None,
                "installationId": "i",
                "serverName": "s",
                "status": "enabled-canary",
            },
        },
        {"method": "thread/name/updated", "params": {"threadId": "t", "threadName": "canary"}},
        {"method": "item/completed", "params": {"item": {"type": "commandExecution"}}},
        {"method": "account/rateLimits/updated", "params": {"rateLimits": {"limitId": 42}}},
    ],
)
async def test_login_still_fails_closed_on_unallowlisted_or_malformed_notices(
    monkeypatch: pytest.MonkeyPatch, notice: dict[str, object]
) -> None:
    runtime = _LoginRuntime(_profile(), [notice, _LOGIN_COMPLETED])

    with pytest.raises(ValueError) as info:
        await _login(monkeypatch, runtime)

    assert str(info.value) in {
        "codex_login_event_invalid",
        "codex_app_server_remote_control_not_disabled",
        "codex_app_server_rate_limits_invalid",
    }
    assert "canary" not in repr(info.value) and "canary" not in repr(info.value.__cause__)
    assert runtime.methods.count("account/login/cancel") == 1


async def test_login_accepts_terminal_event_in_bounded_grace_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [
            TimeoutError(),
            {
                "method": "account/login/completed",
                "params": {"loginId": "login-1", "success": True},
            },
        ],
    )

    result = await _login(monkeypatch, runtime)

    assert result.auth_mode == "chatgpt"
    assert runtime.methods.count("account/login/cancel") == 0
    assert runtime.read_timeouts[-1] <= module._LOGIN_TERMINAL_GRACE_SECONDS  # pyright: ignore[reportPrivateUsage]


async def test_login_timeout_cancels_native_flow_without_masking_primary_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [TimeoutError(), TimeoutError()],
        cancel_error=RuntimeError("native detail must not escape"),
    )

    with pytest.raises(TimeoutError):
        await _login(monkeypatch, runtime)

    assert runtime.methods.count("account/login/cancel") == 1


async def test_login_invalid_terminal_cancels_native_flow_without_masking_primary_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [{"method": "unexpected/notification", "params": {}}],
    )

    with pytest.raises(ValueError, match="codex_login_event_invalid"):
        await _login(monkeypatch, runtime)

    assert runtime.methods.count("account/login/cancel") == 1


@pytest.mark.parametrize("returned_id", [None, 5, "login-other"])
async def test_login_rejects_unbound_or_mismatched_completion(
    monkeypatch: pytest.MonkeyPatch, returned_id: object
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [
            {
                "method": "account/login/completed",
                "params": {"loginId": returned_id, "success": True},
            }
        ],
    )

    with pytest.raises(ValueError, match="codex_login_event_invalid"):
        await _login(monkeypatch, runtime)

    assert runtime.methods.count("account/login/cancel") == 1


async def test_login_rejects_challenge_mode_different_from_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [],
        login_result={
            "type": "chatgptDeviceCode",
            "loginId": "login-1",
            "verificationUrl": "https://auth.openai.com/codex/device",
            "userCode": "ABCD-1234",
        },
    )

    with pytest.raises(ValueError, match="codex_login_response_invalid"):
        await _login(monkeypatch, runtime, mode="browser")

    assert runtime.methods.count("account/login/cancel") == 1


async def test_login_waits_for_account_projection_after_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(
        _profile(),
        [
            {
                "method": "account/login/completed",
                "params": {"loginId": "login-1", "success": True},
            }
        ],
        account_results=[
            {"account": None},
            {"account": {"type": "chatgpt", "planType": "plus"}},
        ],
    )

    result = await _login(monkeypatch, runtime)

    assert result.auth_mode == "chatgpt"
    assert runtime.methods.count("account/read") == 2
    assert runtime.methods.count("account/login/cancel") == 0


async def test_login_preserves_cancellation_and_still_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(_profile(), [], block_read=True)
    cleaned = False

    async def launch(profile: CodexAppServerProfile) -> _LoginRuntime:
        assert profile is runtime.profile
        return runtime

    async def cleanup(value: object) -> str:
        nonlocal cleaned
        assert value is runtime
        cleaned = True
        return "terminated"

    monkeypatch.setattr(module, "_launch", launch)
    monkeypatch.setattr(module, "_cleanup", cleanup)
    task = asyncio.create_task(
        module.codex_login(
            runtime.profile,
            mode="browser",
            present_challenge=lambda _challenge: None,
        )
    )
    await runtime.read_started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned is True
    assert runtime.methods.count("account/login/cancel") == 1


async def test_login_repeated_cancellation_cannot_interrupt_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _LoginRuntime(_profile(), [], block_read=True)
    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()
    cleaned = False

    async def launch(profile: CodexAppServerProfile) -> _LoginRuntime:
        assert profile is runtime.profile
        return runtime

    async def cleanup(value: object) -> str:
        nonlocal cleaned
        assert value is runtime
        cleanup_started.set()
        await release_cleanup.wait()
        cleaned = True
        return "terminated"

    monkeypatch.setattr(module, "_launch", launch)
    monkeypatch.setattr(module, "_cleanup", cleanup)
    task = asyncio.create_task(
        module.codex_login(
            runtime.profile,
            mode="browser",
            present_challenge=lambda _challenge: None,
        )
    )
    await runtime.read_started.wait()
    task.cancel()
    await cleanup_started.wait()
    task.cancel()
    release_cleanup.set()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned is True


async def test_launch_failure_removes_the_private_attempt_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = replace(_profile(), codex_home=tmp_path / "codex-home")

    def allow_local_binding(_profile: CodexAppServerProfile) -> None:
        return None

    def allow_private_bundle(_path: Path) -> None:
        return None

    monkeypatch.setattr(module.CodexAppServerProfile, "verify_local_binding", allow_local_binding)
    monkeypatch.setattr(module, "verify_private_local_bundle", allow_private_bundle)

    async def fail_launch(*_args: object, **_kwargs: object) -> None:
        raise OSError("closed launch failure")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_launch)

    with pytest.raises(OSError, match="closed launch failure"):
        await module._launch(profile)  # pyright: ignore[reportPrivateUsage]

    runtime_root = profile.codex_home / "runtime"
    assert runtime_root.is_dir()
    assert list(runtime_root.glob("attempt-*")) == []


async def test_launch_cancellation_cleans_a_process_returned_after_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = replace(_profile(), codex_home=tmp_path / "codex-home")
    spawn_started = asyncio.Event()
    release_spawn = asyncio.Event()

    class FakeProcess:
        pid = 991_526
        returncode: int | None = None
        stderr = None
        wait_calls = 0

        async def wait(self) -> int:
            self.wait_calls += 1
            self.returncode = 0
            return 0

    process = FakeProcess()

    def allow_local_binding(_profile: CodexAppServerProfile) -> None:
        return None

    def allow_private_bundle(_path: Path) -> None:
        return None

    async def delayed_spawn(*_args: object, **_kwargs: object) -> asyncio.subprocess.Process:
        spawn_started.set()
        await release_spawn.wait()
        return cast(asyncio.subprocess.Process, process)

    def absent_group(_pid: int, _sig: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(module.CodexAppServerProfile, "verify_local_binding", allow_local_binding)
    monkeypatch.setattr(module, "verify_private_local_bundle", allow_private_bundle)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
    monkeypatch.setattr(module.os, "killpg", absent_group)

    launch_task = asyncio.create_task(module._launch(profile))  # pyright: ignore[reportPrivateUsage]
    await spawn_started.wait()
    launch_task.cancel()
    release_spawn.set()

    with pytest.raises(asyncio.CancelledError):
        await launch_task

    assert process.wait_calls == 1
    assert list((profile.codex_home / "runtime").glob("attempt-*")) == []


async def test_cleanup_reaps_child_after_process_group_signal_race(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = replace(_profile(), codex_home=tmp_path / "codex-home")
    workdir = profile.codex_home / "runtime" / "attempt-race"
    workdir.mkdir(parents=True)

    class FakeProcess:
        pid = 991_525
        returncode: int | None = None
        wait_calls = 0

        async def wait(self) -> int:
            self.wait_calls += 1
            self.returncode = 0
            return 0

    async def stderr_drain() -> bool:
        await asyncio.Event().wait()
        return False

    process = FakeProcess()
    runtime = module._CodexProcess(  # pyright: ignore[reportPrivateUsage]
        profile=profile,
        process=cast(asyncio.subprocess.Process, process),
        workdir=workdir,
        stderr_task=asyncio.create_task(stderr_drain()),
        pending_notifications=deque(),
    )
    probes = 0

    def racing_killpg(_pid: int, sig: int) -> None:
        nonlocal probes
        if sig == 0:
            probes += 1
            if probes == 1:
                return
        raise ProcessLookupError

    monkeypatch.setattr(module.os, "killpg", racing_killpg)

    result = await module._cleanup(runtime)  # pyright: ignore[reportPrivateUsage]

    assert result == "terminated"
    assert process.wait_calls == 1
    assert process.returncode == 0
    assert not workdir.exists()


async def test_cleanup_reports_failed_when_process_disappears_without_reap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = replace(_profile(), codex_home=tmp_path / "codex-home")
    workdir = profile.codex_home / "runtime" / "attempt-unreaped"
    workdir.mkdir(parents=True)

    class FakeProcess:
        pid = 991_527
        returncode: int | None = None

        async def wait(self) -> int:
            raise ProcessLookupError

    async def stderr_drain() -> bool:
        await asyncio.Event().wait()
        return False

    runtime = module._CodexProcess(  # pyright: ignore[reportPrivateUsage]
        profile=profile,
        process=cast(asyncio.subprocess.Process, FakeProcess()),
        workdir=workdir,
        stderr_task=asyncio.create_task(stderr_drain()),
        pending_notifications=deque(),
    )

    def absent_group(_pid: int, _sig: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(module.os, "killpg", absent_group)

    result = await module._cleanup(runtime)  # pyright: ignore[reportPrivateUsage]

    assert result == "failed"
    assert not workdir.exists()


@pytest.mark.parametrize("line", [b"private-transport-canary\n", b"[]\n"])
async def test_malformed_jsonl_is_transport_failure_even_after_acknowledgement(
    line: bytes,
) -> None:
    class FakeProcess:
        stdout = asyncio.StreamReader()

    async def stderr_drain() -> bool:
        return False

    process = FakeProcess()
    process.stdout.feed_data(line)
    runtime = module._CodexProcess(  # pyright: ignore[reportPrivateUsage]
        profile=_profile(),
        process=cast(asyncio.subprocess.Process, process),
        workdir=Path("/unused-test-workdir"),
        stderr_task=asyncio.create_task(stderr_drain()),
        pending_notifications=deque(),
    )
    with pytest.raises(ValueError, match="^codex_app_server_message_invalid$") as error:
        await runtime.read(1)
    await runtime.stderr_task
    assert module._classify_runtime_exception(  # pyright: ignore[reportPrivateUsage]
        error.value, turn_acknowledged=True
    ) == ("post_ack_unknown", SemanticFailureClass.TRANSPORT)
    assert "canary" not in repr(error.value)


async def test_success_records_weaker_runtime_boundary_without_identity_or_transcript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert runtime.methods[:3] == ["initialize", "account/read", "model/list"]
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.credential_authority == "external_runtime_oauth"
    assert evidence.auth_mode == "chatgpt"
    assert evidence.plan_type == "plus"
    assert evidence.case_disclosed is True
    assert evidence.turn_acknowledged is True
    assert evidence.upstream_body_observability == "unavailable"
    assert evidence.final_output_sha256 is not None
    assert "discard@example" not in repr(result)
    assert "no_material_discrepancy" not in repr(evidence)


async def test_token_usage_keeps_latest_cumulative_total_and_non_overlapping_subsets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events[0:0] = [
        _token_usage_notice(total_input=100, total_cached=40, total_output=30),
        _token_usage_notice(
            total_input=160,
            total_cached=80,
            total_cache_write=5,
            total_output=50,
            total_reasoning=20,
        ),
    ]

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.token_usage is not None
    assert evidence.token_usage.input_tokens == 160
    assert evidence.token_usage.cached_input_tokens == 80
    assert evidence.token_usage.cache_write_input_tokens == 5
    assert evidence.token_usage.output_tokens == 50
    assert evidence.token_usage.reasoning_output_tokens == 20
    assert evidence.token_usage.total_tokens == 210
    assert result.provenance.token_usage is not None
    assert result.provenance.token_usage.input_tokens == 160
    assert result.provenance.token_usage.output_tokens == 50
    assert result.provenance.token_usage.total_tokens == 210


async def test_token_usage_buffered_before_turn_ack_is_attributed_after_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    original_request = runtime.request

    async def request_with_buffered_usage(
        request_id: int, method: str, params: object, timeout: float
    ) -> dict[str, object]:
        if method == "turn/start":
            runtime.pending_notifications.append(_token_usage_notice(total_cache_write=7))
        return await original_request(request_id, method, params, timeout)

    monkeypatch.setattr(runtime, "request", request_with_buffered_usage)
    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.token_usage is not None
    assert evidence.token_usage.cache_write_input_tokens == 7


async def test_cumulative_token_usage_regression_keeps_larger_snapshot_and_marks_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events[0:0] = [
        _token_usage_notice(total_input=160, total_cached=80, total_output=50),
        _token_usage_notice(total_input=120, total_cached=60, total_output=40),
    ]

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.token_usage is not None
    assert evidence.token_usage.total_tokens == 210
    assert evidence.failure_stage == "token_usage_invalid"


async def test_malformed_matching_token_usage_is_nonterminal_and_stays_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events.insert(
        0,
        {
            "method": "thread/tokenUsage/updated",
            "params": {
                "threadId": _THREAD_ID,
                "turnId": _TURN_ID,
                "tokenUsage": {"last": {}, "total": {}},
            },
        },
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.token_usage is None
    assert evidence.failure_stage == "token_usage_invalid"


async def test_unrelated_token_usage_is_ignored_without_retaining_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events.insert(
        0,
        _token_usage_notice(thread_id="other-thread", turn_id="other-turn"),
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.token_usage is None
    assert evidence.failure_stage is None


async def test_token_usage_survives_terminal_turn_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events[0:0] = [
        _token_usage_notice(total_input=120, total_cached=60, total_output=40),
        {
            "method": "error",
            "params": {"error": {"codexErrorInfo": "usageLimitExceeded"}},
        },
    ]

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.token_usage is not None
    assert evidence.token_usage.total_tokens == 160
    assert result.provenance.token_usage is not None
    assert result.provenance.token_usage.total_tokens == 160


def test_token_usage_parser_rejects_incoherent_counters() -> None:
    notices = [_token_usage_notice(total_cached=101), _token_usage_notice(total_reasoning=31)]
    incoherent_total = _token_usage_notice()
    incoherent_params = cast(dict[str, object], incoherent_total["params"])
    incoherent_usage = cast(dict[str, object], incoherent_params["tokenUsage"])
    incoherent_total_breakdown = cast(dict[str, object], incoherent_usage["total"])
    incoherent_total_breakdown["totalTokens"] = 1
    notices.append(incoherent_total)
    missing_cache_write = _token_usage_notice()
    missing_params = cast(dict[str, object], missing_cache_write["params"])
    missing_usage = cast(dict[str, object], missing_params["tokenUsage"])
    del cast(dict[str, object], missing_usage["total"])["cacheWriteInputTokens"]
    notices.append(missing_cache_write)

    for notice in notices:
        with pytest.raises(ValueError, match="^codex_app_server_token_usage_invalid$"):
            module._runtime_token_usage_from_notification(  # pyright: ignore[reportPrivateUsage]
                notice, thread_id=_THREAD_ID, turn_id=_TURN_ID
            )


async def test_missing_model_fails_before_case_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = await _evaluate(monkeypatch, _Runtime(_profile(), model_available=False))

    assert type(result) is SemanticResultUnavailable
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.case_disclosed is False
    assert evidence.turn_acknowledged is False
    assert evidence.thread_id is None


@pytest.mark.parametrize("account", [False, {"type": "apiKey"}])
async def test_missing_or_wrong_login_fails_before_case_disclosure(
    monkeypatch: pytest.MonkeyPatch, account: object
) -> None:
    runtime = _Runtime(_profile(), account=None if account is False else account)
    if account is False:
        runtime.account = None

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.AUTHENTICATION
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False
    assert all(item.get("method") != "turn/start" for item in runtime.sent)


async def test_stale_capability_evidence_fails_before_child_launch_or_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()

    class StaleClock(_Clock):
        def now_utc(self) -> datetime:
            return datetime(2026, 11, 30, tzinfo=UTC)

    async def forbidden_launch(_profile: object) -> object:
        pytest.fail("stale evidence must fail before child launch")

    monkeypatch.setattr(module, "_launch", forbidden_launch)
    case = _case()
    binding, authority = _attempt(case)
    result = await CodexAppServerEvaluator(profile, binding, authority, StaleClock()).evaluate(
        case, Deadline(_NOW + timedelta(seconds=30), 30.0)
    )

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.UNSUPPORTED_PROFILE
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False
    assert result.provenance.runtime_evidence.process_cleanup == "not_started"


async def test_unknown_predisclosure_event_prevents_case_bytes_crossing_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(
        _profile(),
        predisclosure_event={"method": "config/warning", "params": {}},
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False
    assert result.provenance.runtime_evidence.turn_acknowledged is False
    assert all(method != "turn/start" for method in (item.get("method") for item in runtime.sent))


async def test_linux_missing_bubblewrap_config_warning_fails_before_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The exact notice Codex 0.157.1 emitted after initialize on Linux x86_64 without a system
    # bubblewrap on PATH. It stays outside the pre-disclosure allowlist: no case byte crosses.
    runtime = _Runtime(
        _profile(),
        predisclosure_event={
            "method": "configWarning",
            "params": {
                "summary": (
                    "Codex could not find bubblewrap on PATH. canary-native-text Codex will use "
                    "the bundled bubblewrap in the meantime."
                ),
                "details": None,
            },
        },
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False
    assert result.provenance.runtime_evidence.failure_stage == "predisclosure_event_forbidden"
    assert all(method != "turn/start" for method in (item.get("method") for item in runtime.sent))
    assert "canary" not in repr(result)


async def test_exact_disabled_remote_control_notice_is_discarded_before_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(
        _profile(),
        predisclosure_event={
            "method": "remoteControl/status/changed",
            "params": {
                "environmentId": None,
                "installationId": "discard-installation-canary",
                "serverName": "discard-server-canary",
                "status": "disabled",
            },
        },
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert "discard-installation-canary" not in repr(result)
    assert "discard-server-canary" not in repr(result)


@pytest.mark.parametrize("status", ["enabled", "connecting", None])
async def test_remote_control_notice_must_be_exactly_disabled_before_disclosure(
    monkeypatch: pytest.MonkeyPatch, status: object
) -> None:
    runtime = _Runtime(
        _profile(),
        predisclosure_event={
            "method": "remoteControl/status/changed",
            "params": {
                "environmentId": None,
                "installationId": "discarded",
                "serverName": "discarded",
                "status": status,
            },
        },
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False


async def test_tool_event_is_rejected_after_ack_with_honest_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events[0] = {
        "method": "item/completed",
        "params": {"item": {"type": "commandExecution", "text": "never-retained"}},
    }

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.turn_acknowledged is True
    assert result.provenance.runtime_evidence.process_cleanup == "terminated"
    assert "never-retained" not in repr(result)


async def test_exact_rate_limit_update_is_discarded_after_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events.insert(
        0,
        {
            "method": "account/rateLimits/updated",
            "params": {
                "rateLimits": {
                    "limitId": "codex",
                    "limitName": None,
                    "primary": {
                        "usedPercent": 27,
                        "windowDurationMins": 10080,
                        "resetsAt": 1788698233,
                    },
                    "secondary": None,
                    "credits": {
                        "hasCredits": False,
                        "unlimited": False,
                        "balance": "discard-balance-canary",
                    },
                    "individualLimit": None,
                    "spendControlReached": None,
                    "planType": "prolite",
                    "rateLimitReachedType": None,
                }
            },
            "emittedAtMs": 1788101632944,
        },
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert "discard-balance-canary" not in repr(result)


@pytest.mark.parametrize("malformed", [False, True])
async def test_native_warning_after_ack_is_transport_unknown_without_message_retention(
    monkeypatch: pytest.MonkeyPatch,
    malformed: bool,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events[0] = {
        "method": "warning",
        "params": {
            "threadId": "019a0000-0000-7000-8000-000000000001",
            "message": "discard-native-warning-canary",
        },
        "emittedAtMs": 1788101617712,
    }
    if malformed:
        runtime.events[0]["emittedAtMs"] = "malformed-warning-canary"

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.TRANSPORT
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.turn_acknowledged is True
    assert result.provenance.runtime_evidence.failure_stage == "runtime_warning"
    assert "discard-native-warning-canary" not in repr(result)
    assert "malformed-warning-canary" not in repr(result)


@pytest.mark.parametrize("turn_acknowledged", [False, True])
def test_malformed_warning_classification_preserves_runtime_ambiguity(
    turn_acknowledged: bool,
) -> None:
    assert module._classify_runtime_exception(  # pyright: ignore[reportPrivateUsage]
        ValueError("codex_app_server_warning_invalid"),
        turn_acknowledged=turn_acknowledged,
    ) == (
        "post_ack_unknown" if turn_acknowledged else "unavailable",
        SemanticFailureClass.TRANSPORT,
    )


async def test_unexpected_native_failure_stays_runtime_bounded_before_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_model_check(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("discard-unexpected-native-canary")

    monkeypatch.setattr(module, "_require_model", fail_model_check)
    result = await _evaluate(monkeypatch, _Runtime(_profile()))

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.TRANSPORT
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False
    assert result.provenance.runtime_evidence.turn_acknowledged is False
    assert "discard-unexpected-native-canary" not in repr(result)


async def test_successful_output_with_unconfirmed_cleanup_is_outcome_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = await _evaluate(
        monkeypatch,
        _Runtime(_profile()),
        cleanup_outcome="failed",
    )

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.TRANSPORT
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.turn_acknowledged is True
    assert result.provenance.runtime_evidence.process_cleanup == "failed"


async def test_structured_rate_limit_is_bounded_without_retaining_native_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events[0] = {
        "method": "error",
        "params": {
            "error": {
                "message": "account and native details must not survive",
                "codexErrorInfo": {"responseStreamConnectionFailed": {"httpStatusCode": 429}},
            }
        },
    }

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.RATE_LIMITED
    assert "account and native details" not in repr(result)


def test_structured_turn_failures_classify_quota_auth_and_policy_without_message_text() -> None:
    quota = module._turn_failure(  # pyright: ignore[reportPrivateUsage]
        {"message": "private", "codexErrorInfo": "usageLimitExceeded"}
    )
    auth = module._turn_failure(  # pyright: ignore[reportPrivateUsage]
        {"message": "private", "codexErrorInfo": "unauthorized"}
    )
    policy = module._turn_failure(  # pyright: ignore[reportPrivateUsage]
        {"message": "private", "codexErrorInfo": "cyberPolicy"}
    )

    assert quota.failure_class is SemanticFailureClass.QUOTA_EXHAUSTED
    assert auth.failure_class is SemanticFailureClass.AUTHENTICATION
    assert policy.outcome == "refused"
    assert "private" not in repr((quota, auth, policy))


def test_launcher_and_environment_do_not_inherit_aliases_credentials_or_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")
    monkeypatch.setenv("HTTPS_PROXY", "https://must-not-cross")

    environment = module._process_environment(  # pyright: ignore[reportPrivateUsage]
        profile
    )

    assert profile.launcher_argv[:3] == (
        "/opt/codex/0.157.1/codex",
        "app-server",
        "--stdio",
    )
    assert environment["CODEX_HOME"] == str(profile.codex_home)
    assert "OPENAI_API_KEY" not in environment
    assert "HTTPS_PROXY" not in environment
    assert "HOME" not in environment


def test_factory_binds_every_runtime_authority_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def binding_is_valid(_profile: CodexAppServerProfile) -> None:
        return None

    monkeypatch.setattr(CodexAppServerProfile, "verify_local_binding", binding_is_valid)
    case = _case()
    binding, authority = _attempt(case)
    factory = CodexAppServerExternalFactory(_profile(), _Clock())
    factory.render(case)
    commitment = RequestCommitment("hmac-sha256/yoetz-privacy-egress-request-v1", _COMMITMENT)

    evaluator = factory.build_evaluator(binding, authority, commitment)

    assert type(evaluator) is CodexAppServerEvaluator
    for changed in (
        replace(authority, dispatch_id="dsp_64000000-0000-4000-8000-000000000002"),
        replace(authority, service_generation=2),
        replace(authority, monotonic_deadline=31.0),
        replace(authority, request_commitment="hmac-sha256:" + "b" * 64),
    ):
        with pytest.raises(ValueError, match="codex_runtime_factory_render_required"):
            factory.build_evaluator(binding, changed, commitment)


async def test_evaluator_rejects_deadline_not_bound_to_runtime_authority() -> None:
    case = _case()
    binding, authority = _attempt(case)
    evaluator = CodexAppServerEvaluator(_profile(), binding, authority, _Clock())

    with pytest.raises(ValueError, match="codex_runtime_attempt_binding_invalid"):
        await evaluator.evaluate(case, Deadline(_NOW + timedelta(seconds=30), 31.0))


# --- issue #527: bounded validation-stage diagnostics -------------------------------------------

_REF = "clm_20000000-0000-4000-8000-000000000001"
_NO_DISCREPANCY = (
    '{"conclusion":"no_material_discrepancy","review_summary":"The supplied packet was reviewed.",'
    '"verified":[],"reviewer_challenges":[],"prior_finding_verdicts":[]}'
)


def _challenge_json(**overrides: object) -> str:
    challenge: dict[str, object] = {
        "finding_kind": "claim_without_admissible_evidence",
        "summary": "Evidence gap",
        "cited_refs": [_REF],
        "snippet": "The claim lacks a recorded basis.",
        "discrepancy": "The claim lacks a recorded basis.",
        "alternative_interpretation": "The claim may remain unresolved.",
        "message_to_main_agent": "Main agent: provide evidence for the claim.",
        "requested_next_step": "provide_evidence",
        "uncertainty": "The missing material may exist outside the case.",
    }
    challenge.update(overrides)
    return json.dumps(
        {
            "conclusion": "challenges_returned",
            "review_summary": "The supplied packet was reviewed.",
            "verified": [],
            "reviewer_challenges": [challenge],
            "prior_finding_verdicts": [],
        }
    )


def _agent_message(text: str, *, phase: str | None = None) -> dict[str, object]:
    item: dict[str, object] = {"type": "agentMessage", "text": text}
    if phase is not None:
        item["phase"] = phase
    return {"method": "item/completed", "params": {"item": item}}


def _runtime_with_output(*outputs: dict[str, object]) -> _Runtime:
    runtime = _Runtime(_profile())
    completion = runtime.events[-1]
    runtime.events = [*outputs, completion]
    return runtime


async def test_commentary_phase_is_discarded_and_final_answer_is_the_judgment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime_with_output(
        _agent_message("narration-canary: reviewing the packet now", phase="commentary"),
        _agent_message(_NO_DISCREPANCY, phase="final_answer"),
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage is None
    assert "narration-canary" not in repr(result)


async def test_commentary_alone_never_counts_as_a_judgment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime_with_output(_agent_message(_NO_DISCREPANCY, phase="commentary"))

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultInvalid
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "agent_message_count"


@pytest.mark.parametrize("phase", ["final_answer", None])
async def test_two_candidate_messages_report_the_count_stage(
    monkeypatch: pytest.MonkeyPatch, phase: str | None
) -> None:
    runtime = _runtime_with_output(
        _agent_message(_NO_DISCREPANCY, phase=phase),
        _agent_message(_NO_DISCREPANCY, phase=phase),
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultInvalid
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_SCHEMA
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "agent_message_count"


async def test_unknown_message_phase_is_a_forbidden_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime_with_output(_agent_message(_NO_DISCREPANCY, phase="draft"))

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "event_forbidden"


@pytest.mark.parametrize(
    ("text", "stage"),
    [
        ("```json\n" + _NO_DISCREPANCY + "\n```", "output_not_json"),
        ("Here is my review-canary: " + _NO_DISCREPANCY, "output_not_json"),
        ('{"conclusion":"no_material_discrepancy","reviewer_challenges":[],}', "output_not_json"),
        ('{"result":' + _NO_DISCREPANCY + "}", "judgment_envelope_invalid"),
        ('{"judgment":"' + "prose-canary" + '"}', "judgment_envelope_invalid"),
        (
            '{"conclusion":"maybe-canary","review_summary":"The supplied packet was reviewed.",'
            '"verified":[],"reviewer_challenges":[],"prior_finding_verdicts":[]}',
            "judgment_enum_invalid",
        ),
        (_challenge_json(finding_kind="hunch-canary"), "judgment_enum_invalid"),
        (_challenge_json(requested_next_step="ask-canary"), "judgment_enum_invalid"),
        (_challenge_json(cited_refs=[_REF, _REF]), "judgment_refs_duplicate"),
        (_challenge_json(cited_refs=["item-canary"]), "judgment_refs_invalid"),
        (
            '{"conclusion":"challenges_returned","review_summary":"The supplied packet was reviewed.",'
            '"verified":[],"reviewer_challenges":[],"prior_finding_verdicts":[]}',
            "judgment_conclusion_mismatch",
        ),
        (
            json.dumps(
                {
                    "conclusion": "no_material_discrepancy",
                    "review_summary": "The supplied packet was reviewed.",
                    "verified": [],
                    "reviewer_challenges": json.loads(_challenge_json())["reviewer_challenges"],
                    "prior_finding_verdicts": [],
                }
            ),
            "judgment_conclusion_mismatch",
        ),
        (_challenge_json(summary=""), "judgment_text_bounds"),
        (_challenge_json(summary="canary " * 2000), "judgment_text_bounds"),
        (_challenge_json(extra="field-canary"), "judgment_shape_invalid"),
    ],
)
async def test_invalid_final_answers_name_one_closed_validation_stage(
    monkeypatch: pytest.MonkeyPatch, text: str, stage: str
) -> None:
    runtime = _runtime_with_output(_agent_message(text, phase="final_answer"))

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultInvalid
    assert result.provenance.status is module.SemanticStatus.INVALID
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_SCHEMA
    assert result.raw_size == len(text.encode("utf-8"))
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.failure_stage == stage
    assert evidence.turn_acknowledged is True
    assert evidence.final_output_sha256 == module._sha256_bytes(  # pyright: ignore[reportPrivateUsage]
        text.encode("utf-8")
    )
    assert "canary" not in repr(result)


@pytest.mark.parametrize(
    "text",
    [_NO_DISCREPANCY, '{"judgment":' + _NO_DISCREPANCY + "}", _challenge_json()],
)
async def test_valid_bare_and_enveloped_final_answers_succeed(
    monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    runtime = _runtime_with_output(_agent_message(text, phase="final_answer"))

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage is None


async def test_informational_notifications_and_plan_items_are_discarded_unread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    thread = "019a0000-0000-7000-8000-000000000001"
    runtime.events[0:0] = [
        {"method": "thread/name/updated", "params": {"threadId": thread, "threadName": "canary"}},
        {"method": "turn/moderationMetadata", "params": {"metadata": {"note": "canary"}}},
        {"method": "model/safetyBuffering/updated", "params": {"threadId": thread}},
        {"method": "deprecationNotice", "params": {"message": "canary"}},
        {"method": "configWarning", "params": {"message": "canary"}},
        {"method": "thread/queue/changed", "params": {"threadId": thread}},
        {"method": "thread/compacted", "params": {"threadId": thread}},
        {"method": "item/started", "params": {"item": {"type": "plan", "text": "canary"}}},
        {"method": "item/plan/delta", "params": {"delta": "canary"}},
        {"method": "turn/plan/updated", "params": {"plan": [{"step": "canary"}]}},
        {"method": "item/completed", "params": {"item": {"type": "plan", "text": "canary"}}},
        {"method": "item/started", "params": {"item": {"type": "contextCompaction"}}},
        {"method": "item/completed", "params": {"item": {"type": "contextCompaction"}}},
        {"method": "item/agentMessage/delta", "params": {"delta": "canary"}},
    ]

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert "canary" not in repr(result)


async def test_model_reroute_ends_the_turn_as_refused_with_its_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    runtime.events.insert(
        0,
        {
            "method": "model/rerouted",
            "params": {
                "fromModel": "gpt-5.6-sol",
                "toModel": "other-canary",
                "reason": "highRiskCyberActivity",
                "threadId": "019a0000-0000-7000-8000-000000000001",
                "turnId": "019a0000-0000-7000-8000-000000000002",
            },
        },
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultRefused
    assert result.provenance.failure_class is SemanticFailureClass.AUTHORIZATION
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "model_rerouted"
    assert "other-canary" not in repr(result)


async def test_delta_storm_is_bounded_by_the_event_limit_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    delta: dict[str, object] = {"method": "item/agentMessage/delta", "params": {"delta": "x"}}
    runtime.events[0:0] = [
        delta
        for _ in range(module._MAX_EVENT_COUNT)  # pyright: ignore[reportPrivateUsage]
    ]

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "event_limit"


async def test_large_streamed_judgment_fits_the_event_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())
    delta: dict[str, object] = {"method": "item/agentMessage/delta", "params": {"delta": "x"}}
    runtime.events[0:0] = [delta for _ in range(2000)]

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess


@pytest.mark.parametrize("buffered_count", [1, 4094, 4096])
async def test_buffered_notifications_drain_before_live_events_with_the_same_limit(
    monkeypatch: pytest.MonkeyPatch, buffered_count: int
) -> None:
    class BufferedRuntime(_Runtime):
        reads = 0

        async def request(
            self, request_id: int, method: str, params: object, timeout: float
        ) -> dict[str, object]:
            result = await super().request(request_id, method, params, timeout)
            if method == "turn/start":
                self.pending_notifications.extend(
                    {"method": "item/agentMessage/delta", "params": {"delta": "x"}}
                    for _ in range(buffered_count)
                )
            return result

        async def read(self, timeout: float) -> dict[str, object]:
            self.reads += 1
            return await super().read(timeout)

    runtime = BufferedRuntime(_profile())
    result = await _evaluate(monkeypatch, runtime)
    if buffered_count == 4096:
        assert type(result) is SemanticResultUnavailable
        assert result.provenance.runtime_evidence is not None
        assert result.provenance.runtime_evidence.failure_stage == "event_limit"
        assert runtime.reads == 0
    else:
        assert type(result) is SemanticResultSuccess
        assert runtime.reads == 2
    assert not runtime.pending_notifications


async def test_tool_event_and_unconfirmed_cleanup_name_their_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool_runtime = _Runtime(_profile())
    tool_runtime.events[0] = {
        "method": "item/completed",
        "params": {"item": {"type": "commandExecution", "text": "never-retained"}},
    }
    tool = await _evaluate(monkeypatch, tool_runtime)
    assert type(tool) is SemanticResultUnavailable
    assert tool.provenance.runtime_evidence is not None
    assert tool.provenance.runtime_evidence.failure_stage == "tool_event_forbidden"

    unconfirmed = await _evaluate(monkeypatch, _Runtime(_profile()), cleanup_outcome="failed")
    assert type(unconfirmed) is SemanticResultUnavailable
    assert unconfirmed.provenance.runtime_evidence is not None
    assert unconfirmed.provenance.runtime_evidence.failure_stage == "cleanup_unconfirmed"


async def test_post_ack_read_timeout_names_the_deadline_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())

    async def stalled_read(timeout: float) -> dict[str, object]:
        del timeout
        raise TimeoutError

    runtime.read = stalled_read  # type: ignore[method-assign]

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.TRANSPORT
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.failure_stage == "deadline_expired"


def test_every_adapter_stage_token_is_a_registered_closed_stage() -> None:
    from yoetz.domain.findings import RUNTIME_FAILURE_STAGES

    mapped = set(module._FAILURE_STAGE_BY_TOKEN.values())  # pyright: ignore[reportPrivateUsage]
    assert mapped <= RUNTIME_FAILURE_STAGES
    judgment_stages = {
        "judgment_envelope_invalid",
        "judgment_enum_invalid",
        "judgment_refs_duplicate",
        "judgment_refs_invalid",
        "judgment_conclusion_mismatch",
        "judgment_text_bounds",
        "judgment_shape_invalid",
    }
    assert judgment_stages <= RUNTIME_FAILURE_STAGES
    unmapped = {
        module._failure_stage(  # pyright: ignore[reportPrivateUsage]
            error, turn_acknowledged=acknowledged, launched=True
        )
        for error in (RuntimeError("native detail"), ValueError("unmapped_token"))
        for acknowledged in (True, False)
    }
    assert unmapped == {"unclassified"}


def test_explicit_long_review_budget_is_preserved_by_runtime_profile() -> None:
    for seconds in (120, 900, 3600):
        assert replace(_profile(), timeout_seconds=seconds).timeout_seconds == seconds
    with pytest.raises(ValueError):
        replace(_profile(), timeout_seconds=3601)


# --- issue #571: phase-aware effort and output budgets -------------------------------------------


def _phased_profile(
    *, routine: str | None = "medium", routine_limit: int = 4096, final_limit: int = 8192
) -> CodexAppServerProfile:
    return replace(
        _profile(),
        routine_reasoning_effort=routine,
        routine_output_limit=routine_limit,
        final_output_limit=final_limit,
    )


def test_review_budget_selects_exact_profile_effort_and_output_limit() -> None:
    profile = _phased_profile(routine="low", routine_limit=1024, final_limit=6000)

    assert profile.review_budget("routine") == CodexReviewBudget("routine", "low", 1024)
    assert profile.review_budget("final") == CodexReviewBudget("final", "high", 6000)
    assert profile.required_reasoning_efforts == ("high", "low")
    with pytest.raises(ValueError, match="codex_budget_profile_invalid"):
        profile.review_budget(cast(Literal["routine"], "checkpoint"))


def test_legacy_binding_keeps_its_single_effort_for_routine_checks() -> None:
    profile = _phased_profile(routine=None)

    assert profile.review_budget("routine") == CodexReviewBudget("routine", "high", 4096)
    assert profile.required_reasoning_efforts == ("high",)


def test_background_advice_uses_lower_default_effort_without_routine_config() -> None:
    """Issue #888: background advice is cheaper even when no routine effort is configured.

    Explicit checks (no background scope) keep the legacy single effort.
    """

    legacy = _phased_profile(routine=None)
    assert legacy.review_budget("routine", background=True) == CodexReviewBudget(
        "routine", "low", 4096
    )
    assert legacy.review_budget("routine") == CodexReviewBudget("routine", "high", 4096)
    assert legacy.review_budget("final", background=True) == CodexReviewBudget(
        "final", "high", 8192
    )
    # An owner routine effort always wins, and a configured effort already at or below the
    # background default (or an unknown vendor effort) is never raised or rewritten.
    configured = _phased_profile(routine="medium")
    assert configured.review_budget("routine", background=True).reasoning_effort == "medium"
    for effort in ("minimal", "low", "vendor-custom"):
        profile = replace(_phased_profile(routine=None), reasoning_effort=effort)
        assert profile.review_budget("routine", background=True).reasoning_effort == effort


@pytest.mark.parametrize("limit", [0, 8193, True])
def test_profile_rejects_unbounded_output_limits(limit: object) -> None:
    with pytest.raises(ValueError, match="codex_runtime_output_limit_invalid"):
        replace(_profile(), routine_output_limit=cast(int, limit))


async def test_routine_attempt_dispatches_and_records_the_routine_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _phased_profile(routine="medium", routine_limit=2048)
    runtime = _Runtime(profile)
    runtime.supported_efforts = ("medium",)
    budget = profile.review_budget("routine")

    result = await _evaluate(monkeypatch, runtime, budget=budget)

    assert type(result) is SemanticResultSuccess
    turn = cast(Mapping[str, object], runtime.params["turn/start"])
    assert turn["effort"] == "medium"
    assert turn["model"] == "gpt-5.6-sol"
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.reasoning_effort == "medium"
    assert result.provenance.model == "gpt-5.6-sol"
    assert result.provenance.sampling_params.max_output_tokens == 2048
    assert evidence.selection_sha256 == canonical_digest(
        {
            "budget_profile": "routine",
            "model": "gpt-5.6-sol",
            "output_limit": 2048,
            "reasoning_effort": "medium",
        }
    )


async def test_codex_thread_uses_the_one_shared_reviewer_instruction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #906: the benchmark path sends the same instruction bytes as the API adapters."""

    runtime = _Runtime(_profile())

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    thread = cast(Mapping[str, object], runtime.params["thread/start"])
    assert thread["baseInstructions"] == SEMANTIC_REVIEW_INSTRUCTION
    assert "You are the requested review:" in SEMANTIC_REVIEW_INSTRUCTION
    expected = "sha256:" + hashlib.sha256(SEMANTIC_REVIEW_INSTRUCTION.encode()).hexdigest()
    assert result.provenance.prompt_digest == expected
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.instruction_sha256 == expected


async def test_final_attempt_uses_the_configured_high_effort_and_final_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _phased_profile(routine="low", final_limit=7000)
    runtime = _Runtime(profile)

    result = await _evaluate(monkeypatch, runtime, budget=profile.review_budget("final"))

    assert type(result) is SemanticResultSuccess
    assert cast(Mapping[str, object], runtime.params["turn/start"])["effort"] == "high"
    assert result.provenance.sampling_params.max_output_tokens == 7000
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.reasoning_effort == "high"


async def test_evaluator_without_budget_keeps_the_legacy_final_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile())

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert cast(Mapping[str, object], runtime.params["turn/start"])["effort"] == "high"
    assert result.provenance.sampling_params.max_output_tokens == 8192


async def test_selected_effort_missing_from_catalog_fails_before_case_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _phased_profile(routine="low")
    runtime = _Runtime(profile)  # the catalog lists only ``high``

    result = await _evaluate(monkeypatch, runtime, budget=profile.review_budget("routine"))

    assert type(result) is SemanticResultUnavailable
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.failure_stage == "model_unavailable"
    assert evidence.case_disclosed is False
    assert "turn/start" not in runtime.methods


async def test_visible_output_over_the_selected_limit_interrupts_as_oversize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _phased_profile(routine_limit=100)
    runtime = _Runtime(profile)
    runtime.supported_efforts = ("medium", "high")
    # 400 output tokens of which 250 are reasoning: 150 visible judgment tokens > 100.
    runtime.events[0:0] = [_token_usage_notice(total_output=400, total_reasoning=250)]
    interrupted: list[tuple[str, str]] = []

    async def interrupt(_runtime: object, thread_id: str, turn_id: str) -> None:
        interrupted.append((thread_id, turn_id))

    monkeypatch.setattr(module, "_interrupt", interrupt)

    result = await _evaluate(monkeypatch, runtime, budget=profile.review_budget("routine"))

    assert type(result) is SemanticResultInvalid
    evidence = result.provenance.runtime_evidence
    assert evidence is not None
    assert evidence.failure_stage == "output_oversize"
    assert evidence.token_usage is not None and evidence.token_usage.output_tokens == 400
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_SCHEMA
    assert result.provenance.sampling_params.max_output_tokens == 100
    assert interrupted == [(_THREAD_ID, _TURN_ID)]


async def test_reasoning_tokens_do_not_count_against_the_judgment_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _phased_profile(routine_limit=100)
    runtime = _Runtime(profile)
    runtime.supported_efforts = ("medium",)
    runtime.events[0:0] = [_token_usage_notice(total_output=5000, total_reasoning=4950)]

    result = await _evaluate(monkeypatch, runtime, budget=profile.review_budget("routine"))

    assert type(result) is SemanticResultSuccess


async def test_readiness_probe_requires_every_configured_profile_effort() -> None:
    profile = _phased_profile(routine="low")
    runtime = _Runtime(profile)

    with pytest.raises(ValueError, match="codex_reasoning_effort_unavailable"):
        await module._require_model(  # pyright: ignore[reportPrivateUsage]
            cast(module._CodexProcess, runtime),  # pyright: ignore[reportPrivateUsage]
            profile,
            5.0,
        )
    runtime.supported_efforts = ("high", "low")
    await module._require_model(  # pyright: ignore[reportPrivateUsage]
        cast(module._CodexProcess, runtime),  # pyright: ignore[reportPrivateUsage]
        profile,
        5.0,
    )


def test_factory_builds_the_evaluator_for_the_dispatch_budget_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def binding_is_valid(_profile: CodexAppServerProfile) -> None:
        return None

    monkeypatch.setattr(CodexAppServerProfile, "verify_local_binding", binding_is_valid)
    case = _case()
    binding, authority = _attempt(case)
    factory = CodexAppServerExternalFactory(_phased_profile(routine="low"), _Clock())
    factory.render(case)
    commitment = RequestCommitment("hmac-sha256/yoetz-privacy-egress-request-v1", _COMMITMENT)

    with semantic_budget_profile_scope("routine"):
        routine = factory.build_evaluator(binding, authority, commitment)
    outside = factory.build_evaluator(binding, authority, commitment)

    assert type(routine) is CodexAppServerEvaluator
    assert routine.budget == CodexReviewBudget("routine", "low", 4096)
    assert type(outside) is CodexAppServerEvaluator
    assert outside.budget == CodexReviewBudget("final", "high", 8192)


async def _evaluate_recording_progress(
    monkeypatch: pytest.MonkeyPatch, runtime: _Runtime
) -> tuple[object, list[object]]:
    from yoetz.observability.semantic_context import semantic_progress_sink

    recorded: list[object] = []

    async def sink(phase: object) -> None:
        recorded.append(phase)

    token = semantic_progress_sink.set(sink)
    try:
        result = await _evaluate(monkeypatch, runtime)
    finally:
        semantic_progress_sink.reset(token)
    return result, recorded


async def test_runtime_reports_only_closed_structural_phases_in_execution_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #571 A2: tokens, reasoning, deltas, and account identity never reach progress."""

    from yoetz.protocol.models import SemanticProgressPhase

    sentinel = "SENTINEL-REASONING-DELTA-91c2"
    runtime = _Runtime(_profile())
    runtime.account = {"type": "chatgpt", "email": f"{sentinel}@example", "planType": "plus"}
    runtime.events[0:0] = [
        {"method": "item/agentMessage/delta", "params": {"delta": sentinel}},
        {"method": "item/started", "params": {"item": {"type": "plan", "text": sentinel}}},
        _token_usage_notice(total_input=100, total_cached=40, total_output=30),
    ]

    result, recorded = await _evaluate_recording_progress(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert recorded == [
        SemanticProgressPhase.RUNTIME_STARTING,
        SemanticProgressPhase.ACCOUNT_MODEL_VALIDATION,
        SemanticProgressPhase.PROVIDER_SAMPLING,
        SemanticProgressPhase.RESPONSE_VALIDATION,
        SemanticProgressPhase.CLEANUP,
    ]
    assert all(type(phase) is SemanticProgressPhase for phase in recorded)
    assert sentinel not in repr(recorded)


async def test_runtime_failure_before_sampling_still_reports_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.protocol.models import SemanticProgressPhase

    runtime = _Runtime(_profile(), model_available=False)

    result, recorded = await _evaluate_recording_progress(monkeypatch, runtime)

    assert type(result) is not SemanticResultSuccess
    assert recorded == [
        SemanticProgressPhase.RUNTIME_STARTING,
        SemanticProgressPhase.ACCOUNT_MODEL_VALIDATION,
        SemanticProgressPhase.CLEANUP,
    ]


async def test_progress_sink_failure_never_changes_the_review_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.observability.semantic_context import semantic_progress_sink

    async def failing_sink(phase: object) -> None:
        del phase
        raise RuntimeError("progress store unavailable")

    token = semantic_progress_sink.set(failing_sink)
    try:
        result = await _evaluate(monkeypatch, _Runtime(_profile()))
    finally:
        semantic_progress_sink.reset(token)

    assert type(result) is SemanticResultSuccess
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.process_cleanup == "terminated"


async def test_launch_binding_hash_runs_off_loop_and_failure_prevents_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop_thread = threading.get_ident()
    threads: list[int] = []

    def changed_binding(_profile: CodexAppServerProfile) -> None:
        threads.append(threading.get_ident())
        raise ValueError("codex_runtime_executable_changed")

    async def forbidden_spawn(*_args: object, **_kwargs: object) -> None:
        pytest.fail("changed executable must not launch")

    monkeypatch.setattr(CodexAppServerProfile, "verify_local_binding", changed_binding)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_spawn)
    with pytest.raises(ValueError, match="codex_runtime_executable_changed"):
        await module._launch(_profile())  # pyright: ignore[reportPrivateUsage]
    assert len(threads) == 1 and threads[0] != loop_thread
