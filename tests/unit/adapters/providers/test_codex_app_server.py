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

from builders.codex_capability import (
    LINUX,
    MAC,
    binding_for,
    profile_for,
    record_for,
    retained_runtime,
    write_home,
)
from finishup.adapters.providers import codex_app_server as module
from finishup.adapters.providers.codex_app_server import (
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CodexAppServerEvaluator,
    CodexAppServerExternalFactory,
    CodexAppServerProfile,
    CodexReviewBudget,
    CodexRuntimeStatus,
)
from finishup.adapters.providers.codex_capability import CodexCapabilityRecord
from finishup.adapters.providers.openai_responses import (
    JUDGMENT_JSON_SCHEMA,
    SEMANTIC_REVIEW_INSTRUCTION,
)
from finishup.domain.findings import SemanticFailureClass
from finishup.domain.privacy import (
    ApprovedOutboundCase,
    DataCategory,
    ProviderBinding,
    RequestCommitment,
)
from finishup.ports.secret_memory import ProviderAttemptAuthBinding
from finishup.ports.semantic import (
    Deadline,
    ExternalRuntimeAuthority,
    SemanticResultInvalid,
    SemanticResultRefused,
    SemanticResultSuccess,
    SemanticResultUnavailable,
)
from finishup.ports.semantic_budget import semantic_budget_profile_scope
from finishup.protocol.canonical import canonical_digest, canonical_encode

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
    """A capability-checked Codex 0.159.0 profile whose record is held in memory."""

    return profile_for()


def test_committed_isolated_config_matches_the_runtime_constant() -> None:
    root = Path(__file__).resolve().parents[4]
    config = (root / "support/codex-evaluator/config.toml").read_bytes()

    assert "sha256:" + hashlib.sha256(config).hexdigest() == CODEX_EVALUATOR_CONFIG_SHA256
    assert config.decode("utf-8") == module.CODEX_EVALUATOR_CONFIG
    # The exact pinned 0.157.1 cells are gone: admission is the capability check (ADR-006).
    assert not (root / "support/codex-evaluator/0.157.1").exists()


@pytest.mark.parametrize("version", ["0.157.1", "0.159.0", "0.162.1", "1.0.0"])
def test_any_stable_release_at_or_above_the_floor_forms_a_binding(version: str) -> None:
    record = record_for(b"codex", b"host", version=version)
    profile = profile_for(record)

    assert profile.runtime_version == version
    assert profile.capability_profile == CODEX_EVALUATOR_CAPABILITY_PROFILE
    assert CODEX_EVALUATOR_CAPABILITY_PROFILE == "codex-evaluator/capability/v2"
    assert module.CODEX_EVALUATOR_RUNTIME_FLOOR == "0.157.1"


@pytest.mark.parametrize(
    ("overrides", "token"),
    [
        # Bindings written under the exact pinned cells move through repair, never launch.
        ({"capability_profile": "codex-evaluator/0.157.1/v2"}, "codex_runtime_profile_outdated"),
        ({"capability_profile": "codex-evaluator/0.150.1/v2"}, "codex_runtime_profile_outdated"),
        ({"isolated_config_sha256": "sha256:" + "c" * 64}, "codex_runtime_profile_outdated"),
        (
            {"capability_evidence_expires_at": "2026-12-31T00:00:00Z"},
            "codex_runtime_profile_outdated",
        ),
        # Below the floor, a prerelease, or an identity that disagrees with its version.
        (
            {
                "runtime_version": "0.153.4",
                "source_identity": "openai-codex-npm-darwin-arm64-0.153.4",
            },
            "codex_runtime_version_unsupported",
        ),
        ({"runtime_version": "0.163.0-alpha.9"}, "codex_runtime_version_unsupported"),
        (
            {"source_identity": "openai-codex-npm-darwin-arm64-0.162.1"},
            "codex_runtime_capability_unsupported",
        ),
        (
            {"source_identity": "openai-codex-brew-darwin-arm64-0.159.0"},
            "codex_runtime_capability_unsupported",
        ),
        ({"executable_sha256": "sha256:short"}, "codex_runtime_binding_invalid"),
    ],
)
def test_binding_fields_are_validated_before_any_file_access(
    overrides: dict[str, object], token: str
) -> None:
    profile = profile_for(in_memory=False)

    with pytest.raises(ValueError, match=token):
        replace(profile, **overrides)  # pyright: ignore[reportArgumentType]


def test_an_in_memory_record_must_be_the_one_the_binding_commits_to() -> None:
    record = record_for(b"codex", b"host")
    other = record_for(b"other codex", b"host")

    with pytest.raises(ValueError, match="codex_runtime_capability_record_invalid"):
        replace(profile_for(record), capability_record=other)


def test_local_binding_rejects_a_mac_binding_on_linux_before_file_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")

    with pytest.raises(ValueError, match="codex_runtime_platform_unsupported"):
        _profile().verify_local_binding()


def _launchable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, version: str = "0.159.0"
) -> tuple[Path, CodexCapabilityRecord, CodexAppServerProfile]:
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("platform.machine", lambda: "arm64")

    def allow_private(_path: Path) -> None:
        return None

    monkeypatch.setattr(module, "verify_private_local_bundle", allow_private)
    bundle = tmp_path / "bundle"
    executable, record = retained_runtime(bundle, version=version)
    home = write_home(tmp_path / "home")
    profile = CodexAppServerProfile.from_config(binding_for(record, executable, home))
    return executable, record, profile


def test_launch_fence_accepts_the_retained_bytes_and_record_it_commits_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _executable, record, profile = _launchable(tmp_path, monkeypatch)

    profile.verify_local_binding()
    assert profile.bound_capability_record() == record


@pytest.mark.parametrize("target", ["codex", "codex-code-mode-host", "capability.json"])
def test_launch_fence_refuses_bytes_or_record_changed_after_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    executable, _record, profile = _launchable(tmp_path, monkeypatch)
    changed = executable.parent / target
    changed.chmod(0o700)
    if target == "capability.json":
        replacement = record_for(b"a newer codex", b"its host").to_json()
        changed.write_text(json.dumps(replacement), encoding="utf-8")
    else:
        changed.write_bytes(b"bytes a later update wrote")

    with pytest.raises(ValueError, match="codex_runtime_executable_changed"):
        profile.verify_local_binding()


def test_launch_fence_refuses_a_missing_record_as_a_missing_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, _record, profile = _launchable(tmp_path, monkeypatch)
    (executable.parent / "capability.json").unlink()

    with pytest.raises(FileNotFoundError):
        profile.verify_local_binding()


def test_linux_and_mac_identities_stay_bound_to_their_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    linux = record_for(b"codex", b"host", platform=LINUX)
    profile = profile_for(linux)
    assert profile.source_identity == "openai-codex-npm-linux-x64-0.159.0"
    assert LINUX.native_package_spec("0.159.0") == "npm:@openai/codex@0.159.0-linux-x64"
    assert MAC.native_package_spec("0.159.0") == "npm:@openai/codex@0.159.0-darwin-arm64"
    assert MAC.native_executable_relative.as_posix() == "vendor/aarch64-apple-darwin/bin/codex"
    assert LINUX.native_executable_relative.as_posix() == (
        "vendor/x86_64-unknown-linux-musl/bin/codex"
    )
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("platform.machine", lambda: "arm64")
    with pytest.raises(ValueError, match="codex_runtime_platform_unsupported"):
        profile.verify_local_binding()
    assert module.codex_code_mode_host_path(Path("/store/codex")) == Path(
        "/store/codex-code-mode-host"
    )


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
                "userAgent": "finishup_semantic_evaluator/0.159.0 (Mac OS 26.6.2; arm64) unknown",
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
                "userAgent": "finishup_semantic_evaluator/0.159.0 (Mac OS 26.6.2; arm64) unknown",
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
        # Codex 0.150.1 through 0.162.1 emit this notification while account/login/start is in
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
    # A notice shaped like Codex 0.157.1's missing-bubblewrap warning but not byte-identical to
    # the reviewed 0.162.1 text, from an unreviewed release. It stays outside the pre-disclosure
    # allowlist: no case byte crosses.
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
        "/opt/codex/0.159.0/codex",
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
    from finishup.domain.findings import RUNTIME_FAILURE_STAGES

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
    from finishup.observability.semantic_context import semantic_progress_sink

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

    from finishup.protocol.models import SemanticProgressPhase

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
    from finishup.protocol.models import SemanticProgressPhase

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
    from finishup.observability.semantic_context import semantic_progress_sink

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


# -- capability admission (ADR-006 capability amendment) -----------------------------------------


async def _probe(
    monkeypatch: pytest.MonkeyPatch, runtime: _Runtime, *, cleanup_outcome: str = "terminated"
) -> None:
    async def launch(profile: CodexAppServerProfile) -> _Runtime:
        assert profile is runtime.profile
        return runtime

    async def cleanup(value: object) -> str:
        assert value is runtime
        return cleanup_outcome

    monkeypatch.setattr(module, "_launch", launch)
    monkeypatch.setattr(module, "_cleanup", cleanup)
    await module.codex_capability_probe(runtime.profile)


async def test_capability_probe_proves_isolation_without_any_turn_or_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime(_profile(), predisclosure_event=_REMOTE_CONTROL_NOTICE)

    await _probe(monkeypatch, runtime)

    # No turn is ever started, so nothing is sampled and no task content exists. The second
    # account/read is the barrier that closes the pre-disclosure window.
    assert runtime.methods == ["initialize", "account/read", "thread/start", "account/read"]
    thread = cast(dict[str, object], runtime.params["thread/start"])
    assert (thread["sandbox"], thread["ephemeral"], thread["approvalPolicy"]) == (
        "read-only",
        True,
        "never",
    )
    assert runtime.pending_notifications == deque()


@pytest.mark.parametrize(
    ("event", "token"),
    [
        (
            {"method": "thread/prediction/updated", "params": {}},
            "codex_app_server_predisclosure_event_forbidden",
        ),
        (
            {"method": "configWarning", "params": {"summary": "bubblewrap is unavailable"}},
            "codex_app_server_predisclosure_event_forbidden",
        ),
        (
            {
                "method": "warning",
                "params": {"message": "Code Mode is unavailable", "threadId": "t"},
            },
            "codex_app_server_predisclosure_event_forbidden",
        ),
        (
            {
                "method": "remoteControl/status/changed",
                "params": {
                    "environmentId": None,
                    "installationId": "i",
                    "serverName": "s",
                    "status": "connected",
                },
            },
            "codex_app_server_remote_control_not_disabled",
        ),
        (
            {"id": 7, "method": "item/tool/call", "params": {}},
            "codex_app_server_tool_request_forbidden",
        ),
    ],
)
async def test_capability_probe_fails_closed_on_any_unreviewed_predisclosure_event(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object], token: str
) -> None:
    runtime = _Runtime(_profile(), predisclosure_event=event)

    with pytest.raises(ValueError, match=token):
        await _probe(monkeypatch, runtime)
    assert "turn/start" not in runtime.methods


async def test_capability_probe_refuses_a_runtime_reporting_another_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fake app-server reports 0.159.0; the bytes are being checked as 0.162.1.
    runtime = _Runtime(profile_for(record_for(b"codex", b"host", version="0.162.1")))

    with pytest.raises(ValueError, match="codex_runtime_version_mismatch"):
        await _probe(monkeypatch, runtime)
    assert runtime.methods == ["initialize"]


async def test_capability_probe_refuses_an_unproven_isolated_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NetworkedThread(_Runtime):
        async def request(
            self, request_id: int, method: str, params: object, timeout: float
        ) -> dict[str, object]:
            result = await super().request(request_id, method, params, timeout)
            if method == "thread/start":
                result["sandbox"] = {"type": "readOnly", "networkAccess": True}
            return result

    runtime = NetworkedThread(_profile())

    with pytest.raises(ValueError, match="codex_thread_isolation_unproven"):
        await _probe(monkeypatch, runtime)


async def test_capability_probe_with_unconfirmed_cleanup_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="codex_capability_probe_cleanup_unconfirmed"):
        await _probe(monkeypatch, _Runtime(_profile()), cleanup_outcome="failed")


async def test_a_probe_failure_never_masks_an_unconfirmed_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal raised while probing must not hide a process group that may still run."""

    class NetworkedThread(_Runtime):
        async def request(
            self, request_id: int, method: str, params: object, timeout: float
        ) -> dict[str, object]:
            result = await super().request(request_id, method, params, timeout)
            if method == "thread/start":
                result["sandbox"] = {"type": "readOnly", "networkAccess": True}
            return result

    with pytest.raises(ValueError, match="codex_capability_probe_cleanup_unconfirmed") as raised:
        await _probe(monkeypatch, NetworkedThread(_profile()), cleanup_outcome="failed")
    # The original refusal is preserved as the cause rather than lost.
    assert str(raised.value.__cause__) == "codex_thread_isolation_unproven"


async def test_a_readiness_failure_never_masks_an_unconfirmed_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Warning_(_Runtime):
        async def request(
            self, request_id: int, method: str, params: object, timeout: float
        ) -> dict[str, object]:
            if method == "account/read":
                raise ValueError("codex_app_server_predisclosure_event_forbidden")
            return await super().request(request_id, method, params, timeout)

    runtime = Warning_(_profile())

    async def launch(profile: CodexAppServerProfile) -> _Runtime:
        return runtime

    async def cleanup(value: object) -> str:
        assert value is runtime
        return "failed"

    monkeypatch.setattr(module, "_launch", launch)
    monkeypatch.setattr(module, "_cleanup", cleanup)

    with pytest.raises(ValueError, match="codex_capability_probe_cleanup_unconfirmed") as raised:
        await module.codex_account_status(runtime.profile)
    assert str(raised.value.__cause__) == "codex_app_server_predisclosure_event_forbidden"


@pytest.mark.parametrize(
    "agent",
    [
        "finishup_semantic_evaluator/0.159.1 (Mac OS 26.6.2; arm64) unknown",
        "finishup_semantic_evaluator/0.159.0-alpha.1 (Mac OS 26.6.2; arm64) unknown",
        "something 0.159.0",
        None,
    ],
)
def test_initialize_must_name_exactly_the_checked_release(agent: object) -> None:
    profile = _profile()

    with pytest.raises(ValueError, match="codex_runtime_version_mismatch"):
        module._validate_initialize(  # pyright: ignore[reportPrivateUsage]
            profile, {"codexHome": str(profile.codex_home), "userAgent": agent}
        )


async def test_partial_answer_is_discarded_like_commentary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex 0.162.1 adds ``partial_answer``; only the ``final_answer`` is the judgment."""

    runtime = _runtime_with_output(
        _agent_message("partial-canary: still reviewing", phase="partial_answer"),
        _agent_message(_NO_DISCREPANCY, phase="final_answer"),
    )

    result = await _evaluate(monkeypatch, runtime)

    assert type(result) is SemanticResultSuccess
    assert "partial-canary" not in repr(result)


def test_new_plan_names_stay_bounded_bookkeeping() -> None:
    """Codex 0.159.0 adds the ``promax`` plan; rate-limit plan names are discarded unread."""

    notice = {"method": "account/rateLimits/updated", "params": {"rateLimits": {"planType": ""}}}
    for plan in ("promax", "a_future_plan"):
        cast(dict[str, dict[str, object]], notice["params"])["rateLimits"]["planType"] = plan
        module._discard_rate_limits_notification(notice)  # pyright: ignore[reportPrivateUsage]
    cast(dict[str, dict[str, object]], notice["params"])["rateLimits"]["planType"] = "Not A Plan!"
    with pytest.raises(ValueError, match="codex_app_server_rate_limits_invalid"):
        module._discard_rate_limits_notification(notice)  # pyright: ignore[reportPrivateUsage]
    assert module._account(  # pyright: ignore[reportPrivateUsage]
        {"account": {"type": "chatgpt", "planType": "promax"}}
    ) == ("chatgpt", "promax")


def test_flex_tier_unavailability_is_a_provider_outage() -> None:
    failure = module._turn_failure(  # pyright: ignore[reportPrivateUsage]
        {"codexErrorInfo": "flexUnavailable", "message": "private"}
    )
    assert failure.failure_class is SemanticFailureClass.PROVIDER_OUTAGE


# -- buffered pre-disclosure events (round-2 finding 1 and 2) ------------------------------------


class _StdinRecorder:
    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []

    def write(self, data: bytes) -> None:
        self.messages.append(cast(dict[str, object], json.loads(data)))

    async def drain(self) -> None:
        return None


class _StreamProcess:
    def __init__(self, stdout: asyncio.StreamReader) -> None:
        self.stdin = _StdinRecorder()
        self.stdout = stdout


_BUFFERED_FORBIDDEN_EVENTS: list[dict[str, object]] = [
    {"method": "thread/prediction/updated", "params": {}},
    {"method": "warning", "params": {"message": "private-canary", "threadId": "t"}},
    {"id": 7, "method": "item/tool/call", "params": {}},
]


async def _responses(
    profile: CodexAppServerProfile, *steps: tuple[int, str] | dict[str, object]
) -> list[dict[str, object]]:
    """Real JSONL replies (and raw events) in the order Codex writes them to stdout."""

    fake = _Runtime(profile)
    lines: list[dict[str, object]] = []
    for step in steps:
        if isinstance(step, dict):
            lines.append(step)
        else:
            request_id, method = step
            lines.append(
                {"id": request_id, "result": await fake.request(request_id, method, None, 1.0)}
            )
    return lines


def _stream_runtime(
    profile: CodexAppServerProfile, lines: list[dict[str, object]]
) -> tuple[module._CodexProcess, _StdinRecorder]:  # pyright: ignore[reportPrivateUsage]
    """A real ``_CodexProcess`` whose stdout already holds every line Codex wrote."""

    reader = asyncio.StreamReader()
    for line in lines:
        reader.feed_data(json.dumps(line).encode("utf-8") + b"\n")
    reader.feed_eof()
    process = _StreamProcess(reader)
    stderr_done: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
    stderr_done.set_result(False)
    runtime = module._CodexProcess(  # pyright: ignore[reportPrivateUsage]
        profile=profile,
        process=cast(asyncio.subprocess.Process, process),
        workdir=Path("/private/empty-attempt"),
        stderr_task=cast("asyncio.Task[bool]", stderr_done),
        pending_notifications=deque(),
    )
    return runtime, process.stdin


def _launch_stream(
    monkeypatch: pytest.MonkeyPatch,
    runtime: module._CodexProcess,  # pyright: ignore[reportPrivateUsage]
) -> None:
    async def launch(profile: CodexAppServerProfile) -> object:
        del profile
        return runtime

    async def cleanup(value: object) -> str:
        assert value is runtime
        return "terminated"

    monkeypatch.setattr(module, "_launch", launch)
    monkeypatch.setattr(module, "_cleanup", cleanup)


@pytest.mark.parametrize("event", _BUFFERED_FORBIDDEN_EVENTS)
async def test_event_buffered_right_after_thread_start_blocks_case_disclosure(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object]
) -> None:
    profile = _profile()
    # Codex wrote the event immediately after the thread/start reply: it sits unread in the
    # reader buffer when the reply returns, and must still be inspected before turn/start.
    lines = await _responses(
        profile,
        (0, "initialize"),
        (1, "account/read"),
        (10, "model/list"),
        (30, "thread/start"),
        event,
        (32, "account/read"),
        (31, "turn/start"),
    )
    runtime, stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)
    case = _case()
    binding, authority = _attempt(case)
    evaluator = CodexAppServerEvaluator(profile, binding, authority, _Clock())

    result = await evaluator.evaluate(case, Deadline(_NOW + timedelta(seconds=30), 30.0))

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False
    assert all(message.get("method") != "turn/start" for message in stdin.messages)
    assert "private-canary" not in repr(result)


@pytest.mark.parametrize("event", _BUFFERED_FORBIDDEN_EVENTS)
async def test_capability_probe_inspects_events_buffered_after_thread_start(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object]
) -> None:
    profile = _profile()
    lines = await _responses(
        profile,
        (0, "initialize"),
        (1, "account/read"),
        (30, "thread/start"),
        event,
        (32, "account/read"),
    )
    runtime, _stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    with pytest.raises(ValueError, match="codex_app_server_"):
        await module.codex_capability_probe(profile)


@pytest.mark.parametrize("event", _BUFFERED_FORBIDDEN_EVENTS)
async def test_readiness_probe_is_not_ready_when_codex_queues_a_forbidden_event(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object]
) -> None:
    profile = _profile()
    # A runtime that passed the signed-out scratch probe but warns during the authenticated
    # model/list must not be reported ready (selection then falls back to an older runtime).
    lines = await _responses(
        profile,
        (0, "initialize"),
        (1, "account/read"),
        (10, "model/list"),
        event,
        (32, "account/read"),
    )
    runtime, _stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    with pytest.raises(ValueError, match="codex_app_server_"):
        await module.codex_account_status(profile)


async def test_readiness_probe_stays_ready_with_only_reviewed_notices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    lines = await _responses(
        profile,
        (0, "initialize"),
        _REMOTE_CONTROL_NOTICE,
        (1, "account/read"),
        (10, "model/list"),
        {"method": "account/updated", "params": {}},
        (32, "account/read"),
    )
    runtime, _stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    status = await module.codex_account_status(profile)

    assert (status.runtime_ready, status.auth_mode, status.model_available) == (
        True,
        "chatgpt",
        True,
    )


# -- the two admitted configWarnings: Codex's Linux sandbox without user namespaces or bwrap ----

# Verbatim ``USER_NAMESPACE_WARNING`` from codex-rs/sandboxing/src/bwrap.rs at rust-v0.162.1, in
# the exact ``ConfigWarningNotification`` envelope app-server writes (``details`` serialises as
# null; ``path`` and ``range`` are skipped when absent; the envelope carries ``emittedAtMs``).
_USER_NAMESPACE_WARNING = (
    "Codex's Linux sandbox uses bubblewrap and needs access to create user namespaces."
)
_SANDBOX_UNAVAILABLE_EVENT: dict[str, object] = {
    "method": "configWarning",
    "params": {"summary": _USER_NAMESPACE_WARNING, "details": None},
    "emittedAtMs": 1791958274243,
}
# Verbatim ``MISSING_BWRAP_WARNING`` from the same file, also present byte for byte in the shipped
# 0.162.1 linux-x64 ``codex`` binary (sha256 628e3548...). app-server writes it, in the same
# envelope, when no system ``bwrap`` is on PATH (an official task container without the
# distribution ``bubblewrap`` package).
_MISSING_BWRAP_WARNING = (
    "Codex could not find bubblewrap on PATH. Install bubblewrap with your OS package manager. "
    "See the sandbox prerequisites: "
    "https://developers.openai.com/codex/concepts/sandboxing#prerequisites. "
    "Codex will use the bundled bubblewrap in the meantime."
)
_BWRAP_MISSING_EVENT: dict[str, object] = {
    "method": "configWarning",
    "params": {"summary": _MISSING_BWRAP_WARNING, "details": None},
    "emittedAtMs": 1791958274243,
}
# Each admitted warning with the reason FinishUP discloses for it.
_ADMITTED_SANDBOX_WARNINGS: list[tuple[dict[str, object], str]] = [
    (_SANDBOX_UNAVAILABLE_EVENT, "user_namespaces_unavailable"),
    (_BWRAP_MISSING_EVENT, "bubblewrap_missing"),
]
# Look-alikes that are different warnings and must stay refused before disclosure.
_NOT_THE_SANDBOX_WARNING: list[dict[str, object]] = [
    {
        "method": "configWarning",
        "params": {"summary": _MISSING_BWRAP_WARNING, "details": "private-canary"},
    },
    {
        "method": "configWarning",
        "params": {"summary": _MISSING_BWRAP_WARNING + " ", "details": None},
    },
    {
        "method": "configWarning",
        "params": {"summary": _MISSING_BWRAP_WARNING, "details": None, "range": None},
    },
    {"method": "configWarning", "params": {"summary": _MISSING_BWRAP_WARNING}},
    {"method": "warning", "params": {"message": _MISSING_BWRAP_WARNING, "threadId": "t"}},
    {
        "method": "configWarning",
        "params": {
            "summary": (
                "Codex's Linux sandbox uses bubblewrap, which is not supported on WSL1 because "
                "WSL1 cannot create the required user namespaces. Use WSL2 for sandboxed shell "
                "commands."
            ),
            "details": None,
        },
    },
    {
        "method": "configWarning",
        "params": {"summary": _USER_NAMESPACE_WARNING, "details": "private-canary"},
    },
    {
        "method": "configWarning",
        "params": {"summary": _USER_NAMESPACE_WARNING, "details": None, "path": "/x"},
    },
    {"method": "configWarning", "params": {"summary": _USER_NAMESPACE_WARNING + " "}},
    {
        "method": "configWarning",
        "params": {"summary": _USER_NAMESPACE_WARNING, "details": None},
        "emittedAtMs": "now",
    },
    {"method": "warning", "params": {"message": _USER_NAMESPACE_WARNING, "threadId": "t"}},
]


def _reviewed_profile(version: str = "0.162.1") -> CodexAppServerProfile:
    """A profile for a release whose source review covers the sandbox warning (or ``version``)."""

    return profile_for(record_for(b"codex", b"host", version=version))


async def _release_responses(
    profile: CodexAppServerProfile, *steps: tuple[int, str] | dict[str, object]
) -> list[dict[str, object]]:
    """``_responses`` whose ``initialize`` reports the profile's own release, as Codex does."""

    lines = await _responses(profile, *steps)
    first = cast(dict[str, object], lines[0]["result"])
    first["userAgent"] = (
        f"finishup_semantic_evaluator/{profile.runtime_version} (Linux 6.8; x86_64) unknown"
    )
    return lines


def test_the_sandbox_warning_is_reviewed_only_for_source_verified_releases() -> None:
    assert module.SANDBOX_UNAVAILABLE_REVIEWED_RELEASES == frozenset({"0.162.1"})


@pytest.mark.parametrize(("event", "reason"), _ADMITTED_SANDBOX_WARNINGS)
async def test_capability_probe_admits_the_exact_sandbox_unavailable_warning(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object], reason: str
) -> None:
    profile = _reviewed_profile()
    lines = await _release_responses(
        profile,
        (0, "initialize"),
        event,
        (1, "account/read"),
        (30, "thread/start"),
        (32, "account/read"),
    )
    runtime, stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    await module.codex_capability_probe(profile)

    assert runtime.sandbox_unavailable is True
    assert runtime.sandbox_unavailable_reason == reason
    assert all(message.get("method") != "turn/start" for message in stdin.messages)


@pytest.mark.parametrize("event", _NOT_THE_SANDBOX_WARNING)
async def test_capability_probe_still_refuses_every_other_config_warning(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object]
) -> None:
    profile = _reviewed_profile()
    lines = await _release_responses(
        profile,
        (0, "initialize"),
        event,
        (1, "account/read"),
        (30, "thread/start"),
        (32, "account/read"),
    )
    runtime, _stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    with pytest.raises(ValueError, match="codex_app_server_predisclosure_event_forbidden"):
        await module.codex_capability_probe(profile)
    assert runtime.sandbox_unavailable is False
    assert runtime.sandbox_unavailable_reason is None


@pytest.mark.parametrize(("event", "reason"), _ADMITTED_SANDBOX_WARNINGS)
async def test_readiness_reports_the_unavailable_sandbox_and_stays_ready(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object], reason: str
) -> None:
    profile = _reviewed_profile()
    lines = await _release_responses(
        profile,
        (0, "initialize"),
        event,
        (1, "account/read"),
        (10, "model/list"),
        (32, "account/read"),
    )
    runtime, _stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    status = await module.codex_account_status(profile)

    assert (status.runtime_ready, status.model_available, status.sandbox_unavailable) == (
        True,
        True,
        True,
    )
    assert status.sandbox_unavailable_reason == reason


async def test_readiness_without_the_warning_reports_no_unavailable_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _reviewed_profile()
    lines = await _release_responses(
        profile, (0, "initialize"), (1, "account/read"), (10, "model/list"), (32, "account/read")
    )
    runtime, _stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    status = await module.codex_account_status(profile)
    assert (status.sandbox_unavailable, status.sandbox_unavailable_reason) == (False, None)


@pytest.mark.parametrize(("event", "_reason"), _ADMITTED_SANDBOX_WARNINGS)
async def test_an_attempt_discloses_the_case_despite_the_sandbox_unavailable_warning(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object], _reason: str
) -> None:
    profile = _reviewed_profile()
    lines = await _release_responses(
        profile,
        (0, "initialize"),
        event,
        (1, "account/read"),
        (10, "model/list"),
        (30, "thread/start"),
        (32, "account/read"),
        (31, "turn/start"),
    )
    runtime, stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)
    case = _case()
    binding, authority = _attempt(case)
    evaluator = CodexAppServerEvaluator(profile, binding, authority, _Clock())

    result = await evaluator.evaluate(case, Deadline(_NOW + timedelta(seconds=30), 30.0))

    # The stream ends after turn/start, so the attempt cannot complete; what matters is that
    # the admitted warning did not stop disclosure before the turn.
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is True
    assert any(message.get("method") == "turn/start" for message in stdin.messages)


# A release outside the reviewed set: an older admitted one, and a synthetic newer one that keeps
# the same warning and protocol but whose tool semantics nobody has reviewed.
_UNREVIEWED_RELEASES = ["0.159.0", "1.0.0"]


@pytest.mark.parametrize("version", _UNREVIEWED_RELEASES)
@pytest.mark.parametrize(("event", "_reason"), _ADMITTED_SANDBOX_WARNINGS)
async def test_capability_probe_refuses_the_sandbox_warning_from_an_unreviewed_release(
    monkeypatch: pytest.MonkeyPatch, version: str, event: dict[str, object], _reason: str
) -> None:
    profile = _reviewed_profile(version)
    lines = await _release_responses(
        profile,
        (0, "initialize"),
        event,
        (1, "account/read"),
        (30, "thread/start"),
        (32, "account/read"),
    )
    runtime, stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    with pytest.raises(ValueError, match="codex_sandbox_unavailable_unreviewed_runtime"):
        await module.codex_capability_probe(profile)
    assert all(message.get("method") != "turn/start" for message in stdin.messages)


@pytest.mark.parametrize("version", _UNREVIEWED_RELEASES)
@pytest.mark.parametrize(("event", "_reason"), _ADMITTED_SANDBOX_WARNINGS)
async def test_readiness_refuses_the_sandbox_warning_from_an_unreviewed_release(
    monkeypatch: pytest.MonkeyPatch, version: str, event: dict[str, object], _reason: str
) -> None:
    profile = _reviewed_profile(version)
    lines = await _release_responses(
        profile,
        (0, "initialize"),
        event,
        (1, "account/read"),
        (10, "model/list"),
        (32, "account/read"),
    )
    runtime, _stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)

    with pytest.raises(ValueError, match="codex_sandbox_unavailable_unreviewed_runtime"):
        await module.codex_account_status(profile)


@pytest.mark.parametrize("version", _UNREVIEWED_RELEASES)
@pytest.mark.parametrize(("event", "_reason"), _ADMITTED_SANDBOX_WARNINGS)
async def test_an_attempt_on_an_unreviewed_release_never_discloses_after_the_warning(
    monkeypatch: pytest.MonkeyPatch, version: str, event: dict[str, object], _reason: str
) -> None:
    profile = _reviewed_profile(version)
    lines = await _release_responses(
        profile,
        (0, "initialize"),
        event,
        (1, "account/read"),
        (10, "model/list"),
        (30, "thread/start"),
        (32, "account/read"),
        (31, "turn/start"),
    )
    runtime, stdin = _stream_runtime(profile, lines)
    _launch_stream(monkeypatch, runtime)
    case = _case()
    binding, authority = _attempt(case)
    evaluator = CodexAppServerEvaluator(profile, binding, authority, _Clock())

    result = await evaluator.evaluate(case, Deadline(_NOW + timedelta(seconds=30), 30.0))

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.case_disclosed is False
    assert result.provenance.runtime_evidence.failure_stage == "predisclosure_event_forbidden"
    assert all(message.get("method") != "turn/start" for message in stdin.messages)
