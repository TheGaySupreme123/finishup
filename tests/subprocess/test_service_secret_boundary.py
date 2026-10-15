from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import cast

import pytest
from helpers.child import (
    ChildLimits,
    ChildResult,
    ChildSpec,
    assert_no_owned_children,
    communicate_bounded,
    spawn_installed,
)

_SECRET_CANARY = b"confidential-ingress-canary-2026"

_INGRESS_PROBE = r"""
import asyncio, hashlib, json, os, sys
from datetime import UTC, datetime
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretConsumer
from finishup.service.confidential_protocol import ConfidentialSecretPurpose, SecretIngressBinding, encode_secret_header
from finishup.service.secret_ingress import SecretIngressError, SecretIngressService

class Clock:
    def now_utc(self): return datetime(2026, 7, 19, tzinfo=UTC)
    def monotonic_seconds(self): return 1.0

class Stream:
    def __init__(self, data): self.data = bytearray(data); self.offset = 0
    async def receive(self, maximum):
        if self.offset >= len(self.data): return b""
        end = min(len(self.data), self.offset + maximum)
        result = bytes(self.data[self.offset:end]); self.offset = end; return result
    async def aclose(self): self.data[:] = b"\x00" * len(self.data)

class Listener:
    def __init__(self, stream): self.stream = stream
    async def accept(self): return self.stream
    async def aclose(self): return None

async def main():
    mode = sys.argv[1]
    secret = bytearray(sys.stdin.buffer.read())
    expected = SecretIngressBinding(1, "1"*64, "2"*64, ConfidentialSecretPurpose.VAULT_UNLOCK,
        "svc_33333333-3333-4333-8333-333333333333", 1, 0, None, "sha256:"+"4"*64, 60_000)
    frame = bytearray(encode_secret_header(expected, len(secret)) + secret)
    if mode == "partial": frame = frame[:7]
    elif mode == "crossed": frame[5] = int(ConfidentialSecretPurpose.PROVIDER_CREDENTIAL)
    stream = Stream(frame)
    memory = LocalSecretMemory()
    ingress = SecretIngressService(Clock(), memory, listener=Listener(stream))
    output = {"argv_leak": any(secret in item.encode() for item in sys.argv),
              "env_leak": any(secret in value.encode("utf-8", "surrogateescape") for value in os.environ.values()),
              "endpoint_response_bytes": 0}
    try:
        handle = await ingress.accept_once(expected)
        actual = handle.consume(SecretConsumer.VAULT_ROOT, lambda view: hashlib.sha256(view).hexdigest())
        output["captured"] = actual == hashlib.sha256(secret).hexdigest()
        try:
            await ingress.accept_once(expected)
        except SecretIngressError as exc:
            output["replay_reason"] = exc.reason
    except SecretIngressError as exc:
        output["reason"] = exc.reason
    finally:
        await ingress.close(); memory.close(); secret[:] = b"\x00" * len(secret); frame[:] = b"\x00" * len(frame)
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))

asyncio.run(main())
"""


def _run_probe(mode: str) -> ChildResult:
    spec = ChildSpec(
        executable=Path(sys.executable),
        argv=("-I", "-c", _INGRESS_PROBE, mode),
        limits=ChildLimits(wall_time_seconds=20.0, max_output_bytes=65_536),
    )
    handle = spawn_installed(
        spec,
        {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "VIRTUAL_ENV": sys.prefix},
    )
    result = communicate_bounded(handle, _SECRET_CANARY)
    assert_no_owned_children(result.temp_root)
    assert result.limit_verdict == "passed"
    assert result.exit_code == 0
    assert result.stderr == b""
    assert _SECRET_CANARY not in result.stdout + result.stderr
    return result


def _output(result: ChildResult) -> dict[str, object]:
    return cast(dict[str, object], json.loads(result.stdout))


def test_one_shot_confidential_frame_is_captured_without_an_echo() -> None:
    observed = _output(_run_probe("success"))
    assert observed == {
        "argv_leak": False,
        "captured": True,
        "endpoint_response_bytes": 0,
        "env_leak": False,
        "replay_reason": "binding_invalid",
    }


@pytest.mark.parametrize(
    ("mode", "reason"),
    [("partial", "partial_frame"), ("crossed", "binding_invalid")],
)
def test_partial_and_cross_purpose_frames_fail_closed(mode: str, reason: str) -> None:
    observed = _output(_run_probe(mode))
    assert observed["reason"] == reason
    assert observed["argv_leak"] is False
    assert observed["env_leak"] is False
    assert observed["endpoint_response_bytes"] == 0
