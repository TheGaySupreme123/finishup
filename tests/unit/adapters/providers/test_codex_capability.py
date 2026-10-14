"""Capability admission primitives: the floor, identities, the record, and the schema subset."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from builders.codex_capability import LINUX, MAC, minimal_app_server_schema, record_for
from yoetz.adapters.providers import codex_capability as module
from yoetz.adapters.providers.codex_capability import (
    CODEX_EVALUATOR_RUNTIME_FLOOR,
    CodexCapabilityRecord,
    check_app_server_schema,
    codex_cli_version,
    codex_platform_for,
    codex_source_identity,
    codex_version_key,
    generate_app_server_schema,
    parse_codex_source_identity,
    read_capability_record,
    require_admitted_version,
    write_capability_record,
)


@pytest.mark.parametrize(
    ("version", "admitted"),
    [
        ("0.157.1", True),
        ("0.159.0", True),
        ("0.162.1", True),
        ("1.0.0", True),
        ("0.157.0", False),
        ("0.153.4", False),
        ("0.150.1", False),
        ("0.163.0-alpha.9", False),
        ("0.159", False),
        ("v0.159.0", False),
        ("00.159.0", False),
        (159, False),
    ],
)
def test_only_stable_releases_at_or_above_the_floor_are_admitted(
    version: object, admitted: bool
) -> None:
    assert CODEX_EVALUATOR_RUNTIME_FLOOR == "0.157.1"
    if admitted:
        assert require_admitted_version(version) == version
    else:
        with pytest.raises(ValueError, match="codex_runtime_version_unsupported"):
            require_admitted_version(version)


def test_releases_order_numerically_not_lexically() -> None:
    assert codex_version_key("0.162.1") > codex_version_key("0.159.0")  # pyright: ignore[reportOperatorIssue]
    assert codex_version_key("0.1000.0") > codex_version_key("0.999.9")  # pyright: ignore[reportOperatorIssue]


@pytest.mark.parametrize(
    ("platform_os", "architecture", "suffix"),
    [
        ("darwin", "arm64", "darwin-arm64"),
        ("linux", "x86_64", "linux-x64"),
        ("linux2", "amd64", "linux-x64"),
    ],
)
def test_supported_platforms_map_to_their_npm_native_package(
    platform_os: str, architecture: str, suffix: str
) -> None:
    assert codex_platform_for(platform_os, architecture).npm_suffix == suffix


@pytest.mark.parametrize(
    ("platform_os", "architecture"),
    [("darwin", "x86_64"), ("linux", "aarch64"), ("win32", "AMD64")],
)
def test_other_platforms_are_refused(platform_os: str, architecture: str) -> None:
    with pytest.raises(ValueError, match="codex_runtime_platform_unsupported"):
        codex_platform_for(platform_os, architecture)


def test_source_identities_round_trip_and_reject_anything_else() -> None:
    identity = codex_source_identity(LINUX, "0.162.1")
    assert identity == "openai-codex-npm-linux-x64-0.162.1"
    assert parse_codex_source_identity(identity) == (LINUX, "0.162.1")
    for invalid in (
        "openai-codex-npm-darwin-x64-0.162.1",
        "openai-codex-npm-darwin-arm64-0.162",
        "../openai-codex-npm-darwin-arm64-0.162.1",
        None,
    ):
        assert parse_codex_source_identity(invalid) is None
    with pytest.raises(ValueError, match="codex_runtime_version_unsupported"):
        codex_source_identity(MAC, "0.150.1")


def test_records_are_deterministic_and_strictly_parsed(tmp_path: Path) -> None:
    record = record_for(b"codex", b"host")
    assert record.current
    assert record.digest == record_for(b"codex", b"host").digest
    assert record.digest != record_for(b"other codex", b"host").digest
    assert CodexCapabilityRecord.from_json(record.to_json()) == record

    write_capability_record(tmp_path, record)
    assert read_capability_record(tmp_path) == record

    mutations: tuple[dict[str, object], ...] = (
        {"extra": True},
        {"schema": "yoetz.codex-evaluator-capability/0"},
        {"source_identity": "openai-codex-npm-linux-x64-0.159.0"},
        {"executable_sha256": "sha256:short"},
        {"checks": None},
    )
    for mutation in mutations:
        document: dict[str, object] = {**record.to_json(), **mutation}
        with pytest.raises(ValueError, match="codex_runtime_capability_record_invalid"):
            CodexCapabilityRecord.from_json(document)


def test_a_record_from_an_older_contract_is_not_current() -> None:
    older = CodexCapabilityRecord.from_json(
        {**record_for(b"codex", b"host").to_json(), "capability_profile": "codex-evaluator/x/v0"}
    )
    assert not older.current


def test_reading_a_record_never_follows_a_symlink_or_accepts_garbage(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_capability_record(tmp_path)
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps(record_for(b"codex", b"host").to_json()), encoding="utf-8")
    (tmp_path / "capability.json").symlink_to(target)
    with pytest.raises(ValueError, match="codex_runtime_capability_record_invalid"):
        read_capability_record(tmp_path)
    (tmp_path / "capability.json").unlink()
    (tmp_path / "capability.json").write_bytes(b"{not json")
    with pytest.raises(ValueError, match="codex_runtime_capability_record_invalid"):
        read_capability_record(tmp_path)


# -- the reviewed protocol subset --------------------------------------------------------------


def _definitions(document: dict[str, object]) -> dict[str, dict[str, object]]:
    return cast(dict[str, dict[str, object]], document["definitions"])


def test_the_minimal_subset_passes_and_additive_changes_still_pass() -> None:
    document = minimal_app_server_schema()
    baseline = check_app_server_schema(document)
    definitions = _definitions(document)
    # A new notification, a new client request, and new optional fields are additive: the
    # runtime allowlists still fail closed on anything unreviewed.
    cast(list[object], definitions["ServerNotification"]["oneOf"]).append(
        {"properties": {"method": {"enum": ["thread/prediction/updated"]}}}
    )
    cast(dict[str, object], definitions["TurnStartParams"]["properties"])["rootTurnId"] = {
        "type": ["string", "null"]
    }
    definitions["NewDefinition"] = {"type": "object"}

    assert check_app_server_schema(document) == baseline


def test_required_fields_the_evaluator_sends_pass_and_enter_the_subset_digest() -> None:
    document = minimal_app_server_schema()
    baseline = check_app_server_schema(document)
    definitions = _definitions(document)
    # The real generated shape: required fields the evaluator always sends are compatible, but
    # they are checked facts, so the provenance digest names them.
    definitions["TurnStartParams"]["required"] = ["input", "threadId"]
    definitions["ClientInfo"]["required"] = ["name", "version"]
    with_required = check_app_server_schema(document)
    assert with_required != baseline
    # Sent values are checked facts too: an enum that still admits the sent value passes.
    _properties(definitions, "ThreadStartParams")["sandbox"] = {
        "anyOf": [{"enum": ["read-only", "workspace-write"]}, {"type": "null"}]
    }
    assert check_app_server_schema(document) != with_required


def _properties(definitions: dict[str, dict[str, object]], name: str) -> dict[str, object]:
    return cast(dict[str, object], definitions[name]["properties"])


def _regress(definitions: dict[str, dict[str, object]], regression: str) -> None:
    if regression == "client_method_gone":
        cast(list[object], definitions["ClientRequest"]["oneOf"]).pop(0)
    elif regression == "notifications_gone":
        definitions["ServerNotification"]["oneOf"] = []
    elif regression == "sandbox_field_gone":
        _properties(definitions, "ThreadStartResponse").pop("sandbox")
    elif regression == "ephemeral_not_boolean":
        _properties(definitions, "Thread")["ephemeral"] = {"type": "string"}
    elif regression == "efforts_gone":
        _properties(definitions, "Model").pop("supportedReasoningEfforts")
    elif regression == "read_only_mode_gone":
        definitions["SandboxMode"]["enum"] = ["workspace-write"]
    elif regression == "in_progress_status_gone":
        definitions["TurnStatus"]["enum"] = ["completed"]
    elif regression == "network_flag_gone":
        definitions["SandboxPolicy"]["oneOf"] = [{"properties": {"type": {"enum": ["readOnly"]}}}]
    elif regression == "unreviewed_phase":
        definitions["MessagePhase"]["enum"] = ["commentary", "final_answer", "draft_answer"]
    elif regression == "turn_start_new_required_field":
        # Codex would reject turn/start only after it received the packet.
        definitions["TurnStartParams"]["required"] = ["input", "parentTurnId", "threadId"]
    elif regression == "thread_start_new_required_field":
        definitions["ThreadStartParams"]["required"] = ["sessionSource"]
    elif regression == "text_input_new_required_field":
        variants = cast(list[dict[str, object]], definitions["UserInput"]["oneOf"])
        variants[0]["required"] = ["attachments", "text", "type"]
    elif regression == "sent_sandbox_value_rejected":
        _properties(definitions, "ThreadStartParams")["sandbox"] = {
            "anyOf": [{"enum": ["workspace-write"], "type": "string"}, {"type": "null"}]
        }
    elif regression == "sent_summary_value_rejected":
        _properties(definitions, "TurnStartParams")["summary"] = {"enum": ["auto", "detailed"]}
    else:
        definitions.pop("Turn")


@pytest.mark.parametrize(
    "regression",
    [
        # A method the evaluator sends or waits for is gone.
        "client_method_gone",
        "notifications_gone",
        # A field the isolation proof reads is gone or no longer admits its shape.
        "sandbox_field_gone",
        "ephemeral_not_boolean",
        "efforts_gone",
        # A value the evaluator sends is no longer accepted.
        "read_only_mode_gone",
        "in_progress_status_gone",
        # The read-only sandbox variant lost its network flag.
        "network_flag_gone",
        # A closed value the evaluator interprets gained a member it has not reviewed.
        "unreviewed_phase",
        # A request the evaluator sends gained a required field it does not send.
        "turn_start_new_required_field",
        "thread_start_new_required_field",
        "text_input_new_required_field",
        # A field the evaluator sends no longer admits the exact value it sends.
        "sent_sandbox_value_rejected",
        "sent_summary_value_rejected",
        "turn_definition_gone",
    ],
)
def test_a_protocol_regression_is_incompatible(regression: str) -> None:
    document = minimal_app_server_schema()
    _regress(_definitions(document), regression)

    with pytest.raises(ValueError, match="codex_runtime_protocol_incompatible"):
        check_app_server_schema(document)


@pytest.mark.parametrize("document", [None, [], {"definitions": []}, {"other": {}}])
def test_a_document_without_definitions_is_incompatible(document: object) -> None:
    with pytest.raises(ValueError, match="codex_runtime_protocol_incompatible"):
        check_app_server_schema(document)


# -- zero-inference subprocesses ----------------------------------------------------------------


class _Runner:
    def __init__(self, *, code: int = 0, output: bytes = b"", schema: bytes | None = None) -> None:
        self.code = code
        self.output = output
        self.schema = schema
        self.calls: list[tuple[tuple[str, ...], Path, Mapping[str, str]]] = []

    def __call__(self, argv: Sequence[str], cwd: Path, env: Mapping[str, str]) -> tuple[int, bytes]:
        self.calls.append((tuple(argv), cwd, dict(env)))
        if self.schema is not None:
            out = Path(argv[argv.index("--out") + 1])
            (out / "codex_app_server_protocol.v2.schemas.json").write_bytes(self.schema)
        return self.code, self.output


@pytest.mark.parametrize(
    ("output", "code", "version"),
    [
        (b"codex-cli 0.159.0\n", 0, "0.159.0"),
        (b"codex-cli 0.162.1", 0, "0.162.1"),
        (b"codex-cli 0.163.0-alpha.9\n", 0, None),
        (b"codex 0.159.0\n", 0, None),
        (b"codex-cli 0.159.0\n", 1, None),
        (b"", 0, None),
    ],
)
def test_the_cli_version_is_read_under_a_throwaway_scratch_home(
    tmp_path: Path, output: bytes, code: int, version: str | None
) -> None:
    runner = _Runner(code=code, output=output)
    executable = tmp_path / "codex"

    if version is None:
        with pytest.raises(ValueError, match="codex_runtime_version_unknown"):
            codex_cli_version(executable, scratch_parent=tmp_path, runner=runner)
    else:
        assert codex_cli_version(executable, scratch_parent=tmp_path, runner=runner) == version
    ((argv, cwd, env),) = runner.calls
    assert argv == (str(executable), "--version")
    assert set(env) == {"CODEX_HOME", "LANG", "LC_ALL", "PATH", "RUST_LOG"}
    assert Path(env["CODEX_HOME"]).parent == cwd
    # Nothing is left behind, and no real Codex home was named.
    assert sorted(entry.name for entry in tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("runner", "token"),
    [
        (_Runner(code=1), "codex_runtime_protocol_unavailable"),
        (_Runner(), "codex_runtime_protocol_unavailable"),
        (_Runner(schema=b"{not json"), "codex_runtime_protocol_unavailable"),
    ],
)
def test_a_schema_the_candidate_cannot_produce_is_unavailable(
    tmp_path: Path, runner: _Runner, token: str
) -> None:
    with pytest.raises(ValueError, match=token):
        generate_app_server_schema(tmp_path / "codex", scratch_parent=tmp_path, runner=runner)
    assert list(tmp_path.iterdir()) == []


def test_the_generated_schema_may_carry_floats_the_strict_profile_rejects(tmp_path: Path) -> None:
    document = minimal_app_server_schema()
    _definitions(document)["CodexErrorInfo"] = {"minimum": 0.0, "type": "integer"}
    runner = _Runner(schema=json.dumps(document).encode())

    parsed = generate_app_server_schema(tmp_path / "codex", scratch_parent=tmp_path, runner=runner)

    assert check_app_server_schema(parsed) == check_app_server_schema(minimal_app_server_schema())
    assert module.CODEX_CAPABILITY_RECORD_NAME == "capability.json"


# -- process-group cleanup of the zero-inference subprocesses (real children) ------------------

_POSIX_ONLY = pytest.mark.skipif(not hasattr(os, "killpg"), reason="POSIX process groups")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - a reused pid owned by someone else
        return False
    return not _zombie(pid)


def _zombie(pid: int) -> bool:
    stat_file = Path(f"/proc/{pid}/stat")
    try:
        text = stat_file.read_text()
    except OSError:
        return False
    return text.rpartition(")")[2].split()[0] in {"Z", "X"}


def _gone_within(pid: int, seconds: float) -> bool:
    """Bounded observation of real state: the descendant is reaped by init after the kill."""

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.02)
    return not _alive(pid)


class _Candidate:
    """A synthetic candidate executable that starts one descendant and records its pid."""

    def __init__(self, root: Path, *, stdout_line: str = "", hang: bool) -> None:
        root.mkdir(mode=0o700)
        self.pid_file = root / "descendant.pid"
        self.executable = root / "codex"
        # The descendant detaches its output so it does not hold the pipe; it is still in the
        # candidate's process group, which is what the cleanup must kill.
        body = [
            "#!/bin/sh",
            "sleep 120 </dev/null >/dev/null 2>&1 &",
            f"echo $! > '{self.pid_file}'",
        ]
        if stdout_line:
            body.append(f"echo '{stdout_line}'")
        if hang:
            body.append("exec sleep 120 </dev/null >/dev/null 2>&1")
        self.executable.write_text("\n".join(body) + "\n")
        self.executable.chmod(0o700)

    def descendant(self) -> int | None:
        try:
            return int(self.pid_file.read_text().strip())
        except OSError, ValueError:
            return None

    def reap_own_descendant(self) -> None:
        """Teardown: kill only the pid this test's own candidate spawned."""

        pid = self.descendant()
        if pid is not None and _alive(pid):
            # The probe's own group kill may still be landing; a pid that exits in between is fine.
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


@pytest.fixture
def short_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "_SUBPROCESS_TIMEOUT_SECONDS", 1.0)


@_POSIX_ONLY
@pytest.mark.usefixtures("short_timeout")
@pytest.mark.parametrize("probe", ["version", "schema"])
def test_a_timed_out_probe_kills_the_candidates_whole_process_group(
    tmp_path: Path, probe: str
) -> None:
    candidate = _Candidate(tmp_path / "candidate", hang=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    try:
        if probe == "version":
            with pytest.raises(ValueError, match="codex_runtime_version_unknown"):
                codex_cli_version(candidate.executable, scratch_parent=scratch)
        else:
            with pytest.raises(ValueError, match="codex_runtime_protocol_unavailable"):
                generate_app_server_schema(candidate.executable, scratch_parent=scratch)
        pid = candidate.descendant()
        assert pid is not None
        assert _gone_within(pid, 5.0), "a descendant of the timed-out candidate is still running"
        assert list(scratch.iterdir()) == []
    finally:
        candidate.reap_own_descendant()


@_POSIX_ONLY
def test_a_candidate_that_exits_leaving_a_descendant_has_the_descendant_killed(
    tmp_path: Path,
) -> None:
    candidate = _Candidate(tmp_path / "candidate", stdout_line="codex-cli 0.162.1", hang=False)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    try:
        assert codex_cli_version(candidate.executable, scratch_parent=scratch) == "0.162.1"
        pid = candidate.descendant()
        assert pid is not None
        assert _gone_within(pid, 5.0), "the candidate's background descendant outlived the probe"
    finally:
        candidate.reap_own_descendant()


@_POSIX_ONLY
@pytest.mark.usefixtures("short_timeout")
@pytest.mark.parametrize("probe", ["version", "schema"])
def test_an_unconfirmed_group_cleanup_is_a_typed_failure_not_a_probe_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, probe: str
) -> None:
    candidate = _Candidate(tmp_path / "candidate", hang=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    real_killpg = os.killpg
    spawned: list[int] = []

    def refusing_killpg(group: int, sig: int) -> None:
        spawned.append(group)
        raise PermissionError(1, "denied")

    monkeypatch.setattr(module.os, "killpg", refusing_killpg)
    monkeypatch.setattr(module, "_GROUP_CLEANUP_GRACE_SECONDS", 0.2)
    try:
        with pytest.raises(
            ValueError, match="codex_capability_probe_cleanup_unconfirmed"
        ) as raised:
            if probe == "version":
                codex_cli_version(candidate.executable, scratch_parent=scratch)
            else:
                generate_app_server_schema(candidate.executable, scratch_parent=scratch)
        # The original timeout is preserved as the cause, not masked or lost.
        assert isinstance(raised.value.__cause__, subprocess.TimeoutExpired)
    finally:
        monkeypatch.undo()
        for group in sorted(set(spawned)):
            # Teardown kills only the process group this test's own candidate started.
            try:
                real_killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        candidate.reap_own_descendant()


@_POSIX_ONLY
def test_a_transient_eperm_while_killed_members_exit_is_confirmed_gone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """macOS briefly answers EPERM for a group whose killed members are still exiting."""

    candidate = _Candidate(tmp_path / "candidate", stdout_line="codex-cli 0.162.1", hang=False)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    real_killpg = os.killpg
    probes: list[int] = []

    def transient_eperm(group: int, sig: int) -> None:
        if sig == 0:
            probes.append(group)
            if len(probes) <= 3:
                raise PermissionError(1, "Operation not permitted")
        real_killpg(group, sig)

    monkeypatch.setattr(module.os, "killpg", transient_eperm)
    try:
        assert codex_cli_version(candidate.executable, scratch_parent=scratch) == "0.162.1"
        assert len(probes) > 3
        pid = candidate.descendant()
        assert pid is not None
        assert _gone_within(pid, 5.0)
    finally:
        monkeypatch.undo()
        candidate.reap_own_descendant()


@_POSIX_ONLY
def test_a_group_that_stays_visible_past_the_grace_is_unconfirmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A member that genuinely survives (persistent EPERM) still fails closed."""

    candidate = _Candidate(tmp_path / "candidate", stdout_line="codex-cli 0.162.1", hang=False)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    real_killpg = os.killpg

    def persistent_eperm(group: int, sig: int) -> None:
        if sig == 0:
            raise PermissionError(1, "Operation not permitted")
        real_killpg(group, sig)

    monkeypatch.setattr(module.os, "killpg", persistent_eperm)
    monkeypatch.setattr(module, "_GROUP_CLEANUP_GRACE_SECONDS", 0.2)
    try:
        with pytest.raises(ValueError, match="codex_capability_probe_cleanup_unconfirmed"):
            codex_cli_version(candidate.executable, scratch_parent=scratch)
    finally:
        monkeypatch.undo()
        candidate.reap_own_descendant()
