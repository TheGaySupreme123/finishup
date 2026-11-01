"""Bounded local file ingestion for a caller-asserted test result (issue #1170).

This reads an existing script and report; it never runs the script or establishes that the
script produced the report. The ordinary publication and disclosure boundaries still apply.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Final, cast

from finishup.domain.events import (
    ResultVerification,
    VerificationDataSource,
    VerificationExpectedFrom,
)
from finishup.domain.repository_excerpt import credential_named_path
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.errors import ProtocolValueError

MAX_TEST_FILE_BYTES: Final = 65_536
MAX_RESULTS_FILE_BYTES: Final = 4_096
MAX_SUMMARY_BYTES: Final = 8_192
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class TestRecordError(ValueError):
    """A fixed-token refusal; file names, content and OS errors are never exposed."""

    __test__ = False


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
        info.st_uid,
    )


def _relative_path(value: str) -> tuple[str, ...]:
    if (
        not value
        or len(value) > 1_024
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise TestRecordError("test_record_path_invalid")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", "..", ".git"} or credential_named_path(part) for part in parts):
        raise TestRecordError("test_record_path_invalid")
    return parts


def _read_file(workspace: Path, parts: tuple[str, ...], maximum: int) -> bytes:
    # Walk the workspace's ancestors too: O_NOFOLLOW on only the final name does not prevent
    # an ancestor symlink from escaping the explicit root. Keep every descriptor until the
    # bytes and the names have both been checked, including ancestor replacements.
    opened: list[int] = []
    names: list[tuple[int, str, int]] = []
    try:
        if not workspace.is_absolute() or any(part in {".", ".."} for part in workspace.parts):
            raise TestRecordError("test_record_path_invalid")
        current = os.open("/", _DIRECTORY_FLAGS)
        opened.append(current)
        for part in (*workspace.parts[1:], *parts[:-1]):
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            opened.append(child)
            names.append((current, part, child))
            current = child
        descriptor = os.open(parts[-1], _FILE_FLAGS, dir_fd=current)
        opened.append(descriptor)
        names.append((current, parts[-1], descriptor))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise TestRecordError("test_record_file_unsafe")
        if before.st_size > maximum:
            raise TestRecordError("test_record_file_too_large")
        chunks: list[bytes] = []
        count = 0
        while count <= maximum:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        if count > maximum:
            raise TestRecordError("test_record_file_too_large")
        if count != before.st_size or _identity(before) != _identity(os.fstat(descriptor)):
            raise TestRecordError("test_record_file_changed")
        for parent, name, child in names:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(child)
            if (named.st_dev, named.st_ino, named.st_mode) != (
                held.st_dev,
                held.st_ino,
                held.st_mode,
            ):
                raise TestRecordError("test_record_file_changed")
        return b"".join(chunks)
    except (OSError, UnicodeError, ValueError) as error:
        if isinstance(error, TestRecordError):
            raise
        raise TestRecordError("test_record_file_unsafe") from None
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _report(raw: bytes) -> Mapping[str, JsonValue]:
    try:
        report = strict_json_parse(raw)
    except (ProtocolValueError, ValueError, RecursionError):
        raise TestRecordError("test_record_report_invalid") from None
    if not isinstance(report, Mapping) or set(report) - {
        "cases",
        "failing",
        "worst",
        "failing_cases",
    }:
        raise TestRecordError("test_record_report_invalid")
    cases, failing, worst = report.get("cases"), report.get("failing"), report.get("worst")
    if (
        type(cases) is not int
        or type(failing) is not int
        or not 0 <= failing <= cases <= 2**53 - 1
        or (
            "worst" in report
            and (not isinstance(worst, str) or not worst.strip() or len(worst) > 64)
        )
    ):
        raise TestRecordError("test_record_report_invalid")
    if "failing_cases" in report:
        named = report["failing_cases"]
        if (
            not isinstance(named, list)
            or len(named) > min(failing, 64)
            or any(
                not isinstance(item, str) or not item.strip() or len(item) > 256 for item in named
            )
            or len(set(named)) != len(named)
        ):
            raise TestRecordError("test_record_report_invalid")
    return report


def prepare_test_record(
    request: Mapping[str, JsonValue],
    *,
    test_file: str,
    results_file: str,
    workspace: Path,
    checks: str | None = None,
    expected_from: str | None = None,
) -> dict[str, JsonValue]:
    """Fill one result draft from local files, preserving all publication identities.

    ``verification`` must already contain ``criterion_quote`` and ``data_source``. Counts
    and ``worst`` come exclusively from the strict report. ``checks`` and ``expected_from``
    (#1219) fill the optional manifest fields; one that contradicts the request is refused.
    No input mapping is modified.
    """

    drafts = request.get("event_drafts")
    if not isinstance(drafts, (list, tuple)):
        raise TestRecordError("test_record_request_invalid")
    matches: list[int] = []
    for index, draft in enumerate(drafts):
        if isinstance(draft, Mapping):
            schema = draft.get("schema")
            if isinstance(schema, Mapping) and schema.get("name") == "result_recorded":
                matches.append(index)
    if len(matches) != 1:
        raise TestRecordError("test_record_requires_one_result")
    draft = drafts[matches[0]]
    assert isinstance(draft, Mapping)
    payload = draft.get("payload")
    if not isinstance(payload, Mapping) or not isinstance(payload.get("verification"), Mapping):
        raise TestRecordError("test_record_request_invalid")
    verification_value = payload["verification"]
    assert isinstance(verification_value, Mapping)
    verification: dict[str, JsonValue] = dict(verification_value)
    for name, value in (("checks", checks), ("expected_from", expected_from)):
        if value is not None:
            if name in verification and verification[name] != value:
                raise TestRecordError("test_record_request_invalid")
            verification[name] = value
    summary = payload.get("summary", "")
    if not isinstance(summary, str):
        raise TestRecordError("test_record_request_invalid")
    test_parts, results_parts = _relative_path(test_file), _relative_path(results_file)
    script = _read_file(workspace, test_parts, MAX_TEST_FILE_BYTES)
    raw_report = _read_file(workspace, results_parts, MAX_RESULTS_FILE_BYTES)
    report = _report(raw_report)
    report_digest = "sha256:" + hashlib.sha256(raw_report).hexdigest()
    verification.update(
        cases=report["cases"],
        failing=report["failing"],
        test_file=test_file,
        results_file=results_file,
        report_digest=report_digest,
    )
    verification.pop("worst", None)
    if "worst" in report:
        verification["worst"] = report["worst"]
    try:
        # Validate the declaration before returning it to the ordinary publish-work validator.
        ResultVerification(
            criterion_quote=cast(str, verification.get("criterion_quote")),
            data_source=VerificationDataSource(cast(str, verification.get("data_source"))),
            cases=cast(int, verification["cases"]),
            failing=cast(int, verification["failing"]),
            worst=cast(str | None, verification.get("worst")),
            tuned_on_these_cases=cast(bool | None, verification.get("tuned_on_these_cases")),
            test_file=test_file,
            results_file=results_file,
            report_digest=report_digest,
            checks=cast(str | None, verification.get("checks")),
            expected_from=(
                None
                if verification.get("expected_from") is None
                else VerificationExpectedFrom(cast(str, verification["expected_from"]))
            ),
        )
        script.decode("utf-8")
    except (ValueError, TypeError, UnicodeError):
        raise TestRecordError("test_record_request_invalid") from None
    if b"\x00" in script:
        raise TestRecordError("test_record_file_unsafe")
    source_digest = "sha256:" + hashlib.sha256(script).hexdigest()
    # Bind the files by digest only. Their text (test source, failing-case names) stays in the
    # workspace: a result summary travels in every detailed review timeline, including profiles
    # that select no test excerpts, so copying repository content here would widen disclosure.
    record = (
        "Caller-asserted test files; execution and report origin are not observed.\n"
        f"Test source digest: {source_digest}; {len(script)} bytes.\n"
        f"Report digest: {report_digest}; {len(raw_report)} bytes."
    )
    combined = f"{summary}\n\n{record}" if summary else record
    try:
        summary_size = len(combined.encode("utf-8"))
    except UnicodeError:
        raise TestRecordError("test_record_request_invalid") from None
    if summary_size > MAX_SUMMARY_BYTES:
        raise TestRecordError("test_record_summary_too_large")
    updated_payload: dict[str, JsonValue] = {
        **payload,
        "summary": combined,
        "verification": verification,
    }
    original_schema = draft["schema"]
    assert isinstance(original_schema, Mapping)
    updated_draft: dict[str, JsonValue] = {
        **draft,
        "schema": {**original_schema, "version": "1.1.0"},
        "payload": updated_payload,
    }
    updated_drafts = list(drafts)
    updated_drafts[matches[0]] = updated_draft
    return {**request, "event_drafts": updated_drafts}
