"""No bare INTERNAL_ERROR (tb4n3 RC-2, #1025): every producer carries a typed reason.

An `INTERNAL_ERROR` that says only "internal error" tells the agent nothing about whether its
write was recorded or what to read next. This scans every place under `src/yoetz` that builds a
public error with `PublicErrorCode.INTERNAL_ERROR` and requires a typed `reason_code` (through
`safe_details`, `reason` or `details_reason_code`). The start-catalog adapters build theirs through
one helper that adds `start_state_inconsistent` by default, and `exit_code_for` only maps a code to
a process exit status; both are checked directly rather than allowlisted blindly.
"""

from __future__ import annotations

import ast
from pathlib import Path

from yoetz.adapters.memory import start_catalog as memory_catalog
from yoetz.adapters.sqlite import start_catalog as sqlite_catalog
from yoetz.application.maintenance import (
    _internal_error as maintenance_internal_error,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.protocol.errors import PROTOCOL_REASON_CODES, PublicErrorCode
from yoetz.protocol.recovery import REASON_REMEDIES

_SRC = Path(__file__).resolve().parents[3] / "src" / "yoetz"
_HELPER_TYPED = {
    "adapters/memory/start_catalog.py": "_error",
    "adapters/sqlite/start_catalog.py": "_error",
}
_NOT_A_PRODUCER = {"exit_code_for"}


def _is_internal_error(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "INTERNAL_ERROR"
        and isinstance(node.value, ast.Name)
        and node.value.id == "PublicErrorCode"
    )


def test_every_internal_error_producer_carries_a_typed_reason() -> None:
    untyped: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        relative = path.relative_to(_SRC).as_posix()
        if relative.startswith("resources/"):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            candidates = [*node.args[:1], *(k.value for k in node.keywords if k.arg == "code")]
            if not any(_is_internal_error(value) for value in candidates):
                continue
            function = ast.unparse(node.func)
            if function in _NOT_A_PRODUCER or _HELPER_TYPED.get(relative) == function:
                continue
            keywords = {keyword.arg for keyword in node.keywords}
            if not keywords & {"safe_details", "reason", "details_reason_code"}:
                untyped.append(f"{relative}:{node.lineno} {function}")
    assert untyped == [], untyped


def test_no_dictionary_literal_builds_an_untyped_internal_error() -> None:
    """The constructor scan above cannot see a hand-built wire dictionary (the last-resort
    result): every dict literal naming code INTERNAL_ERROR must carry safe_details."""

    untyped: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        relative = path.relative_to(_SRC).as_posix()
        if relative.startswith("resources/"):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Dict):
                continue
            keys = [key.value for key in node.keys if isinstance(key, ast.Constant)]
            names_it = any(
                isinstance(key, ast.Constant)
                and key.value == "code"
                and isinstance(value, ast.Constant)
                and value.value == "INTERNAL_ERROR"
                for key, value in zip(node.keys, node.values, strict=True)
            )
            if names_it and "safe_details" not in keys:
                untyped.append(f"{relative}:{node.lineno}")
    assert untyped == [], untyped


def test_the_last_resort_error_is_typed_and_its_remedy_renders() -> None:
    from yoetz.mcp.errors import build_last_resort_internal_error_result
    from yoetz.mcp.summaries import render_safe_compact_summary

    result = build_last_resort_internal_error_result()
    assert result["error"]["safe_details"] == {"reason_code": "internal_error"}  # type: ignore[index]
    text = render_safe_compact_summary(result)
    assert "Reason: internal_error." in text
    assert "Remedy:" in text and "status view=operation" in text


def test_the_start_catalog_helpers_type_their_internal_error() -> None:
    for module in (memory_catalog, sqlite_catalog):
        error = module._error(PublicErrorCode.INTERNAL_ERROR)  # pyright: ignore[reportPrivateUsage]
        assert error.safe_details["reason_code"] == "start_state_inconsistent"


def test_the_maintenance_internal_error_is_typed_and_says_what_it_did() -> None:
    error = maintenance_internal_error()
    assert error.safe_details["reason_code"] == "maintenance_state_unverified"
    assert "changed nothing" in error.message


def test_every_typed_internal_stage_has_a_registered_reason_and_a_remedy_sentence() -> None:
    stages = {
        "bridge_request_validation_failed",
        "bridge_invoke_failed",
        "bridge_error_mapping_failed",
        "bridge_result_wire_failed",
        "bridge_result_validate_failed",
        "internal_error",
        "response_projection_failed",
        "read_projection_failed",
        "closure_prepare_failed",
        "check_pipeline_failed",
        "import_publication_failed",
        "maintenance_state_unverified",
        "start_state_inconsistent",
    }
    assert stages <= PROTOCOL_REASON_CODES
    assert set(REASON_REMEDIES) == stages
