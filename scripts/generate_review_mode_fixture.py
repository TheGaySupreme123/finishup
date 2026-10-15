"""Generate canonical ADR-049 review-mode vectors for check-result and status-result 1.4.0."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/review-mode-1.4.0.case.json"
_FIXTURE_ID: Final = "CAN-018"
_SWITCH: Final = "evt_00000000-0000-4000-8000-0000000000e1"


def _status(**members: JsonValue) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "ai_review_available": True,
        "mode": "local",
        "requested": "local",
        "setting": "local_agent_opt_in",
        "setting_explicit": True,
    }
    body.update(members)
    return {"review_mode": {key: value for key, value in body.items() if value is not None}}


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    # (vector_id, surface, payload, admitted)
    cases: tuple[tuple[str, str, dict[str, JsonValue], bool], ...] = (
        (
            "check_local_conversation_default",
            "check_result",
            {"review_mode": {"mode": "local", "source": "conversation_default"}},
            True,
        ),
        (
            "check_ai_powered_conversation_switch",
            "check_result",
            {
                "review_mode": {
                    "mode": "ai_powered",
                    "source": "conversation_switch",
                    "switch_event_id": _SWITCH,
                }
            },
            True,
        ),
        (
            "check_local_review_disabled",
            "check_result",
            {
                "review_mode": {
                    "local_reason": "review_disabled",
                    "mode": "local",
                    "source": "conversation_switch",
                    "switch_event_id": _SWITCH,
                }
            },
            True,
        ),
        (
            "check_request_route_local_only",
            "check_result",
            {
                "review_mode": {
                    "local_reason": "route_local_only",
                    "mode": "local",
                    "source": "check_request",
                }
            },
            True,
        ),
        (
            "check_reason_on_ai_powered",
            "check_result",
            {
                "review_mode": {
                    "local_reason": "review_disabled",
                    "mode": "ai_powered",
                    "source": "check_request",
                }
            },
            False,
        ),
        (
            "check_switch_without_event",
            "check_result",
            {"review_mode": {"mode": "local", "source": "conversation_switch"}},
            False,
        ),
        (
            "check_status_only_reason",
            "check_result",
            {
                "review_mode": {
                    "local_reason": "switched_to_local",
                    "mode": "local",
                    "source": "conversation_default",
                }
            },
            False,
        ),
        (
            "status_hybrid_not_set_up",
            "status_result",
            _status(ai_review_available=False, local_reason="conversation_default"),
            True,
        ),
        (
            "status_released_local_only",
            "status_result",
            _status(
                ai_review_available=False,
                local_reason="conversation_default",
                setting="local_only",
                setting_explicit=False,
            ),
            True,
        ),
        (
            "status_every_task_switch_to_local",
            "status_result",
            _status(
                mode="ai_powered",
                setting="ai_powered",
                switch_event_id=_SWITCH,
                switch_sequence="7",
            ),
            True,
        ),
        (
            "status_review_disabled",
            "status_result",
            _status(local_reason="review_disabled", requested="ai_powered"),
            True,
        ),
        (
            "status_without_setting_explicit",
            "status_result",
            _status(setting_explicit=None),
            False,
        ),
        (
            "status_unknown_reason",
            "status_result",
            _status(local_reason="owner_said_no"),
            False,
        ),
    )
    vectors: list[dict[str, JsonValue]] = []
    for vector_id, surface, payload, admitted in cases:
        vectors.append(
            {
                "vector_id": vector_id,
                "surface": surface,
                "admitted": admitted,
                "payload": payload,
                "canonical_hex": canonical_encode(payload).hex(),
                "digest": canonical_digest(payload),
            }
        )
    return tuple(vectors)


def document() -> dict[str, JsonValue]:
    return {
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "minimum_versions": {
            "check_result_schema": "1.4.0",
            "engine": "0.1.0",
            "protocol": "0.1",
            "status_result_schema": "1.4.0",
        },
        "owns_requirements": ["ADR-049:review-mode-wire"],
        "purpose": (
            "Freeze the optional review_mode member of check-result and status-result 1.4.0: "
            "the closed source and local_reason tokens (review_disabled included), the switch "
            "event id rule, the required setting_explicit, and rejected shapes."
        ),
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "forbidden",
        },
        "input": {"vectors": list(_vectors())},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    data = canonical_encode(cast(JsonValue, document()))
    target = root / "fixtures" / _PATH
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    unrelated = [item for item in manifest["members"] if item["path"] != _PATH]
    if any(item["fixture_id"] == _FIXTURE_ID for item in unrelated):
        raise ValueError("fixture_identity_conflict")
    member = {
        "fixture_id": _FIXTURE_ID,
        "path": _PATH,
        "byte_length": len(data),
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if args.check:
        if (
            not target.is_file()
            or target.read_bytes() != data
            or [item for item in manifest["members"] if item["path"] == _PATH] != [member]
        ):
            raise ValueError("review_mode_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("review mode fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
