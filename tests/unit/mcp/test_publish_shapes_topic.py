"""Ordinary publish is one guidance read (n6 item 5).

Smoke trials fetched ``request-templates.md`` once per family. ``#publish-shapes`` holds the seven
ordinary drafts in one default page, and each family section stays for the long form.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator

from finishup.mcp import resources
from finishup.mcp.descriptors import descriptor_for
from finishup.mcp.resources import DEFAULT_GUIDANCE_PAGE_SIZE
from finishup.protocol.guidance_uris import ALL_GUIDANCE_URIS, GUIDANCE_TOPIC_URIS
from finishup.protocol.models import PublishWorkRequestModel

_ROOT = Path(__file__).resolve().parents[3]
_URI = "finishup://guidance/request-templates.md#publish-shapes"
_FAMILIES = (
    "plan_published",
    "obligation_published",
    "action_recorded",
    "result_recorded",
    "evidence_recorded",
    "claim_recorded",
    "plan_revised",
    "decision_recorded",
)


def _read_canonical_resource(logical_name: str) -> bytes:
    return (_ROOT / logical_name).read_bytes()


def test_publish_shapes_is_one_default_guidance_page(monkeypatch: pytest.MonkeyPatch) -> None:
    """One read returns every ordinary draft, inside the default page, schema-valid."""

    assert _URI in GUIDANCE_TOPIC_URIS
    assert _URI in ALL_GUIDANCE_URIS
    monkeypatch.setattr(resources, "read_verified_resource", _read_canonical_resource)
    resources._topic_resource.cache_clear()  # pyright: ignore[reportPrivateUsage]

    topic = resources.resource_for_uri(_URI)
    payload = topic.bytes
    assert payload.startswith(b"#")
    assert len(payload) <= DEFAULT_GUIDANCE_PAGE_SIZE
    page = resources.read_resource_page(_URI)
    assert page.page_count == 1
    assert page.complete
    assert page.continuation is None

    text = payload.decode("utf-8")
    for family in _FAMILIES:
        assert family in text
    # Issue #1084: each reference is written once; the envelope mirror is FinishUP's to copy.
    assert text.count('"evidence_refs":["evd_') == 1
    for boilerplate in ('"request_id"', '"expected_frontier"', '"event_id"', '"occurred_at"'):
        assert boilerplate not in text
    assert '"limitation_refs":["res_' in text
    assert '"supporting_refs":["evd_' in text
    assert "Not one live batch." in text
    assert "Skip a resolved obligation." in text

    block = re.search(r"```json\n(.*?)\n```", text, re.DOTALL)
    assert block is not None
    request = cast(dict[str, Any], json.loads(block.group(1)))
    descriptor = descriptor_for("publish_work")
    for schema in (
        descriptor.advertised_input_schema,
        descriptor.catalog_input_schema,
        descriptor.input_schema,
    ):
        cast(Any, Draft202012Validator(cast(Any, schema))).validate(request)
    PublishWorkRequestModel.model_validate(request)
