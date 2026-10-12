"""Provider-bound review-input manifests for scripted AI-powered review successes.

A successful review without the exact provider-bound manifest is disclosed as
``semantic_provider_input_manifest_missing`` (#965). Scripted evaluators that stand in for a
real provider call return this minimal, schema-valid manifest so their success stays a clean
success; it describes an empty packet and never stands in for real provider bytes.
"""

from __future__ import annotations

from yoetz.domain.values import JsonObject


def provider_bound_manifest() -> JsonObject:
    section = JsonObject(
        {
            "status": "missing",
            "source_refs": [],
            "item_ids": [],
            "omitted_refs": [],
            "omission_reasons": [],
            "revision": None,
            "content_digest": None,
            "content_bytes": 0,
        }
    )
    return JsonObject(
        {
            "schema": "yoetz.review-input-manifest/1",
            "phase": "provider_bound",
            "specification": section,
            "current_diff": section,
            "caller_evidence": section,
            "latest_verification": section,
            "prior_finding_context": section,
            "missing_inputs": [],
            "selected_item_count": 0,
            "selected_excerpt_bytes": 0,
            "omitted_item_count": 0,
        }
    )
