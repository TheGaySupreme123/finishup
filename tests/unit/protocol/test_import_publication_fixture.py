"""Golden import-publication authorization target vectors for issue #301."""

from __future__ import annotations

from typing import Any, cast

from finishup.protocol.canonical import canonical_digest
from finishup.protocol.consent import ImportPublicationPreviewModel
from fixture_loader import FixtureLoader


def test_import_publication_target_fixture_is_exact_and_content_free(
    fixture_loader: FixtureLoader,
) -> None:
    case = cast(
        dict[str, Any],
        fixture_loader.load_json("imports/codex/publication-authorization.case.json"),
    )
    target = cast(dict[str, Any], case["input"]["target"])
    expected = cast(dict[str, Any], case["expected"])
    digest = canonical_digest(target)
    assert digest == expected["target_digest"]
    preview = ImportPublicationPreviewModel.model_validate(
        {
            **target,
            "schema": "yoetz.import-publication-preview/1",
            "authorization_target_digest": digest,
        }
    )
    assert preview.reasoning_items_included is False
    assert preview.complete_transcript_included is False
    assert preview.reviewer_egress_changed is False
    assert "source_bytes" not in preview.model_dump(mode="json")
    assert "excerpt" not in preview.model_dump(mode="json")

    changed = {**target, "session_id": "ses_10000000-0000-4000-8000-000000000004"}
    assert canonical_digest(changed) != digest
