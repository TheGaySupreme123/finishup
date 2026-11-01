"""Current consent artifacts contain no reusable approval or structural secret transport."""

from __future__ import annotations

import json
from pathlib import Path

from finishup.service.elevated_bootstrap import catalog_payload, status_payload

_ROOT = Path(__file__).resolve().parents[3]
_PUBLIC_ROOTS = (
    _ROOT / "docs",
    _ROOT / "guidance",
    _ROOT / "schemas",
    _ROOT / "src" / "finishup" / "resources",
)
_FORBIDDEN = (
    "confirmation_phrase",
    "approve_command",
    "secret_fds",
    "credential_fd",
    "passphrase_fd",
    "reauth_fd",
    "passphrase-fd",
    "reauth-fd",
    "credential-fd",
    "consent approve",
)


def test_public_consent_artifacts_expose_no_reusable_authorization_or_secret_transport() -> None:
    for root in _PUBLIC_ROOTS:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {".json", ".md"}:
                text = path.read_text(encoding="utf-8")
                for forbidden in _FORBIDDEN:
                    assert forbidden not in text, path


def test_live_agent_projection_contains_only_bounded_review_data(tmp_path: Path) -> None:
    rendered = json.dumps(
        {"catalog": catalog_payload(), "status": status_payload(_state=tmp_path)},
        sort_keys=True,
    )
    for forbidden in _FORBIDDEN:
        assert forbidden not in rendered
    assert '"agent_attestation_is_independent_proof": false' in rendered
    assert '"trusted_console_is_not_authority": true' in rendered
