from __future__ import annotations

import pytest

from finishup.cli.exits import PUBLIC_EXIT_CODES, exit_code_for
from finishup.protocol.errors import PublicErrorCode

_EXPECTED = {
    PublicErrorCode.INVALID_REQUEST: 2,
    PublicErrorCode.PROTOCOL_VERSION_UNSUPPORTED: 20,
    PublicErrorCode.SESSION_NOT_FOUND: 10,
    PublicErrorCode.SESSION_CONFLICT: 10,
    PublicErrorCode.IDEMPOTENCY_CONFLICT: 10,
    PublicErrorCode.REQUEST_IDENTITY_CONFLICT: 10,
    PublicErrorCode.OPERATION_PENDING: 11,
    PublicErrorCode.FRONTIER_CONFLICT: 10,
    PublicErrorCode.EVENT_INVALID: 2,
    PublicErrorCode.LIMIT_EXCEEDED: 2,
    PublicErrorCode.BUNDLE_BUSY: 20,
    PublicErrorCode.STORAGE_UNSAFE: 20,
    PublicErrorCode.STORAGE_CORRUPT: 40,
    PublicErrorCode.MIGRATION_REQUIRED: 20,
    PublicErrorCode.SERVICE_UNAVAILABLE: 20,
    PublicErrorCode.VAULT_LOCKED: 20,
    PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED: 20,
    PublicErrorCode.PROVIDER_UNAVAILABLE: 30,
    PublicErrorCode.PROVIDER_REFUSED: 30,
    PublicErrorCode.PROVIDER_TIMEOUT: 30,
    PublicErrorCode.SEMANTIC_RESULT_INVALID: 30,
    PublicErrorCode.CANCELLED: 130,
    PublicErrorCode.INTERNAL_ERROR: 70,
}


def test_public_exit_mapping_is_exact_and_exhaustive() -> None:
    assert dict(PUBLIC_EXIT_CODES) == _EXPECTED
    assert set(PUBLIC_EXIT_CODES) == set(PublicErrorCode)
    assert exit_code_for("success") == 0
    assert exit_code_for("cancelled") == 130


@pytest.mark.parametrize(("code", "expected"), tuple(_EXPECTED.items()))
def test_each_public_code_has_the_stable_shell_exit(code: PublicErrorCode, expected: int) -> None:
    assert exit_code_for(code) == expected


def test_unknown_outcome_is_rejected() -> None:
    with pytest.raises(TypeError, match="public_outcome_invalid"):
        exit_code_for("unknown")  # pyright: ignore[reportArgumentType]
