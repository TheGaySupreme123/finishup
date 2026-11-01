"""Fixed first-start recovery wording selected only by service-owned reason tokens."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.recovery import continuation_for_reason, directive_for


def start_recovery_guidance(code: object, retryable: object, safe_details: object) -> str:
    """Never render an error message, arbitrary detail, or caller-supplied identity."""

    if retryable is not True or not isinstance(safe_details, Mapping):
        return ""
    reason = cast(Mapping[str, object], safe_details).get("reason_code")
    if type(reason) is not str:
        return ""
    yielded = code == PublicErrorCode.BUNDLE_BUSY and reason in {
        "start_runtime_rebind_retry_ready",
        "start_catalog_retry_ready",
        "start_busy_retry_ready",
    }
    pending = code == PublicErrorCode.OPERATION_PENDING and reason == "start_lease_pending"
    if not (yielded or pending):
        return ""
    directive = directive_for(continuation_for_reason(reason))
    return "" if directive is None else " " + directive.directive
