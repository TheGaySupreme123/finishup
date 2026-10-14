"""macOS LocalAuthentication authority for one exact plugin-artifact review.

This adapter is deliberately narrower than the service-wide ``UserPresencePort``. It proves
device-owner authentication only for the already validated, digest-bound
``plugin_artifact_apply`` pending consumed by ``ElevatedPortableArtifactReview``.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Final

from finishup.ports.plugin_artifacts import ArtifactAuthority

__all__ = ["MacOSArtifactUserPresence"]

_OSASCRIPT: Final = "/usr/bin/osascript"
_TIMEOUT_SECONDS: Final = 130
_JXA_LOCAL_AUTHENTICATION: Final = r"""
ObjC.import('Foundation');
ObjC.import('LocalAuthentication');

function run(argv) {
    if (argv.length !== 1) {
        return 'invalid';
    }
    const context = $.LAContext.alloc.init;
    context.touchIDAuthenticationAllowableReuseDuration = 0;
    const policy = $.LAPolicyDeviceOwnerAuthentication;
    const error = Ref();
    if (!ObjC.unwrap(context.canEvaluatePolicyError(policy, error))) {
        return 'unavailable';
    }

    let completed = false;
    let approved = false;
    context.evaluatePolicyLocalizedReasonReply(policy, $(argv[0]), function(success, replyError) {
        // JXA represents Objective-C nil error pointers with a truthy proxy on some macOS builds.
        // LocalAuthentication's success boolean is the authoritative result; Apple specifies the
        // error only as diagnostic detail when success is false.
        approved = Boolean(success);
        completed = true;
    });

    const deadline = Date.now() + 120000;
    while (!completed && Date.now() < deadline) {
        $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.05));
    }
    return completed && approved ? 'approved' : 'denied';
}
""".lstrip()


class MacOSArtifactUserPresence:
    """Prompt through Apple LocalAuthentication for one exact pending artifact action."""

    def verify_artifact_review(self, authority: ArtifactAuthority) -> None:
        if (
            sys.platform != "darwin"
            or type(authority) is not ArtifactAuthority
            or authority.channel != "review_only"
            or authority.review_id is None
        ):
            raise RuntimeError("human_authority_unavailable")

        reason = (
            "Approve the one-time FinishUP plugin_artifact_apply action for preview "
            f"{authority.target_digest} and pending review {authority.review_id}."
        )
        try:
            completed = subprocess.run(  # noqa: S603 - fixed SIP-protected Apple executable
                [_OSASCRIPT, "-l", "JavaScript", "-", reason],
                check=False,
                input=_JXA_LOCAL_AUTHENTICATION.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                },
                timeout=_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("human_authority_unavailable") from exc
        if completed.returncode != 0 or completed.stdout.strip() != b"approved":
            raise RuntimeError("human_authority_unavailable")
