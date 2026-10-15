"""A declined confidential ceremony must not be reported as an unavailable service.

The supervised dogfood run failed here: the daemon refused a disclosure decision with
`kind_forbidden`, the client collapsed every unmapped server code to `protocol_error`, and the
CLI printed `service_unavailable`. The operator was told to restart a service that was running
correctly, and the one fact that explained what to do next never reached them.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from finishup.cli.app import _trusted_exception_failure
from finishup.cli.exits import ceremony_refusal_message, exit_code_for, remediation_message
from finishup.cli.unlock import HumanCeremonyCliError
from finishup.protocol.errors import PublicErrorCode
from finishup.service.confidential_client import ConfidentialClientError

_REFUSALS = (
    "ceremony_unsupported",
    "kind_forbidden",
    "pending_not_actionable",
    "pending_unavailable",
    "state_forbidden",
)


@pytest.mark.parametrize("reason", _REFUSALS)
def test_structural_refusals_survive_the_client_boundary(reason: str) -> None:
    """The client must carry these codes through rather than flattening them."""

    error = ConfidentialClientError(reason)

    assert error.reason == reason


@pytest.mark.parametrize("reason", _REFUSALS)
def test_refusals_report_their_cause_and_not_service_unavailable(
    reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _trusted_exception_failure(ConfidentialClientError(reason))

    captured = capsys.readouterr().err
    assert reason in captured
    assert "service_unavailable" not in captured
    # A refused ceremony is a request the service answered, not a transport failure.
    assert code == exit_code_for(PublicErrorCode.INVALID_REQUEST)


def test_state_forbidden_names_the_unlock_command() -> None:
    message = ceremony_refusal_message("state_forbidden")

    assert message is not None
    assert "finishup service unlock" in message


def test_pending_unavailable_does_not_confirm_whether_the_id_existed() -> None:
    message = ceremony_refusal_message("pending_unavailable")

    assert message is not None
    # Absent and expired share one message on purpose; distinguishing them would confirm
    # whether an unknown proposal id was ever real.
    assert "no longer exists or has expired" in message


def test_genuine_transport_failure_still_reports_service_unavailable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = _trusted_exception_failure(ConfidentialClientError("service_unavailable"))

    assert "service_unavailable" in capsys.readouterr().err
    assert code == exit_code_for(PublicErrorCode.SERVICE_UNAVAILABLE)


def test_cancellation_is_not_a_refusal(capsys: pytest.CaptureFixture[str]) -> None:
    code = _trusted_exception_failure(ConfidentialClientError("cancelled"))

    assert capsys.readouterr().err.strip() == "cancelled"
    assert code == exit_code_for("cancelled")


def test_unknown_reasons_have_no_refusal_message() -> None:
    assert ceremony_refusal_message("timeout") is None


def test_trusted_console_required_is_not_reported_as_bad_command_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing foreground console is an environment fact, not a malformed command."""

    code = _trusted_exception_failure(HumanCeremonyCliError("trusted_console_required"))

    captured = capsys.readouterr().err
    assert "trusted_console_required" in captured
    assert "invalid_request: the command input is invalid" not in captured
    assert "finishup consent prepare" in captured
    assert "finishup consent authorize" in captured
    assert code == exit_code_for(PublicErrorCode.INVALID_REQUEST)


@pytest.mark.parametrize(
    "reason",
    [
        "confirmation_mismatch",
        "input_invalid",
    ],
)
def test_genuine_input_errors_still_report_invalid_request(
    reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _trusted_exception_failure(HumanCeremonyCliError(reason))

    assert "invalid_request: the command input is invalid" in capsys.readouterr().err
    assert code == exit_code_for(PublicErrorCode.INVALID_REQUEST)


def test_rotation_stage_failures_are_not_input_invalid() -> None:
    from finishup.adapters.keys.os_keyring import OSKeyringError
    from finishup.cli.unlock import _raise_for_rotation_stage_error

    _raise_for_rotation_stage_error(OSKeyringError("missing"))
    _raise_for_rotation_stage_error(OSKeyringError("unsupported"))
    with pytest.raises(HumanCeremonyCliError) as captured:
        _raise_for_rotation_stage_error(OSKeyringError("locked"))
    assert captured.value.reason == "result_invalid"


def test_result_invalid_is_internal_not_malformed_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = _trusted_exception_failure(HumanCeremonyCliError("result_invalid"))

    assert "internal_error: the confidential ceremony could not be completed" in (
        capsys.readouterr().err
    )
    assert code == exit_code_for(PublicErrorCode.INTERNAL_ERROR)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("chat_user_attestation_invalid", "--client-kind"),
        ("chat_user_reauthentication_unavailable", "local terminal"),
        ("chat_user_target_mismatch", "finishup consent prepare"),
        ("pending_already_active", "finishup consent authorize"),
        ("pending_expired", "finishup consent prepare"),
        ("provider_credential_invalid", "8192"),
        ("provider_not_configured", "finishup --set"),
        ("repository_privacy_scope_unavailable", "finishup --privacy"),
        ("trusted_console_required", "finishup consent prepare"),
    ],
)
def test_bare_tokens_carry_the_exact_next_command(reason: str, expected: str) -> None:
    """Every mapped token must name what to run next, not restate the token."""

    message = remediation_message(reason)

    assert message is not None
    assert expected in message


def test_unmapped_tokens_have_no_remediation() -> None:
    assert remediation_message("authorize_failed") is None


def test_subscription_config_failures_all_carry_recovery_guidance() -> None:
    reasons = {
        "config_file_too_large",
        "config_file_unreadable",
        "config_preimage_mismatch",
        "config_schema_unsupported",
        "config_toml_invalid",
        "config_value_invalid",
        "durability_unsupported",
        "external_profile_forbids_local_model",
        "external_runtime_forbids_local_model",
        "external_runtime_forbids_provider",
        "external_runtime_required_for_semantic",
        "https_origin_invalid",
        "local_model_locator_forbidden",
        "max_findings_out_of_range",
        "owner_declared_endpoint_forbidden",
        "owner_declared_endpoint_required",
        "payload_logging_forbidden",
        "privacy_bootstrap_unsafe",
        "provider_required_for_semantic",
        "release_probe_not_a_user_profile",
        "secret_in_config",
        "strict_local_forbids_provider",
        "test_fake_forbids_local_model",
        "test_fake_forbids_provider",
        "unknown_config_key",
    }

    for reason in reasons:
        message = remediation_message(reason)
        assert message is not None, reason
        assert any(word in message for word in ("retry", "upgrade", "provision")), reason


def test_vault_result_family_names_the_failed_approval_and_the_retry() -> None:
    """Every bounded `vault_result_<reason>` projection shares one honest remediation."""

    for reason in ("vault_result_throttle_record_exists", "vault_result_keyring_unavailable"):
        message = remediation_message(reason)
        assert message is not None, reason
        assert "recorded as failed" in message, reason
        assert "finishup consent prepare" in message, reason
    assert remediation_message("vault_result") is None
    assert remediation_message("result_invalid") is not None


def test_grant_unconfirmed_remediation_points_at_status_not_a_blind_retry() -> None:
    """#519: an unprovable grant outcome must send the owner to the authoritative state read."""

    message = remediation_message("repository_privacy_grant_unconfirmed")

    assert message is not None
    assert "finishup provider status" in message
    assert "may already be effective" in message


def test_resource_count_remediation_names_the_owning_sync_script() -> None:
    message = remediation_message("resource_counts_invalid")

    assert message is not None
    assert "scripts/sync_resource_ripple.py --write" in message
    assert "REVIEWED_RESOURCE_COUNT" in message
    assert "update the compiled count" not in message


def test_resource_remediation_never_names_a_single_step_of_the_ripple() -> None:
    """A dependent generator alone reproduces the mis-ordered regeneration these tokens report."""

    for reason in (
        "manifest_digest_mismatch",
        "resource_counts_invalid",
        "support_digest_mismatch",
        "support_resource_set_mismatch",
    ):
        message = remediation_message(reason)
        assert message is not None, reason
        assert "verify_resource_manifest.py" not in message, reason
        assert "generate_schemas.py" not in message, reason


def test_secret_rejected_names_the_credential_and_the_retry() -> None:
    """A refused or unusable key must not look like a dead service; name the retry."""

    message = ceremony_refusal_message("secret_rejected")

    assert message is not None
    assert "not accepted" in message
    assert "finishup provider credential set" in message


class TestEveryHumanCliErrorCarriesADirective:
    """Issue #741: `REMEDIATION_MESSAGES` reached a subset of call sites and no directive.

    #743 gave `render_human_error` and one lifecycle helper their directive lines. These are the
    remaining human-rendered CLI surfaces: the trusted-ceremony mapper, the interactive menu, the
    instance/path refusal line, the observe verbs, and `finishup version`. A remedy an agent only
    sees on one of five surfaces is the defect this class exists to catch.
    """

    def test_a_declined_ceremony_names_its_continuation(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = _trusted_exception_failure(ConfidentialClientError("kind_forbidden"))

        captured = capsys.readouterr().err
        assert "kind_forbidden: that ceremony is not permitted" in captured
        assert "Continuation: ceremony_refusal_terminal" in captured
        assert "Guidance: finishup://guidance/request-templates.md#setup-and-consent" in captured
        assert code == exit_code_for(PublicErrorCode.INVALID_REQUEST)

    def test_a_console_refusal_names_its_continuation(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _trusted_exception_failure(HumanCeremonyCliError("trusted_console_required"))

        captured = capsys.readouterr().err
        assert captured.startswith("trusted_console_required: ")
        assert "Continuation: consent_ceremony_required" in captured

    def test_a_reason_with_only_a_directive_still_renders_one(self) -> None:
        """A reason carries a remedy, a directive, or both; the line must not require the first.

        The call sites used to gate on `remediation_message(...) is not None`, so a reason whose
        only answer lives in the registry would have fallen through to a generic input complaint.
        """

        from finishup.cli.exits import remediation_message
        from finishup.cli.render import bounded_failure_line

        assert remediation_message("vault_locked") is None
        line = bounded_failure_line("vault_locked")

        assert line.splitlines()[0] == "vault_locked"
        assert "Continuation: vault_unlock_required" in line

    def test_a_reason_with_neither_is_returned_bare_so_a_caller_can_tell(self) -> None:
        from finishup.cli.render import bounded_failure_line

        assert bounded_failure_line("confirmation_mismatch") == "confirmation_mismatch"

    def test_the_menu_renders_the_same_refusal_as_the_command_tree(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from finishup.cli import menu

        async def refuse() -> object:
            raise ConfidentialClientError("pending_unavailable")

        menu._run_ceremony(refuse)

        captured = capsys.readouterr().err
        assert "pending_unavailable: that pending decision no longer exists" in captured
        assert "Continuation: pending_decision_refresh" in captured

    def test_the_menu_renders_a_bounded_setup_token_with_its_directive(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from finishup.cli import menu

        async def refuse() -> object:
            raise ValueError("provider_not_configured")

        menu._run_ceremony(refuse)

        captured = capsys.readouterr().err
        assert captured.startswith("provider_not_configured: ")
        assert "finishup --set" in captured
        assert "Continuation: provider_setup_required" in captured

    def test_the_menu_still_falls_back_for_a_token_nothing_is_known_about(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from finishup.cli import menu

        async def refuse() -> object:
            raise ValueError("confirmation_mismatch")

        menu._run_ceremony(refuse)

        assert capsys.readouterr().err.strip() == "invalid_request: the ceremony input is invalid"

    def test_an_instance_refusal_names_its_continuation(self) -> None:
        from finishup.cli.instance import instance_failure_line
        from finishup.config.paths import PathSafetyError

        line = instance_failure_line(PathSafetyError("path_on_network_filesystem"))

        assert line.startswith("path_on_network_filesystem: ")
        assert "Continuation: local_state_repair" in line
        assert "Next: FinishUP could not safely open local state" in line

    def test_an_observe_refusal_names_its_continuation(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from finishup.cli import observe as observe_cli

        code = observe_cli.observe_status(workspace="", json_output=False, _state=tmp_path)

        captured = capsys.readouterr().err
        assert code == exit_code_for(PublicErrorCode.INVALID_REQUEST)
        assert captured.startswith("observation_status_failed:workspace_unresolvable: ")
        assert "Continuation: storage_root_unsafe" in captured

    def test_an_observe_json_failure_carries_the_resolved_directive(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """ADR-030 as amended for #741: a CLI-owned JSON body carries what the human line says.

        The token stays authoritative and the text is resolved by this renderer, so the JSON
        ``recovery`` object and the human ``Continuation:``/``Next:`` lines cannot disagree.
        """

        from finishup.cli import observe as observe_cli
        from finishup.cli.render import local_recovery_json, render_local_recovery_lines

        observe_cli.observe_status(workspace="", json_output=True, _state=tmp_path)

        body = json.loads(capsys.readouterr().out)["error"]
        assert set(body) == {"code", "message", "operation", "reason", "retryable", "recovery"}
        recovery = body["recovery"]
        assert recovery == local_recovery_json("workspace_unresolvable")
        assert recovery["continuation"] == "storage_root_unsafe"
        lines = render_local_recovery_lines("workspace_unresolvable")
        assert f"Continuation: {recovery['continuation']}" in lines
        assert f"Next: {recovery['directive']}" in lines

    def test_a_resource_integrity_version_failure_names_its_continuation(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import finishup
        from finishup.cli.app import version_command
        from finishup.version import ResourceIntegrityError

        def refuse() -> object:
            raise ResourceIntegrityError("resource_missing")

        monkeypatch.setattr(finishup, "get_version_manifest", refuse)
        with pytest.raises(typer.Exit):
            version_command(json_output=True)

        captured = capsys.readouterr().err
        assert captured.startswith("version: FAIL (resource_missing)")
        assert "version: remediation: a reviewed installed resource is absent" in captured
        assert "version: Continuation: resource_integrity_repair" in captured


def test_reauthentication_recovery_includes_repository_privacy_and_rotation() -> None:
    message = remediation_message("chat_user_reauthentication_unavailable")
    assert message is not None
    assert "finishup --privacy" in message
    assert "finishup service rotate-passphrase" in message
    assert "finishup provider credential set" in message
