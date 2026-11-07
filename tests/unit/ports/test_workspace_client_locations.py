"""Client locations: what a server read may name on a claim-bound client's machine (ADR-051)."""

from __future__ import annotations

import pytest

from finishup.adapters.repository_identity import claim_repository_privacy_context
from finishup.kernel.declared_checks import declared_test_location
from finishup.ports.change_capture import CheckWorkspaceSource
from finishup.ports.control import WorkspaceClaim
from finishup.ports.keys import REPOSITORY_CLAIM_MAC_DOMAIN, REPOSITORY_PRIVACY_MAC_DOMAIN
from finishup.ports.workspace_agent import (
    ListBeneathArguments,
    ReadDeclaredTestArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    WorkspaceCodecError,
    WorkspaceOperation,
    client_location_valid,
    operation_spec,
    resolve_client_location,
    workspace_handle_for_claim,
)

_HANDLE = "client:0123456789abcdef"
_OTHER = "client:fedcba9876543210"


@pytest.mark.parametrize(
    ("value", "relative", "valid"),
    (
        ("/srv/dev/project", False, True),
        (_HANDLE, False, True),
        (_HANDLE + "/tests/test_a.py", True, True),
        (_HANDLE + "/tests/test_a.py", False, False),
        (_HANDLE + "/", True, False),
        (_HANDLE + "/a//b.py", True, False),
        (_HANDLE + "/../etc/passwd", True, False),
        (_HANDLE + "/./a.py", True, False),
        ("client:0123", True, False),
        ("relative/root", True, False),
        ("", True, False),
        ("/bad\x00path", True, False),
    ),
)
def test_a_location_is_an_absolute_path_or_beneath_the_handle(
    value: str, relative: bool, valid: bool
) -> None:
    assert client_location_valid(value, relative=relative) is valid


def test_the_agent_resolves_only_its_own_handle_against_its_own_root() -> None:
    root = "/srv/dev/project"
    assert resolve_client_location(_HANDLE, _HANDLE, root) == root
    assert resolve_client_location(_HANDLE + "/src/a.py", _HANDLE, root) == root + "/src/a.py"
    assert resolve_client_location("/srv/shared/data", _HANDLE, root) == "/srv/shared/data"
    assert resolve_client_location(_OTHER + "/src/a.py", _HANDLE, root) is None
    with pytest.raises(ValueError, match="client_location_invalid"):
        resolve_client_location("relative", _HANDLE, root)
    with pytest.raises(ValueError, match="client_root_invalid"):
        resolve_client_location(_HANDLE, _HANDLE, "relative")


def test_read_arguments_name_the_claimed_root_by_its_handle_and_round_trip() -> None:
    cases = (
        (
            WorkspaceOperation.READ_TEXT_BENEATH,
            ReadTextBeneathArguments(_HANDLE, "a.py", (_HANDLE,)),
        ),
        (WorkspaceOperation.LIST_BENEATH, ListBeneathArguments(_HANDLE, "", ("/srv/state",))),
        (
            WorkspaceOperation.READ_DECLARED_TEST,
            ReadDeclaredTestArguments(_HANDLE + "/tests/test_a.py", ("/srv/state",)),
        ),
        (
            WorkspaceOperation.READ_OUTSIDE_INPUTS,
            ReadOutsideInputsArguments(("/srv/shared",), ("/srv/shared/a.csv",), 4, (_HANDLE,)),
        ),
    )
    for operation, arguments in cases:
        spec = operation_spec(operation)
        assert spec is not None
        assert spec.decode_arguments(spec.encode_arguments(arguments)) == arguments


def test_a_handle_never_stands_for_an_outside_root_or_a_relative_root() -> None:
    with pytest.raises(ValueError):
        ReadOutsideInputsArguments((_HANDLE,), (), 4)
    with pytest.raises(ValueError):
        ReadTextBeneathArguments(_HANDLE + "/src", "a.py")
    spec = operation_spec(WorkspaceOperation.READ_TEXT_BENEATH)
    assert spec is not None
    with pytest.raises(WorkspaceCodecError):
        spec.decode_arguments({"excluded": [], "relative": "a.py", "root": _HANDLE + "/src"})


def test_a_relative_declared_test_stays_beneath_the_handle() -> None:
    assert declared_test_location("tests/test_a.py", _HANDLE) == _HANDLE + "/tests/test_a.py"
    assert declared_test_location("tests/../secret.py", _HANDLE) is None
    assert declared_test_location("tests/.hidden/test_a.py", _HANDLE) is None
    assert declared_test_location("tests/test_a.py", "/work/repo") == "/work/repo/tests/test_a.py"
    assert declared_test_location("tests/test_a.py", "client:not-a-handle") is None


def test_a_check_source_may_name_a_handle_but_never_a_relative_path() -> None:
    commitment = "hmac-sha256:" + "1" * 64
    assert CheckWorkspaceSource(_HANDLE, commitment).workspace == _HANDLE
    with pytest.raises(ValueError):
        CheckWorkspaceSource("client:short", commitment)
    with pytest.raises(ValueError):
        CheckWorkspaceSource("relative/repo", commitment)


class _Key:
    def __init__(self) -> None:
        self.domains: list[bytes] = []
        self.messages: list[bytes] = []

    def mac(self, domain: bytes, message: bytes) -> str:
        import hashlib
        import hmac

        self.domains.append(domain)
        self.messages.append(message)
        return "hmac-sha256:" + hmac.new(b"k" * 32, domain + message, hashlib.sha256).hexdigest()


def test_a_claim_is_keyed_under_its_own_domain_into_a_pathless_identity() -> None:
    key = _Key()
    claim = WorkspaceClaim("git_common_root", "sha256:" + "a" * 64, "sha256:" + "b" * 64)
    context = claim_repository_privacy_context(claim, key)
    assert key.domains == [REPOSITORY_CLAIM_MAC_DOMAIN]
    assert REPOSITORY_CLAIM_MAC_DOMAIN != REPOSITORY_PRIVACY_MAC_DOMAIN
    # The repository commitment is over the claim only; the worktree digest never enters it.
    assert key.messages == [b"git_common_root\x00sha256:" + b"a" * 64]
    assert context.identity_kind == "client_claim"
    assert context.workspace_locator is None
    assert context.workspace_handle == workspace_handle_for_claim(
        context.commitment, claim.worktree
    )
    other = claim_repository_privacy_context(
        WorkspaceClaim("directory", claim.digest, claim.worktree), key
    )
    assert other.commitment != context.commitment
    # Another worktree of the same repository: the same commitment, its own handle.
    sibling = claim_repository_privacy_context(
        WorkspaceClaim("git_common_root", claim.digest, "sha256:" + "c" * 64), key
    )
    assert sibling.commitment == context.commitment
    assert sibling.workspace_handle != context.workspace_handle
    with pytest.raises(TypeError):
        claim_repository_privacy_context(object(), key)  # pyright: ignore[reportArgumentType]
