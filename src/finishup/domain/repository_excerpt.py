"""Path names a repository excerpt never shows (ADR-031).

The check-time change lists a file with one of these names and does not show its bytes.
Auto-supplied command output uses the same name check, so a command that names such a file
cannot send what the change would have withheld. The list is a name heuristic: common
conventions, not every file that holds a secret.
"""

from __future__ import annotations

from typing import Final

_CREDENTIAL_NAMES: Final = frozenset(
    {
        b".env",
        b".envrc",
        b".git-credentials",
        b".htpasswd",
        b".netrc",
        b"_netrc",
        b".npmrc",
        b".pgpass",
        b".pypirc",
        b"credentials",
        b"credentials.json",
        b"credentials.toml",
        b"id_dsa",
        b"id_ecdsa",
        b"id_ed25519",
        b"id_rsa",
    }
)
_CREDENTIAL_PREFIXES: Final = (b".env.",)
_CREDENTIAL_SUFFIXES: Final = (
    b".jks",
    b".kdbx",
    b".key",
    b".keystore",
    b".p12",
    b".pem",
    b".pfx",
    b".tfstate",
    b".tfvars",
)


def credential_named_bytes(path: bytes) -> bool:
    """Whether ``path``'s final component is a credential file name (ADR-031)."""

    if type(path) is not bytes:
        raise TypeError("credential_path_not_bytes")
    name = path.rsplit(b"/", 1)[-1].lower()
    return (
        name in _CREDENTIAL_NAMES
        or name.startswith(_CREDENTIAL_PREFIXES)
        or name.endswith(_CREDENTIAL_SUFFIXES)
    )


def credential_named_path(path: str) -> bool:
    """``credential_named_bytes`` for one command operand or repository-relative path."""

    if type(path) is not str or "\x00" in path:
        return False
    return credential_named_bytes(path.replace("\\", "/").encode("utf-8", errors="surrogateescape"))


def credential_name_patterns() -> tuple[str, ...]:
    """The same final-component heuristic as glob patterns, for pre-read selection."""

    return tuple(
        sorted(
            name.decode("ascii")
            for name in (
                *_CREDENTIAL_NAMES,
                *(prefix + b"*" for prefix in _CREDENTIAL_PREFIXES),
                *(b"*" + suffix for suffix in _CREDENTIAL_SUFFIXES),
            )
        )
    )
