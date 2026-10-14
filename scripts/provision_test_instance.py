"""Provision, inspect, and dispose an independent FinishUP test instance (issue #604).

One instance is one directory tree beneath a short, owner-private base outside every repository:

    <base>/<tag>/dist/       the wheel built from the exact requested revision
    <base>/<tag>/runtime/    a virtual environment holding only that wheel (pinned to the root)
    <base>/<tag>/state/      the FINISHUP_ISOLATED_ROOT of that instance (config, data, state, run,
                             cache, log) sealed by the instance-identity marker
    <base>/<tag>/provenance.json   digest-only record of what was built and from where

``create`` builds the wheel with ``uv build --no-sources`` from the exact revision (refusing a
modified working tree unless ``--allow-dirty``), installs it into the runtime with ``uv``, and lets
the snapshot's own ``finishup instance create --bind-runtime`` seal the root. Because the runtime is
pinned, ``<base>/<tag>/runtime/bin/finishup`` resolves that root even when a host or shell drops the
environment variable, and never the everyday installation. ``dispose`` stops only the service
holding that root's singleton, removes the root through ``finishup instance dispose``, then removes
the runtime and wheel. Repeating ``dispose`` is a no-op. Nothing here touches the everyday install,
host configuration, or vaults.

An instance built from a revision before the FinishUP rename ships only the legacy ``yoetz``
launcher and package and reads ``YOETZ_ISOLATED_ROOT`` (ADR-028 upgrade tests). Every command
probes ``bin/finishup`` first, then ``bin/yoetz``, and drives whichever package that launcher
belongs to; snapshot commands never inherit either variable prefix (ADR-048).

This is contributor tooling; the shipped product surface is ``finishup instance``. Documented in
``docs/runbooks/test-instances.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast

_REPO_ROOT: Final = Path(__file__).resolve().parents[1]
# Frozen legacy identifier (ADR-048): existing instances' provenance.json carries this schema tag.
_PROVENANCE_SCHEMA: Final = "yoetz.test-instance-provenance/1"
_DEFAULT_BASE: Final = Path.home() / ".yz-instances"
_TAG_ALPHABET: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_VCS_MARKERS: Final = (".git", ".hg", ".svn", ".jj")
# Launcher name -> the package it runs, FinishUP first. A pre-rename runtime has only the legacy
# ``yoetz`` launcher and package; a runtime that ships both resolves to FinishUP (ADR-048).
_RUNTIME_LAUNCHERS: Final = (("finishup", "finishup"), ("yoetz", "yoetz"))
# Product variable prefixes a snapshot command must not inherit: FinishUP and legacy (ADR-048).
_ENV_PREFIXES: Final = ("FINISHUP_", "YOETZ_")
_ISOLATED_ROOT_ENV_NAMES: Final = ("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT")


class ProvisionError(Exception):
    """A bounded provisioning failure; the message names the condition, never content."""


def _fail(message: str) -> ProvisionError:
    return ProvisionError(message)


def _run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: int = 600,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed argv assembled from validated inputs
        args, capture_output=True, env=env, cwd=cwd, timeout=timeout, check=False
    )


def _clean_env(home: Path | None = None) -> dict[str, str]:
    """The environment a snapshot command runs under: no FINISHUP_ or YOETZ_ variables leak in."""

    env = {name: value for name, value in os.environ.items() if not name.startswith(_ENV_PREFIXES)}
    if home is not None:
        env["HOME"] = str(home)
    return env


def _runtime_launcher(runtime: Path) -> tuple[Path, str] | None:
    """Return the runtime's launcher and its package: ``bin/finishup``, else ``bin/yoetz``."""

    for name, package in _RUNTIME_LAUNCHERS:
        launcher = runtime / "bin" / name
        if launcher.is_file():
            return launcher, package
    return None


def _environment_export(root: Path) -> str:
    """Both isolation-root spellings with one value, so either launcher generation isolates."""

    return " ".join(f"{name}={root}" for name in _ISOLATED_ROOT_ENV_NAMES)


def _digest_bytes(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1_048_576), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _identity_digest(path: Path) -> str:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path
    return "sha256:" + hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()


def _validate_tag(tag: str) -> str:
    if not tag or len(tag) > 32 or set(tag) - _TAG_ALPHABET or tag.startswith("-"):
        raise _fail("tag_invalid: use 1-32 lowercase letters, digits, or hyphens")
    return tag


def _validate_base(base: Path) -> Path:
    if not base.is_absolute():
        raise _fail("base_invalid: --base must be absolute")
    for ancestor in (base, *base.parents):
        if any((ancestor / marker).exists() for marker in _VCS_MARKERS):
            raise _fail("base_in_repository: choose a base outside every repository")
    if base.is_relative_to(Path("/tmp")) or base.is_relative_to(Path("/private/tmp")):
        raise _fail("base_shared_temp: choose an owner-private base such as ~/.yz-instances")
    return base


def _layout(base: Path, tag: str) -> dict[str, Path]:
    root = base / tag
    return {
        "root": root,
        "dist": root / "dist",
        "runtime": root / "runtime",
        "state": root / "state",
        "src": root / "src",
        "provenance": root / "provenance.json",
    }


def _resolve_revision(checkout: Path, revision: str) -> tuple[str, bool]:
    resolved = _run(["git", "-C", str(checkout), "rev-parse", "--verify", f"{revision}^{{commit}}"])
    if resolved.returncode != 0:
        raise _fail(
            "revision_unresolvable: the requested revision is not a commit in that checkout"
        )
    sha = resolved.stdout.decode("ascii").strip()
    head = _run(["git", "-C", str(checkout), "rev-parse", "HEAD"]).stdout.decode("ascii").strip()
    return sha, sha == head


def _tree_modified(checkout: Path) -> bool:
    status = _run(["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=no"])
    return status.returncode != 0 or bool(status.stdout.strip())


def _export_revision(checkout: Path, sha: str, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(dir=destination.parent) as scratch:
        archive = Path(scratch) / "src.tar"
        with archive.open("wb") as sink:
            exported = subprocess.run(  # noqa: S603 - fixed git argv
                ["git", "-C", str(checkout), "archive", "--format=tar", sha],
                stdout=sink,
                stderr=subprocess.PIPE,
                check=False,
            )
        if exported.returncode != 0:
            raise _fail("revision_export_failed: git archive did not produce the tree")
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter="data")


def _build_wheel(source: Path, dist: Path) -> Path:
    dist.mkdir(mode=0o700, exist_ok=True)
    built = _run(["uv", "build", "--no-sources", "-o", str(dist), str(source)])
    if built.returncode != 0:
        sys.stderr.write(built.stderr.decode("utf-8", errors="replace"))
        raise _fail("wheel_build_failed")
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise _fail("wheel_build_ambiguous: expected exactly one wheel")
    return wheels[0]


def _install_runtime(runtime: Path, wheel: Path, python: str, env: dict[str, str]) -> Path:
    created = _run(["uv", "venv", "--python", python, str(runtime)], env=env)
    if created.returncode != 0:
        sys.stderr.write(created.stderr.decode("utf-8", errors="replace"))
        raise _fail("runtime_venv_failed")
    interpreter = runtime / "bin" / "python"
    args = ["uv", "pip", "install", "--python", str(interpreter), str(wheel)]
    installed = _run([*args[:2], "--offline", *args[2:]], env=env)
    if installed.returncode != 0:
        installed = _run(args, env=env)
    if installed.returncode != 0:
        sys.stderr.write(installed.stderr.decode("utf-8", errors="replace"))
        raise _fail("runtime_install_failed")
    found = _runtime_launcher(runtime)
    if found is None:
        raise _fail("runtime_launcher_missing")
    return found[0]


def _snapshot_command(launcher: Path, args: list[str], env: dict[str, str]) -> dict[str, object]:
    result = _run([str(launcher), *args, "--json"], env=env)
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
        raise _fail(
            f"snapshot_command_failed: {launcher.name} {' '.join(args)} exited {result.returncode}"
        )
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise _fail("snapshot_command_invalid_output")
    return cast(dict[str, object], parsed)


def _write_private_json(path: Path, body: dict[str, object]) -> None:
    encoded = json.dumps(body, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


def _read_provenance(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    parsed = json.loads(path.read_bytes())
    return cast(dict[str, object], parsed) if isinstance(parsed, dict) else None


def command_create(args: argparse.Namespace) -> dict[str, object]:
    base = _validate_base(Path(args.base).expanduser())
    tag = _validate_tag(args.tag)
    checkout = Path(args.checkout).expanduser().resolve()
    if not (checkout / "pyproject.toml").is_file():
        raise _fail("checkout_invalid: --checkout must be a FinishUP source checkout")
    base.mkdir(mode=0o700, exist_ok=True)
    os.chmod(base, 0o700)
    layout = _layout(base, tag)
    if layout["root"].exists():
        raise _fail("instance_exists: dispose that tag first or choose another")
    layout["root"].mkdir(mode=0o700)
    try:
        sha, is_head = _resolve_revision(checkout, args.revision)
        source_state = "clean"
        source = checkout
        if is_head:
            if _tree_modified(checkout):
                if not args.allow_dirty:
                    raise _fail(
                        "checkout_modified: the working tree differs from HEAD; commit, stash, "
                        "pass --revision <commit>, or pass --allow-dirty to record source_state "
                        "modified"
                    )
                source_state = "modified"
        else:
            _export_revision(checkout, sha, layout["src"])
            source = layout["src"]
        wheel = _build_wheel(source, layout["dist"])
        package_digest = _digest_bytes(wheel)
        env = _clean_env()
        launcher = _install_runtime(layout["runtime"], wheel, args.python, env)
        create_args = [
            "instance",
            "create",
            "--root",
            str(layout["state"]),
            "--lifecycle",
            args.lifecycle,
            "--source-ref",
            sha,
            "--source-state",
            source_state,
            "--package-digest",
            package_digest,
            "--bind-runtime",
        ]
        if args.expires_in is not None:
            create_args += ["--expires-in", str(args.expires_in)]
        created = _snapshot_command(launcher, create_args, env)
        provenance: dict[str, object] = {
            "schema": _PROVENANCE_SCHEMA,
            "tag": tag,
            "lifecycle": args.lifecycle,
            "installation_id": created.get("installation_id"),
            "created_at": created.get("created_at"),
            "expires_at": created.get("expires_at"),
            "source_ref": sha,
            "source_state": source_state,
            "package_version": created.get("package_version"),
            "package_digest": package_digest,
            "wheel_name": wheel.name,
            "runtime_digest": _identity_digest(layout["runtime"]),
            "state_digest": _identity_digest(layout["state"]),
            "provisioned_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }
        _write_private_json(layout["provenance"], provenance)
    except BaseException:
        shutil.rmtree(layout["root"], ignore_errors=True)
        raise
    return {
        **provenance,
        "launcher": str(launcher),
        "isolated_root": str(layout["state"]),
        "environment_export": _environment_export(layout["state"]),
    }


def command_status(args: argparse.Namespace) -> dict[str, object]:
    layout = _layout(_validate_base(Path(args.base).expanduser()), _validate_tag(args.tag))
    provenance = _read_provenance(layout["provenance"])
    found = _runtime_launcher(layout["runtime"])
    if provenance is None or found is None:
        return {"tag": args.tag, "state": "absent"}
    status = _snapshot_command(found[0], ["instance", "status"], _clean_env())
    return {"tag": args.tag, "state": "present", "provenance": provenance, "instance": status}


def command_dispose(args: argparse.Namespace) -> dict[str, object]:
    layout = _layout(_validate_base(Path(args.base).expanduser()), _validate_tag(args.tag))
    if not layout["root"].exists():
        return {"tag": args.tag, "state": "absent", "disposed": False}
    found = _runtime_launcher(layout["runtime"])
    disposer = [str(found[0])] if found is not None else [sys.executable, "-m", "finishup"]
    dispose_args = [*disposer, "instance", "dispose", "--root", str(layout["state"]), "--json"]
    if args.retain_logs is not None:
        dispose_args += ["--retain-logs", str(Path(args.retain_logs).expanduser().resolve())]
    result = _run(dispose_args, env=_clean_env())
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
        raise _fail("instance_dispose_failed: the root was left in place")
    outcome = json.loads(result.stdout)
    retained_root = layout["runtime"].parent / f".{layout['runtime'].name}-releases"
    if retained_root.exists():
        # Newer installed processes keep read-only runtime copies. The instance's service is
        # already stopped above; use the runtime's own lease-aware cleanup before removal.
        cleaned = _run(
            [
                str(layout["runtime"] / "bin" / "python"),
                "-I",
                "-c",
                _prune_bootstrap("finishup" if found is None else found[1]),
            ],
            env=_clean_env(),
            timeout=60,
        )
        if cleaned.returncode != 0:
            raise _fail("runtime_cleanup_failed: retained runtimes were left in place")
        counts = json.loads(cleaned.stdout)
        if not isinstance(counts, list):
            raise _fail("runtime_cleanup_failed: retained runtimes were left in place")
        values = cast(list[object], counts)
        if len(values) != 2 or type(values[1]) is not int or values[1] != 0:
            raise _fail("runtime_in_use: close this instance's host sessions and retry disposal")
    shutil.rmtree(layout["root"])
    return {"tag": args.tag, "state": "removed", "disposed": True, "instance": outcome}


def _prune_bootstrap(package: str) -> str:
    """The retained-runtime cleanup, run with the package the instance's runtime ships."""

    return (
        "import json,sys; from pathlib import Path; "
        f"from {package}.adapters.release_runtime import prune_release_runtimes; "
        "print(json.dumps(prune_release_runtimes(Path(sys.prefix), wait_seconds=5.0)))"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--base", default=str(_DEFAULT_BASE), help="Owner-private base directory."
        )
        command.add_argument("--tag", required=True, help="Instance name beneath the base.")
        command.add_argument("--json", action="store_true", help="Emit JSON instead of text.")

    create = sub.add_parser("create", help="Build, install, and seal a new instance.")
    common(create)
    create.add_argument("--checkout", default=str(_REPO_ROOT), help="Source checkout to build.")
    create.add_argument("--revision", default="HEAD", help="Commit to build (default HEAD).")
    create.add_argument("--lifecycle", choices=("persistent", "disposable"), default="disposable")
    create.add_argument("--expires-in", type=float, default=None, help="Hours until expiry.")
    create.add_argument("--allow-dirty", action="store_true", help="Record a modified tree.")
    create.add_argument("--python", default=sys.executable, help="Interpreter for the runtime.")

    status = sub.add_parser("status", help="Report the instance's provenance and status.")
    common(status)

    dispose = sub.add_parser("dispose", help="Stop, remove, and forget the instance.")
    common(dispose)
    dispose.add_argument("--retain-logs", default=None, help="Copy logs here before removal.")
    return parser


def _render(result: dict[str, object]) -> str:
    lines = [f"{key}: {value}" for key, value in result.items() if not isinstance(value, dict)]
    for key, value in result.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            lines.extend(
                f"  {inner}: {item}" for inner, item in cast(dict[str, object], value).items()
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handlers = {"create": command_create, "status": command_status, "dispose": command_dispose}
    try:
        result = handlers[args.command](args)
    except ProvisionError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    sys.stdout.write(
        (json.dumps(result, indent=2, sort_keys=True) if args.json else _render(result)) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
