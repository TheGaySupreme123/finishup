"""Run a deterministic partition of tracked pytest modules without dropping tests."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def tracked_test_files(roots: Sequence[str]) -> tuple[str, ...]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", *roots],
        cwd=_ROOT,
        capture_output=True,
        check=True,
    ).stdout
    return tuple(
        sorted(
            name
            for raw in listed.split(b"\0")
            if raw
            and (name := raw.decode("utf-8")).endswith(".py")
            and (Path(name).name.startswith("test_") or Path(name).name.endswith("_test.py"))
        )
    )


def select_shard(files: Sequence[str], shard: int, count: int) -> tuple[str, ...]:
    return tuple(
        name
        for name in files
        if int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:8], "big") % count == shard
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 1 <= args.shards <= 32 or not 0 <= args.shard < args.shards:
        parser.error("invalid_ci_test_shard")
    files = tracked_test_files(args.root)
    selected = select_shard(files, args.shard, args.shards)
    if not selected:
        parser.error("empty_ci_test_shard")
    print(
        f"CI shard {args.shard + 1}/{args.shards}: {len(selected)}/{len(files)} modules", flush=True
    )
    pytest_args = args.pytest_args
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    return subprocess.run(
        [sys.executable, "-m", "pytest", *selected, *pytest_args], cwd=_ROOT, check=False
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
