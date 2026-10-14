from __future__ import annotations

import base64
import subprocess
import sys
import textwrap
from itertools import product
from pathlib import Path

import pytest

from fixture_loader import FixtureLoader

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src"
_PARSE_CASE = "canonical/restricted-json-positive.case.json"
_DIGEST_CASES = (
    "canonical/rfc8785-applicable.case.json",
    "canonical/restricted-json-positive.case.json",
)
_MATRIX_HASH_SEEDS = ("0", "1", "4294967295")
_MATRIX_TZS = ("UTC", "Pacific/Honolulu")
_MATRIX_OPTIMIZATION = (False, True)
_CHILD_SCRIPT = textwrap.dedent(
    """
    import base64
    import json
    import os
    import sys
    import time
    from pathlib import Path

    repo_root = Path(sys.argv[1])
    payload = base64.b64decode(sys.argv[2])
    sys.path.insert(0, str(repo_root / "src"))
    if hasattr(time, "tzset"):
        time.tzset()

    from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse

    case = json.loads(payload.decode("utf-8"))
    fixture_id = case["fixture_id"]
    if fixture_id not in {"CAN-001", "CAN-002", "CAN-004"}:
        raise AssertionError(f"unexpected fixture_id: {fixture_id}")

    def _expect(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    vectors = case["input"]["vectors"]
    for vector in vectors:
        if "source_base64" in vector:
            parsed = strict_json_parse(base64.b64decode(vector["source_base64"]))
            _expect(
                canonical_encode(parsed).hex() == vector["canonical_hex"],
                f"{fixture_id}:{vector['vector_id']}:canonical_hex",
            )
            _expect(
                canonical_digest(parsed) == vector["canonical_sha256"],
                f"{fixture_id}:{vector['vector_id']}:canonical_sha256",
            )
            continue
        if "source_members" in vector:
            value = {member["key"]: member["value"] for member in vector["source_members"]}
            _expect(
                canonical_encode(value).hex() == vector["canonical_hex"],
                f"{fixture_id}:{vector['vector_id']}:canonical_hex",
            )
            _expect(
                canonical_digest(value) == vector["canonical_sha256"],
                f"{fixture_id}:{vector['vector_id']}:canonical_sha256",
            )
            continue
        if "value" in vector:
            value = vector["value"]
            _expect(
                canonical_encode(value).hex() == vector["canonical_hex"],
                f"{fixture_id}:{vector['vector_id']}:canonical_hex",
            )
            _expect(
                canonical_digest(value) == vector["canonical_sha256"],
                f"{fixture_id}:{vector['vector_id']}:canonical_sha256",
            )
            continue
        raise AssertionError(f"unexpected vector shape: {sorted(vector)}")

    print("ok")
    """
).strip()


def _run_child(
    case_bytes: bytes,
    *,
    cwd: Path,
    hash_seed: str,
    tz: str,
    optimized: bool,
) -> subprocess.CompletedProcess[str]:
    env = {
        "PYTHONHASHSEED": hash_seed,
        "TZ": tz,
        "LC_ALL": "C",
    }
    command = [sys.executable, "-I"]
    if optimized:
        command.append("-O")
    command.extend(
        ["-c", _CHILD_SCRIPT, str(_SRC_ROOT.parent), base64.b64encode(case_bytes).decode("ascii")]
    )
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )


def test_parse_encode_bytes_match_across_processes(
    fixture_loader: FixtureLoader,
    tmp_path: Path,
) -> None:
    case_bytes = fixture_loader.load_bytes(_PARSE_CASE)
    result = _run_child(case_bytes, cwd=tmp_path, hash_seed="0", tz="UTC", optimized=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok\n"
    assert result.stderr == ""


@pytest.mark.parametrize("case_path", _DIGEST_CASES)
def test_digest_match_across_processes(
    fixture_loader: FixtureLoader,
    case_path: str,
    tmp_path: Path,
) -> None:
    case_bytes = fixture_loader.load_bytes(case_path)
    result = _run_child(
        case_bytes,
        cwd=tmp_path,
        hash_seed="1",
        tz="Pacific/Honolulu",
        optimized=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("hash_seed", "tz", "optimized"),
    tuple(product(_MATRIX_HASH_SEEDS, _MATRIX_TZS, _MATRIX_OPTIMIZATION)),
    ids=lambda value: str(value),
)
def test_registered_environment_matrix_does_not_change_output(
    fixture_loader: FixtureLoader,
    hash_seed: str,
    tz: str,
    optimized: bool,
    tmp_path: Path,
) -> None:
    case_bytes = fixture_loader.load_bytes("canonical/utf16-property-order.case.json")
    result = _run_child(case_bytes, cwd=tmp_path, hash_seed=hash_seed, tz=tz, optimized=optimized)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok\n"
    assert result.stderr == ""
