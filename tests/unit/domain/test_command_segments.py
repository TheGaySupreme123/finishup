"""Bounded, quote-aware command segmentation for planned-verification matching (#977 E3)."""

from __future__ import annotations

import pytest

from yoetz.domain.command_segments import (
    MAX_SEGMENT_COMMITMENTS,
    command_segment_commitments,
    command_segments,
    requested_command_shape,
)
from yoetz.domain.observation import normalize_observed_command, observed_command_commitment
from yoetz.kernel.observed_failures import (
    command_identity,
    command_segment_identities,
    observed_command_field,
)

_KEY = b"k" * 32


def _segments(command: str) -> tuple[tuple[str, ...], str] | None:
    normalized = normalize_observed_command(command)
    assert normalized is not None
    result = command_segments(normalized)
    return None if result is None else (result.segments, result.composition)


@pytest.mark.parametrize(
    ("command", "segments", "composition"),
    [
        (
            "cd /app && python evaluate.py --out r.json && git diff --check",
            ("cd /app", "python evaluate.py --out r.json", "git diff --check"),
            "and_chain",
        ),
        (
            "bash /app/run_pretrain.sh > /tmp/pretrain-before.log 2>&1",
            ("bash /app/run_pretrain.sh",),
            "single",
        ),
        ("time python run.py", ("python run.py",), "single"),
        ("FOO=1 X=2 make test", ("make test",), "single"),
        ("env -i FOO=1 pytest -q", ("pytest -q",), "single"),
        ("python x.py 2>/dev/null >> out.log < in.txt", ("python x.py",), "single"),
        ("pytest -q | tee log.txt", ("pytest -q", "tee log.txt"), "masked"),
        ("/bin/bash -lc 'cd /app && pytest -q'", ("cd /app", "pytest -q"), "and_chain"),
        ("! pytest", ("pytest",), "masked"),
        (
            "bash <<'EOF'\nset -e\ncd /app\npython check.py\nEOF",
            ("bash", "set -e", "cd /app", "python check.py"),
            "masked",
        ),
        ('pytest -k "a and b" && ls', ('pytest -k "a and b"', "ls"), "and_chain"),
        ("pytest $(echo -q) && ls", ("pytest $(echo -q)", "ls"), "and_chain"),
    ],
)
def test_segments_and_composition(
    command: str, segments: tuple[str, ...], composition: str
) -> None:
    assert _segments(command) == (segments, composition)


@pytest.mark.parametrize(
    "command",
    [
        "pytest -q",  # already simple: the whole identity is its only one
        "echo 'a && b'",  # quoted separators are text
        'echo "unterminated',  # unsplittable: whole identity only
        "bash <<'EOF'\npytest\n",  # unterminated here-document
    ],
)
def test_simple_or_unsplittable_commands_have_no_segments(command: str) -> None:
    assert _segments(command) is None


def test_non_shell_heredoc_bodies_are_not_commands() -> None:
    result = _segments("python3 - <<'PY'\nimport os\npython check.py\nPY")
    assert result is not None
    assert "python check.py" not in result[0]
    result = _segments("cat > f.sh <<EOF\nrm -rf build\nEOF\npytest")
    assert result is not None
    assert "rm -rf build" not in result[0]
    assert "pytest" in result[0]


def test_commitments_are_keyed_sorted_bounded_and_exclude_the_whole() -> None:
    normalized = normalize_observed_command("cd /app && pytest -q")
    assert normalized is not None
    committed = command_segment_commitments(_KEY, normalized)
    assert committed is not None
    values, composition = committed
    assert composition == "and_chain"
    assert values == tuple(sorted(values))
    assert observed_command_commitment(_KEY, "pytest -q") in values
    assert observed_command_commitment(_KEY, normalized) not in values
    assert all(value.startswith("hmac-sha256:") for value in values)

    script = "bash <<'EOF'\n" + "\n".join(f"step{n}" for n in range(80)) + "\nfinal\nEOF"
    normalized = normalize_observed_command(script)
    assert normalized is not None
    committed = command_segment_commitments(_KEY, normalized)
    assert committed is not None
    assert len(committed[0]) == MAX_SEGMENT_COMMITMENTS
    # The last lines survive the cap: a script's final verification line still matches.
    assert observed_command_commitment(_KEY, "final") in committed[0]


def test_the_command_field_round_trips_and_keeps_simple_commands_byte_identical() -> None:
    whole = observed_command_commitment(_KEY, "pytest -q")
    assert observed_command_field(whole) == f"omitted:{whole}"
    assert command_segment_identities(f"omitted:{whole}") is None

    segment = observed_command_commitment(_KEY, "ls")
    field = observed_command_field(whole, (segment,), "and_chain")
    assert command_identity(field) == whole
    assert command_segment_identities(field) == (frozenset({segment}), "and_chain")
    # A malformed suffix never widens a match and never costs the whole identity.
    assert command_segment_identities(f"omitted:{whole} weird {segment}") is None
    assert command_identity(f"omitted:{whole} weird {segment}") == whole
    assert observed_command_field(whole, ("not-a-commitment",), "single") == f"omitted:{whole}"


@pytest.mark.parametrize(
    ("value", "shape"),
    [
        ("python cracker.py <ciphertext_file>", "placeholder"),
        (
            "python -m parityctl rebuild --packet <incident-packet> --out <output-dir>",
            "placeholder",
        ),
        ("Broad GSEA CLI", "prose"),
        ("Run the unit tests.", "prose"),
        ("legacy-score", "command"),
        ("npm test", "command"),
        ("Rscript analysis.R", "command"),
        ("grep '<div>' index.html", "command"),
        ("sort <in.txt >out.txt", "command"),
        ("python run.py < input.txt", "command"),
    ],
)
def test_requested_command_shape(value: str, shape: str) -> None:
    assert requested_command_shape(value) == shape


@pytest.mark.parametrize(
    "value",
    [
        "sort <in.txt>out.txt",
        "python x.py <input.txt 2>/dev/null",
        "mysql db <dump.sql 2>&1",
        "grep '<div>' x.html",
        "cat <file",
        "a<b",
        "R CMD check pkg",
    ],
)
def test_redirections_and_short_leaders_are_commands(value: str) -> None:
    """Adversarial review of E3: input redirections were refused as placeholders, and an
    uppercase one-letter leader (`R CMD check`) read as prose."""

    assert requested_command_shape(value) == "command"


@pytest.mark.parametrize(
    "value",
    [
        "python cracker.py <ciphertext_file>",
        "python -m parityctl rebuild --packet <incident-packet> --out <output-dir>",
        "run <input file>",
    ],
)
def test_template_placeholders_stay_placeholders(value: str) -> None:
    assert requested_command_shape(value) == "placeholder"
