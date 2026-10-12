"""The Codex skill's code-mode section works in a sandbox without `crypto` (issue #918).

Codex code mode runs Yoetz calls from JavaScript cells. Its sandbox has no `crypto`, yet every
`request_id` and event-draft id must be a strict prefixed UUIDv4: the DeepSWE v2 run recorded 45
`crypto is not defined` failures and hand-rolled ids the `request_id` pattern rejected. These
tests execute the skill's exact helper snippet in JavaScript runtimes with and without `crypto`
and check its output against the id patterns in the packaged schemas. The helper must prefer
`crypto.randomUUID()`, then `crypto.getRandomValues()`, and fall back to `Math.random()` only when
neither exists. They also keep the section's yield guidance equal to the bridge's real call
deadlines, so a semantic check returns in its own turn.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Final, cast

import pytest

from yoetz.mcp import server as bridge
from yoetz.protocol.schemas import load_schema_catalog, schema_document_for

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_SKILL: Final = _REPO_ROOT / "guidance" / "startup.md"
_PACKAGED_SKILL: Final = _REPO_ROOT / "src" / "yoetz" / "resources" / "guidance" / "startup.md"
_NODE: Final = shutil.which("node")
_SAMPLES: Final = 10_000
# Every id prefix the section tells the agent to mint with the helper.
_DRAFT_PREFIXES: Final = ("evt", "act", "res", "evd", "clm", "obl")
_JS_BLOCK: Final = re.compile(r"^```js\n(.*?)^```$", re.MULTILINE | re.DOTALL)

needs_node = pytest.mark.skipif(_NODE is None, reason="node is a contributor-only tool")


def _section() -> str:
    text = _SKILL.read_text(encoding="utf-8")
    start = text.index("\n## Code mode\n")
    end = text.find("\n## ", start + 1)
    return text[start:] if end < 0 else text[start:end]


def _blocks() -> list[str]:
    return _JS_BLOCK.findall(_section())


def _block_containing(marker: str) -> str:
    matches = [block for block in _blocks() if marker in block]
    assert len(matches) == 1, marker
    return matches[0]


def _walk_patterns(value: object) -> Iterator[str]:
    # Catalog schemas are frozen: mappings are read-only proxies and arrays are tuples.
    if isinstance(value, Mapping):
        for key, item in cast(Mapping[str, object], value).items():
            if key == "pattern" and isinstance(item, str):
                yield item
            else:
                yield from _walk_patterns(item)
    elif isinstance(value, tuple | list):
        for item in cast(tuple[object, ...] | list[object], value):
            yield from _walk_patterns(item)


def _schema_id_pattern(prefix: str) -> re.Pattern[str]:
    found = {
        pattern
        for document in load_schema_catalog().documents
        for pattern in _walk_patterns(document.json_schema)
        if pattern.startswith(f"^{prefix}_")
    }
    assert len(found) == 1, (prefix, found)
    return re.compile(found.pop())


def _defs_pattern(name: str, version: str, key: str) -> re.Pattern[str]:
    schema = schema_document_for(name, version).json_schema
    definitions = cast(Mapping[str, Mapping[str, str]], schema["$defs"])
    return re.compile(definitions[key]["pattern"])


def _run_node(tmp_path: Path, name: str, source: str) -> str:
    assert _NODE is not None
    script = tmp_path / name
    script.write_text(source, encoding="utf-8")
    completed = subprocess.run(
        [_NODE, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


_GENERATE: Final = f"""
const minted = {{ req: [], {", ".join(f"{p}: []" for p in _DRAFT_PREFIXES)} }};
for (let i = 0; i < {_SAMPLES}; i++) {{
  for (const prefix of Object.keys(minted)) minted[prefix].push(newId(prefix));
}}
"""
_NO_CRYPTO: Final = """
if (typeof crypto !== "undefined" || typeof globalThis.crypto !== "undefined") {
  throw new Error("crypto is present");
}
"""
# Proves a stronger source was used: the non-cryptographic fallback must not run.
_POISON_MATH_RANDOM: Final = 'Math.random = () => { throw new Error("Math.random used"); };\n'
_POISON_GET_RANDOM_VALUES: Final = '() => { throw new Error("getRandomValues used"); }'

# runtime -> (script name, context globals as JavaScript source or None, preamble inside the cell)
_RUNTIMES: Final[dict[str, tuple[str, str | None, str]]] = {
    # A fresh V8 context holds only the JavaScript builtins: no `crypto`, `require` or `process`.
    "vm-no-crypto": ("vm.cjs", "{}", _NO_CRYPTO),
    # Code-mode cells run as ES modules (strict mode); remove the Node global before the snippet.
    "es-module-no-crypto": ("cell.mjs", None, "delete globalThis.crypto;\n" + _NO_CRYPTO),
    "vm-get-random-values-only": (
        "vm.cjs",
        '{ crypto: { getRandomValues: (b) => require("node:crypto").getRandomValues(b) } }',
        _POISON_MATH_RANDOM,
    ),
    "vm-random-uuid": (
        "vm.cjs",
        '{ crypto: { randomUUID: () => require("node:crypto").randomUUID(), '
        f"getRandomValues: {_POISON_GET_RANDOM_VALUES} }} }}",
        _POISON_MATH_RANDOM,
    ),
    "es-module-native-crypto": ("cell.mjs", None, _POISON_MATH_RANDOM),
}


def _vm_driver(context: str, body: str) -> str:
    return (
        'const vm = require("node:vm");\n'
        f"const out = vm.runInContext({json.dumps(body)}, vm.createContext({context}));\n"
        "process.stdout.write(out);\n"
    )


def _driver(runtime: str, snippet: str, tail: str) -> tuple[str, str]:
    name, context, preamble = _RUNTIMES[runtime]
    if context is not None:
        return name, _vm_driver(context, preamble + snippet + tail + "JSON.stringify(minted);\n")
    source = preamble + snippet + tail + "process.stdout.write(JSON.stringify(minted));\n"
    return name, source


def test_the_packaged_skill_carries_the_same_section() -> None:
    assert _PACKAGED_SKILL.read_text(encoding="utf-8") == _SKILL.read_text(encoding="utf-8")
    assert "\n## Code mode\n" in _SKILL.read_text(encoding="utf-8")


@needs_node
@pytest.mark.parametrize("runtime", sorted(_RUNTIMES))
def test_the_uuid_helper_mints_schema_valid_unique_ids(runtime: str, tmp_path: Path) -> None:
    snippet = _block_containing("const uuid4=")
    name, driver = _driver(runtime, snippet, _GENERATE)
    minted = cast(dict[str, list[str]], json.loads(_run_node(tmp_path, name, driver)))
    request_pattern = _defs_pattern("publish-work-request", "1.2.0", "request_id")
    event_pattern = _defs_pattern("event-draft", "1.2.0", "event_id")
    assert request_pattern.pattern == _schema_id_pattern("req").pattern
    assert event_pattern.pattern == _schema_id_pattern("evt").pattern
    assert len(minted["req"]) == _SAMPLES
    assert all(request_pattern.fullmatch(value) for value in minted["req"])
    assert all(event_pattern.fullmatch(value) for value in minted["evt"])
    for prefix in _DRAFT_PREFIXES:
        pattern = _schema_id_pattern(prefix)
        assert len(minted[prefix]) == _SAMPLES
        bad = [value for value in minted[prefix] if pattern.fullmatch(value) is None]
        assert bad == [], (prefix, bad[:3])
    everything = [value for values in minted.values() for value in values]
    assert len(set(everything)) == len(everything)
    uuids = {value.split("_", 1)[1] for value in everything}
    assert len(uuids) == len(everything)


@needs_node
@pytest.mark.parametrize(
    ("fill", "expected"),
    [
        (0x00, "00000000-0000-4000-8000-000000000000"),
        (0xFF, "ffffffff-ffff-4fff-bfff-ffffffffffff"),
    ],
)
def test_the_uuid_helper_sets_the_version_and_variant_bits(
    fill: int, expected: str, tmp_path: Path
) -> None:
    # A getRandomValues that fills every byte with the same value pins the bit masks exactly.
    snippet = _block_containing("const uuid4=")
    context = f"{{ crypto: {{ getRandomValues: (b) => {{ b.fill({fill}); return b; }} }} }}"
    body = _POISON_MATH_RANDOM + snippet + "JSON.stringify([uuid4(), newId('req')]);\n"
    printed = cast(
        list[str], json.loads(_run_node(tmp_path, "bits.cjs", _vm_driver(context, body)))
    )
    assert printed == [expected, f"req_{expected}"]


@needs_node
def test_the_uuid_helper_prefers_random_uuid_and_lowercases_it(tmp_path: Path) -> None:
    snippet = _block_containing("const uuid4=")
    context = (
        '{ crypto: { randomUUID: () => "0A1B2C3D-4E5F-4A6B-8C7D-8E9FA0B1C2D3", '
        f"getRandomValues: {_POISON_GET_RANDOM_VALUES} }} }}"
    )
    body = _POISON_MATH_RANDOM + snippet + "newId('req');\n"
    printed = _run_node(tmp_path, "prefer.cjs", _vm_driver(context, body))
    assert printed == "req_0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3"


def test_the_uuid_helper_labels_its_non_cryptographic_fallback() -> None:
    snippet = _block_containing("const uuid4=")
    assert snippet.index("randomUUID") < snippet.index("getRandomValues")
    assert snippet.index("getRandomValues") < snippet.index("Math.random")
    fallback = next(line for line in snippet.splitlines() if "Math.random" in line)
    assert "not cryptographic" in fallback
    # A bare `crypto` reference throws ReferenceError in a sandbox without it.
    assert re.search(r"(?<![.\w])crypto\b", snippet.replace("globalThis.crypto", "")) is None
    assert "not cryptographic" in " ".join(_section().split())


def test_the_request_id_pattern_still_rejects_the_hand_rolled_workaround() -> None:
    # Example 2 of #918: four Math.random slices joined and cut to 36 characters. The helper is
    # the fix; relaxing the pattern is not.
    request_pattern = _defs_pattern("publish-work-request", "1.2.0", "request_id")
    hand_rolled = "req_" + "-".join(["9f86d081"] * 4)[:36]
    assert request_pattern.fullmatch(hand_rolled) is None
    assert request_pattern.fullmatch("req_00000000-0000-4000-8000-000000000000") is not None
    assert request_pattern.fullmatch("req_00000000-0000-1000-8000-000000000000") is None
    assert request_pattern.fullmatch("req_00000000-0000-4000-c000-000000000000") is None


@needs_node
def test_the_discovery_pattern_prints_only_the_declaration(tmp_path: Path) -> None:
    snippet = _block_containing("exec tool declaration:")
    description = (
        "# Yoetz: call start first\\n\\nInstructions.\\n\\nTool description.\\n\\n"
        "exec tool declaration:\\ndeclare const start: (args: StartRequest) => Promise<unknown>;"
    )
    driver = (
        'const vm = require("node:vm");\n'
        "const printed = [];\n"
        "const context = vm.createContext({\n"
        f'  ALL_TOOLS: [{{ name: "mcp__yoetz__start", description: "{description}" }}],\n'
        "  text: (value) => printed.push(value),\n"
        "});\n"
        f"vm.runInContext({json.dumps(snippet)}, context);\n"
        "process.stdout.write(JSON.stringify(printed));\n"
    )
    printed = cast(list[str], json.loads(_run_node(tmp_path, "discover.cjs", driver)))
    assert printed == [
        "exec tool declaration:\ndeclare const start: (args: StartRequest) => Promise<unknown>;"
    ]


@needs_node
def test_every_code_mode_snippet_is_valid_javascript(tmp_path: Path) -> None:
    blocks = _blocks()
    assert len(blocks) == 4
    driver = (
        'const vm = require("node:vm");\n'
        f"for (const code of {json.dumps(blocks)}) new vm.Script(`(async () => {{\\n${{code}}\\n}})`);\n"
        'process.stdout.write("ok");\n'
    )
    assert _run_node(tmp_path, "syntax.cjs", driver) == "ok"


def test_guidance_is_read_from_the_structured_text() -> None:
    snippet = _block_containing("mcp__yoetz__read_guidance")
    # The page body is the structured result's `text`, never the pointer-only `content`.
    assert "const p=g.structuredContent;" in snippet
    assert 'typeof p.text!=="string"' in snippet
    assert ".content" not in snippet
    assert "structured result" in " ".join(_section().split())


def test_the_yield_guidance_matches_the_bridge_call_deadlines() -> None:
    deadlines = dict(bridge._DEFAULT_RPC_DEADLINES_MS)  # pyright: ignore[reportPrivateUsage]
    section = " ".join(_section().split())
    assert f"`check` {deadlines['check']}" in section
    assert deadlines["respond"] == deadlines["receipt"]
    assert f"`respond` and `receipt` {deadlines['receipt']}" in section
    assert deadlines["start"] == deadlines["publish_work"] == deadlines["status"]
    assert f"`start`, `publish_work` and `status` {deadlines['status']} each" in section
    assert "Set `yield_time_ms` at or above the call deadline" in section
    # Scoped to Yoetz calls: a big yield must not stall builds or tests.
    assert "keep builds, tests and other non-Yoetz work in separate cells" in section
    assert "not a series of short waits" in section
    example = _block_containing("mcp__yoetz__check")
    pragma = re.match(r'// @exec: \{"yield_time_ms": (\d+)\}\n', example)
    assert pragma is not None
    assert int(pragma.group(1)) >= deadlines["check"]
    # The example keeps its request id for same-request recovery.
    assert "text(JSON.stringify({ request_id, result: r.structuredContent }))" in example
