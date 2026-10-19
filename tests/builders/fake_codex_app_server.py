"""A scripted Codex app-server *process* speaking the JSONL wire on stdin and stdout.

Run as ``python -I fake_codex_app_server.py SCRIPT LOG``. ``SCRIPT`` is a JSON object with the
``codex_home`` and ``version`` ``initialize`` reports, the ``model`` and ``efforts`` ``model/list``
lists, and ``answers``: the final agent message of each ``turn/start``, in order. Every request
the client writes is appended to ``LOG`` as one JSON line, so a test sees the exact wire the real
evaluator sent. No model, network, credential or Codex binary is involved.

``launch`` spawns it the way ``codex_app_server._launch`` spawns Codex (own process group, owner
private attempt directory, bounded pipes) and returns the adapter's own ``_CodexProcess``, so the
real request, read, interrupt and process-group cleanup paths all run against it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

__all__ = ["launcher"]


def _serve(script_path: str, log_path: str) -> None:
    script = json.loads(Path(script_path).read_text(encoding="utf-8"))
    answers: list[str] = list(script["answers"])
    turns = 0
    log = Path(log_path).open("a", encoding="utf-8")

    def write(message: dict[str, object]) -> None:
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        request = cast(dict[str, Any], json.loads(line))
        log.write(json.dumps(request, sort_keys=True) + "\n")
        log.flush()
        method, rid = request.get("method"), request.get("id")
        params = cast(dict[str, Any], request.get("params") or {})
        if rid is None:
            continue  # ``initialized`` and other client notifications
        result: dict[str, object] = {}
        if method == "initialize":
            result = {
                "codexHome": script["codex_home"],
                "userAgent": f"codex_cli_rs/{script['version']} (Fake; test)",
            }
        elif method == "account/read":
            result = {"account": {"type": "chatgpt", "planType": "plus"}}
        elif method == "model/list":
            efforts = [{"reasoningEffort": effort} for effort in script["efforts"]]
            result = {"data": [{"id": script["model"], "supportedReasoningEfforts": efforts}]}
        elif method == "thread/start":
            cwd = params["cwd"]
            result = {
                "thread": {"id": "thr-fake", "ephemeral": True, "path": None, "cwd": cwd},
                "cwd": cwd,
                "model": script["model"],
                "modelProvider": "openai",
                "sandbox": {"type": "readOnly", "networkAccess": False},
                "instructionSources": [],
            }
        elif method == "turn/start":
            turns += 1
            turn = f"turn-{turns}"
            write({"id": rid, "result": {"turn": {"id": turn, "status": "inProgress"}}})
            item = {"type": "agentMessage", "phase": "final_answer", "text": answers.pop(0)}
            write({"method": "item/completed", "params": {"item": item}})
            done = {"id": turn, "status": "completed", "error": None}
            write({"method": "turn/completed", "params": {"threadId": "thr-fake", "turn": done}})
            continue
        write({"id": rid, "result": result})


def launcher(script: Path, log: Path):  # noqa: ANN201 - returns the adapter's private launch type
    """A drop-in for ``codex_app_server._launch`` that runs this file as the app-server."""

    import asyncio
    import os
    import tempfile
    from collections import deque

    from finishup.adapters.providers import codex_app_server as codex

    async def launch(profile: codex.CodexAppServerProfile) -> object:
        runtime_root = profile.codex_home / "runtime"
        runtime_root.mkdir(mode=0o700, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="attempt-", dir=runtime_root))
        os.chmod(workdir, 0o700)
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            __file__,
            str(script),
            str(log),
            cwd=workdir,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        return codex._CodexProcess(  # pyright: ignore[reportPrivateUsage]
            profile=profile,
            process=process,
            workdir=workdir,
            stderr_task=asyncio.create_task(
                codex._drain_stderr(process.stderr)  # pyright: ignore[reportPrivateUsage]
            ),
            pending_notifications=deque(),
        )

    return launch


if __name__ == "__main__":
    _serve(sys.argv[1], sys.argv[2])
