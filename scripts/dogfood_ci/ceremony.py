"""Drive one FinishUP trusted-console ceremony from a real pseudo-terminal.

The trusted foreground console (``src/finishup/cli/trusted_console.py``) requires stdin and stderr
to be the same terminal, ``/dev/tty`` to open, and the process to own the foreground process
group. ``pty.fork`` gives the child exactly that, so an unattended CI lane can answer the
passphrase, credential, privacy-decision, and PAM password prompts with run-scoped secrets that
exist only for that runner. The transcript is echoed with every secret masked; the child's exit
code is returned unchanged. This is contributor tooling for disposable instances only: it does
not weaken the console check, it satisfies it, and it never targets an everyday installation.

Usage as a library::

    replies = [Reply(r"Passphrase \\(", passphrase), Reply(r"Confirm passphrase", passphrase)]
    result = run_ceremony([launcher, "service", "initialize-passphrase", "--json"], replies)

Usage as a command::

    ceremony.py --secret-env DOGFOOD_VAULT_PASSPHRASE \\
        --reply 'Passphrase \\(=@secret' --reply 'Confirm passphrase=@secret' \\
        -- /path/to/finishup service initialize-passphrase --json

Each ``--reply`` is ``REGEX=TEXT``; ``@secret`` in TEXT expands to the named environment
variable. Every reply is used at most once, in whatever order its prompt appears.
"""

from __future__ import annotations

import argparse
import os
import re
import select
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = ["CeremonyResult", "Reply", "run_ceremony"]

_READ_CHUNK: Final = 4096
_SETTLE_SECONDS: Final = 0.05


@dataclass(frozen=True, slots=True)
class Reply:
    """One prompt pattern and the line typed in answer to it."""

    pattern: str
    text: str
    secret: bool = True

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern)


@dataclass(slots=True)
class CeremonyResult:
    exit_code: int
    transcript: str
    answered: list[str]
    timed_out: bool


def _mask(text: str, secrets: list[str]) -> str:
    for value in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(value, "<secret>")
    return text


def run_ceremony(
    argv: list[str],
    replies: list[Reply],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 180.0,
) -> CeremonyResult:
    """Run ``argv`` under a controlling pty, answering prompts, and return the masked outcome."""

    import pty

    compiled = [(reply.compiled(), reply) for reply in replies]
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - child process
        try:
            if cwd is not None:
                os.chdir(cwd)
            if env is not None:
                os.execvpe(argv[0], argv, env)
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)
    deadline = time.monotonic() + timeout
    window = ""
    transcript: list[str] = []
    answered: list[str] = []
    used: set[int] = set()
    timed_out = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                os.kill(pid, 9)
                break
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if fd not in ready:
                continue
            try:
                chunk = os.read(fd, _READ_CHUNK)
            except OSError:
                break
            if not chunk:
                break
            text = chunk.decode("utf-8", errors="replace")
            transcript.append(text)
            window += text
            for index, (pattern, reply) in enumerate(compiled):
                if index in used or not pattern.search(window):
                    continue
                used.add(index)
                answered.append(reply.pattern)
                window = ""
                time.sleep(_SETTLE_SECONDS)
                os.write(fd, (reply.text + "\n").encode("utf-8"))
                break
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    _, status = os.waitpid(pid, 0)
    secrets = [reply.text for reply in replies if reply.secret]
    return CeremonyResult(
        exit_code=124 if timed_out else os.waitstatus_to_exitcode(status),
        transcript=_mask("".join(transcript), secrets),
        answered=answered,
        timed_out=timed_out,
    )


def _parse_reply(item: str, secret: str) -> Reply:
    pattern, separator, text = item.partition("=")
    if not separator or not pattern:
        raise argparse.ArgumentTypeError("reply must be REGEX=TEXT")
    return Reply(pattern, text.replace("@secret", secret), secret="@secret" in text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--secret-env", default=None, help="Environment variable for @secret.")
    parser.add_argument("--reply", action="append", default=[], help="REGEX=TEXT (repeatable).")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--cwd", default=None)
    parser.add_argument("child", nargs=argparse.REMAINDER, help="-- <command> [args...]")
    args = parser.parse_args(argv)
    child = args.child[1:] if args.child and args.child[0] == "--" else args.child
    if not child:
        parser.error("missing child command after --")
    secret = os.environ.get(args.secret_env, "") if args.secret_env else ""
    if args.secret_env and not secret:
        parser.error(f"{args.secret_env} is not set")
    replies = [_parse_reply(item, secret) for item in args.reply]
    result = run_ceremony(
        child,
        replies,
        cwd=Path(args.cwd) if args.cwd else None,
        timeout=args.timeout,
    )
    sys.stderr.write(result.transcript)
    if not result.transcript.endswith("\n"):
        sys.stderr.write("\n")
    if result.timed_out:
        sys.stderr.write("ceremony_timeout\n")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
