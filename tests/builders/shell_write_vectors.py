"""Exact shell commands with the paths, hook scope and stream scope they must earn (ADR-045).

One table, read by the domain parser test, the hook test (``runtime_structural_facts``) and the
Codex stream test (``envelope_from_stream_record``), so the three callers cannot drift apart.
The hook's workspace is ``/app`` (absolute paths are classified); the stream knows no workspace
root, so it claims only a relative write. Provenance: the independent Codex review of the
tb4n3 shell-write parser (issue #1028, ``codex_review_4``) is quoted by ``source``; the rest are
the same constructs in their neighbouring spellings.
"""

from __future__ import annotations

from typing import NamedTuple


class ShellWriteVector(NamedTuple):
    command: str
    paths: list[str]
    hook: str | None  # write_scope the hook claims with workspace /app
    stream: str | None  # write_scope the rollout stream claims (relative writes only)
    source: str


def _v(
    command: str, paths: list[str], hook: str | None, stream: str | None, source: str
) -> ShellWriteVector:
    return ShellWriteVector(command, paths, hook, stream, source)


_R = "codex review 4"
_C = "command substitution"
_H = "heredoc"

VECTORS: list[ShellWriteVector] = [
    # The commit-message idiom: a heredoc inside `$(...)`; its body (quotes, parens) is data.
    _v(
        'git commit -m "$(cat <<\'EOF\'\nfix 1) the 5" pipe > not-a-file.txt\nEOF\n)" > log.txt',
        ["log.txt"],
        "workspace",
        "workspace",
        f"{_C} with a heredoc",
    ),
    _v("echo $(cat <<EOF\n)\nEOF\n) > real.txt", ["real.txt"], "workspace", "workspace", _C),
    _v("echo $(echo a # ) > ghost.txt\n) > real.txt", ["real.txt"], "workspace", "workspace", _C),
    _v("echo $[1<<2] > real.txt", ["real.txt"], "workspace", "workspace", "legacy arithmetic"),
    # Review round 1 (this fix): a comment inside a substitution closes nothing.
    _v("echo $(echo x # ) > ghost\n)", [], None, None, "round 1: comment in a substitution"),
    # A quoted or escaped keyword is a command name, not syntax.
    _v("'!' touch out", [], None, None, "round 1: quoted keyword"),
    _v("\\! touch out", [], None, None, "round 1: escaped keyword"),
    _v("'then' cp a b", [], None, None, "round 1: quoted keyword"),
    _v("'{' touch out", [], None, None, "round 1: quoted keyword"),
    # A wrapper argument the outer shell expands is unknown; a literal one is read.
    _v(
        "OUT=/opt/actual; bash -c \"printf x > '$OUT'\"", [], None, None, "round 1: outer expansion"
    ),
    _v('bash -c "printf x > \\"\\$OUT\\""', [], None, None, "round 1: inner expansion"),
    _v('bash -c "cat > solve.py"', ["solve.py"], "workspace", "workspace", "double-quoted wrapper"),
    # cp / mv / install that fail before writing name nothing.
    _v("cp -tout", [], None, None, "round 1: -t without a source"),
    _v("cp -tout -T src", [], None, None, "round 1: -t with -T"),
    _v("cp -tone -ttwo src", [], None, None, "round 1: two target directories"),
    _v("mv -t out", [], None, None, "round 1: -t without a source"),
    # Help and version print and exit.
    _v("sed -i -e's/a/b/' --help f", [], None, None, "round 1: --help"),
    _v("touch --version -- -out", [], None, None, "round 1: --version"),
    _v("install -d --help out", [], None, None, "round 1: --help"),
    _v("tee --help out.txt", [], None, None, "round 1: --help"),
    _v("dd --help of=out.bin", [], None, None, "round 1: --help"),
    # A directory destination is classified by where it is, not by a notes or receipt file name.
    _v("cp -tNOTES.md source.py", ["NOTES.md"], "workspace", "workspace", "round 1: -t dir"),
    _v(
        "cp -t/opt/finishup_receipt.json source.py",
        ["/opt/finishup_receipt.json"],
        "outside_workspace",
        None,
        "round 1: -t dir",
    ),
    _v(
        "rsync -a src/ NOTES.md/",
        ["NOTES.md/"],
        "workspace",
        "workspace",
        "round 1: dest/ is a dir",
    ),
    _v(
        "install -d finishup_receipt.md",
        ["finishup_receipt.md"],
        "workspace",
        "workspace",
        "install -d",
    ),
    # macOS `sed -i ''` and GNU `sed -i ''` (an empty script) differ by their operand count.
    _v("gsed -i '' solve.py", ["solve.py"], "workspace", "workspace", "round 1: GNU empty script"),
    _v("sed -i '' solve.py", [], None, None, "round 2: macOS and GNU disagree: no guess"),
    _v(
        "gsed -i '' solve.py NOTES.md",
        ["solve.py", "NOTES.md"],
        "workspace",
        "workspace",
        "round 2: gsed is GNU: an empty script, two files",
    ),
    _v("sed -i .bak 's/a/b/' f.py", ["f.py"], "workspace", "workspace", "macOS separate suffix"),
    # An ANSI-C-quoted heredoc delimiter is its decoded text.
    _v("cat <<$'EOF'\nEOF\n: > out", ["out"], "workspace", "workspace", "round 1: $'EOF'"),
    _v('cat <<$"EOF"\nEOF\n: > out', ["out"], "workspace", "workspace", 'round 1: $"EOF"'),
    _v("cat <<$'E\\x4fF'\nEOF\n: > out", [], None, None, "round 1: undecodable delimiter"),
    # The scratch exemption never overrides ownership or the mixed-class rule.
    _v(
        ": > /tmp/finishup_receipt.json",
        ["/tmp/finishup_receipt.json"],
        "yoetz_owned",
        None,
        "round 1: owned in /tmp",
    ),
    _v(
        ": > NOTES.md; : > /tmp/finishup_receipt.json",
        ["NOTES.md", "/tmp/finishup_receipt.json"],
        "workspace",
        "notes",
        "round 1: notes + owned in /tmp",
    ),
    _v(": > /tmp/NOTES.md", ["/tmp/NOTES.md"], None, None, "scratch claims nothing"),
    # `1>& file` is an explicit stdout redirect; `2>& file` is ambiguous.
    _v(": 1>& out", ["out"], "workspace", "workspace", "round 1: explicit stdout"),
    # Review round 2: nothing a cut, malformed or failed command did not run is a write.
    _v("f() { cp a b; }", [], None, None, "round 2: a function definition runs nothing"),
    _v("while false; do touch out; done", [], None, None, "round 2: control flow"),
    _v("for x in; do touch out; done", [], None, None, "round 2: control flow"),
    _v(": 2>& missing > out", [], None, None, "round 2: an ambiguous redirect runs nothing"),
    _v(
        ": > real.txt 2>& missing > ghost",
        ["real.txt"],
        "workspace",
        "workspace",
        "round 2: bash opens redirections left to right and stops at the failed one",
    ),
    _v("cat > ghost >", [], None, None, "round 2: a redirect with no target is a syntax error"),
    _v(
        "cat > real.txt\n>\n: > ghost",
        ["real.txt"],
        "workspace",
        "workspace",
        "round 2: bash runs the lines before a syntax error, and none after",
    ),
    # Heredocs inside substitutions and continued lines in a body.
    _v("echo $(cat <<0\n) > ghost\n0\n)", [], None, None, "round 2: numeric delimiter"),
    _v("echo $(cat <<!\n) > ghost\n!\n)", [], None, None, "round 2: punctuation delimiter"),
    _v("echo $(cat <<$'EOF'\n) > ghost\nEOF\n)", [], None, None, "round 2: $'EOF' delimiter"),
    _v('echo $(cat <<$"EOF"\n) > ghost\nEOF\n)', [], None, None, 'round 2: $"EOF" delimiter'),
    _v("cat <<EOF\ntext\\\nEOF\n: > ghost\nEOF", [], None, None, "round 2: continued body line"),
    _v(
        "cat <<'EOF'\ntext\\\nEOF\n: > real.txt",
        ["real.txt"],
        "workspace",
        "workspace",
        "round 2: a quoted delimiter joins no lines",
    ),
    _v('echo "$(case x in x) echo "hi > ghost";; esac)"', [], None, None, "round 2: case pattern"),
    _v("echo $((1<<2)) > real.txt", ["real.txt"], "workspace", "workspace", "round 2: shift"),
    # Boolean operators and parentheses inside [[ ]] are test syntax.
    _v("[[ x == y || tee == out ]]", [], None, None, "round 2: || in [[ ]]"),
    _v("[[ x == y || touch > out ]]", [], None, None, "round 2: || in [[ ]]"),
    _v(
        "[[ ( a == b ) && c ]] && echo > out.txt",
        ["out.txt"],
        "workspace",
        "workspace",
        "round 2: after [[ ]]",
    ),
    # rsync that transfers nothing, and its option values.
    _v("rsync --dry-run src/ dest/", [], None, None, "round 2: dry run"),
    _v("rsync -an src/ dest/", [], None, None, "round 2: dry run"),
    _v("rsync --list-only src/ dest/", [], None, None, "round 2: list only"),
    _v("rsync src/ --exclude pattern", [], None, None, "round 2: an option value is no path"),
    _v(
        "rsync -a --exclude '*.pyc' -e ssh src/ dest/",
        ["dest/"],
        "workspace",
        "workspace",
        "round 2",
    ),
    # Wrappers that run nothing.
    _v("bash -nc 'touch out'", [], None, None, "round 2: bash -n"),
    _v("timeout --help 1 touch out", [], None, None, "round 2: wrapper --help"),
    _v("env --help touch out", [], None, None, "round 2: wrapper --help"),
    # Mandatory operands and the last `of=`.
    _v("truncate out", [], None, None, "round 2: truncate needs -s or -r"),
    _v("dd of=/opt/ghost of=NOTES.md count=0", ["NOTES.md"], "notes", "notes", "round 2: last of="),
    # macOS and GNU sed agree only on the files after the script.
    _v(
        "sed -i .bak -e 's/a/b/' solve.py", ["solve.py"], "workspace", "workspace", "round 2: macOS"
    ),
    _v("sed -i -e 's/a/b/' .env", [".env"], "workspace", "workspace", "round 2: a dotted file"),
    _v("sed -i 's/a/b/' .gitignore", [".gitignore"], "workspace", "workspace", "round 2: dotted"),
    # `#` in a substitution is a comment only at the start of a word.
    _v("echo ${#HOME} > real", ["real"], "workspace", "workspace", "round 2: ${#x}"),
    _v(
        'printf "%s" "${#HOME}" | tee result.txt',
        ["result.txt"],
        "workspace",
        "workspace",
        "round 2: ${#x}",
    ),
    _v("echo $(printf %s a\\ #) > real", ["real"], "workspace", "workspace", "round 2: a\\ #"),
    # A file named `-` is a file (stdout only for touch).
    _v(": > -", ["-"], "workspace", "workspace", "round 2: file named -"),
    _v("dd of=- count=0", ["-"], "workspace", "workspace", "round 2: file named -"),
    _v("touch -", [], None, None, "round 2: touch - is stdout"),
    # 1. A command substitution is opaque: its quotes are not the enclosing word's quotes.
    _v('echo "$(echo "x > solve.py")"', [], None, None, f"{_R} 1"),
    _v('echo "$(echo "$(echo "x > solve.py")")"', [], None, None, _C),
    _v('echo "`echo "x > solve.py"`"', [], None, None, _C),
    _v("echo $(echo 'x > solve.py')", [], None, None, _C),
    _v("echo $(echo 'a)' > ghost.txt) > real.txt", ["real.txt"], "workspace", "workspace", _C),
    _v('echo "${X:-"a > b.txt"}"', [], None, None, _C),
    _v("echo $((1 > 0)) > real.txt", ["real.txt"], "workspace", "workspace", _C),
    _v('echo "$(echo x"', [], None, None, "unterminated: no guess"),
    _v('echo "unterminated > solve.py', [], None, None, "unterminated: no guess"),
    _v("echo x > solve.py'", [], None, None, "unterminated: no guess"),
    # 2. Attached sed expression and script-file arguments.
    _v("sed -i -e's/a/b/' solve.py", ["solve.py"], "workspace", "workspace", f"{_R} 2"),
    _v("sed -i -fscript.sed solve.py", ["solve.py"], "workspace", "workspace", f"{_R} 2"),
    _v("sed -ie 's/a/b/' solve.py", ["solve.py"], "workspace", "workspace", "-ie: suffix e"),
    _v("sed -n -e's/a/b/p' solve.py", [], None, None, "not in place"),
    _v("sed --in-place=.bak -e 's/a/b/' f.py", ["f.py"], "workspace", "workspace", "long form"),
    _v(
        "sed -i --expression='s/a/b/' f.py g.py", ["f.py", "g.py"], "workspace", "workspace", "long"
    ),
    _v("sed -i -- 's/a/b/' f.py", ["f.py"], "workspace", "workspace", "after --"),
    _v("sed -i.bak1 's/a/b/' solve.py", ["solve.py"], "workspace", "workspace", f"{_R} sed"),
    _v("sed -i '' 's/a/b/' NOTES.md", ["NOTES.md"], "notes", "notes", f"{_R} sed (macOS)"),
    _v("sed -i '' -e 's/a/b/' solve.py", ["solve.py"], "workspace", "workspace", "macOS -e"),
    _v("sed -E -i 's/(a)/b/' solve.py", ["solve.py"], "workspace", "workspace", "-E -i"),
    # 3. One classifier: a FinishUP receipt copied outside the workspace is FinishUP-owned.
    _v(
        "cp source.json /opt/finishup_receipt.json",
        ["/opt/finishup_receipt.json"],
        "yoetz_owned",
        None,
        f"{_R} 3",
    ),
    _v("cp source.json /opt/result.json", ["/opt/result.json"], "outside_workspace", None, "3"),
    _v(
        "cp a /opt/finishup_receipt.json; cp b /opt/result.json",
        ["/opt/finishup_receipt.json", "/opt/result.json"],
        "outside_workspace",
        None,
        "3: outside wins",
    ),
    # 4. Quoting makes `$` and `*` literal, and a literal path is an attributable target.
    _v(
        "echo x > '/opt/$report.txt'",
        ["/opt/$report.txt"],
        "outside_workspace",
        None,
        f"{_R} 4",
    ),
    _v("echo x > /opt/file\\*.py", ["/opt/file*.py"], "outside_workspace", None, f"{_R} 4"),
    _v('echo x > "/opt/\\$report.txt"', ["/opt/$report.txt"], "outside_workspace", None, "4"),
    _v("echo x > /opt/file*.py", [], None, None, "4: an unquoted glob is not a path"),
    _v('echo x > "/opt/$report.txt"', [], None, None, "4: an expansion is not a path"),
    _v("echo x > $OUT", [], None, None, "4: an expansion is not a path"),
    _v("echo x > ~/out.txt", [], None, None, "4: ~ is not a path"),
    _v("echo x > '~/out.txt'", ["~/out.txt"], "workspace", "workspace", "4: quoted ~ is literal"),
    _v("echo x > file{1,2}.txt", [], None, None, "4: brace expansion is not a path"),
    _v("echo x > 'file{1,2}.txt'", ["file{1,2}.txt"], "workspace", "workspace", "4: quoted"),
    # Heredocs: a quoted operator or here-string starts none; a body is data, never syntax.
    _v("echo '<<EOF'\n: > solve.py", ["solve.py"], "workspace", "workspace", f"{_R} heredoc"),
    _v("cat <<<EOF\n: > solve.py", ["solve.py"], "workspace", "workspace", f"{_R} heredoc"),
    _v(
        "cat <<'END-DATA'\necho x > solve.py\nEND-DATA",
        [],
        None,
        None,
        f"{_R} heredoc delimiter",
    ),
    _v("cat <<EOF\n  EOF\necho x > solve.py\nEOF", [], None, None, f"{_R} heredoc indented"),
    _v("cat <<-EOF\n\tx > a.txt\n\tEOF\n: > b.txt", ["b.txt"], "workspace", "workspace", _H),
    _v("cat <<-EOF\n  EOF\n: > b.txt\nEOF", [], None, None, f"{_H}: <<- strips tabs only"),
    _v("cat <<A <<B\nx > a\nA\ny > b\nB\n: > c.txt", ["c.txt"], "workspace", "workspace", _H),
    _v("cat > solve.py <<EOF\nx > other.txt\nEOF", ["solve.py"], "workspace", "workspace", _H),
    _v("cat <<EOF > solve.py\nx\nEOF", ["solve.py"], "workspace", "workspace", _H),
    _v("cat <<EOF\nnever closed > solve.py", [], None, None, f"{_H}: unterminated body is data"),
    _v("cat <<'EOF'\n$(echo x > a.txt)\nEOF\n: > b.txt", ["b.txt"], "workspace", "workspace", _H),
    # `>& file` writes a file; a descriptor target duplicates or closes one. `<>` creates.
    _v("echo hi >& solve.py", ["solve.py"], "workspace", "workspace", f"{_R} >&"),
    _v(": <> solve.py", ["solve.py"], "workspace", "workspace", f"{_R} <>"),
    _v("echo hi >&2", [], None, None, "fd dup"),
    _v("echo hi 2>&1", [], None, None, "fd dup"),
    _v("echo hi >&-", [], None, None, "fd close"),
    _v("echo hi 2>&- >&1", [], None, None, "fd dup"),
    _v("echo hi 2>& solve.py", [], None, None, "bash: ambiguous redirect"),
    _v("cmd 2>&1 > out.txt", ["out.txt"], "workspace", "workspace", "redirect order"),
    _v("cat < in.txt", [], None, None, "a read"),
    # cp / mv / install destinations.
    _v(
        "cp --target-directory=/app/out source NOTES.md",
        ["/app/out"],
        "workspace",
        None,
        f"{_R} cp -t",
    ),
    _v("cp -t/app/out source NOTES.md", ["/app/out"], "workspace", None, f"{_R} cp -t"),
    _v("cp --target-directory=out source NOTES.md", ["out"], "workspace", "workspace", "cp -t"),
    _v("cp -t out a b", ["out"], "workspace", "workspace", "cp -t"),
    _v("cp -rt out a b", ["out"], "workspace", "workspace", "cp -t in a cluster"),
    _v("mv --target-directory out a b", ["out"], "workspace", "workspace", "mv -t"),
    _v("cp -S .bak a b", ["b"], "workspace", "workspace", "cp -S takes a value"),
    _v("install -d outdir", ["outdir"], "workspace", "workspace", f"{_R} install -d"),
    _v("install -d -m 755 a b", ["a", "b"], "workspace", "workspace", "install -d"),
    _v("install -m755 -o root a /app/b", ["/app/b"], "workspace", None, "install options"),
    _v("install -t out a b", ["out"], "workspace", "workspace", "install -t"),
    _v("rsync -a src/ dest/", ["dest/"], "workspace", "workspace", "rsync"),
    _v("rsync -a src/ user@host:/data/", [], None, None, "a remote destination is no file"),
    _v("rsync -a src/ rsync://host/mod/", [], None, None, "a remote destination is no file"),
    # Operands after `--`.
    _v("tee -- -result.txt", ["-result.txt"], "workspace", "workspace", f"{_R} --"),
    _v("cp -- src -result.py", ["-result.py"], "workspace", "workspace", f"{_R} --"),
    _v("touch -- -f.txt", ["-f.txt"], "workspace", "workspace", "--"),
    _v("echo x | tee -a out.txt", ["out.txt"], "workspace", "workspace", "tee -a"),
    # touch -r reads its reference.
    _v("touch -r /etc/motd NOTES.md", ["NOTES.md"], "notes", "notes", f"{_R} touch -r"),
    _v("touch --reference=/etc/motd out.txt", ["out.txt"], "workspace", "workspace", "touch -r"),
    _v("touch -d '2020-01-01' -c x.txt", ["x.txt"], "workspace", "workspace", "touch -d"),
    _v("touch -t 202001010000 x.txt", ["x.txt"], "workspace", "workspace", "touch -t"),
    _v("truncate -s0 f.bin", ["f.bin"], "workspace", "workspace", "truncate"),
    _v("truncate -r ref f.bin", ["f.bin"], "workspace", "workspace", "truncate -r"),
    _v("dd if=a of=b.bin bs=1", ["b.bin"], "workspace", "workspace", "dd"),
    _v("dd if=a of=$X", [], None, None, "dd of=$X"),
    # Mixed non-counting classes in one command keep counting, like a mixed edit-tool call.
    _v(
        ": > NOTES.md; : > finishup_receipt.md",
        ["NOTES.md", "finishup_receipt.md"],
        "workspace",
        "workspace",
        f"{_R} mixed",
    ),
    _v(": > NOTES.md", ["NOTES.md"], "notes", "notes", "one class stays non-counting"),
    _v(
        ": > finishup_receipt.md",
        ["finishup_receipt.md"],
        "yoetz_owned",
        "yoetz_owned",
        "one class",
    ),
    _v(
        "echo x > NOTES.md && cp a.txt b.txt",
        ["NOTES.md", "b.txt"],
        "workspace",
        "workspace",
        "mix",
    ),
    # Arithmetic and test constructs compare with `>`/`<`; they redirect nothing.
    _v("(( x > 5 )) && echo y", [], None, None, "arithmetic"),
    _v("if (( count > 5 )); then echo big; fi", [], None, None, "arithmetic"),
    _v("for ((i=n; i>0; i--)); do echo $i; done", [], None, None, "arithmetic"),
    _v("while (( i < 10 )); do i=$((i+1)); done", [], None, None, "arithmetic"),
    _v('[[ "$a" > "b.txt" ]] && echo y', [], None, None, "string comparison"),
    _v("if [[ $x > 5 && $y < 3 ]]; then echo y; fi", [], None, None, "string comparison"),
    _v("[[ -f a ]] && echo y > out.txt", ["out.txt"], "workspace", "workspace", "after [[ ]]"),
    _v("test a \\> b && echo y", [], None, None, "escaped"),
    # Control flow is not modelled: whether a compound body runs is unknown, so it is not read.
    _v("if true; then cp a b; fi", [], None, None, "control flow"),
    _v("for f in a b; do touch out.txt; done", [], None, None, "control flow"),
    _v("! touch out.txt", [], None, None, "negation: the bang is a command name here"),
    _v("{ touch out.txt; }", [], None, None, "control flow"),
    # Text is not syntax.
    _v('echo ">" output.txt', [], None, None, "quoted operator"),
    _v("echo tee output.txt", [], None, None, "tee as an argument"),
    _v("echo x # > hidden.txt", [], None, None, "comment"),
    _v("echo a#b > real.txt", ["real.txt"], "workspace", "workspace", "# inside a word"),
    # The host's own shell wrapper runs the real command.
    _v("/bin/bash -lc 'cat > solve.py'", ["solve.py"], "workspace", "workspace", "wrapper"),
    _v(
        "/bin/bash -lc 'cat > solve.py <<EOF\nx > other.txt\nEOF'",
        ["solve.py"],
        "workspace",
        "workspace",
        "wrapper with a heredoc",
    ),
    _v('bash -c "echo $(echo "x > solve.py")"', [], None, None, "wrapper with a substitution"),
]
