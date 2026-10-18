"""Task inputs as text or FinishUP's own summary, and the admitted outside-workspace read (#1082)."""

from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest

from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.task_input_read import (
    MAX_TASK_INPUT_READ_BYTES,
    read_outside_inputs,
    task_input_from_bytes,
    task_input_from_ends,
)
from finishup.observability.privacy import scan_for_sensitive_content
from finishup.ports.change_capture import (
    MAX_TASK_INPUT_TEXT_BYTES,
    CheckChangeCapture,
    TaskInputFile,
    decode_check_change,
    encode_check_change,
)

_PNG = (
    b"\x89PNG\r\n\x1a\n"
    + struct.pack(">I", 13)
    + b"IHDR"
    + struct.pack(">IIBBBBB", 640, 480, 8, 2, 0, 0, 0)
    + b"\x00\x00\x00\x00"
)


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    ).stdout


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "test@example.invalid")
    _git(repository, "config", "user.name", "Test")
    (repository / "README.md").write_text("readme\n", encoding="utf-8")
    _git(repository, "add", "--", "README.md")
    _git(repository, "commit", "-q", "-m", "init")
    return repository


def test_binary_bytes_become_a_summary_and_text_stays_text() -> None:
    image = task_input_from_bytes("figures/plot.png", _PNG)
    assert image is not None and image.summary and image.origin == "task"
    assert image.size == len(_PNG)
    assert b"format: PNG image" in image.text and b"dimensions: 640x480" in image.text
    assert _PNG not in image.text

    text = task_input_from_bytes("DESIGN.md", b"# Design\n")
    assert text is not None and not text.summary and text.text == b"# Design\n"


@pytest.mark.parametrize(
    ("path", "origin", "summary", "valid"),
    [
        ("dedup/", "task", True, True),
        ("./", "task", True, True),
        ("My Docs/", "task", True, True),
        ("dedup/config.py", "task_directory", False, True),
        ("dedup/", "task", False, False),
        ("dedup/", "task_directory", True, False),
        ("dedup/", "verification", True, False),
        ("../", "task", True, False),
        ("a//", "task", True, False),
        ("/abs/", "task", True, False),
    ],
)
def test_only_a_task_summary_may_be_a_directory_listing(
    path: str, origin: str, summary: bool, valid: bool
) -> None:
    """Issue #1102: a path ending in ``/`` is FinishUP's own listing of a named directory."""

    def build() -> TaskInputFile:
        return TaskInputFile(path, b"listing\n", 8, origin=cast(Any, origin), summary=summary)

    if valid:
        item = build()
        capture = CheckChangeCapture("task_start", b"diff\n", 0, 0, 0, False, inputs=(item,))
        assert decode_check_change(encode_check_change(capture)) == capture
    else:
        with pytest.raises(ValueError):
            build()


def test_a_file_too_large_to_read_whole_keeps_its_two_ends_or_a_summary() -> None:
    size = MAX_TASK_INPUT_READ_BYTES * 3
    head = b"id,value\n" + b"1,2\n" * 1000
    tail = b"9999,LAST_ROW_MARKER\n"
    rows = task_input_from_ends("data/big.csv", head, tail, size)
    assert rows is not None and not rows.summary
    assert rows.size == size and len(rows.text) <= MAX_TASK_INPUT_TEXT_BYTES
    assert rows.text.startswith(b"id,value\n") and rows.text.endswith(b"LAST_ROW_MARKER\n")
    assert b"bytes elided here; head and tail kept]" in rows.text

    blob = task_input_from_ends("data/big.bin", b"\x00\x01" * 100, b"", size)
    assert blob is not None and blob.summary and f"size: {size} bytes".encode() in blob.text


def test_the_repository_read_summarizes_a_binary_and_a_large_untracked_input(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "figures").mkdir()
    (repository / "figures" / "plot.png").write_bytes(_PNG)
    _git(repository, "add", "--", "figures/plot.png")
    _git(repository, "commit", "-q", "-m", "figure")
    big = b"id,value\n" + b"1,2\n" * (MAX_TASK_INPUT_READ_BYTES // 4 + 10) + b"END_MARKER\n"
    (repository / "big.csv").write_bytes(big)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (repository / "solution.py").write_text("print(1)\n", encoding="utf-8")

    capture = adapter.capture(
        os.fspath(repository), base, input_paths=("figures/plot.png", "big.csv")
    )

    plot, rows = capture.inputs
    assert plot.path == "figures/plot.png" and plot.summary
    assert b"dimensions: 640x480" in plot.text
    assert rows.path == "big.csv" and not rows.summary and rows.size == len(big)
    assert rows.text.endswith(b"END_MARKER\n")
    assert decode_check_change(encode_check_change(capture)) == capture


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    root = (tmp_path / "shared").resolve()
    (root / "legacy_app" / "forms").mkdir(parents=True)
    (root / "legacy_app" / "Module1.bas").write_text("Sub Main()\nEnd Sub\n", encoding="utf-8")
    (root / "legacy_app" / "forms" / "Form1.frm").write_text("FORM_MARKER\n", encoding="utf-8")
    (root / "legacy_app" / ".env").write_text("TOKEN=hidden\n", encoding="utf-8")
    (root / "legacy_app" / "secrets.pem").write_text("not a key\n", encoding="utf-8")
    (root / "spec.md").write_text("SPEC_MARKER\n", encoding="utf-8")
    (root / "scan.png").write_bytes(_PNG)
    return root


def test_outside_inputs_are_read_only_beneath_an_admitted_root(
    shared: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other.md"
    other.write_text("OUTSIDE_ROOT_MARKER\n", encoding="utf-8")
    root = os.fspath(shared)

    inputs = read_outside_inputs(
        (root,),
        (
            f"{root}/spec.md",
            os.fspath(other),  # not beneath an admitted root
            f"{root}/../other.md",  # normalizes outside the root
            f"{root}/legacy_app/.env",  # hidden
            f"{root}/legacy_app/secrets.pem",  # credential-named
            f"{root}/missing.md",
            f"{root}/scan.png",
        ),
        limit=4,
    )

    assert [item.path for item in inputs] == [f"{root}/spec.md", f"{root}/scan.png"]
    spec, scan = inputs
    assert spec.origin == "outside_workspace" and spec.text == b"SPEC_MARKER\n"
    assert scan.summary and b"format: PNG image" in scan.text
    joined = b"".join(item.text for item in inputs)
    assert b"OUTSIDE_ROOT_MARKER" not in joined and b"hidden" not in joined


def test_a_named_directory_offers_its_visible_files_in_order(shared: Path) -> None:
    root = os.fspath(shared)

    inputs = read_outside_inputs((root,), (f"{root}/legacy_app/",), limit=4)

    assert [item.path for item in inputs] == [
        f"{root}/legacy_app/Module1.bas",
        f"{root}/legacy_app/forms/Form1.frm",
    ]
    assert read_outside_inputs((root,), (f"{root}/legacy_app/",), limit=1)[0].path.endswith(
        "Module1.bas"
    )


def test_an_admitted_directory_named_without_a_slash_is_listed(
    shared: Path, tmp_path: Path
) -> None:
    """Issue #1102 (RC6d): "the legacy app in /shared/legacy_app" read nothing without its ``/``."""

    root = os.fspath(shared)
    (shared / "linked_app").symlink_to(shared / "legacy_app")

    inputs = read_outside_inputs((root,), (f"{root}/legacy_app",), limit=4)

    assert [item.path for item in inputs] == [
        f"{root}/legacy_app/Module1.bas",
        f"{root}/legacy_app/forms/Form1.frm",
    ]
    # A link at the last component is still never a directory, whichever way it is spelled.
    assert read_outside_inputs((root,), (f"{root}/linked_app",)) == ()
    assert read_outside_inputs((root,), (f"{root}/linked_app/",)) == ()


def test_the_head_word_of_a_quoted_spaced_path_never_lists_a_folder(shared: Path) -> None:
    """Issue #1102 review goal-r1-2: ``"/shared/legacy app/main.c"`` names one file. The word
    the space cut from its head, ``/shared/legacy``, is no folder the task names, even when one
    exists there beneath the admitted root."""

    from builders.policy_cases import make_case
    from finishup.application.check_change import task_input_paths

    root = os.fspath(shared)
    (shared / "legacy app").mkdir()
    (shared / "legacy app" / "main.c").write_text("int main(void) { return 0; }\n", "utf-8")
    (shared / "legacy").mkdir()
    (shared / "legacy" / "unrelated_notes.txt").write_text("UNRELATED_MARKER\n", "utf-8")

    candidates = task_input_paths(make_case().projection, f'Port "{root}/legacy app/main.c".')
    inputs = read_outside_inputs((root,), candidates, limit=4)

    assert candidates == (f"{root}/legacy app/main.c",)
    assert [item.path for item in inputs] == [f"{root}/legacy app/main.c"]


def test_links_and_unsafe_roots_admit_nothing(shared: Path, tmp_path: Path) -> None:
    root = os.fspath(shared)
    target = tmp_path / "target.md"
    target.write_text("LINK_TARGET_MARKER\n", encoding="utf-8")
    (shared / "link.md").symlink_to(target)
    (shared / "linked_dir").symlink_to(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(shared)
    writable = shared / "writable.md"
    writable.write_text("WRITABLE_MARKER\n", encoding="utf-8")
    writable.chmod(0o666)

    assert read_outside_inputs((root,), (f"{root}/link.md",)) == ()
    assert read_outside_inputs((root,), (f"{root}/linked_dir/target.md",)) == ()
    assert read_outside_inputs((root,), (f"{root}/writable.md",)) == ()
    # A root reached through a link, or one the domain refuses, admits nothing.
    assert read_outside_inputs((os.fspath(alias),), (f"{alias}/spec.md",)) == ()
    assert read_outside_inputs(("/etc",), ("/etc/hosts",)) == ()
    assert read_outside_inputs((), (f"{root}/spec.md",)) == ()


def test_the_service_reader_binds_only_the_admitted_roots_and_the_room(
    shared: Path, tmp_path: Path
) -> None:
    """The reader the service hands the capture takes ``(values, room, workspace)`` positionally,
    and never reads the workspace or the service's own protected directories (R1-02)."""

    from finishup.service import ready_composition

    workspace = os.fspath(tmp_path / "repo")
    reader = ready_composition._outside_input_reader(  # pyright: ignore[reportPrivateUsage]
        (os.fspath(shared),), (os.fspath(shared / "legacy_app" / "forms"),)
    )
    values = (f"{shared}/spec.md", f"{shared}/legacy_app/")
    assert [item.path for item in reader(values, 1, workspace)] == [f"{shared}/spec.md"]
    # The protected directory is never listed, so only Module1.bas is offered from legacy_app.
    assert [item.path for item in reader(values, 3, workspace)] == [
        f"{shared}/spec.md",
        f"{shared}/legacy_app/Module1.bas",
    ]
    # The workspace is refused the same way, whichever directory it is.
    assert reader(values, 3, os.fspath(shared / "legacy_app")) == (
        next(iter(reader(values, 1, workspace))),
    )


# --- PR #1086 review R1-02: an admitted directory never re-enters the workspace -----------------


def test_an_admitted_directory_that_contains_the_workspace_never_lists_it(tmp_path: Path) -> None:
    """R1-02 probe: admitting ``/shared`` with the workspace at ``/shared/repo`` and naming
    ``/shared/`` must not return an ignored workspace file, or any workspace file, as outside."""

    from finishup.application import check_change

    root = (tmp_path / "shared").resolve()
    workspace = root / "repo"
    workspace.mkdir(parents=True)
    _git(workspace, "init", "-q")
    (workspace / ".gitignore").write_text("private-note.txt\n", encoding="utf-8")
    (workspace / "private-note.txt").write_text("IGNORED_WORKSPACE_CONTENT\n", encoding="utf-8")
    (workspace / "solution.py").write_text("AGENT_WRITTEN_CODE\n", encoding="utf-8")
    (root / "spec.md").write_text("SPEC_MARKER\n", encoding="utf-8")

    def reader(values: tuple[str, ...], room: int, excluded: str) -> tuple[TaskInputFile, ...]:
        return read_outside_inputs((os.fspath(root),), values, limit=room, excluded=(excluded,))

    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/solution.py b/solution.py\n+x\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
    )
    with_outside = getattr(check_change, "_with_outside_inputs")
    result = with_outside(
        capture, (f"{root}/",), reader, os.fspath(workspace), verification_paths=frozenset()
    )

    assert [item.path for item in result.inputs] == [f"{root}/spec.md"]
    joined = b"".join(item.text for item in result.inputs)
    assert b"IGNORED_WORKSPACE_CONTENT" not in joined and b"AGENT_WRITTEN_CODE" not in joined
    # Named one by one, the workspace files are refused too.
    assert (
        read_outside_inputs(
            (os.fspath(root),),
            (f"{workspace}/private-note.txt", f"{workspace}/solution.py"),
            excluded=(os.fspath(workspace),),
        )
        == ()
    )


def test_the_workspace_is_refused_by_identity_whatever_its_spelling(tmp_path: Path) -> None:
    """R1-02: the exclusion compares device and inode, so another spelling of the workspace (a
    case alias on a case-insensitive file system, a bind mount, here a link to it) is refused at
    every level of the walk, not only the spelling the check was given."""

    root = (tmp_path / "shared").resolve()
    workspace = root / "repo"
    (workspace / "docs").mkdir(parents=True)
    (workspace / "docs" / "note.md").write_text("WORKSPACE_NOTE\n", encoding="utf-8")
    (root / "spec.md").write_text("SPEC_MARKER\n", encoding="utf-8")
    alias = tmp_path / "workspace-alias"
    alias.symlink_to(workspace, target_is_directory=True)

    inputs = read_outside_inputs(
        (os.fspath(root),),
        (f"{root}/", f"{workspace}/docs/note.md", f"{root}/repo/docs/"),
        excluded=(os.fspath(alias),),
    )

    assert [item.path for item in inputs] == [f"{root}/spec.md"]
    # A root inside the workspace is refused while it is opened.
    assert (
        read_outside_inputs(
            (os.fspath(workspace / "docs"),),
            (f"{workspace}/docs/note.md",),
            excluded=(os.fspath(alias),),
        )
        == ()
    )
    # An exclusion that exists but cannot be examined leaves nothing provably outside it.
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0o000)
    try:
        if os.access(locked / "inner", os.F_OK):
            pytest.skip("running with privileges that ignore directory modes")
        assert (
            read_outside_inputs(
                (os.fspath(root),), (f"{root}/spec.md",), excluded=(f"{locked}/inner",)
            )
            == ()
        )
    finally:
        locked.chmod(0o700)


def test_a_case_alias_of_the_workspace_is_refused_on_a_case_insensitive_file_system(
    tmp_path: Path,
) -> None:
    """R1-02 probe: workspace ``CaseRepo``, requested ``caserepo/private-note.txt``."""

    from finishup.application import check_change

    root = (tmp_path / "shared").resolve()
    workspace = root / "CaseRepo"
    workspace.mkdir(parents=True)
    (workspace / "private-note.txt").write_text("CASE_ALIAS_CONTENT\n", encoding="utf-8")
    alias = root / "caserepo" / "private-note.txt"
    if not alias.exists():
        pytest.skip("this file system distinguishes case")

    def reader(values: tuple[str, ...], room: int, excluded: str) -> tuple[TaskInputFile, ...]:
        return read_outside_inputs((os.fspath(root),), values, limit=room, excluded=(excluded,))

    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+x\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
    )
    with_outside = getattr(check_change, "_with_outside_inputs")
    result = with_outside(
        capture, (os.fspath(alias),), reader, os.fspath(workspace), verification_paths=frozenset()
    )
    assert result.inputs == ()
    # The reader refuses it by identity even when the caller's own lexical check is bypassed.
    assert (
        read_outside_inputs(
            (os.fspath(root),), (os.fspath(alias),), excluded=(os.fspath(workspace),)
        )
        == ()
    )


# --- PR #1086 review R1-03: the admitted root is opened without an ancestor race ---------------


@pytest.mark.parametrize(
    "swap_at", ("first_open", "parent_component", "final_component", "absolute_root_open")
)
def test_an_ancestor_swapped_for_a_link_during_the_open_admits_nothing(
    tmp_path: Path, swap_at: str
) -> None:
    """R1-03 probe: approve ``approved_parent/inputs``; while the root is being opened, rename
    ``approved_parent`` and put a link to ``unapproved_parent`` in its place. The unapproved
    content is never read, whenever during the open the swap happens: before the walk reaches
    the parent its link fails to open, and after it the root path no longer names the directory
    opened. ``absolute_root_open`` is the review's own trigger, an absolute open of the root,
    which the component walk never performs."""

    base = tmp_path.resolve()
    parent = base / "approved_parent"
    root = parent / "inputs"
    root.mkdir(parents=True)
    (root / "spec.md").write_text("APPROVED_SPEC\n", encoding="utf-8")
    other = base / "unapproved_parent"
    (other / "inputs").mkdir(parents=True)
    (other / "inputs" / "spec.md").write_text("UNAPPROVED_CONTENT\n", encoding="utf-8")
    real_open = os.open
    swapped = False

    def racing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        trigger = {
            "first_open": True,
            "parent_component": path == "approved_parent",
            "final_component": path == "inputs",
            "absolute_root_open": path == os.fspath(root),
        }[swap_at]
        if trigger and not swapped:
            swapped = True
            parent.rename(base / "saved_parent")
            parent.symlink_to(other, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    with patch("finishup.adapters.task_input_read.os.open", side_effect=racing_open):
        inputs = read_outside_inputs((os.fspath(root),), (f"{root}/spec.md",))

    assert all(b"UNAPPROVED_CONTENT" not in item.text for item in inputs)
    if swap_at == "absolute_root_open":
        assert not swapped and [item.text for item in inputs] == [b"APPROVED_SPEC\n"]
    else:
        assert swapped and inputs == ()


# --- PR #1086 review R1-07: another account's write access is refused ------------------------


def test_a_group_writable_input_is_refused_unless_the_group_is_the_owners_own(
    shared: Path,
) -> None:
    """R1-07 probe: a mode-0660 file in a group another account may belong to is refused; the
    owner's private group (the established ``writable_by_others`` policy) is not another account."""

    root = os.fspath(shared)
    spec = shared / "spec.md"
    spec.chmod(0o660)

    with patch("finishup.config.foreign_write.owner_private_group", return_value=False):
        assert read_outside_inputs((root,), (f"{root}/spec.md",)) == ()
    with patch("finishup.config.foreign_write.owner_private_group", return_value=True):
        (item,) = read_outside_inputs((root,), (f"{root}/spec.md",))
        assert item.text == b"SPEC_MARKER\n"


def test_a_directory_another_account_may_write_admits_nothing_beneath_it(
    shared: Path, tmp_path: Path
) -> None:
    """R1-07: the root and every directory on the way get the same test as the file; a sticky
    directory (``/tmp``) is the exception, because no other account can rename beneath it."""

    root = os.fspath(shared)
    forms = shared / "legacy_app" / "forms"
    values = (f"{root}/legacy_app/forms/Form1.frm",)
    with patch("finishup.config.foreign_write.owner_private_group", return_value=False):
        forms.chmod(0o770)
        assert read_outside_inputs((root,), values) == ()
        assert [item.path for item in read_outside_inputs((root,), (f"{root}/legacy_app/",))] == [
            f"{root}/legacy_app/Module1.bas"
        ]
        forms.chmod(0o1777)
        assert [item.path for item in read_outside_inputs((root,), values)] == list(values)
        forms.chmod(0o755)
        shared.chmod(0o775)
        assert read_outside_inputs((root,), (f"{root}/spec.md",)) == ()
        shared.chmod(0o755)
        tmp_path.chmod(0o777)
        try:
            assert read_outside_inputs((root,), (f"{root}/spec.md",)) == ()
        finally:
            tmp_path.chmod(0o700)


# --- PR #1086 review R1-08: a recognized document signature is summarized without a NUL -------


def _ascii_pdf() -> bytes:
    stream = b"BT /F1 12 Tf 10 10 Td (PAGE_CONTENT_MARKER) Tj ET\n"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream",
    ]
    pdf = b"%PDF-1.4\n"
    offsets: list[int] = []
    for index, body in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += str(index).encode() + b" 0 obj\n" + body + b"\nendobj\n"
    xref = len(pdf)
    pdf += b"xref\n0 5\n0000000000 65535 f \n"
    pdf += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    pdf += b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n"
    assert b"\0" not in pdf
    return pdf


def test_an_all_ascii_pdf_is_summarized_not_sent_as_text(shared: Path) -> None:
    """R1-08 probe: a complete one-page PDF with no NUL byte is FinishUP's summary, whichever
    reader takes it, and its page text never travels."""

    pdf = _ascii_pdf()
    item = task_input_from_bytes("/shared/input.pdf", pdf, origin="outside_workspace")
    assert item is not None and item.summary
    assert b"format: PDF document" in item.text and b"pages (estimated): 1" in item.text
    assert b"PAGE_CONTENT_MARKER" not in item.text
    large = task_input_from_ends("big.pdf", pdf, b"", MAX_TASK_INPUT_READ_BYTES * 2)
    assert large is not None and large.summary and b"PAGE_CONTENT_MARKER" not in large.text
    (shared / "input.pdf").write_bytes(pdf)
    (read,) = read_outside_inputs((os.fspath(shared),), (f"{shared}/input.pdf",))
    assert read.summary and b"PAGE_CONTENT_MARKER" not in read.text
    # A PDF header after leading bytes counts only beside object structure; a text file that
    # merely mentions the signature stays text.
    junk = b"leading junk line\n" + pdf
    assert (summarized := task_input_from_bytes("x.pdf", junk)) is not None and summarized.summary
    note = b"Check that the upload starts with %PDF-1.7 before parsing.\n"
    text = task_input_from_bytes("notes.md", note)
    assert text is not None and not text.summary and text.text == note
    gif = task_input_from_bytes("logo.gif", b"GIF89a\x10\x01\x20\x01" + b"x" * 20)
    assert gif is not None and gif.summary and b"dimensions: 272x288" in gif.text


# --- PR #1086 review R1-04: no cut splits a recognized credential -----------------------------

_TOKEN = b"ghp_" + b"B7" * 20


def _straddling(total: int, offset: int) -> bytes:
    """``total`` bytes of text with a credential across each of the head and tail cuts."""

    from finishup.adapters import task_input_read

    elision = cast(str, getattr(task_input_read, "_ELISION"))
    marker = elision.format(elided="0" * len(str(total)), total=total)
    side = (MAX_TASK_INPUT_TEXT_BYTES - len(marker.encode("utf-8"))) // 2
    token = b" " + _TOKEN + b" "
    content = bytearray(((b"a" * 79 + b"\n") * (total // 80 + 1))[:total])
    for start in (side + offset - len(token) // 2, total - side + offset - len(token) // 2):
        content[start : start + len(token)] = token
    return bytes(content)


@pytest.mark.parametrize("offset", (*range(-21, 22, 7), 300))
def test_a_head_or_tail_cut_never_splits_a_recognized_credential(offset: int) -> None:
    """R1-04: the head and tail cuts of a long text move clear of a credential before cutting, so
    the redaction pass sees every kept credential whole and no fragment survives it. At offset
    300 the head's credential lies wholly in the elided middle and the tail's wholly inside the
    kept tail, where it is redacted."""

    from finishup.application.check_change import (
        _redacted_inputs,  # pyright: ignore[reportPrivateUsage]
    )

    total = 600_000
    content = _straddling(total, offset)
    assert len(scan_for_sensitive_content(content)) == 2
    for item in (
        task_input_from_bytes("big.txt", content),
        task_input_from_ends("huge.txt", content, content[-(12 * 1024) :], total),
    ):
        assert item is not None and not item.summary
        # Every ``ghp_`` kept is a whole credential the scanner recognizes.
        assert item.text.count(b"ghp_") == item.text.count(_TOKEN)
        assert item.text.count(b"B7" * 20) == item.text.count(_TOKEN)
        (kept,) = _redacted_inputs((item,))
        assert b"ghp_" not in kept.text and b"B7B7B7B7" not in kept.text
        if offset == 300:
            assert kept.redacted and kept.text.count(b"[REDACTED]") == 1


def test_the_tail_is_read_with_room_to_move_its_cut(shared: Path) -> None:
    root = os.fspath(shared)
    big = shared / "big.log"
    tail_text = b"z" * 79 + b"\n"
    big.write_bytes(b"a" * 79 + b"\n" + tail_text * (MAX_TASK_INPUT_READ_BYTES // 80 + 200))
    (item,) = read_outside_inputs((root,), (f"{root}/big.log",))
    assert item.size == big.stat().st_size and not item.summary
    assert len(item.text) <= MAX_TASK_INPUT_TEXT_BYTES
