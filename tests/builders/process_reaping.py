"""Keep a test's escaped children reparenting away from the test process (PR #1080 round 7).

Running an approved check in-process makes that process a child subreaper
(``finishup.adapters.approved_checks``), and the flag lasts for the rest of the pytest session. A
child a test lets escape would then reparent to the test process itself, which the lingering check
rightly counts as the host's own work, so the outcome of a real escaped-child test would depend on
which tests ran before it. ``not_a_child_subreaper`` clears the flag for one block and restores it.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

_PR_SET_CHILD_SUBREAPER: Final = 36
_PR_GET_CHILD_SUBREAPER: Final = 37


@contextmanager
def not_a_child_subreaper() -> Iterator[None]:
    """Clear ``PR_SET_CHILD_SUBREAPER`` on this process for the block (Linux only)."""

    if not sys.platform.startswith("linux"):
        yield
        return
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.restype = ctypes.c_int
    current = ctypes.c_int(0)
    assert prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(current), 0, 0, 0) == 0
    if current.value:
        assert prctl(_PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(0), 0, 0, 0) == 0
    try:
        yield
    finally:
        if current.value:
            prctl(_PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(current.value), 0, 0, 0)
