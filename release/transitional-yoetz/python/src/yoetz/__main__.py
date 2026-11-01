"""Deprecated module entry point ``python -m yoetz`` (ADR-048); runs ``python -m finishup``."""

from __future__ import annotations

from finishup.cli.entry import main

main()
