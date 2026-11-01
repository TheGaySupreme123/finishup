"""Deprecated ``yoetz.cli.entry`` console entry point (ADR-048); forwards to FinishUP."""

from __future__ import annotations

from finishup.cli.entry import main

__all__ = ["main"]
