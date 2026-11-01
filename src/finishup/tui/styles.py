"""The FinishUP terminal stylesheet.

Held as a string rather than a ``.tcss`` file so the distribution stays a pure
set of Python modules: the wheel contract allows package code and reviewed
resources under ``finishup/resources/`` only, and a stylesheet is neither a
reviewed resource nor worth the manifest machinery that would make it one.

The visual language is deliberately restrained: the default terminal
background, no panel chrome around ordinary content, and colour used only where
it carries meaning. Rounded borders appear on exactly three surfaces — the
session header, focused text entry, and a focused detail panel — because a
border here means "this is the thing you are working on", and that signal is
destroyed by boxing everything.
"""

from __future__ import annotations

from typing import Final

__all__ = ["FINISHUP_CSS"]

FINISHUP_CSS: Final = """\
Screen {
    background: $background;
    layout: vertical;
}

/* -- session header ----------------------------------------------------- */

#session-header {
    border: round $primary 60%;
    padding: 0 1;
    height: auto;
    max-height: 9;
    margin: 0 0 1 0;
    color: $foreground;
}

#session-header.compact {
    border: none;
    padding: 0 1;
    margin: 0;
}

/* -- transcript --------------------------------------------------------- */

#history {
    height: 1fr;
    min-height: 3;
    padding: 0 1;
    scrollbar-size-vertical: 1;
    background: $background;
}

#history-tip {
    padding: 0 1;
    height: auto;
}

.event {
    height: auto;
    margin: 0 0 1 0;
}

/* -- bottom pane -------------------------------------------------------- */

#bottom-pane {
    height: auto;
    max-height: 60%;
    dock: bottom;
    background: $background;
}

/* A Vertical defaults to 1fr, which would take the transcript's space. The
 * composer must only ever be as tall as its popup plus one input line. */
#composer-area {
    height: auto;
}

#command-popup {
    height: auto;
    max-height: 12;
    padding: 0 1;
}

#composer-row {
    height: auto;
    padding: 0 1;
}

#composer {
    border: none;
    padding: 0;
    height: 1;
    background: $background;
}

#composer:focus {
    border: none;
}

#footer-row {
    height: 1;
    padding: 0 1;
    color: $text-muted;
}

/* -- temporary views ---------------------------------------------------- */

.view {
    height: auto;
    max-height: 100%;
    padding: 0 1;
    background: $background;
}

.view-title {
    height: auto;
    padding: 0 0 1 0;
}

.view-body {
    height: auto;
    max-height: 24;
    overflow-y: auto;
    overflow-x: auto;
}

.view-hint {
    height: auto;
    padding: 1 0 0 0;
    color: $text-muted;
}

#option-list {
    height: auto;
    max-height: 16;
    overflow-y: auto;
}

/* Text and secret entry are focused moments, so they get a border. */
.entry {
    border: round $primary 60%;
    padding: 0 1;
    height: 3;
}

.entry-label {
    height: auto;
    padding: 0 0 0 0;
}

#details-panel {
    border: round $primary 40%;
    padding: 0 1;
    height: auto;
    max-height: 22;
    overflow-y: auto;
    overflow-x: auto;
}
"""
