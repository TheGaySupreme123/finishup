# ADR-013 — Interactive control menu as the default terminal entry point

**Status:** Working decision (2026-07-21), founder-authorized amendment of ADR-012 decision 2.
**Amended by:** [ADR-017](ADR-017-full-screen-terminal-interface.md) (2026-07-26). Decisions 1
and 2 below, and the "full-screen TUI framework" rejection under *Alternatives considered*, are
superseded: bare `finishup` and `finishup menu` on a real terminal now open the full-screen interface,
with first run folded into it. Decisions 3 and 4 — the surface adds no authority, and bounded
failures stay bounded — are carried forward unchanged and still bind. The prompt-loop menu
described here remains implemented and supported as the fallback when the rendering dependency
is unavailable or `FINISHUP_TUI=0` is set.
**Implemented by:** `src/finishup/cli/menu.py` (new), plus the amended
`src/finishup/cli/app.py`.
**Relates to:** ADR-008 (local service/vault trust boundary), ADR-009 (privacy/egress),
ADR-012 (first-run setup wizard).

## Context

ADR-012 gave a fresh install one guided moment — the first-run wizard — and then returned every
later bare `finishup` invocation to the historical help screen. Users who wanted to manage the
install afterwards (re-check the Codex MCP registration, rotate a provider credential, inspect
the privacy posture, unlock or stop the service) had to reassemble the correct subcommands from
`--help` each time. The command tree is correct but is an assembly manual, not a control panel.

## Decisions

1. **Bare `finishup` on a real terminal opens an interactive menu (amends ADR-012 decision 2).**
   The root callback keeps the exact ADR-012 order with one added final state: stdin+stdout both
   TTYs and no completion marker → first-run wizard, then the menu; both TTYs with the marker →
   the menu; every non-TTY, piped, CI, `--help`, and named-subcommand invocation remains
   byte-for-byte the historical behavior (help text for bare non-TTY invocations).

2. **`finishup menu` is a new top-level command** that opens the same menu explicitly. On a
   non-TTY it fails closed with a usage error (exit 2) and never prompts.
   Founder-authorized amendment (2026-07-29): `finishup --privacy` is a direct root shortcut to the
   trusted privacy ceremony. It first renders the exact recommended `assisted_review` draft only
   for a current, exact-route eligible provider record, and otherwise renders `private`, with its
   tradeoffs; only declining that draft opens the detailed one-by-one questions. The shortcut
   cannot be combined with a subcommand or provider-setup flags. The ceremony is bound to the
   repository derived from the command's actual working directory. It renders the service-returned
   grant and migration state; it never accepts public `workspace_ref` as privacy authority.

3. **The menu is a dispatcher, not a new authority.** Every menu action invokes an operation the
   command tree already exposes, with its existing gates intact: MCP registration keeps
   preview → digest-bound confirm → verify; provider credentials keep the confidential YZH1/YZS1
   ceremony (the menu collects only the nonsecret identifiers `provider credential set|rotate`
   already accepts as flags); privacy policy mutation stays in the explicit
   `privacy setup|propose|tighten` commands and trusted decision ceremonies — the menu only
   reads posture, including the repository grant and bounded legacy-migration state; service
   lifecycle uses the same client calls, and the menu never spawns the
   service (ADR-008). No secret is ever read by a menu prompt.

4. **Bounded failures keep the menu open.** A `ControlError` renders the same guidance strings
   as the corresponding command and returns to the menu; ceremony cancellation renders
   `cancelled`. Quitting is exit 0; Ctrl-C/EOF at a menu prompt quits cleanly.

## Consequences

After install, `finishup` in a terminal is always a navigable control panel: status overview
(service reachability, vault mode, per-binary Codex registration state, first-run posture) plus
sections for the wizard, harness connection, LLM provider credentials, privacy, and service.
Discoverability no longer depends on memorizing the command tree, while scripts, CI, and pipes
see unchanged output. The cost is that the bare-TTY invocation is no longer the help screen;
`finishup --help` remains untouched for that purpose.

## Alternatives considered

**A full-screen TUI framework (textual/urwid).** Rejected for v0.1: new dependency surface and
render complexity for no authority gain; a prompt-loop menu over the existing operations delivers
the discoverability with zero new trust boundary.

**Keep help as the bare-TTY output and only add `finishup menu`.** Rejected: the discoverability
problem is exactly that users do not know the command to type; the marker plus TTY guard already
distinguishes a human at a terminal from automation.

**Let the menu edit privacy policy inline.** Rejected: policy widening is a trusted-local
decision with its own ceremony (ADR-009); the menu must not become a second, softer path.
