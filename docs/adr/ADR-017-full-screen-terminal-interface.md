# ADR-017 — Full-screen terminal interface as the interactive entry point

**Status:** Working decision (2026-07-26), founder-authorized amendment of ADR-013 decisions 1
and 2, and of the "alternatives considered" rejection of a TUI framework in that same ADR.
ADR-013's decisions 3 and 4 — the menu adds no authority, and bounded failures stay bounded —
are not amended; they are restated here and carried forward unchanged.
**Implemented by:** `src/finishup/tui/` (new package), plus the amended `src/finishup/cli/app.py`,
`src/finishup/cli/setup.py`, and `support/npm-launcher/bin/finishup.js`.
**Relates to:** ADR-008 (local service/vault trust boundary), ADR-009 (privacy/egress),
ADR-010 (harness integration port), ADR-012 (first-run setup wizard), ADR-013 (interactive
control menu), ADR-016 (human review for non-default actions).

## Context

ADR-012 gave a fresh install one guided moment; ADR-013 turned every later bare `finishup` into a
numbered prompt loop over the same operations. Both were correct and neither was usable by the
person this product is for.

The prompt loop reaches its limit in three specific places, all of which matter to the honesty
model rather than to aesthetics:

1. **Readiness cannot be shown as layers.** A prompt loop prints one screen and scrolls it away.
   The thing a user most needs to see — that MCP is *registered* but not *verified*, that a
   provider credential is *stored* but the connection is *untested* — is exactly the thing that
   a scrolling, re-printed screen flattens into whatever line was last.
2. **Approvals compete with output.** `typer.prompt` puts the question in the same stream as the
   preview it refers to. On a narrow terminal the digest a user is being asked to trust has often
   scrolled past the fold by the time the question appears.
3. **The vocabulary has nowhere to live.** ADR-013's menu had no way to distinguish "verified",
   "not proven", "not configured", and "blocked" other than prose, and prose is where honest
   distinctions go to be smoothed over.

ADR-013 rejected a TUI framework for v0.1 on the grounds of "new dependency surface and render
complexity for no authority gain". The first half of that is now much cheaper to answer than it
was: `rich` is already in the tree via Typer, so the marginal cost is four MIT packages. The
second half was correct and stays correct — and is the reason this ADR is careful to add no
authority at all.

## Decisions

1. **Bare `finishup` on a real terminal opens a full-screen interface (amends ADR-013 decision 1).**
   The gate is stricter than ADR-013's, not looser: stdin *and* stdout must both be TTYs, `TERM`
   must be neither empty nor `dumb`, no CI marker (`CI`, `CONTINUOUS_INTEGRATION`,
   `BUILD_NUMBER`, `GITHUB_ACTIONS`, `GITLAB_CI`, `TEAMCITY_VERSION`) may be set, and
   `FINISHUP_TUI=0` is an explicit opt-out. Every non-TTY, piped, redirected, CI, `--help`,
   JSON-output, named-subcommand, and MCP-server invocation keeps its exact previous bytes,
   including the help text for a bare non-TTY invocation.

2. **First run is folded into the interface rather than preceding it (amends ADR-012 decision 2 as
   ADR-013 left it).** There is no separate wizard pass followed by a menu. A terminal with no
   completion marker opens the interface in first-run mode, where welcome, detection, trust,
   preview, approval, activity, and finish are the opening steps of the same surface; completed
   steps collapse into concise lines in the transcript above the active one. There is no "step N of
   M" chrome, because the number of steps genuinely depends on what was found. Founder-authorized
   amendment (2026-07-29): the opening flow ends with an explicit Local only versus Add AI-powered
   review choice. AI-powered review reuses the existing provider credential and privacy ceremonies
   through terminal suspension; the completion marker is not written when either ceremony is
   incomplete.

   The privacy ceremony is scoped to the canonical repository derived by the service from the
   interface session's actual working directory. Git branches and linked worktrees share the common
   root; independent clones do not. The interface never derives privacy scope from public
   `workspace_ref` and never retains the raw locator after handing it to trusted control.

3. **`finishup menu` opens the same interface (amends ADR-013 decision 2).** The command name is
   kept for compatibility. On a non-TTY it still fails closed with a usage error (exit 2) and
   never prompts.

4. **The interface degrades to the ADR-013 prompt loop, and never fails.** If the rendering
   dependency is unavailable in an installation for any reason, `run_tui` reports that rather
   than raising, and the caller falls back to `src/finishup/cli/menu.py`. The prompt loop remains a
   complete, supported interface over the same operations; it is not deprecated by this ADR.

5. **The interface is a presentation layer and adds no authority (restates ADR-013 decision 3).**
   `src/finishup/tui/runtime.py` is the only module that speaks to application services, and it
   originates no decision. MCP registration keeps preview → digest-bound confirm → verify;
   plugin installation keeps its own verification; observation consent is still granted only
   after both are verified; privacy policy mutation stays in the explicit
   `privacy setup|propose|tighten` ceremonies. The interface may suspend and hand the controlling
   terminal to those existing ceremonies, but never reimplements or bypasses them; service
   lifecycle uses the same client calls and the interface never spawns a
   service. A foreign MCP entry is a terminal block with no force-replace path anywhere in the
   surface.

   Repository commitment, grant state, migration state, composed policy, and the authority digest
   all come from the trusted service; the interface originates none of them.

   Connection display is true when any discovered installation is FinishUP-owned. Discovery order
   has no authority: a different first binary cannot make an owned `codex-testing` registration
   render as disconnected.

6. **A digest-bound apply replaces, and is stricter than, the `--accept` shortcut.**
   `setup.apply_codex_integration` requires the caller to echo back both the preview digest and
   the policy digest it displayed. It re-previews and refuses as `preview_stale` when either has
   moved — the same staleness gate `integrate mcp install --preview-digest` already enforces —
   and only an explicitly echoed policy digest activates policy trust. `--accept` is unchanged
   and still declines to activate policy trust at all.

7. **No secret ever reaches a widget.** When a credential or passphrase is required, the
   interface asks for explicit consent, then *suspends itself* and hands the controlling terminal
   to the existing ceremony in `src/finishup/cli/unlock.py`, which opens `/dev/tty`, verifies it is
   the controlling terminal, and disables echo itself. No secret byte can enter the widget tree,
   the transcript, a log line, a config file, an event payload, MCP context, or a test snapshot.
   Where the environment cannot suspend, the interface says so and names the command that runs
   the same ceremony directly; it does not fall back to typing a secret into the window.

8. **Rendering is pure, and the vocabulary is fixed.** `src/finishup/tui/render.py` is a function
   from value objects to lines of text with no rendering-framework import, so safety-relevant
   wording is snapshot-tested byte for byte and narrow-terminal behaviour is asserted at any
   width without a terminal. The six status symbols (`›` selected, `•` active, `✓` verified,
   `!` unproven or limited, `■` blocked, `○` not configured) and their colours are defined once
   in `src/finishup/tui/symbols.py`. `✓` is reachable only from a layer the owning service reported
   as verified.

9. **Readiness layers are never collapsed.** Harness detected, MCP registered, MCP verified,
   plugin installed, hooks installed, project consent active, policy digest trusted, local
   service reachable, vault ready, provider binding saved, credential stored, provider transport
   tested, AI-powered evaluator composed, machine privacy ceiling permits review, exact repository
   grant active, and AI-powered review ready
   each render as their own line with their own certainty. A stored provider binding is never
   rendered as a working provider, and an unavailable deeper review is rendered as a limitation.

10. **Bounded failures keep the interface open (restates ADR-013 decision 4).** A `ControlError`
    or bounded runtime failure becomes a transcript event carrying the same reason code the
    corresponding command would print, with technical details behind `D`. Ceremony cancellation
    renders as cancelled. `Esc` never means approval; `Ctrl+C` closes a temporary view before it
    interrupts work, and interrupts work before it leaves.

## Framework choice

**Textual 8.2.8**, pinned, as a required runtime dependency.

The requirement list — full-screen rendering, responsive resize, keyboard input, scrollable
history, a pop-up/bottom-pane view stack, styled text, secret input, searchable selection lists,
testable rendering, cross-platform support — was evaluated against Textual, prompt-toolkit, and
urwid.

Textual is the smallest option that supplies all of them without the project writing its own
layout, scroll, and view-stack machinery. Three properties decided it:

- **Testability.** `App.run_test()` drives real keystrokes through a headless pilot, which is
  what makes the input-safety rules in this ADR assertable rather than aspirational. The
  interaction tests in `tests/tui/` press the actual keys.
- **Suspension.** `App.suspend()` gives the controlling terminal back cleanly, which is what
  makes decision 7 possible without reimplementing the confidential ceremony.
- **Marginal dependency cost.** `rich` and `platformdirs` are already in the tree; Textual adds
  `textual`, `linkify-it-py`, `mdit-py-plugins`, and `uc-micro-py`, all MIT, all already passing
  the reviewed-license allowlist in `tests/packaging/test_dependency_lock_and_licenses.py`.

prompt-toolkit adds fewer packages (`prompt-toolkit`, `wcwidth`) but supplies none of the view
stack, scroll, or resize behaviour, and its testing story would not have let this ADR's keyboard
rules be tested at the keystroke level. urwid is maintained but has a weaker style and testing
surface for no dependency saving.

The dependency is required rather than optional because bare `finishup` is the default human entry
point; decision 4 keeps a missing renderer from being fatal.

The stylesheet is a Python string in `src/finishup/tui/styles.py` rather than a `.tcss` file: the
wheel contract in `tests/packaging/test_wheel_and_sdist_contents.py` allows package Python and
reviewed resources under `finishup/resources/` only, and a stylesheet is not worth the resource
manifest machinery that would make it one.

## Consequences

A nontechnical user can run `npx finishup` and finish setup without meeting the words MCP, hook,
digest, vault, or binding. The honesty model gets *stronger* rather than weaker: readiness that
used to be prose is now fifteen independently falsifiable lines, the approval preview can no
longer scroll away from the question it belongs to, and the wording of every safety-relevant
screen is locked by snapshot.

The costs are real and bounded. Four new runtime packages enter the distribution. There is a new
module tree to maintain, though it holds no security logic. And the interface can only show what
the services expose — see the limitations below.

Scripts, CI, and pipes see nothing new at all.

## Known limitations

These are recorded rather than papered over, because the interface must not imply capability the
system does not have.

- **No task index exists.** The control protocol has no task-listing operation, and this ADR does
  not add one — the six canonical operations are unchanged. `/work` therefore opens a task by the
  title the agent used, via `start` in attach mode, and says plainly that no browsable index is
  available. Adding one would be a protocol decision, not a presentation one.
- **No bounded provider probe exists.** The local service exposes no live provider test, so
  `/provider` reports that a connection test is unavailable rather than reporting a pass. The
  `provider_transport_tested` layer is consequently never verified in this build. This is the
  intended failure mode: a test that cannot run is not a test that succeeded. `/provider` does
  expose Codex subscription status, disconnect, rollback, and optional account switch, and
  recomposes the service after a binding mutation.
- **Privacy widening is selected here and authorized only in the trusted terminal.** `/privacy`
  shows the current posture and the one recommended policy — Private without current eligible
  exact-route evidence, Assisted review with it — together with what accepting it costs, then offers exactly
  `Keep current`, `Review recommended change`, and `Other privacy options`. Choosing anything but
  `Keep current` suspends the interface and hands the decision to the trusted CLI ceremony, which
  renders the complete `before → after` policy diff, reauthenticates, and commits.

  For a repository with no grant, the diff may contain both a machine-ceiling change and insertion
  of the first repository row. They are one authority-digest-bound transition; the interface never
  presents either half as already effective. Eligible legacy carry-forward is separately labeled as
  bounded no-reapproval narrowing, and new repositories after its entitlement remain Private.

  The interface takes **no approval of its own.** An earlier revision rendered a disclosure preview
  and took an explicit "yes, allow this" here, and then handed off to a second, differently worded
  approval in the trusted terminal. Only the second one gated anything; the first was a consent
  ritual in an untrusted surface, which is precisely the habit this ADR's trust boundary exists to
  avoid teaching. Removing it also removed the drift it enabled: this screen listed profile-shaped
  labels ("Minimal external review") while the CLI listed recipe names, so the same policy had two
  names depending on where you met it. `Other privacy options` now lists the CLI's five recipe
  names verbatim — Private, Metadata only, Assisted review, Expanded review, Custom.

## Alternatives considered

**Keep the ADR-013 prompt loop and improve its wording.** Rejected: the three problems in the
context section are structural. Layered readiness, a preview that stays adjacent to its approval,
and a fixed certainty vocabulary all need a surface that can hold two regions at once.

**Ship the interface as an optional extra (`finishup[tui]`).** Rejected: bare `finishup` on a terminal
is the default human entry point, and an install whose default experience depends on an extra the
user did not know to ask for is worse than the four packages. Decision 4 covers the case the
extra was meant to cover.

**Let the interface collect secrets in a password field and forward them.** Rejected outright.
A hidden `Input` still puts secret bytes in widget state, the render tree, and anything that
serialises either. Suspension keeps the existing ceremony's `/dev/tty` and echo-disabling
guarantees exactly as they are, which is the only version of this that is worth having.

**Have the interface own privacy widening and provider probing directly.** Rejected for the same
reason ADR-013 rejected inline privacy editing: these are trusted-local decisions with their own
ceremonies, and a friendlier path to them is a weaker path to them.

**Keep an approval step in the interface as "informed consent before the handoff."** Rejected. Two
approvals for one decision do not make it twice as considered; they make the first one a formality
the user learns to click through, and the formality lives in the surface that cannot authenticate
anyone. The exact change and the authorization belong in the same place, and that place is the
trusted terminal.
