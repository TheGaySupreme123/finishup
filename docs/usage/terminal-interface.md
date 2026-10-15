# The FinishUP terminal interface

Running `finishup` at a terminal opens a full-screen interface: a compact session header, a
scrollable record of what FinishUP did, and a composer at the bottom where you type commands. When
FinishUP needs an answer, a temporary view takes the composer's place; dismissing it puts your
half-typed line back exactly as it was.

There is no settings dashboard, no sidebar, and no page counter. Every command is something the
`finishup` command tree already does, named in ordinary words.

See [ADR-017](../adr/ADR-017-full-screen-terminal-interface.md) for the decision and its limits.

## When it opens — and when it does not

The interface opens **only** when all of these hold:

- stdin and stdout are both real terminals;
- `TERM` is set and is not `dumb`;
- no CI marker is set (`CI`, `CONTINUOUS_INTEGRATION`, `BUILD_NUMBER`, `GITHUB_ACTIONS`,
  `GITLAB_CI`, `TEAMCITY_VERSION`);
- `FINISHUP_TUI` is not `0`;
- the invocation is a bare `finishup` or `finishup menu`.

Everything else behaves exactly as it did before: pipes, redirects, CI, `finishup --help`, `--json`
output, every named subcommand, `finishup mcp serve`, and the protocol fixtures. A bare `finishup` with
a redirected stream still prints help.

Set `FINISHUP_TUI=0` to always get the prompt-loop menu instead. If the rendering dependency is
missing from an installation, FinishUP falls back to that menu on its own rather than failing.

## Reading the screen

Six symbols carry all of FinishUP's certainty. They mean exactly what they say:

| Symbol | Meaning |
|---|---|
| `›` | the item your cursor is on |
| `•` | something is happening right now |
| `✓` | **verified** — a postcondition was actually observed |
| `!` | a warning, a limitation, or a state that was never proven |
| `■` | a failure, or a safety boundary that stopped an action |
| `○` | optional, disabled, or not configured |

`✓` is never used for "configured". Saving a provider binding earns `✓ Provider binding saved`
and, in the same breath, `! Live provider connection has not been tested`, because those are two
different facts and only one of them was checked.

## Keys

```text
Up / Down       move through options
Enter           confirm or select
Esc             go back, cancel, or close the current view
1 to 9          pick a numbered option
/               open the command list
?               show shortcuts
D               show technical details where they are offered
Ctrl+C          close the current view, or interrupt running work
Page Up/Down    scroll a long list or the history
Home / End      jump to the first or last option
```

Three rules are guaranteed, not conventions:

- **`Esc` never approves anything.** Dismissing an approval means nothing changed.
- **Printable keys never trigger shortcuts while you are typing.** In a search box or a text
  field, `1` and `d` are characters.
- **Disabled options cannot be chosen** — not by arrow key and not by number.

## First run

The first `finishup` on a new machine walks a linear path, each finished step collapsing into a short
line above the active one:

1. **Welcome and detection.** What FinishUP found: your agent installation, your project, whether
   system secure storage is available, and whether FinishUP is connected yet.
2. **Which installation** — only if more than one was found. Friendly names first; the executable
   path appears when the row is selected, and in full under `D`.
3. **Project trust.** The canonical Git common root, and what allowing project-local guidance and hooks
   actually permits. If you started FinishUP in a subfolder, it says so and names the root the trust
   applies to.
4. **The exact proposed change**, in words, with a `Safety` block stating what will *not* happen.
   `D` shows the executable path, managed paths, MCP command, preview digest, policy digest, and
   planned file count. When the change also rewrites or removes an existing entry (a review-route
   change, a registration under the former Yoetz name, an earlier Yoetz plugin activation and its
   cache versions, or Yoetz-era plugin or skill folders), each one is listed as a `~` line before
   you approve.
5. **Installation activity**, step by step. A step is only reported as done once its postcondition
   was checked.
6. **Secure storage** — system keyring (macOS Keychain, or a running Secret Service on Linux),
   or a FinishUP passphrase entered on the trusted terminal (masked, re-prompted, 16–1024 UTF-8
   bytes). When the keyring is unusable — no store loaded, or a backend FinishUP does not approve for
   the vault — the option is disabled with that reason and the passphrase is offered. Change it
   later with `/service` or `finishup service rotate-passphrase`.
7. **Review mode** — Local only, or Add AI-powered review.
8. **AI-powered review setup, when selected** — an explicit choice between OpenAI API / compatible
   API and Codex with ChatGPT subscription, followed by the matching secure API-key or Codex-owned
   login flow and the trusted recommendation-first privacy ceremony.
9. **Finish**, with each readiness layer stated separately.

You are never required to configure a provider: Local only is complete and useful. If you choose
AI-powered review, setup does not claim completion until provider credentials and privacy approval
finish.

If an MCP entry named `finishup` already exists and FinishUP does not own it, setup stops there. You can
inspect it, continue locally, or read manual resolution steps. **There is no force-replace option
and there will not be one.**

## Commands

Type `/` to open the filtered command list.

| Command | Does |
|---|---|
| `/status` | show setup, readiness, and current work |
| `/work` | open a task by title to view claims, evidence, and findings |
| `/findings` | show the open task's findings as a to-do list, each with its state |
| `/check` | run a verification check |
| `/progress` | show the latest check's review phase and elapsed time |
| `/receipt` | view or export an honest receipt |
| `/connect` | connect or repair an agent integration |
| `/privacy` | choose what may leave this computer |
| `/provider` | configure optional deeper review |
| `/service` | manage the protected local service |
| `/observe` | show observation selection and change local retention capacity |
| `/doctor` | diagnose installation problems |
| `/help` | show what FinishUP can do here |
| `/quit` | leave FinishUP |

### `/status`

Reports each readiness layer separately, because they can and do disagree. `D` opens the full
list:

```text
Harness detected                    Local service reachable
MCP registered                      Vault ready
MCP verified                        Local checks
Guidance installed                  Provider binding saved
Structural hooks installed          Credential stored
Project consent active              Provider connection tested
Approved-check policy trusted       Deeper-review evaluator composed
                                    Privacy permits external review
                                    Privacy sends the task statement
                                    Deeper review ready
                                    Codex agent route permits deeper review
                                    Host auto-review admits the AI-powered check
                                    Background AI-powered advice
```

The last five are deliberately separate lines, because each can be true while the others are not:

- **Privacy permits external review** — the effective privacy policy for this repository allows
  external LLM inference. Unknown when the policy could not be read; its detail line carries the
  policy summary.
- **Privacy sends the task statement** — whether the policy lets your request, as the agent
  transcribed it, reach the reviewer. The detail is the sentence `finishup privacy show` prints;
  unknown when the policy could not be read. Whether a given task recorded a statement, and what
  the reviewer had in its place, is on that task's receipt.
- **Deeper review ready** — the installation reports `semantic_ready`: AI-powered review enabled, a
  bound provider with a stored credential, a policy that permits inference, and an exact grant for
  this repository. Configured, not proven working. Otherwise the detail says external review is
  off.
- **Codex agent route permits deeper review** — whether the registered Codex MCP route can dispatch
  AI-powered review. A route registered as `strict` is verified installation-side and still shows
  here as not permitting review, with the command that changes it; unknown when the registration
  could not be read.
- **Host auto-review admits the AI-powered check** — whether at least one host's automatic reviewer
  has been admitted for this repository; the detail names each host as present or absent, and a
  stale admission that outlives its grant or route is called out for revocation.
- **Background AI-powered advice** — whether AI-powered advice between checks is switched on, and
  why. It is on by default wherever AI-powered review is configured; the detail names the
  `[observation]` setting that turns it off, or turns it back on after you switched it off. When
  on it is still shown as unproven, because it runs only while a provider is usable.

"Connected" is never a substitute for any of these. If the privacy policy could not be read,
`/status` says so rather than claiming nothing is leaving your computer.

### `/connect`

Inspect the current connection, connect or repair it, or view the exact technical state. Any
action that would change something shows the same preview and approval the first run does. When a
newer package is available under the durable `update_checks` policy, `/connect` offers upgrade
first or continue with the running version before harness add/repair — it never reinstalls the same
package bits to add a harness.

### `/privacy`

Shows where privacy stands and the one recommended policy — **Private** without current eligible
exact-route provider evidence, **Assisted review** with it — with both what accepting it buys and what it costs.
Then three choices: **Keep current**, **Review recommended change**, and **Other privacy options**.
The last lists the same five names the command line uses: Private, Metadata only, Assisted review,
Expanded review, and Custom. If the current policy already matches the recommendation, it is not
offered as a change.

The posture is for the repository derived by the service from the interface session's actual working
directory. Branches and linked worktrees share the Git common root; independent clones do not. The
screen shows machine ceiling, exact repository grant, and legacy migration state separately, and
whether the task statement is sent. It never uses task `workspace_ref` as privacy scope.

This screen selects; it never authorizes. Choosing anything but *Keep current* suspends the
interface and hands the controlling terminal to `finishup privacy setup`, and that trusted ceremony is
where the exact `before -> after` policy diff is rendered, where reauthentication happens, and where
a widening is actually approved. If the terminal cannot be handed over, nothing changes and the
interface prints the command to run.

A first repository grant may preview both a machine-ceiling widening and insertion of the exact
repository row. They commit atomically against one authority digest. Eligible legacy carry-forward
is shown as bounded automatic narrowing; later repositories remain Private.

Tightening also goes through that handoff, and commits only after an ordinary explicit
confirmation.

### `/provider`

Choose a preset — OpenAI, Fireworks AI, Anthropic, Google Gemini, OpenRouter, Grok (xAI), Vercel
AI Gateway, or a custom OpenAI-compatible HTTPS endpoint — or choose **Codex with ChatGPT
subscription**.
The same command also offers Codex subscription **status**, **disconnect**, **rollback**, and
**switch account**. FinishUP shows the endpoint/runtime and privacy posture before asking for an API
key or opening Codex login, and states plainly that storing a binding does not switch external
review on.

API-provider keys are entered through the secure prompt described under *Secrets* below. For a
subscription, `/provider` asks for the exact Codex executable, dedicated evaluator home, model,
final-review reasoning effort, and routine-checkpoint reasoning effort; validates the supported digest-bound cell; shows destination, plan/terms notice,
privacy boundary, disconnect, rollback, and optional account switch; then suspends the UI while
Codex proves the existing sign-in or, when the home is not signed in, runs its browser flow. The
result says which of the two happened. OAuth credentials never pass through a widget or FinishUP
vault. After setup,
disconnect, or rollback, the local service is recomposed so a running daemon cannot keep the old
cell.

Afterwards FinishUP reports what it actually knows:

```text
✓ Provider binding saved
✓ API key stored securely
! Live provider connection has not been tested
! External AI-powered review is not yet proven ready
```

The subscription variant replaces the API-key line with `✓ Codex-managed ChatGPT login is
available`. Its status is a structural account/model read with no task case. Live AI-powered review
proof still requires a privacy-authorized `check` and terminal provenance/receipt.

**This build exposes no bounded live provider probe**, so a connection test reports itself as
unavailable rather than reporting a pass. A provider that fails never affects local-check
readiness.

### `/work`, `/check`, `/receipt`

`/work` opens a task by the title the agent used and shows its claims, evidence count, checks,
coverage, findings, limitations, and whether a receipt is available. **FinishUP has no browsable
task index** — the local service exposes no task-listing operation and this interface does not
invent one — so tasks are reached by name.

`/check` offers three modes, mapping to the existing check modes: use deeper review when
available, require deeper review, or local checks only. An unavailable deeper
review is reported as a limitation, never as a success. While a check with deeper review is
running, its line shows the review phase, attempt, elapsed time, and time left before the fixed
deadline, refreshed every few seconds. `/progress` reads the latest check of the open task again,
including after the result arrives. Progress names phases only; it is not evidence that the
review is correct.

`/findings` lists every finding of the open task as one to-do item with its state: `[ ]` open
(with review rounds against the budget, for example `(2/5)`), `[x]` verified resolved, `[~]`
acknowledged, not done, and `[-]` rejection accepted. It reads the same `status` findings view the
agent sees, verified items included.

`/receipt` produces Markdown, plain text, or JSON. The readable view leads with the verdict, then
coverage, open findings, limitations, whether deeper review contributed, freshness, and — always
— what was *not* verified. It then asks which receipt you want. *The receipt your agents see*
withholds the repository file names your privacy policy keeps from agents. *Your full receipt*
hands this terminal to a secure prompt where you confirm it is you, and shows the full receipt
once; nothing else changes. On a Mac a system dialog asks for Touch ID or your login password and
shows the confirmation code the prompt prints; elsewhere you enter a vault passphrase you chose. If
FinishUP cannot confirm it is you on this installation, or another confirmation is already open, it
says so and shows nothing.

### `/service` and `/doctor`

`/service` shows state and offers unlock, passphrase setup, change passphrase, lock, and stop.
Stopping asks for confirmation with the cursor on *no*. Change passphrase uses the same trusted
terminal handoff as first-time setup: input is masked with `*`, the helper states the 16–1024
UTF-8 byte contract, and it re-prompts after invalid or mismatched input. The shell equivalent is
`finishup service rotate-passphrase`.

`/doctor` runs bounded read-only checks across runtime, package version, installation folders
(FinishUP folders, an isolated root, or Yoetz-era folders used in place, which must be kept), the
platform cell
(certified, or untested such as Linux aarch64), the approved-check sandbox (Seatbelt on macOS,
bubblewrap on Linux, with the install step named when it is missing or blocked), system secure
storage (with the reason when it is unusable), discovery, registration, managed files, hooks,
consent, policy digest, service reachability, vault, provider, and privacy, then suggests safe
next steps. When policy permits package update checks and a newer release is
known, the package line is optional with remediation `finishup upgrade` (`yoetz upgrade` on an
installation upgraded through the transitional `yoetz` package, where only `yoetz` is on `PATH`);
when the check is allowed but fails, the line is unproven with "could not check for updates." When
FinishUP finds folders under both its current and its former name, the installation folders line
is blocked with the [upgrade guide's remedy](upgrading.md#if-something-refuses-after-the-rename)
and the checks that would need those folders are skipped. **It never changes anything.**

### `/observe`

`/observe` shows the selected and effective observation detail and capacity for the current
workspace, the effective budget (which limit is closest to full), and whether No FinishUP cap is
available. It then asks **Change local retention capacity?** with the cursor on keeping the
current setting. The other options are recommended (512), larger (2,048), largest (8,192), custom
(type a queue count from 64 to 8,192), and No FinishUP cap. A choice changes the workspace default and
keeps the current detail mode.

Before anything changes, `/observe` shows the current and proposed values, the scope, the possible
disk, memory, and CPU cost, what stays limited, and how to lower it, pause new observation ingest,
and resume it, then asks you to apply or cancel. An increase also says that the shared workspace
queue follows the largest active selection, so it can raise the queue and state-document bounds for
every session in the workspace. The commands it shows use `<workspace>` and `<session-id>`
placeholders rather than your typed path. Cancelling or `Esc` changes nothing and says so. No FinishUP
cap is not available for this queue: choosing it explains the 16 MiB state-document ceiling, names
the largest supported capacity, and changes nothing. See [Observation
selection](observation-selection.md) for the limits and the equivalent `finishup observe` commands.

## Secrets

FinishUP never accepts a secret through this window.

When a credential or passphrase is needed, the interface explains what is about to happen and asks
for explicit consent. On approval it **suspends itself** and hands the terminal to the existing
confidential ceremony, which opens the controlling terminal directly, turns off echo, and masks
accepted input with `*`. Invalid or mismatched passphrases are overwritten and re-prompted; they
are not accepted. What you type there goes straight into the local vault.

No secret byte can reach the transcript, the interface's state, a log, a config file, an event
payload, MCP context, or a screenshot — because no secret byte ever enters this process's UI at
all.

If your environment cannot suspend, FinishUP says so and names the command to run instead. It does
not offer to take the secret through the window as a fallback.

For an operation-specific next command outside the interface, run
`finishup setup status --next --operation local|review|connection` with the same selected project,
host executable and configuration root. Local setup does not require a provider; connection-only
setup does not require provider sign-in. AI-powered review needs the provider binding before its
repository privacy grant. Secrets still belong only in the trusted terminal ceremony. See
[setup order and recovery](install-and-first-run.md#find-the-next-setup-step).

`finishup setup vault` initializes or unlocks only the selected installation's storage using the
existing protected terminal ceremony. It diagnoses credential-store availability, retains the
explicit passphrase fallback where needed, and stops before provider selection or privacy grants.
It requires a local interactive terminal; agents show that continuation without supplying secrets.
