# Install and first run

Choose an installed Codex, Claude Code, Cursor IDE or Cursor Agent CLI, select your project and
review mode, then approve the connection preview. Yoetz handles each agent's installation steps
and tells you when a fresh session or a local authentication prompt is needed. Exact installation
details remain available when you need them. The desktop platforms are macOS, Linux, and Windows
through WSL 2; this does not add native Windows or mobile support.

Use `/connect` to connect or repair and `/disconnect` to remove an integration while retaining
your Yoetz data. From a terminal, `yoetz setup run`, `yoetz setup status`, and
`yoetz setup disconnect --host codex|claude|cursor-ide|cursor-cli` expose the same lifecycle.
The [Codex](../runbooks/codex-integration.md), [Claude Code](../runbooks/claude-code-integration.md)
and [Cursor](../runbooks/cursor-integration.md) runbooks retain version/platform evidence and
operator details. Configuration success alone does not prove a fresh host session is connected.

## Install

For guided setup, click **Set up with your agent** on [yoetz.dev](https://yoetz.dev).
The popup confirms the instruction was copied. Paste it into your agent’s chat, then send it
to start setup.
The **Install with PyPI** and **Install with npm** buttons show the copied command in the popup:
paste it into your terminal, then press Enter.
After the PyPI installation finishes, run `yoetz` in your terminal to start setup.
The npm command, `npx yoetz`, starts setup directly.

Install the latest published version through Python via [`uv`](https://docs.astral.sh/uv/):

```text
uv tool install --managed-python --python 3.14.6 yoetz
yoetz
```

**Python.** Yoetz needs Python 3.14 and `uv` provides it: with `--managed-python` it downloads
the exact interpreter on demand, so it does not matter which other Pythons are installed, which
one `python3` resolves to, or whether pyenv, Homebrew, or a system Python is on your `PATH`. The
install is unaffected by them and touches none of them. Only two configurations block it, and both
say so in the error: `uv` configured never to download Pythons (`python-downloads = "never"`), and
`uv` configured to use system interpreters only (`python-preference = "only-system"`) on a machine
without 3.14. `pip install yoetz` or `pipx install yoetz` on an older Python cannot work; the
package requires 3.14, and a pip that resolves it anyway is not installing Yoetz.

**Git.** Yoetz reads your repository with the system Git, the first `git` in `/bin` or
`/usr/bin`, never one that only your shell's `PATH` puts first (a conda or Homebrew Git, for
example). That Git must be 2.25 or later, the Git of Ubuntu 20.04; the Xcode Command Line Tools
and every current Linux distribution ship a newer one. With an older system Git, Yoetz names the
cause instead of failing obscurely: commands run inside a repository report
`service_handshake_failed` with the Git requirement, `yoetz state capture` reports
`git_version_unsupported`, and a check discloses
`check_time_change_unavailable_git_version_unsupported`. Upgrade the system Git, then retry;
restarting the service does not help. A directory that is not a Git repository needs no Git.

**Where it lands.** `uv tool install` places the `yoetz` command in `~/.local/bin`. If a new
terminal cannot find it, run `uv tool update-shell` once and open another terminal.

Yoetz refuses to run from files another account could change, because your agents would then
launch a program someone else can replace. A file only you can write is fine. A file your *own*
group can write is also fine when that group is yours alone: Ubuntu, Debian, Fedora and RHEL give
each account a private group of the same name and a umask of `0002`, so an ordinary `uv tool
install` there works as is (on a machine whose accounts come from a directory service such as
LDAP or SSSD, Yoetz cannot prove the group is yours alone and treats it as shared; use the
`umask 022` below). A file writable by everyone, or by a group someone else belongs to (a
shared `venv`, Homebrew's `/opt/homebrew`, or a `users` group), is refused. The service, the agent
connection (MCP) and the hooks then stop with `release_runtime_group_writable` or
`release_runtime_world_writable`, and `yoetz service run` in a terminal prints the exact repair
for your installation, of the form

```bash
chmod -R go-w ~/.local/share/uv/tools/yoetz ~/.local/share/uv/python/cpython-3.14.6-<platform>
```

To keep a later reinstall private from the start, run `umask 022` in that shell before
`uv tool install`.

`uvx --python 3.14 yoetz` works for a one-off run, but do not connect an agent from it: a one-off
run lives in `uv`'s cache, and connecting an agent binds the agent to that exact launcher. If you
are a coding agent installing Yoetz on a user's behalf, follow [Agent start](agent-start.md)
instead — setup's questions require the human's own terminal. With `uv` already installed,
`npx yoetz` makes the same persistent `uv tool install` (a no-op when it is already there) and
then runs that exact version, so the `yoetz` command lands in `~/.local/bin` (see above if a new
terminal cannot find it) and agents connected from `npx yoetz` keep working after
`uv cache clean`. The launcher passes arguments
through unchanged, inherits stdio so the child sees your real terminal, and propagates exit codes
— including `128+n` for a signal. It bundles and downloads nothing itself: when `uv` is missing it
prints the install command and stops.

Compatibility extras (the standard install already contains these exact dependencies):

| Extra | Adds |
|---|---|
| `semantic-openai` | Existing install-command alias for the HTTP client and OpenAI SDK |
| `portable-recovery` | Existing install-command alias for Argon2 recovery/passphrase support |

## Find the next setup step

Run `yoetz setup status --next --operation local` from your project for local-only use,
`--operation review` for AI-powered review, or `--operation connection` to connect an agent
without provider sign-in. Add `--host codex|claude|cursor-ide|cursor-cli`, `--host-path`,
`--host-config-root`, and `--project` to inspect a specific installation. For Codex,
`--codex-path` and `--codex-home` are also accepted. `--json` returns the same next command.
This read-only check does not start services, unlock the vault, grant permission, or activate a host.

Follow the displayed command, then rerun status. Local use needs a running service, an initialized
and unlocked vault, and repository privacy setup. AI-powered review additionally needs a provider
binding before approving a provider-backed privacy recipe; run `yoetz --set` to configure one.
The connection-only path checks the selected host without requiring a provider or a vault login.
Use the command exactly as displayed: it retains the selected Yoetz installation and project.

`yoetz setup vault` initializes or unlocks only the selected installation's storage using the
existing protected terminal ceremony. It diagnoses credential-store availability, retains the
explicit passphrase fallback where needed, and stops before provider selection or privacy grants.
It requires a local interactive terminal; agents show that continuation without supplying secrets.

If a service-dependent approval reports `ceremony_service_unavailable` before it is claimed,
start the selected service and inspect `yoetz consent status`; the same unexpired pending decision
can be retried. If the service fails after the approval was claimed, the attempt is consumed and
requires fresh preparation. Denial, cancellation, expiry, and target checks still apply.
`--accept` does not approve unseen activation: `activation_confirmation_required` includes the
exact `recommend accept codex-plugin-activation` command with the selected executable and home.

For Codex inspection, plugin status, MCP status, provider status, and setup disconnect all accept
`--codex-home`.
Selection is explicit flag, then `CODEX_HOME`, then `CODEX_TESTING_HOME`, then `~/.codex`.
The payload's `inspected_codex_home` names the selected home; invoked Codex commands receive both
home variables set to it. Use that same explicit home for removal and reconnection. A foreign
configuration is preserved. To use a separate installation, create a fresh directory owned only
by you (mode 0700) and select it with `--host-config-root` (or legacy `--codex-home`). A project
marketplace conflict still requires inspecting the project; changing the home does not fix it.

## Linux

Yoetz runs on macOS and Linux. The certified cells are macOS 11 or later on Apple silicon and
glibc 2.28 or later Linux on x86-64. The package also installs on other Linux architectures, such
as aarch64 (Raspberry Pi, Graviton, Asahi, or WSL on a Windows-on-ARM laptop); those installs are
untested, not presumed compatible: `yoetz version --json` lists `platform_cell_untested` under
`limitations`, `yoetz setup status --json` reports the cell, and `/doctor` shows the platform line
as *not proven*. Nothing is refused there, and nothing is claimed either.

Three things on Linux differ from macOS, and each is reported once, up front, by `/doctor` and
`yoetz setup status --json` rather than discovered later:

- **Approved checks that deny network need bubblewrap.** Install it before trusting a check
  policy (Debian and Ubuntu: `sudo apt install bubblewrap`; Fedora: `sudo dnf install
  bubblewrap`). Without a usable `bwrap`, every network-denied check is rejected as
  `sandbox_unavailable`. Ubuntu 24.04 and later restrict unprivileged user namespaces through
  AppArmor: use the distribution package, which ships the profile that permits `bwrap`; if a
  hand-built copy still fails, `/doctor` says `bwrap_unusable` and names the sysctl to relax.
  Sandbox readiness is a fact about the computer that runs your checks, so exactly three
  places answer it: `/doctor`, `yoetz setup status --json`, and
  `yoetz observe checks status --json` (per workspace). `yoetz service status` reports the
  local service itself and stays silent about the sandbox.
- **System secure storage needs a running Secret Service.** The "system keyring" choice at setup
  means macOS Keychain on macOS and, on Linux, a Freedesktop Secret Service on your session bus
  (GNOME Keyring, or KWallet through its Secret Service bridge). Headless sessions, servers, and
  WSL usually have none. Setup then disables that option, states the reason, and offers a Yoetz
  passphrase, which is the supported route there.
- **State stays on a local disk.** A state directory on a network or cross-machine filesystem
  is refused with `path_on_network_filesystem`; the message names the safe location.

## Windows

Yoetz runs on macOS and Linux. On Windows it runs inside WSL 2 (Windows Subsystem for Linux),
Microsoft's supported way to run Linux programs on Windows. A native Windows install succeeds, but
every command except `yoetz version`, `--version`, and `--help` then refuses with
`unsupported_platform` and points here.

1. Open **PowerShell as administrator** and run `wsl --install`. Restart Windows when asked.
2. Open **Ubuntu** from the Start menu. The first launch asks you to choose a Linux username and
   password.
3. Inside that Ubuntu window, install `uv`, then Yoetz:

   ```text
   curl -LsSf https://astral.sh/uv/install.sh | sh
   source "$HOME/.local/bin/env"
   uv tool install --managed-python --python 3.14.6 yoetz
   yoetz
   ```

Everything else on this page happens inside that Ubuntu window, including `yoetz service run` and
the steps that need your own terminal. Installing the Cursor or Claude Code plugin is one of
those steps: on Linux and inside WSL 2 it asks for your Linux account password in that terminal
(the one you chose at first launch) before it changes anything, where macOS shows its own
authentication dialog instead. A coding agent driving the install from the Windows side
can run each command with `wsl -e bash -lc "..."`. Connecting a Windows-native Codex, Claude Code,
or Cursor to a Yoetz inside WSL is untested and not claimed: connect from the same WSL
environment, or keep Yoetz local-only through the CLI.

Inside WSL, the [Linux](#linux) notes above apply, with these specifics:

- **Keep Yoetz on the Linux filesystem.** Install and run it from your WSL home. Windows drives
  under `/mnt/c` and the other drive letters reach Linux through a transport (`9p`, `drvfs`, or
  `virtiofs`) whose locking and durability Yoetz has not certified, so a state directory there — including one
  named by `YOETZ_ISOLATED_ROOT` — is refused with `path_on_network_filesystem`. Your projects
  can live on a Windows drive; Yoetz's own state cannot.
- **Choose a Yoetz passphrase.** A default WSL session has no Secret Service, so system secure
  storage is unavailable and setup says why.
- **Install bubblewrap** (`sudo apt install bubblewrap`) before trusting a check policy whose
  checks deny network.
- **Windows-on-ARM laptops** run an aarch64 Ubuntu, which is an untested platform cell (see
  [Linux](#linux)); Yoetz installs and says so.
- **Claude Code and Cursor plugins** need a supported approval mechanism. Inspect the plugin
  preview: Linux-capable builds name PAM through the trusted terminal and ask for your Linux
  account password there. Builds without Linux approval support refuse
  `human_authority_unavailable`. Linux and WSL native host coverage remains unproven; both hosts
  can use Yoetz over MCP with a `yoetz mcp serve` entry in their own configuration.

## First run

The first bare `yoetz` on an interactive terminal opens the full-screen interface in first-run
mode ([ADR-017](../adr/ADR-017-full-screen-terminal-interface.md), amending
[ADR-012](../adr/ADR-012-first-run-setup-wizard.md)). Every non-interactive invocation — CI,
pipes, redirected streams — prints help instead, exactly as before.

Setup is a linear path inside the interface, each finished step collapsing into a short line:

1. **Detection.** Installed Codex, Claude Code, Cursor IDE and Cursor Agent CLI, your project and its canonical Git common
   root (or resolved non-Git directory), whether system secure storage is available, and whether
   Yoetz is connected yet.
2. **Which installation**, when several supported agents are found. Select your preferred agent
   in the same setup flow. Friendly names lead;
   executable paths appear on selection and under `D`.
3. **Project trust.** The repository root and what project-local guidance and hooks are permitted
   to do. Starting in a subfolder is called out, with the root the trust applies to.
4. **The exact proposed change** — a discoverable project skill under `.agents/skills/yoetz`,
   managed plugin/hook source files under `.agents/plugins/yoetz`, the `yoetz mcp serve` MCP
   registration, bounded structural event recording, and the approved-check policy digest — plus
   what will *not* happen. Nothing is applied before an explicit approval, and the approval is
   bound to the exact preview and policy digests that were displayed: if either has moved, the
   apply refuses as stale rather than proceeding.
5. **Installation activity**, with each step reported only once its postcondition was checked.
6. **Secure storage** — the system keyring (macOS Keychain, or a running Secret Service on
   Linux; see [Linux](#linux)), or a Yoetz passphrase. When the keyring is unusable the option is
   disabled with the reason stated. A passphrase is entered on the
   trusted terminal: input is masked with `*`, must be 16–1024 UTF-8 bytes with no control
   characters, and the helper re-prompts after invalid or mismatched input. Later changes use
   `yoetz service rotate-passphrase` (or **Change the passphrase** under `/service`).
7. **Review mode** — finish in complete local-only mode, or configure AI-powered review.
8. **AI-powered review setup, when selected** — provider/model, hidden API-key entry, then one exact
   recommended privacy policy. **Assisted review** is recommended only for an exact provider route
   with current reviewed no-training evidence and retention no longer than 30 days; it is bounded
   to the current repository and does not re-prompt for ordinary attempts after approval. Branches
   and linked worktrees share that grant; an independent clone does not. Otherwise
   **Private** is recommended. Accepting it asks nothing
   further; declining it opens the named recipes, and only **Custom** opens the settings
   themselves, in five grouped sections. The exact disclosure and separately reauthenticated
   widening decision remain mandatory.
9. **Finish**, stating each readiness layer separately. When the durable privacy policy permits
   package update checks (product default: on) and a newer `yoetz` release is available on PyPI,
   the finish screen appends a short tip with the installed version, available version, and the
   exact upgrade command `uv tool upgrade yoetz`. Work receipts never carry update metadata.

On later interactive launches, the resume tip may show the same package-update advisory instead of
the generic Codex tip when a newer package is available. `/doctor` reports the package line as
optional with the upgrade command when a newer release is known, or notes that a check could not
be completed when policy allowed the check but the registry was unreachable.

When re-running setup or `/connect` with the same installed package version and a newer release
available, Yoetz offers **upgrade first** or **continue with this version** rather than reinstalling
the same bits. Continuing still adds or repairs harness integration (project skill + structural
plugin sources + MCP) without a package reinstall. Yoetz never auto-upgrades.

Upgrading replaces package bytes without rewriting accepted machine privacy-policy bytes. Eligible
legacy authority may be automatically narrowed onto a bounded pre-upgrade repository route when its
trusted locator next arrives; when no route existed, one first-repository carry-forward is available.
Neither case asks again because no new repository gains authority. Every later repository remains
Private until approved.

**Network honesty:** zero-egress for task content remains the product promise. Structural package
version checks are opt-out network (disable `update_checks` in privacy setup). Non-interactive CLI,
MCP, CI, and pipes do not open that path as a surprise.

Credential status is presence-only. Human output shows the fixed mask `********` when the trusted
service confirms that the configured provider has a stored credential, `not stored` when absence
is confirmed, and `unknown` when the service or vault cannot answer. The mask is constant: it never
contains or encodes any character, length, prefix, suffix, or fingerprint of the API key.
When a credential is already stored for the exact provider/model, setup asks whether to reuse it
(the default) or replace it through a new hidden-input ceremony.

`codex mcp get` runs first; an existing foreign entry is always preserved, never replaced, and
there is no force-replace option anywhere in the interface.

Setup reports these activation layers independently. `installed_exact` at
`.agents/skills/yoetz` proves the reviewed project skill bytes are present, not that a running Codex
session loaded or followed them. `.agents/plugins/yoetz` proves only that Yoetz's managed plugin and
hook source files are present. Codex plugin activation requires a separate standing-trust flow,
which setup offers only through an exact digest-bound preview and explicit approval. The preview is
bound to the selected executable and its SHA-256, an explicitly selected existing absolute,
non-symlink Codex home, the executable's network-free `--version` result, repository marketplace and
home-config preimages/proposals, managed source digest, versioned cache target/digest, and the exact
post-consent `plugin list --marketplace yoetz --json` and `plugin add yoetz@yoetz --json` commands.
Before approval, the version probe forces both Codex home variables to a fresh owner-private
temporary home and removes its scratch afterward; it does not inspect inventory in the selected
home. After approval, both variables are forced to that selected home for list/add, whose possible
scratch, cache, config, and marketplace effects are included in the disclosed activation boundary.
Setup reports `active` only when canonical Codex
inventory says the repository plugin is installed and enabled and its versioned cache is byte-exact
to the managed source, in addition to exact marketplace/config state. MCP `registered` proves only
the separate configuration entry. Neither active inventory nor MCP registration proves a later
session loaded a hook or delivered an observation. A stopped service can prevent a later MCP call,
but it cannot explain a session that never discovered the skill or attempted a Yoetz tool.

Two different things are called a default here, and only one of them is a policy. The **seeded
policy** is `local_only`: every installation starts with external LLM disclosure denied, and
nothing moves it without a provider binding, a stored credential, and a separately reauthenticated
policy commit. The
**recommended answer** to first run's "How should Yoetz review work?" is AI-powered review, because
an installation that never reaches it can only ever report local-check coverage. Accepting the
recommendation opens those steps; it does not perform them, and local-only needs no provider and
stays one keystroke away. Setup is not marked complete if a chosen AI-powered review path's provider
credential or privacy decision is incomplete.

The official Codex App exists on macOS and Windows. Linux setup uses the same flow for the
standalone Codex CLI and does not fabricate an app installation that OpenAI does not publish.

Re-run any time with `yoetz setup run` (the prompt-driven wizard, unchanged) or `/connect` in the
interface. Change privacy any time with `yoetz --privacy`. Inspect posture read-only with
`yoetz setup status`. Manage registration directly with `yoetz integrate codex mcp
status|preview|preview-remove|install|remove`. Inspect or reverse marketplace activation with
`yoetz integrate codex plugin preview|status|remove` (cache purge is default-off); those three are
the whole Codex plugin command surface, and activation itself stays in `yoetz setup run`. See the
[Codex integration runbook](../runbooks/codex-integration.md) removal section.

## Re-run or repair a ceremony

The wizard uses these same commands and trusted boundaries; each remains available directly:

```text
yoetz service run                  # foreground service under a supervisor you choose
yoetz --privacy                    # recommended policy first; customize only when declined
yoetz privacy setup                # equivalent long-form command
yoetz provider endpoint            # bind a reviewed preset or owner-declared HTTPS origin + model
yoetz provider credential set      # provision the API credential through the terminal ceremony
```

`yoetz service run` runs in the foreground on purpose when invoked directly — you choose the
supervisor (launchd, systemd, a terminal). Interactive setup may use the bounded on-demand launcher.
Related: `yoetz service status`, `lock`, `unlock`, `initialize-passphrase`,
`rotate-passphrase`, `idle-relock`, `stop`; `restart` stops the running service — even one from
another installation — and starts this one; `isolation` reports the resolved identity roots and
isolation mode as path digests, without connecting to a service (a path digest names which file
is used, not its contents; add `--content-digests` to also fingerprint the selected config file's
bytes without revealing them); `diagnostics --correlation-id
<err_...>` resolves one durable owner-only diagnostic record by the correlation id printed with a
public error. Two sub-trees sit beneath it: `yoetz service auto-unlock status|enable|repair`
inspects or repairs restart-safe passphrase unlock after proving the current vault passphrase, and
`yoetz service recovery status|provision|rotate|revoke|export|import|restore` provisions and uses
installation-vault recovery without exposing secrets to agents. Passphrase setup and rotation mask
input with `*` and re-prompt invalid or mismatched values; they never accept a secret through a
flag, pipe, or the full-screen window.

A service that cannot start says why. `yoetz service run` names the failing stage and the kind of
error and prints a correlation id for `yoetz service diagnostics --correlation-id`; a command that
started the service for you (`yoetz service restart`, `yoetz setup vault`, `yoetz setup llm --set`,
`yoetz observe drain`) prints the same stage and id, and an agent whose session tried to start the
service receives `service_start_failed` with that stage and id instead of being told to start it
again.

## What a fresh installation does not do

An unconfigured installation is **provider-egress-free and local-only**. No task content is sent
to an external provider; the separately configurable structural package update check may still be
enabled. No provider is bound, no credential exists, and AI-powered review is unavailable — checks
run the local packs only and say so in their coverage vector.

That state is fully useful: the ledger, local checks, findings, and receipts all work. You
opt into external review deliberately, or never.

## More than one Yoetz on one machine

Your everyday installation is the **permanent** instance: it uses the platform's own application
directories and nothing else touches them. To try a change, reproduce a defect, or run a test
against a real installed Yoetz without disturbing that installation, create a separate instance
with its own root, service, and vault:

```text
yoetz instance create --root ~/.yz-try/state --lifecycle disposable --expires-in 8 --bind-runtime
yoetz instance status --json
yoetz instance dispose --root ~/.yz-try/state
```

`--bind-runtime` pins the Yoetz you ran to that root, so it keeps using its own state even when a
program starts it without the `YOETZ_ISOLATED_ROOT` variable; a different root in the variable is
refused rather than obeyed. `status` never prints paths, only digests, and reports whether the
instance is `permanent`, `persistent`, `disposable`, or an older unlabeled isolated root, and
whether it has expired. `dispose` removes only a root that carries such an instance record, stops
only the service holding that root, and can be repeated safely; it will not remove your everyday
installation. Contributors building instances from source use the procedure in the project's
contributor documentation.

## After setup

Bare `yoetz` opens the interface. Type `/` for commands — `/status` for layered readiness,
`/connect`, `/privacy`, `/provider`, `/service`, `/doctor`, `/work`, `/check`, `/receipt`.

Set `YOETZ_TUI=0`, or run in an installation without the rendering dependency, to get the
prompt-loop menu ([ADR-013](../adr/ADR-013-interactive-control-menu.md)) instead; it remains
supported and covers the same operations.

From here:

- [Agent start](agent-start.md) — this same setup from the installing agent's side.
- [The terminal interface](terminal-interface.md) — the interface in detail.
- [The six operations](six-operations.md) — the actual workflow.
- [Privacy and AI-powered review](privacy-and-semantic-review.md) — before you enable any egress.
- [`docs/runbooks/codex-integration.md`](../runbooks/codex-integration.md) — integration detail and
  the exact tested Codex version set.
- [`docs/runbooks/claude-code-integration.md`](../runbooks/claude-code-integration.md) and
  [`docs/runbooks/cursor-integration.md`](../runbooks/cursor-integration.md) — the exact Claude
  Code and Cursor cells, their commands, and what each host's hooks do and do not observe.
