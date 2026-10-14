# Upgrade FinishUP

Ask your agent: **“Update FinishUP to the newest version and keep my current settings.”**
The agent can use the upgrade guide:

```text
finishup upgrade
```

This command shows the package, data, host refresh, and verification stages without changing
anything. Select only your existing hosts with repeated `--host codex`, `--host claude`, or
`--host cursor`. Supply the existing target values shown by your host registration when the guide
requests them. It never guesses a home, installs another host, or chooses a new privacy recipe.

For an ordinary installation managed by `uv tool`, you do not need to quit your agent app or stop
anything first. The package step is:

```text
finishup upgrade --accept
```

This installs the newest eligible version through uv, replacing an old version pin and keeping
supported extras. It confirms the result using a fresh launcher; an unchanged version is reported
as unchanged. Source checkouts, pinned test instances, isolated runtimes and custom uv resolution
settings are refused so their installation choices cannot be silently replaced. For a different package manager,
use that manager's upgrade procedure and then return to the guide. A failed or timed-out package
command is reported without claiming success; inspect the installed version before retrying.

Your agent can run it from inside the session you are using. Running processes keep their own
release files while the installed package changes. That session, and any other session
that is already open, keeps working on the previous version. When you next reopen your agent app
or start a new session, its first FinishUP call retires the previous FinishUP service and starts the new
one. You do not need to stop or restart anything to make that happen; `finishup service restart`
switches immediately if you do not want to wait. A process from before the update never replaces
the newer service. If a still-open older session later reports that FinishUP was updated, reopen that
session.

Upgrading **from 0.2.x** is the exception: 0.2's own upgrade command still asks you to stop hosts,
hooks, and the service first, because 0.2 cannot safely share the newer local observation state.
Follow that procedure once; later updates do not need it.

Unused old runtime copies are cleaned up automatically when a new process starts. For explicit
cleanup, `finishup upgrade --prune-runtimes` removes only copies no process is using. It does not stop
sessions or remove settings, task data or credentials. Before uninstalling FinishUP, close its host
sessions, stop its service through the supported lifecycle, and run this cleanup so unused release
copies do not remain after the package manager removes the launcher. Uninstalling the package keeps
your data; see [Where your data lives](#where-your-data-lives).

Run `finishup upgrade` again with the same host target options to continue with host refresh. Do not
repeat `--accept` just to continue. Package replacement does not itself refresh host files. When
the package and the existing data are a supported pair, the first controlled startup of the new
service performs the backup-first data upgrade before the service becomes ready. It preserves
existing tasks, settings, permissions, host integrations, observation consent, and recorded
history; there is no per-task migration ceremony:

- **Codex:** refresh the existing skill and inspect the exact plugin activation and MCP target.
  Apply only the fresh preview supplied by those surfaces, preserving its route and home.
- **Claude Code:** use the native plugin update preview and its authorization procedure, apply
  with the same request and digest, then reload or start a fresh session when convenient.
- **Cursor:** use the native replacement preview and install procedure, then fully relaunch when
  runtime status requires it. Portable/development carriers use their original install procedure.
- **Existing data:** the service handles a compatible 0.2-to-0.3 bundle upgrade during startup and
  verifies the result before accepting new work. A recoverable interruption resumes the recorded
  operation at the next unlocked startup. A newer schema, an unrecognized older layout, or a
  failed integrity check stays unavailable and points to the supported recovery procedure.
  Do not edit the database or retry with a new migration identity.

The agent should verify the package version, service identity, selected host artifact/runtime
status, and the completed data-upgrade result before saying the upgrade is complete. Host trust
prompts and any explicit backup, restore, or manual migration remain separate reviewed actions. The
guide automates the package step and compatible startup migration; host refresh and activation are
still separate actions with their own exact target and evidence.

## Upgrading from Yoetz

FinishUP was named **Yoetz** through version 0.2.5. The rename changes the name you type, not your
installation: your tasks, receipts, vault, settings, permissions and connected agents carry over,
and nothing is moved or rewritten.

What changes:

- The command and the package are `finishup` (PyPI and npm). New messages, receipts and the files
  FinishUP writes into your agent hosts use the FinishUP name.
- For this release only, an upgraded Yoetz installation keeps a `yoetz` command that runs FinishUP.
  In an interactive terminal it prints a one-line notice pointing here. Such an installation has
  only `yoetz` on its `PATH`, so until you move, any `finishup ...` command FinishUP shows you can
  be run as `yoetz ...` with the same subcommand. Update tips, the upgrade plan and consent requests
  started through `yoetz` already name `yoetz` there. A later release removes the alias, so move to
  `finishup` (below) when convenient.

What stays where it is:

- **Your data.** An installation first made as Yoetz keeps using its Yoetz-era folders in place (see
  [Where your data lives](#where-your-data-lives)). Nothing is moved, copied or renamed, and those
  folders now hold your FinishUP data: do not delete them. `/doctor` in the terminal interface shows
  which folders an installation uses, and `finishup service status` adds a note when they are the
  Yoetz-era ones.
- **Your settings.** Every `YOETZ_...` environment variable is still read under its new
  `FINISHUP_...` name, but only when the `FINISHUP_...` variable is not set. A repository's
  `.yoetz/checks.toml` is still read when it is the only check policy; you can move it unchanged to
  `.finishup/checks.toml` and it stays trusted, because trust follows the file's exact bytes. Keep
  its `format = "yoetz.approved-check-policy/1"` line as it is.
- **Your agents.** Hosts connected by Yoetz keep working until you reconnect them: their `yoetz`
  registrations, tool names and installed guidance are still recognized.
- **Recorded history.** Tasks and receipts recorded before the rename keep the names they were
  recorded with. Some technical identifiers in JSON output and stored files (for example
  `yoetz_owned` or `yoetz.<name>/<n>` schema tags) stay spelled `yoetz` permanently; they are not
  leftovers to clean up.

### 1. Update the existing installation

Run `yoetz upgrade` and follow its package step. From 0.2.x this is 0.2's stop-first procedure
described above. The update keeps the installation under the `yoetz` name and adds FinishUP to it,
so agents connected through that installation keep running. `npx yoetz` likewise updates an existing
`yoetz` installation in place. Neither replaces or removes another installation.

### 2. Move to the `finishup` command

```text
uv tool install --managed-python --python 3.14.6 finishup
```

If you installed `yoetz` with extras, install the same ones, for example
`uv tool install --managed-python --python 3.14.6 'finishup[semantic-openai]'`. `yoetz upgrade`
ends with a *Move from the yoetz name* step that prints this command with your extras when it can
confirm them, and otherwise asks you to add them yourself.

Then reconnect each agent host with the new command. The guided connection, `finishup setup run
--host codex|claude|cursor-ide|cursor-cli`, shows one reviewed change that replaces the host's
Yoetz-era registration with the FinishUP one; `finishup upgrade` lists the same host steps. Check
each host afterwards with `finishup setup status --host <host>`: a registration reported as
`legacy_only` or `duplicate` still uses the old name and needs reconnecting. Something reported as
`foreign` under the old name is not provably FinishUP's, so FinishUP leaves it alone; the host's
integration guide ([Codex](../runbooks/codex-integration.md#legacy-yoetz-registrations), [Claude
Code](../runbooks/claude-code-integration.md#legacy-yoetz-registrations),
[Cursor](../runbooks/cursor-integration.md#legacy-yoetz-registrations)) says how to remove it by
hand.

Only after every host is reconnected, remove the old command:

```text
uv tool uninstall yoetz
```

A host still connected through `yoetz` stops working when that tool is removed. Your data is not
affected: it stays in the folders the installation already uses.

### If something refuses after the rename

- **`installation_root_ambiguous`**: FinishUP found folders under both the FinishUP name and the
  Yoetz name, so it will not choose between them and reads or changes nothing. A settings file
  (`config.toml`) on its own counts. The folders that hold your vault and catalog are your
  installation's data: keep them where they are. If the other name holds only a settings file,
  move that file into the folders that hold your vault and catalog and retry. If both names hold
  a vault or catalog, decide which installation you keep (normally the Yoetz-era one, which holds
  your existing tasks and vault), close your agent sessions, move the other installation's folders
  aside by renaming them, not deleting them, and retry. A leftover `service.lock` from a stopped
  older service can be moved aside the same way. Do not move the folders of the installation you keep: its automatic
  unlock from system secure storage, if you use one, is bound to their location.
- **`config_env_conflict`**: a `FINISHUP_...` variable and its older `YOETZ_...` spelling are both
  set to different values. Unset the `YOETZ_...` one, or set both to the same value.
- **`isolation_root_env_conflict`**: `FINISHUP_ISOLATED_ROOT` and `YOETZ_ISOLATED_ROOT` name
  different roots. Set both to the same root, or unset `YOETZ_ISOLATED_ROOT`. Nothing needs to be
  removed or recreated. (`isolation_root_conflict` is different: a root variable that disagrees
  with the root a test instance's runtime is pinned to.)
- **`policy_ambiguous`** from `finishup observe checks ...`: the repository has both
  `.finishup/checks.toml` and `.yoetz/checks.toml`. Keep one, normally by moving the old file
  unchanged to the new path, and remove the other.

A consent request prepared before the upgrade and still waiting keeps working: review shows the
warning recorded when it was prepared, which still says `yoetz consent review` and "Yoetz cannot…",
and it expires after 15 minutes as usual.

## Where your data lives

Uninstalling the package (`uv tool uninstall finishup`, or `uv tool uninstall yoetz` for the old
name) removes the program, not your data. FinishUP keeps tasks, receipts, the vault, settings, logs
and caches in per-user folders named for the product. A new installation uses `finishup`; an
installation first made as Yoetz keeps using the `yoetz` folders in place.

| | FinishUP folders | Yoetz-era folders |
|---|---|---|
| macOS | `~/Library/Application Support/finishup`, `~/Library/Caches/finishup`, `~/Library/Logs/finishup` | `~/Library/Application Support/yoetz`, `~/Library/Caches/yoetz`, `~/Library/Logs/yoetz` |
| Linux and WSL 2 | `~/.local/share/finishup`, `~/.config/finishup`, `~/.local/state/finishup`, `~/.cache/finishup`, `$XDG_RUNTIME_DIR/finishup` | `~/.local/share/yoetz`, `~/.config/yoetz`, `~/.local/state/yoetz`, `~/.cache/yoetz`, `$XDG_RUNTIME_DIR/yoetz` |

The Linux paths assume the default `XDG_*` locations. An installation started with
`FINISHUP_ISOLATED_ROOT` (or `YOETZ_ISOLATED_ROOT`) keeps everything under that root instead. If you
chose system secure storage, the operating system keyring also holds entries under the service names
`yoetz.vault-root.v1` and `yoetz.auto-unlock.v1`; both the old and the new name use these same
entries.

Deleting these folders permanently deletes your FinishUP tasks, receipts and vault, and nothing in
FinishUP can recover them afterwards. Back them up first if you may want them again.

## Release notices and new settings

When update checks are allowed, a READY service checks the cached PyPI result on startup and hourly
thereafter. The network result is cached for 24 hours. A later eligible session can tell your agent
about a discovered release; this is not an operating-system notification or an immediate alert.
Offline operation, a locked/stopped service, disabled checks, or higher-priority task advice can
delay the notice. Hooks only read the cache and never perform a network check.

Use the exact release-specific accept/decline command in the notice. Declining a newly advertised
release skips that release; a later release can be offered. Older permanent declines remain
respected. Turning off update checks remains the global network opt-out.

Upgrading preserves your choices. Expanded review and other new features can be discussed afterward
and enabled only with their own approval. Accepting an update notice does not authorize package
execution, new observation consent, or broader disclosure.

## AI-powered review with a ChatGPT subscription

A successful package, service, and host upgrade does not by itself show that subscription-backed
AI-powered review still runs. When Codex with a ChatGPT subscription is set up, the upgrade guide
ends with a check that starts no Codex process and does not check your sign-in:

```text
finishup provider codex-subscription runtime status --json
```

If it names a next command, usually `finishup provider codex-subscription repair` after FinishUP adopted
a newer reviewed capability identity or after your everyday Codex was replaced, review that
command's preview before applying it. Repair keeps your ChatGPT sign-in, model, reasoning effort,
timeout, retries, and privacy permissions, and never signs in again on its own. Updating your
everyday Codex later does not affect the evaluator: FinishUP uses its own verified copy of the admitted
release. See [Providers](providers.md#keeping-the-evaluator-working-when-codex-updates).
