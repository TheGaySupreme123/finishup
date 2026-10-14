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
copies do not remain after the package manager removes the launcher.

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
