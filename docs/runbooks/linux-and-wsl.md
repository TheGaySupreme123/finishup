# Linux and WSL host facts

Operator reference for what Yoetz needs, refuses, and claims on Linux and on Windows through
WSL 2 (Windows Subsystem for Linux). Product wording for users lives on
[the install page](../usage/install-and-first-run.md#linux); this page records the decisions and
their evidence state. Filed from the Linux/WSL parity sweep (issues #716, #720–#725).

## Shared desktop installation

`yoetz setup run` discovers installed Codex, Claude Code, Cursor IDE and Cursor Agent CLI.
The selected host uses the common preview, status, disconnect and reconnect flow. Installing the
Yoetz integration does not require signing in to a model provider. Host account sign-in is a
separate prerequisite for model use.

Claude and Cursor plugin changes retain the exact-plan operating-system identity check. On
Linux and WSL, setup and the suspended terminal interface keep that PAM ceremony on the
foreground main thread; a worker thread cannot own its signal deadline. A missing trusted
console or failed password leaves the integration unchanged and returns a terminal continuation.
Issue #767 owns installation verification; it does not certify full model/observation behavior.

## Certified platform cells

ADR-007 advertises exactly two cells: macOS 11.0+ arm64 (`macosx_11_0_arm64`) and glibc 2.28+
Linux x86-64 (`manylinux_2_28_x86_64`). The dependency lock resolves `apsw` wheels for Linux
aarch64 too, so `uv tool install` succeeds on WSL 2 under Windows-on-ARM (Snapdragon X), Graviton,
Raspberry Pi, and Asahi. Those installs are **untested, not presumed compatible**: `yoetz version
--json` lists `platform_cell_untested` under `limitations`, `yoetz setup status --json` reports the
cell under `platform.cell`, and `/doctor` shows the platform line as *not proven*. Nothing is
refused; nothing is claimed. musl, macOS x86-64, and native Windows remain outside the matrix
(native Windows refuses with `unsupported_platform`, issue #709).

| Reported by | Field | Certified cell | Untested cell |
|---|---|---|---|
| `yoetz version --json` | `limitations` | no platform token | `platform_cell_untested` |
| `yoetz setup status --json` | `platform.cell` | `certified: true`, `cell: <tag>` | `certified: false`, `cell: null` |
| `/doctor` | Platform | ok | not proven, with the certified cells named |

Certifying Linux aarch64 needs a real `ubuntu-24.04-arm` release runner and release evidence in
`support/runtime-support.json`; until then the diagnostic is the whole claim (issue #724).

## Service startup on glibc before 2.32

Issue #1040: on `condaforge/miniforge3:24.9.2-0` every `yoetz service run` exited 70 with only
`internal_error: the command could not be completed`. That image is Ubuntu 20.04 with glibc 2.31.
glibc before 2.32 has no no-follow `fchmodat`, so CPython raises `NotImplementedError` for
`os.chmod(..., follow_symlinks=False)`, which is how the service set the mode of each endpoint it
had just bound. The binder now falls back to a by-name `chmod` only after `lstat` shows the entry
is still the socket it bound, inside the runtime directory it has just verified as owner-only;
the post-`chmod` check of type, mode, link count and inode is unchanged. Conda itself was not the
cause: the image sets no `LD_LIBRARY_PATH` or `PYTHON*` variables, and the uv-managed Python does
not load conda's OpenSSL or SQLite.

Reproduced and fixed in that exact image. The no-follow `fchmodat` arrived in glibc 2.32, so the
same failure applies by construction, not by test, to every glibc 2.28–2.31 system inside the
certified cell (Ubuntu 20.04, Debian 11, RHEL/Rocky/Alma 8, and images built on them). Release
verification runs on
`ubuntu-24.04` (glibc 2.39), which is why the floor was never exercised. PR CI now installs the
candidate wheel in that exact image (by digest) and runs `scripts/ci/service_image_smoke.sh` there
(next section), and `tests/subprocess/test_service_startup_failure.py` repeats the start under the
image's environment with the glibc 2.31 `chmod` behaviour on every platform.

## Git 2.25 is the minimum; older Gits are named, not obscure

The same images ship an old Git (2.25 on Ubuntu 20.04, 2.30 on Debian 11). With the `chmod` fix the
service started and reported `locked`, the passphrase vault initialized, and then every command
failed with `service_incompatible` naming the service's own pid and version (tb4n5). Once the vault
is ready, the control handshake resolves the caller's repository identity with
`git rev-parse --path-format=absolute --git-common-dir`. `--path-format` exists only since Git 2.31,
and an older `rev-parse` does not reject it: it echoes any argument it does not recognise, so the
answer gained a line and the identity resolver refused. The handshake closed without answering, and
the client called that silent close another installation. Check-time change capture also passed
`diff --no-relative` (Git 2.28) and `config --show-scope` (Git 2.26), which Git 2.25 refuses, so
every capture was `git_failed`.

The documented minimum is now Git 2.25, and Yoetz always uses the system Git (the first `git` in
`/bin:/usr/bin`, never one a conda environment puts first on `PATH`). ADR-031's #1040 amendment
lists each replaced argument; in short, no Yoetz Git call needs anything newer, repository
commitments are the ones `--path-format=absolute` produced, and the hardened runners read no global
Git configuration on any Git (on Git before 2.32, which ignores `GIT_CONFIG_GLOBAL`, a
`.gitconfig` committed to the repository used to become the global configuration, because `HOME`
named the workspace). A system Git older than 2.25 is refused with `git_version_unsupported` and
the continuation `system_git_upgrade_required`.

A handshake the service fails is named on both sides. The service records it once (`component`
`service.daemon`, `operation` `control_handshake`, `reason` `handshake_service_fault` with
`reason_code` the closed refusal such as `git_version_unsupported`, or the unexpected exception's
class token and origin with `phase` `handshake`); no path, Git output or stderr is recorded. The
client reports `service_incompatible` only when a validated field of the singleton stamp names
another installation. For this installation's own holder, and for a holder whose stamp identity is
unreadable, partly readable or absent, it reports `service_handshake_failed`:

| Surface | What it shows |
|---|---|
| CLI (`yoetz service status`, any repository-bound command) | `service_unavailable: service_handshake_failed: the local service closed the connection while setting it up …; correlation_id err_…` (holder pid included), exit 20; with an old system Git the line names Git 2.25 and the `system_git_upgrade_required` directive |
| MCP | `SERVICE_UNAVAILABLE`, `retryable: false`, `safe_details.reason_code: service_handshake_failed`, `safe_details.phase: handshake` or `handshake_git_version` (then also `continuation: system_git_upgrade_required`) |
| `yoetz service diagnostics` | the service's `handshake_service_fault` record with its `reason_code`, and the client's `service_handshake_failed` record |

`yoetz service restart` does not help (it reports the same failure rather than signalling the
holder); repair the cause the diagnostics name, typically the system Git. The one exception is a
holder whose stamp carries no identity key at all (an older Yoetz, or a service whose stamp lost
its identity when its schema manifest could not be read): nothing replaces it automatically, and
an explicit `yoetz service restart` does. PR CI's image smoke
(`scripts/ci/service_image_smoke.sh`) records `git --version` (and fails unless it is 2.25.x),
initializes a passphrase vault under an isolated root, and from inside a Git repository reads ready
status, starts a task and runs a deterministic check whose change capture must succeed (its test-edit
baseline must be known). `tests/unit/adapters/test_git_old_versions.py` reproduces Git 2.25's
behaviour with the real Git behind a shim. To run the smoke elsewhere, set `YOETZ` to a candidate
launcher and `SMOKE_BASE` to a private 0700 directory outside `/tmp`; `SMOKE_GIT` only builds the
repository and is the version `EXPECT_GIT_SERIES` checks, because Yoetz itself always uses the
system Git.

## Reading a service startup failure

Every startup failure is recorded once, with the stage that failed, the reviewed exception-class
token, the innermost `yoetz` source location and one correlation id (never exception text or
paths). Each surface shows the same facts:

| Surface | What it shows |
|---|---|
| `yoetz service run` stderr (a harness's `service.log`) | for example `internal_error: the service could not start (stage: activation; exception_not_implemented_error; at yoetz.adapters.control.unix_socket:434); correlation_id err_…`, exit 70; `stopped unexpectedly` when it failed after serving |
| The structural stderr line before it | `{"component":"service.daemon","operation":"service_startup_failed","phase":…,"reason":…,"origin":…}` |
| `yoetz service diagnostics --correlation-id err_… --json` | the durable record (`phase`, `reason`, `origin`, and `reason_code` for a typed refusal) |
| MCP `start`, or any tool call that started the service on demand | `SERVICE_UNAVAILABLE`, `retryable: false`, `safe_details.reason_code: service_start_failed`, `safe_details.phase: <stage>`, the spawned service's correlation id; text `Reason: service_start_failed (stage: <stage>).` |
| A CLI command that started the service on demand (`yoetz service restart`) | `service_unavailable: the local service exited while starting (stage: …; …); correlation_id err_…`, exit 20 |
| Setup and drain commands that start it on demand (`yoetz setup vault`, `yoetz setup llm --set`, the interactive `yoetz setup`, the restart after a provider or Codex-subscription change, `yoetz observe drain`) | the same `service_unavailable: … exited while starting …` line on stderr, then the command's own unchanged result and exit code (for example `provider_setup_failed: service_unavailable`, exit 20); the restart stops at the first such failure instead of spawning again. The full-screen window does not print it; `yoetz setup status --next` leads to `yoetz service restart`, which does |

Stages: `import` (a service module or native extension could not load, for example a wheel built
for a newer C library), `configuration` (configuration or the log sink), `composition` (instance
identity, singleton, vault), `activation` (endpoint publication, after ready activation when the
vault unlocks), `serving` (after the service had started). The origin names the source line; the
exception token names the class. Typed refusals keep their own lines (`instance_expired`,
`path_contains_symlink`, `service_already_running`, `invalid_request: <config reason>`, …), and
their record carries that token as `reason_code`. An unsafe runtime directory or endpoint, unsafe
storage or a required migration stays an unexpected failure (exit 70), but its line and record
name its own token after the class, for example `(stage: activation;
exception_local_control_transport_error; runtime_directory_unsafe; at …)`. A spawned service that loses the singleton to a
live one is not a failure: on-demand start connects to the holder. The bridge stops waiting as
soon as its spawned service exits with a record, instead of spending its 30-second start budget.

## Umask 0002 and user-private groups

Ubuntu, Debian, Fedora and RHEL create normal accounts with a user-private group
(`USERGROUPS_ENAB yes`) and umask 0002 through `pam_umask`; WSL's Ubuntu inherits the same
defaults. Every file such an account creates, including `uv tool install`'s environment and uv's
managed interpreter under `~/.local/share/uv/python`, is group-writable by a group of one.
Yoetz treats that group write as owner-only (ADR-007, 2026-10-14 amendment): the group must be
the owner's primary group, named like the owner, with no other member and no other account using
it as its primary group, as read from `/etc/passwd`, `/etc/group` and (when readable)
`/etc/gshadow`. That is only trusted when `/etc/nsswitch.conf` serves `passwd` and `group` from
`files`/`systemd` alone (the Ubuntu, Debian and Fedora defaults) with no userdb records beyond
dynamic users. Every `passwd`, `group` and `initgroups` line counts, including a duplicate or a
line written without the colon (`initgroups files sss`); a malformed one (for example an unknown
`[ACTION]` word) makes the check refuse. On machines joined to a directory service (`sss`, `ldap`, `nis`, `winbind`),
membership cannot be proved complete, so group write is treated as shared: install with
`umask 022`, or run the printed `chmod -R go-w`. World write, and group write through any other group, are
refused everywhere Yoetz checks who can write (installed runtime, launcher, host configuration
roots, workspace and Git capture).

A refused runtime stops `yoetz service run`, `yoetz mcp serve`, `yoetz upgrade` and every hook
with `release_runtime_group_writable` or `release_runtime_world_writable` (exit 20). Terminal
commands print the exact repair for that installation, for example
`chmod -R go-w /home/alice/.local/share/uv/tools/yoetz
/home/alice/.local/share/uv/python/cpython-3.14.6-linux-x86_64-gnu`; hooks print the token
without paths and point at `yoetz service run`. A service started on demand records the token as
its startup failure (`stage: import; …; release_runtime_group_writable`), and CLI
`service_unavailable` results, `yoetz service status` and `yoetz setup status` print the same
refusal; `yoetz setup run` refuses to connect Codex, Claude Code or Cursor to that runtime
(`reason` is the token, `next_step` the repair) while its status view and disconnect still work.
`yoetz upgrade --accept`, `npx yoetz` and `scripts/provision_test_instance.py` install under umask
022; the provisioner also clears group/other write on the runtime it creates.

Evidence (2026-10-14, Boat Ubuntu 24.04, fresh normal account, `umask` 0002 from `pam_umask`):
`uv tool install` produced a 775/664 environment and a 775 managed interpreter; `service run`,
`mcp serve` (initialize, tools/list), Codex, Claude Code and Cursor hooks (exit 0), `state capture`
on a 775 repository, and `setup run` previews for Codex, Claude Code (user-owned executable) and
Cursor Agent CLI all succeeded. The previous release refused every one of them. Moving the
runtime to a group shared with a second account produced the token on each surface. Not covered: a
root-owned Claude Code executable, which the separate executable-ownership rule refuses as
`target_unsafe` regardless of umask. The interpreter a retained generation links to is
re-checked on every reuse, so a later group change is refused then too.

## Root-owned project directories (containers)

Container images often keep the working directory root-owned and run the agent as a non-root
`USER` (for example `/app` as `root:root 0755`, or sticky `1777`, with `USER nobody`). Yoetz
admits such a project root for the non-root user when no other account can write it, or when it is
sticky (ADR-007, 2026-10-14); a directory another non-root account owns stays refused. Everything
Yoetz creates inside it (`.agents/`, `.cursor/`) must belong to the user, so when the user cannot
create entries there, have root pre-create that directory owned by the user. Git refuses a
root-owned worktree for another user, so such a project is used as a plain directory, not a
repository. For the runtime itself in such an image: install it as the user (or give the user its
prefix and a 0700 `.<prefix>-releases` sibling), because binding an instance writes into the
prefix and every serving start uses that sibling. A runtime the user cannot use this way is
refused by name (ADR-007, 2026-10-14):

- `release_runtime_not_owned` (exit 20) from `service run`, `mcp serve`, `upgrade` and every hook
  when `.<prefix>-releases` belongs to another account, or does not exist and the user cannot
  create it in the prefix's parent. Terminal commands print that directory; hooks print the token
  only. `setup run` refuses to connect a host to such a runtime and `service status` names it.
  Before, these printed `release_runtime_unavailable: permission_denied` (no directory yet) or
  "could not be verified" (root had already run Yoetz and made the directory).
- `runtime_pin_unwritable` (exit 20) from `instance create --bind-runtime` when the user cannot
  write the prefix; the command keeps nothing, so it can simply be run again after the repair.

If the image must keep the runtime root-owned, root can create the sibling for exactly one user
before anyone runs Yoetz:

```bash
install -d -m 0700 -o agent /opt/yu/.runtime-releases   # for a runtime at /opt/yu/runtime
```

That user then builds and serves its own private copies from root's files (verified as `nobody`,
2026-10-14). Root itself is then refused by the same rule, the runtime serves only that user, and
it cannot be pinned (a pin must be the running user's own), so a pinned instance still needs a
runtime the user owns. If root has already run Yoetz from that runtime, the existing sibling holds
root's copies and lock: leave it and install a runtime for the user instead.

## Retained-runtime bytecode and slow starts

Serving processes (`service run`, `mcp serve`, every hook, `upgrade`) run from a sealed,
read-only copy of the installation (ADR-007). That copy ships unchecked-hash bytecode for every
module, so a start costs what an ordinary run costs. Building the copy reuses the installation's
own bytecode only when it is hash-based and matches the source. `npx yoetz` and
`yoetz upgrade --accept` install that way (they set `SOURCE_DATE_EPOCH` for the uv install and
the build backends it runs for any sdist dependency, nothing else); after a plain
`uv tool install --compile-bytecode`, which writes timestamp bytecode, the first serving start
compiles the package once (roughly 2-3 times as long on an M-series Mac, longer on WSL under
nested virtualization). To get the faster first start from a manual install, run it as
`SOURCE_DATE_EPOCH=315532800 uv tool install --compile-bytecode …`. A start that outlives the client's budget is reported as
`service_unavailable: service_handshake_timeout` (CLI) or `safe_details.phase:
handshake_timeout` (MCP): wait and retry; do not run `yoetz service run` or `restart` for it.

## Approved-check sandbox

Network-denied approved checks run only under an enforcing sandbox: Seatbelt (`sandbox-exec`,
ships with macOS) or bubblewrap (`bwrap`) on Linux, including WSL 2. Without a usable `bwrap`
every such check is rejected `sandbox_unavailable`; that is the correct fail-closed outcome, and
since issue #720 the dependency is named once instead of per run:

| Surface | Field / line |
|---|---|
| `yoetz observe checks status --json` | `sandbox: {status, mechanism, reason, remediation}` (also when `state: not_configured`) |
| `yoetz setup status --json` | `platform.check_sandbox` (same shape) |
| `/doctor` | Approved-check sandbox: ok / not configured, with the remediation |

Reason tokens: `ready`, `bwrap_missing`, `bwrap_unusable`, `sandbox_exec_missing`,
`platform_unsupported`. The Linux adapter probes **usability**, not presence: one bounded
`bwrap --die-with-parent --unshare-net --bind / / --dev /dev --proc /proc -- true` per process.
Ubuntu 24.04 (the default WSL image) restricts unprivileged user namespaces through AppArmor; a
`bwrap` that is present but blocked passes a `which` probe and fails at run time, which the
usability probe reports as `bwrap_unusable`. The distribution `bubblewrap` package ships the
AppArmor profile that permits it; a still-blocked host can relax
`kernel.apparmor_restrict_unprivileged_userns`. The check itself runs with the same wrapper
prefix plus `--chdir <workspace>`: the whole host filesystem is bound read-write and only the
network namespace is unshared, mirroring the macOS profile `(allow default) (deny network*)`.

**`yoetz service status` does not report sandbox availability, and is not going to.** Issue #720
asked for the fact to be named once in setup diagnostics *and* in `yoetz service status`; the
second half is deliberately declined here, and those three surfaces are the whole supported set.
`service status` answers a versioned wire contract (`service-status-1.0.0`, closed to unknown
fields and a member of the schema manifest whose digest the control handshake pins on both sides)
about one subject — the local service holder's state, identity, and liveness — and it answers
while the vault is still locked. Sandbox availability is not a property of that holder. It is a
live capability probe of whichever process asks: one bounded `bwrap` execution whose answer
depends on that process's `PATH`, its AppArmor profile, and its permission to create an
unprivileged user namespace. Each of the three surfaces above reports the answer for the
environment the operator is actually standing in, which is what decides whether to install
`bubblewrap`. Because the service is a per-user singleton on the same machine, that is normally
also the answer its own check worker gets; where the service was started from a different
installation or `PATH`, a field on `service status` would report the service process's environment
under a name operators read as their own, which is the worse answer, not the missing one. A
service-side answer, if one is ever needed, belongs in its own versioned diagnostic.

Evidence state: issue #786 records an installed 0.2.3 candidate on Ubuntu 24.04 under WSL 2
(Windows Server 2025), tested 2026-09-19. The real `ApprovedCheckRunner` used bubblewrap, verified
a different network namespace, and could not connect to a live listener in the parent namespace.
This bounded check passed; it does not establish every distribution or native host integration,
and no Linux sandbox capability cell is claimed from it.

## Codex evaluator without a system bubblewrap

The Codex-subscription evaluator is a different consumer from approved checks. With a
source-reviewed Codex release (today `0.162.1`), it admits Codex's exact missing-bubblewrap and
no-user-namespace warnings (ADR-006, 2026-10-14). It runs no commands and writes no files, so
there is nothing for the sandbox to confine. Without a system `bwrap`, setup and repair still
pass. `yoetz provider codex-subscription status --json` reports
`codex_sandbox_unavailable: true` and `codex_sandbox_unavailable_reason: bubblewrap_missing`,
and the terminal interface says the evaluator runs without Codex's verified Linux sandbox. On WSL 2
the same applies. WSL 1 is unsupported, and Codex's WSL1 warning stays refused. Installing the
`bubblewrap` package is still what approved network-denied checks need (above).

## System credential store

The vault-root key may live only in an approved keyring backend. Auto-unlock accepts a wider set,
because it stores a scoped restart secret rather than the root key, and its entry is verified by
proof on every load:

| Backend (`keyring` id) | Vault root | Auto-unlock | Notes |
|---|---|---|---|
| `keyring.backends.macOS.Keyring` | approved | accepted | macOS Keychain |
| `keyring.backends.SecretService.Keyring` | approved | accepted | Freedesktop Secret Service over the session D-Bus: GNOME Keyring, or KWallet through its Secret Service bridge |
| `keyring.backends.kwallet.DBusKeyring` | not approved | accepted | KWallet's own D-Bus API; lock/unlock semantics not reviewed for the root key (ADR-008) |
| `keyring.backends.libsecret.Keyring` | not approved | accepted | libsecret binding of the same service; the Secret Service backend is the reviewed path |
| `keyring.backends.Windows.WinVaultKeyring` | not approved | accepted | native Windows is not a supported host |
| anything else (`fail`, `null`, `chainer`, file-based `keyrings.alt`) | not approved | rejected | no plaintext or file fallback exists |

ADR-008 grounds the root-key boundary in the Secret Service protocol's explicit locked/unlocked
object model and Apple's Keychain data-protection classes; the KWallet and libsecret backends are
auto-unlock-only until a release cell reviews their locked-session behaviour for the root key.

What the user sees when the store is unusable (issue #721): the interface's storage step disables
**Use system secure storage** with the reason (no store loaded, or the loaded backend is not
approved, naming its id) and what Yoetz needs on that platform; `yoetz setup run` prints the same
in its "Platform credential store unavailable" line; `yoetz setup status --json` reports
`platform.secure_storage: {approved, backend_id, reason, requirement}`; `/doctor` shows a System
secure storage line. Reason tokens: `approved`, `keyring_unavailable`, `backend_not_approved`.
For Secret Service, approval also requires a successful ten-second bounded D-Bus/service
availability probe. The probe reads no credential and never unlocks or creates a collection;
it does not prove that a later credential operation will succeed.

Headless Linux sessions and WSL 2 normally have no session D-Bus and no Secret Service daemon, so
the vault passphrase is the supported route there; `yoetz service auto-unlock enable` remains
available only where an accepted backend is loaded. Capability CI runs `platform-key-matrix` on
`ubuntu-24.04` with a desktop Secret Service; headless Linux and WSL 2 keyring evidence is
**outstanding**.

## Where state may live

`config/paths.py` refuses a state directory on a network or cross-machine filesystem with
`path_on_network_filesystem` (`STORAGE_UNSAFE`). On Linux the denylist includes `9p` (how WSL 2
mounts Windows drives by default), `drvfs` (WSL 1), and `virtiofs` (WSL and VM shared folders
generally), alongside NFS, SMB, sshfs, and the rest. These transports
cross a host/guest boundary whose locking and crash durability Yoetz has not certified; the
refusal is a conservative support decision recorded in ADR-003 (issue #723), not a claim that
all such implementations lack locks. For example,
[virtiofsd supports configurable POSIX locks](https://virtio-fs.gitlab.io/qemu/tools/virtiofsd.html).
Inside WSL, Yoetz state must stay on the distribution's own ext4 disk — the WSL home is the default — never under `/mnt/<letter>`. The refusal's remediation says so, and it applies to
`YOETZ_ISOLATED_ROOT`, `yoetz instance create --root`, and `storage.data_dir` alike.

Evidence state: in the 2026-09-19 WSL 2 run recorded in #786, the installed candidate initialized
and restarted/unlocked on the Linux filesystem. `yoetz instance create` with a `/mnt/c` root
refused with `path_on_network_filesystem` and exit 20. A full `wsl --terminate` followed by
distribution startup preserved the installed instance: the service started locked and returned
ready after passphrase unlock. Native agent acceptance remains a separate, incomplete cell.

## Host integrations on Linux and WSL

Codex CLI on Linux uses the same first-run and `yoetz integrate codex` flow as macOS; OpenAI
publishes no Linux Codex App, so the interface labels every Linux Codex as a command-line
installation by definition. Claude Code and Cursor plugin mutation requires a supported
presence mechanism, reported by the installed preview's `authorization.human_presence`. The
Linux PAM ceremony is tracked separately in #719; builds without it refuse
`human_authority_unavailable` on Linux and WSL 2. That ceremony alone does not prove a Linux
native host cell. Both hosts can use a hand-added `yoetz mcp serve` entry. The per-host decisions
are recorded in
[`claude-code-integration.md`](claude-code-integration.md#linux-and-wsl) and
[`cursor-integration.md`](cursor-integration.md#linux-and-wsl); the Linux x86-64 evidence cases
for session activation/observation remain **outstanding** (issue #722). Separately, issue #767
records successful installed 0.2.4 setup lifecycles for all three CLIs on both Ubuntu x86-64 and
actual WSL 2, plus the Cursor IDE installation on Ubuntu. Successful real PAM approval was
exercised using disposable local accounts; no provider authentication or model task was required.

The Cursor IDE identity inspector can read a Linux package or extracted AppImage's native
executable and package metadata without launching it (#722). This identifies installed bytes;
it does not admit a native-session evidence case. On WSL, use the Linux installation root for
that inspection. Windows executables and the Windows-side IDE with Remote WSL are separate,
unverified surfaces; an accessible Windows launcher is not a Linux IDE identity. Layout and
failure details are in the [Cursor runbook](cursor-integration.md#linux-and-wsl).

## Setup and vault acceptance still owned by #737

Use `setup status --next --operation local|review|connection` to identify the next prerequisite
for the selected installation. The common host flow and the terminal interface retain the same
storage capability diagnosis and human-secret boundary. No Windows credential bridge is added.

The [0.2.4 installation evidence](https://github.com/TheGaySupreme123/yoetz/issues/767#issuecomment-5750168131)
records preview, connect, status, no-op, disconnect and reconnect on macOS, Ubuntu 24.04, and actual
WSL 2 for Codex CLI, Claude Code and Cursor Agent CLI. It excludes provider login and model tasks.
The prior 0.2.3 WSL run recorded above tested passphrase unlock after distribution restart. These
are historical installed-artifact observations, not execution of the #737 repair revision.

Remaining acceptance is owned by the setup/security maintainer in #737: fresh published-flow
first useful native-agent use on WSL; desktop Secret Service locked/unavailable and interruption
recovery on the repair revision; and a safe revocation design for stored auto-unlock. Existing
unit tests cover staged initialization/rotation recovery, secret wiping, lock state and rejected
backends. They do not replace those native acceptance runs. Native-session capability and the
Windows-side Cursor IDE/Remote WSL cell remain with #722.

`service lock` locks the live vault; it does not revoke a stored restart secret. ADR-008 deliberately
withholds a delete-only auto-unlock disable operation because a generated-passphrase vault could
become unrecoverable. Do not delete credential-store entries as a workaround. The remaining
revocation requirement needs an atomic human-passphrase rewrap plus removal design before it can
be called complete. Passphrase-only users must still unlock after service/WSL restart; the prompt
keeps their vault key out of plaintext files, shell history, and agent chat.
