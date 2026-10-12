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
