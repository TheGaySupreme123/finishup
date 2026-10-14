# ADR-028 — Instance identity and runtime-pinned isolated roots

**Status:** Accepted (2026-09-05), maintainer-requested in
[issue #604](https://github.com/TheGaySupreme123/yoetz/issues/604); design decisions recorded on
that issue before implementation.
**Implemented by:** `src/yoetz/config/installation.py` (instance identity marker, runtime pin
writer, service-start binding gate), `src/yoetz/config/paths.py` (`read_runtime_pin()`,
`isolation_binding()`, pin-aware `isolated_root()`), `src/yoetz/cli/instance.py` and the
`yoetz instance create|status|dispose` commands, `src/yoetz/service/daemon.py` (gate before the
singleton), `src/yoetz/service/lifecycle.py` (lifecycle in the lock stamp),
`src/yoetz/service/client.py` (resolved-root forwarding), `scripts/provision_test_instance.py`,
`tests/unit/config/test_instance_identity.py`, `tests/unit/cli/test_instance_cli.py`, and
`tests/packaging/test_instance_lifecycle.py`.
**Relates to:** ADR-026 (the isolated-root contract this builds on), ADR-001 (single service
authority per instance), ADR-003 (durable storage), ADR-024 (installation vault recovery).

## Context

ADR-026 made `YOETZ_ISOLATED_ROOT` the one way to give a test or dogfood runtime its own config,
storage, state, endpoints, cache, and logs. It bound the *environment* to a root; it did not bind
the *executable*. A snapshot runtime launched without the variable — by a host whose registration
names a bare `yoetz`, by a hook that drops the environment, by a shell where a test runtime is
earlier on `PATH` — resolves the ambient platform directories and reaches the everyday service.
That service rejects the foreign handshake as `service_incompatible` and the client advises
`yoetz service restart`, whose supersede path is the supported upgrade-over-running-service
mechanism: run from the foreign runtime it replaces the everyday service with the snapshot's, and
every everyday client is refused until a human restarts again. The maintainer's diagnostics ring
recorded exactly this sequence (`control_handshake`/`service_incompatible` followed by
`service_supersede`) on 2026-08-31 and 2026-09-03 after testing with several instances.

Separate directories were never the missing piece. Nothing recorded *which kind* of instance a
root was (a permanent install, a kept development instance, or a disposable snapshot), what source
revision or wheel it was built from, when it should stop serving, or which executable belonged
to it. Contributors also had no shipped, supported way to create, inspect, and dispose such
instances; every dogfood run re-derived a private layout.

## Decisions

1. **Three lifecycles, one marker.** An instance is `permanent`, `persistent`, or `disposable`.
   The everyday installation is the permanent instance: it carries no marker and resolves ambient
   platform directories, exactly as before. A persistent development instance or a disposable
   test snapshot is an ADR-026 isolated root whose state directory carries
   `instance-identity.json` (`yoetz.instance-identity/1`): canonical JSON, owner-only, sealed by a
   domain-separated `record_digest`, recording `installation_id` (`ins_`), `lifecycle`,
   `created_at`, optional `expires_at` (disposable only, at most 30 days), `source_ref` (an exact
   40/64-hex commit or null), `source_state` (`clean|modified|unknown`), `package_version`,
   optional `package_digest` (wheel SHA-256), and `runtime_prefix_digest`. A malformed, tampered,
   foreign-owned, or over-permissive marker is `instance_identity_invalid` and refuses the
   runtime; it is never ignored. An isolated root without a marker keeps working under ADR-026
   and is reported as `unlabeled`.
2. **The executable is bound to its root.** `yoetz instance create --bind-runtime` writes
   `yoetz-instance-pin.json` (`yoetz.runtime-instance-pin/1`: the exact root and the
   `installation_id`) into the snapshot's own virtual environment (`sys.prefix`), next to the
   interpreter every launcher, hook command, and MCP bridge of that snapshot resolves.
   `config/paths.isolated_root()` resolves the environment variable when set; otherwise the pin,
   under the same validation; both present and different is `isolation_root_conflict` and fails
   closed; neither is ambient. A pinned runtime whose root was removed is `isolation_root_invalid`,
   never ambient. Only owner-written, non-group/world-writable, exactly-shaped pins are honoured
   (`runtime_pin_invalid` otherwise), because a pin anyone else could write is a way to redirect
   one installation to another. `isolation_binding()` names the source
   (`ambient|environment|runtime_pin|environment_and_pin`) and `yoetz service isolation --json`
   reports it with the lifecycle.
3. **The service binds before it takes the singleton.** `service/daemon.py` reads the marker and
   the pin before `acquire_singleton()`: a pin without a marker, or naming another installation,
   is `installation_identity_mismatch` (a re-pointed runtime is refused, not redirected); a marker
   in ambient state is `instance_lifecycle_requires_isolated_root`; a disposable instance past
   `expires_at` is `instance_expired` and can be disposed but never served. The marker's
   `installation_id` is the highest-precedence candidate for the existing installation-identity
   selection, so the vault marker, unlock throttle, and service generation must all agree with it.
   The singleton lock stamp carries `instance_lifecycle` and `source_ref`, so a refused client and
   `yoetz instance status` can name what kind of instance holds a root. `service/client.py`
   forwards the resolved root to the detached service it spawns, so the pinned and
   environment-selected cases spawn identically. All refusals are bounded tokens with the
   documented exit codes (`INSTANCE_PUBLIC_CODES`), never tracebacks.
4. **Lifecycle commands are connection-free and owned-root-only.** `yoetz instance create --root
   <dir> --lifecycle persistent|disposable [--source-ref] [--source-state] [--package-digest]
   [--expires-in|--expires-at] [--bind-runtime]` creates the root itself (owner-only; the parent
   must exist; the same path-safety gate as every private directory; the socket path beneath it
   must fit `sun_path`) and seals the marker; it echoes the exact root once for local review, like
   an MCP registration preview. `yoetz instance status [--json]` is digest-only and reports mode,
   binding, lifecycle, provenance (`matched|drifted|unrecorded` against the running prefix and
   package version), expiry, and the lock-stamped holder. `yoetz instance dispose --root <dir>
   [--retain-logs <dir>] [--no-stop]` refuses anything that is not a marked persistent or
   disposable root (`instance_not_disposable`: the everyday install and unlabeled ADR-026 roots
   are never removed here), stops only the process stamped in *that root's* lock after the flock
   probe confirms the singleton is held (SIGTERM, bounded wait; `instance_service_running` leaves
   the root in place; nothing is matched by name, path, or pattern), optionally copies the log
   files out, removes the root, and removes a pin that names it. Repeating `dispose` is a no-op
   success. Expiry is enforced at service start and reported by status; there is no background
   sweeper and no claim of secure erasure.
5. **Contributor provisioning is a script over the shipped commands.**
   `scripts/provision_test_instance.py create|status|dispose` builds a wheel from an exact
   checkout revision with `uv build --no-sources` (refusing a modified tree unless
   `--allow-dirty`, which records `source_state: modified`), installs it into
   `<base>/<tag>/runtime`, and creates `<base>/<tag>/state` through the snapshot's own
   `yoetz instance create --bind-runtime`, writing a digest-only `provenance.json`. Concurrent
   workers use distinct tags beneath a short owner-private base outside every repository.
6. **Hosts.** Codex external registration keeps its `--env` root binding (ADR-026 §6); with a
   pinned runtime the pin is a second guard, and the everyday registration should name the
   absolute everyday executable rather than a bare `yoetz`. Claude Code gains no mutation path:
   plugin hook and MCP commands that name a pinned executable bind through the pin. Cursor native
   artifacts keep their environment binding (issue #594); the pin is a second guard. No host
   registration is rewritten by this decision.

## Reverse states and rollback

`yoetz instance dispose` is the reverse of `create`; removing the pin file from the runtime
prefix (which `dispose` does when the pin names the disposed root) is the reverse of
`--bind-runtime`; unsetting `YOETZ_ISOLATED_ROOT` on an unpinned runtime restores ambient
resolution as under ADR-026. A permanent install is unaffected by every instance operation:
nothing writes into ambient directories, and `dispose` cannot target them. The packaged
regression runs one synthetic ambient install and two pinned snapshots from two different
revisions concurrently, proves pin resolution with the environment dropped, disposes one snapshot
leaving the others' identity records byte-identical and their services reachable, and repeats the
disposal as a no-op.

## Consequences

- A test or dogfood runtime that was pinned can no longer reach, supersede, or be superseded by
  the everyday service, whatever its `PATH` position or environment.
- Instances are self-describing: there is deliberately no global registry or `instance list`; a
  shared index that can name roots is itself a redirection surface. Selection is by root, through
  the environment or the pin.
- Out of scope and recorded on issue #604: service-status wire schema changes, automatic expiry
  sweeps, relaxing `tests/packaging` serialization or the `~/.yz-*` shared-root rule, per-worker
  CI fixture adoption beyond the documented script, and live-host activation proof of Claude Code
  or Cursor plugins on a pinned snapshot.

## Amendment — `instance create` is whole or nothing (2026-10-14, owner request)

The owner asked for this fix while admitting non-root container users (ADR-007, 2026-10-14
amendment, issue #1073). `yoetz instance create --bind-runtime` on a runtime the current user
cannot write (a runtime another account installed, as root does in a container image) created the
root and sealed its marker, then failed writing the pin with a raw permission error: the command
reported `internal_error`, and the retry after fixing permissions reported `instance_exists`.

1. **A typed refusal.** Any failure writing the pin (no write permission, a read-only or full
   disk) is `runtime_pin_unwritable` (`STORAGE_UNSAFE`, exit 20, continuation
   `local_state_repair`), with a remediation that names both causes and both repairs: install
   Yoetz as the account that runs it, or fix the environment directory. The pin's temporary file
   is removed on every failure, as is the marker's.
2. **Rollback of exactly what this command made.** When sealing the marker or writing the pin
   fails, `create` removes its own marker (only while it still holds this command's identity),
   then the state directory and, when this command created it, the root, each only when empty.
   A root the operator created beforehand stays, empty as it was; another instance's pin is never
   touched; nothing is removed recursively. The refusal is raised after the rollback, so the same
   command succeeds once the cause is fixed. The rollback covers every refusal after the root is
   created, including a pin conflict found only at write time.

Verification: unit tests that simulate the kernel's refusal for a superuser runner (and use the
real mode bits otherwise), a pre-existing empty root, a late pin conflict, and failed open, write
and rename of the pin; and a real run as `nobody` against a root-owned runtime (previous release:
`internal_error`, then `instance_exists`; now `runtime_pin_unwritable` with nothing left, and the
retry succeeds once the prefix is the user's).
