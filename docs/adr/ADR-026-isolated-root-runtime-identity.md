# ADR-026 — Exact-target isolated-root runtime identity

**Status:** Accepted (2026-09-01), maintainer-authorized in
[issue #518](https://github.com/TheGaySupreme123/finishup/issues/518); amended 2026-09-03,
maintainer-authorized in [issue #534](https://github.com/TheGaySupreme123/finishup/issues/534), to
exempt one explicitly passed dedicated Codex evaluator home from the "every artifact lives beneath
the root" reverse state; amended 2026-09-04, maintainer-authorized in
[issue #561](https://github.com/TheGaySupreme123/finishup/issues/561), to bind the root into
FinishUP-owned external Codex MCP registrations; amended 2026-09-22, maintainer-authorized in
[issue #571](https://github.com/TheGaySupreme123/finishup/issues/571) (item B1, from
[#567](https://github.com/TheGaySupreme123/finishup/issues/567)), to name path-identity digests
apart from byte-content digests (decision 8).
**Implemented by:** `src/finishup/config/paths.py` (`isolated_root()`, `runtime_dir()`,
`ISOLATED_ROOT_ENV`), `src/finishup/adapters/control/unix_socket.py`, `src/finishup/config/load.py`,
`src/finishup/service/client.py`, `src/finishup/cli/isolation_status.py`, the
`finishup service isolation` CLI command and its `yoetz.isolation-report/1` contract
(`src/finishup/protocol/isolation_report.py`), `scripts/check_codex_dogfood_parity.py`
(`yoetz.codex-dogfood-parity/4`), `tests/packaging/test_isolated_root_boundary.py`, and
`tests/packaging/test_codex_mcp_isolated_registration.py`.
**Relates to:** ADR-001 (single service/writer authority), ADR-003 (durable storage), and the
[Codex dogfood parity runbook](../runbooks/codex-dogfood.md).

## Context

Every FinishUP identity root previously resolved independently: `storage.data_dir` (and
`FINISHUP_STORAGE_DATA_DIR`) relocated only the storage bundle, while the platform `state_dir()` kept
owning the service singleton lock, service generation, and setup markers, and the platform runtime
directory kept owning the control endpoints. A dogfood or test environment could therefore hold an
isolated Codex home, candidate wheel, plugin tree, and storage bundle and still transparently
connect to — and write through — the live user's FinishUP singleton. In a real run, a repository
privacy grant intended for a disposable dogfood environment committed into the normal FinishUP
state, and the parity preflight had no facet that could expose the shared service identity.

Internal test isolation existed only as unsupported mechanisms: monkeypatched path functions in
unit tests and whole-`HOME` overrides in packaging tests. A `HOME` override is not an exact-target
contract — it drags the host's Codex home, keychain-adjacent state, and every other `HOME`-derived
identity along with it, and nothing validates or proves it.

## Decisions

1. **One isolation contract, one variable.** `FINISHUP_ISOLATED_ROOT` (owned by
   `finishup.config.paths`) is the sole supported way to isolate a FinishUP runtime. When set, every
   identity root derives from the single root: config `<root>/config/config.toml`, default
   storage bundle `<root>/data`, state `<root>/state` (service lock, generation, setup markers),
   runtime endpoints `<root>/run` (control, secret-ingress, human-control sockets), cache
   `<root>/cache`, and logs `<root>/log`. There is deliberately no pile of per-subsystem
   overrides: partial mechanisms (`FINISHUP_STORAGE_DATA_DIR`, `storage.data_dir`) remain storage
   relocation, never isolation.
2. **Fail closed, never fall back.** A set but unusable root raises
   `PathSafetyError("isolation_root_invalid")` (empty, relative, missing, or not a directory) or
   the precise existing path-safety reason (symlink component, shared temp, repository, sync
   folder, network filesystem, foreign owner, broad permissions) from the same
   `verify_private_local_bundle` gate that guards every private directory. No code path resolves
   to an ambient platform directory while the variable is set. At the endpoint layer this
   surfaces as the bounded `runtime_directory_unsafe` transport reason.
3. **The endpoint follows the root.** `runtime_dir()` in `config/paths.py` now owns the runtime
   endpoint directory and `adapters/control/unix_socket.py` consumes it, so an isolated runtime
   binds and connects only beneath its root. Not sharing an endpoint (or lock, which already
   derives from `state_dir()`) is what makes reaching the ambient singleton structurally
   impossible rather than merely discouraged.
4. **The variable is paths authority, not configuration.** `config/load.py` recognizes
   `FINISHUP_ISOLATED_ROOT` as mapping to no configuration leaf (like `FINISHUP_TUI`), and
   `service/client.py` forwards it to the detached service process it spawns, so an isolated
   client can never start a service whose state lands in the ambient install. An explicit
   `storage.data_dir` still wins over the isolated default `<root>/data`; the parity gate, not
   silent rejection, is what exposes an override that reaches shared storage.
5. **Isolation is proved from two exact target snapshots.** `finishup service isolation [--json]`
   resolves — locally, without connecting to a service or opening a ledger — only the identity
   roots of the executable and environment that invoked it. Dogfood captures one report from the
   exact normal executable/config environment and one from the exact isolated candidate. The gate
   compares those reports; it never substitutes platform defaults for the normal target, because
   its config or storage may be relocated. Each report contains canonical path-identity digests,
   never raw paths (decision 8 names them `*_path_digest`). The command is CLI-only; MCP and hooks
   inherit isolation through environment.
6. **The host-launched external Codex MCP child keeps the same identity.** In ambient mode the
   FinishUP-owned registration has no environment block. In isolated mode preview and apply bind
   exactly one allowed entry, `FINISHUP_ISOLATED_ROOT=<validated-root>`, into `codex mcp add`; the
   preview digest covers the exact root, and post-apply observation re-reads both argv and the
   environment block. Missing or different roots are FinishUP-owned but require re-registration;
   unknown keys, inherited-variable declarations, malformed roots, or any other environment
   shape are foreign and never overwritten. Status reports only the closed binding state
   (`ambient|isolated_exact|missing|different`), while preview shows the exact proposed root for
   local review. This exception is limited to external Codex registration; plugin-managed routes
   retain their own host-specific environment contracts.
7. **The dogfood parity gate fails closed on shared or unlaunched identity.** Report schema
   `yoetz.codex-dogfood-parity/4` retains the `service_isolation` preflight facet, the
   `identity.finishup_isolation` path-digest block, and the `observed.finishup_isolation_state` closed
   state (`isolated|shared|ambient|unknown`). The facet can pass only when the observed state is
   `isolated`, the candidate mode is `isolated`, the normal mode is `ambient`, and every resolved
   state/endpoint/storage/config/executable path digest differs from its exact normal-target
   counterpart;
   any equality, wrong mode, or unknown
   state is rejected or fails preflight, and a non-pass row must carry the
   `provision_isolated_finishup_root` continuation. It adds `mcp_child_isolation`, which can pass only
   when registration status is `yoetz_owned`, its binding is `isolated_exact`, and a pre-model
   Codex app-server inventory starts the registered child successfully. A non-pass row carries
   `reregister_isolated_mcp` when the registration or its binding is not exact, and
   `recapture_isolated_mcp_child` when the binding is already exact and only the child start is
   unproven. Version 1, 2, and 3 reports are no longer accepted.
8. **Path identity is not byte content (issue #567).** A path-identity digest binds only the
   canonical resolved path; an in-place or atomic edit of the file leaves it unchanged, so it can
   prove *which* target a runtime uses but never that the target's bytes stayed the same. The
   0.2 isolation output blurred this: its `identity.config_digest` was a path digest that a
   dogfood operator could read as an "unchanged config" proof. `yoetz.isolation-report/1` (wire
   schema `service/isolation-report-1.0.0.schema.json`) therefore renames the block to
   `path_identity` with `state|endpoint|storage|config|executable_path_digest` fields, and adds an
   opt-in, bounded byte-content lane: `finishup service isolation --json --content-digests` fills
   `config_content` with one observation of the selected config — `path_digest`, `presence`
   (`present|absent|not_regular|oversized|unreadable|unstable`), SHA-256 `content_digest` and
   `size_bytes` (both only when `present`, ≤ 16 MiB), and `observed_at`. It never records content.
   Symlinks are followed, so a retargeted link with identical bytes changes `path_digest` but not
   `content_digest`; a read the file changes under is retried and otherwise `unstable`, never a
   digest of mixed bytes. `yoetz.codex-dogfood-parity/4` renames its isolation fields to the same
   `*_path_digest` names and adds a required top-level `normal_target` key: `null`, or a bounded
   list (≤ 32) of slot-labelled before/after observations of normal-target files, captured with
   `scripts/check_codex_dogfood_parity.py --observe <path>`. When present it binds the
   `normal_target_unchanged` facet: a path-stable byte change must fail with
   `normal_target_content_changed`, a move with identical bytes with `normal_target_path_moved`,
   both with `normal_target_path_and_content_changed`, and an unobservable file with
   `normal_target_content_unobservable`; a missing after snapshot cannot pass, and a passing
   `normal_target_snapshot` needs every before observation `present` or `absent`. **Compatibility:**
   the isolation JSON gains a `schema` tag and drops the untagged 0.2 `identity` block (consumers
   detect the old shape by the absent tag); `finishup instance status` carries the same
   `path_identity` block; parity reports must be rebuilt at version 4. Nothing persisted changes.

**Amended 2026-10-14 (ADR-048).** The variable keeps its pre-rename spelling `YOETZ_ISOLATED_ROOT`
as an alias: it is read only when `FINISHUP_ISOLATED_ROOT` is unset, both set to one root is
accepted, and two different roots fail closed as `isolation_root_env_conflict` (continuation
`config_correction_required`: set both to one root or unset `YOETZ_ISOLATED_ROOT`; the instance
itself needs no disposal). `isolation_root_conflict` keeps its meaning of a variable that
disagrees with the runtime pin. While the deprecated
`yoetz` launcher ships, everything that exports the root (the Codex external registration in
decision 6, Cursor artifacts and hooks, the detached service and child processes, instance
exports) writes both names with the same value, so an older launcher found through `PATH` still
isolates (#604). Readers accept either name alone or both equal.

## Reverse states and rollback

Unsetting `FINISHUP_ISOLATED_ROOT` restores ambient resolution with no residue: every artifact an
isolated runtime creates lives beneath the root, so deleting the root is complete rollback and
cannot touch unrelated user state. One explicit exemption (issue #534): a dedicated Codex
evaluator home that the operator passes by path to `finishup provider codex-subscription setup
--codex-home` may live outside the root and be reused across runs. It holds Codex-owned OAuth
state plus the exact Codex `config.toml` FinishUP writes into it, and no FinishUP identity, state,
endpoint, or storage, so deleting the root still removes every FinishUP identity artifact and the
parity gate still fails on any shared FinishUP identity. That home is reverse-stated by
`finishup provider codex-subscription disconnect` — Codex logout plus binding removal — and then by
the operator deleting the directory they provisioned; root deletion is not its rollback. The
default evaluator home (no explicit path) stays beneath the root. The packaged regressions lock
both boundaries: `test_isolated_root_boundary.py` proves an isolated service run leaves the ambient
home tree byte-identical before/after, an ambient client cannot reach the isolated singleton, and
removing the root removes every trace; `test_codex_mcp_isolated_registration.py` uses installed
Codex 0.150.1 to launch a registered child from an ambient parent and proves that only the reviewed
registration supplied the exact root.

## Consequences

- Dogfood and test environments get a natively separate temporary FinishUP whose service singleton,
  storage, config, and endpoints cannot reach the live install, with a preflight that proves it.
- The isolation root must be provisioned deliberately (existing, owner-only, symlink-free,
  outside shared temp and repositories) before launch; there is no auto-creation, so a typoed
  root is an error instead of a silently different target.
- Existing unsupported isolation mechanisms remain internal test details; new tooling must use
  this contract.
