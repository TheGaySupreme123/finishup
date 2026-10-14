# Independent test instances

This runbook is for contributors who want to run one FinishUP for real coding while developing and
testing FinishUP on the same machine, and for CI jobs that need throwaway instances. It builds on the
isolated-root contract (ADR-026) and the instance identity contract (ADR-028, issue #604).

Vocabulary:

| Lifecycle | What it is | How it resolves its roots |
|---|---|---|
| `permanent` | The everyday installation (`uv tool install finishup` or the documented install path). | Ambient platform directories; no marker, no pin. |
| `persistent` | A development instance you keep across runs. | Its own isolated root, sealed by `instance-identity.json`; usually pinned into its runtime. |
| `disposable` | A test snapshot built from one exact revision with a bounded lifetime. | Same as persistent, plus `expires_at`; disposed after the run. |

A *snapshot* is the tested code and runtime. It never clones the permanent vault or user data;
every instance has a fresh vault, config, ledger catalog, locks, endpoints, cache, and logs.

## Prerequisites and constraints

- macOS arm64 or Linux x86-64 (the certified cells), `uv`, `git`, and a Python the runtime can
  use (the script defaults to the interpreter running it).
- A short, owner-private base directory outside every repository and outside shared temp, for
  example `~/.yz-instances`. Unix control sockets bind beneath each instance root, so the whole
  path `<base>/<tag>/state/run/secret-ingress.sock` must stay under 100 bytes;
  `finishup instance create` refuses a longer root (`instance_root_too_long`). The root must not be a
  symlink, must be owned by you, and must not sit under `/tmp` (macOS resolves it through a
  symlink and the runtime refuses it as `path_contains_symlink`).
- Nothing here needs, reads, or writes the maintainer's workstation paths, credentials, host
  configuration, or vault. Do not point an instance at the everyday install's directories.

## Create a snapshot from the code under test

From a checkout (a linked worktree is fine):

```text
uv run python scripts/provision_test_instance.py create --base ~/.yz-instances --tag pr604 \
    --lifecycle disposable --expires-in 8
```

What happens, in order:

1. The exact revision is resolved (`--revision` defaults to `HEAD`). A modified working tree is
   refused unless you pass `--allow-dirty`, which records `source_state: modified`; a non-HEAD
   revision is exported with `git archive` and built from that clean tree.
2. `uv build --no-sources` produces the wheel into `<base>/<tag>/dist/`; its SHA-256 becomes the
   instance's `package_digest`.
3. `uv venv` plus `uv pip install <wheel>` creates `<base>/<tag>/runtime/`, a runtime holding
   only that wheel.
4. The snapshot's own launcher runs `finishup instance create --root <base>/<tag>/state --lifecycle
   ... --source-ref <sha> --package-digest <sha256> --bind-runtime`, which creates the root
   (owner-only), seals `state/instance-identity.json`, and writes `yoetz-instance-pin.json` into
   the runtime's virtual environment.
5. `<base>/<tag>/provenance.json` records the tag, lifecycle, installation id, source revision and
   state, package version and digest, and digest-only identities of the runtime and root.

The command prints the launcher path and the environment export, which names the root under both
spellings, `FINISHUP_ISOLATED_ROOT=<root> YOETZ_ISOLATED_ROOT=<root>` (ADR-048): a pre-rename
`yoetz` launcher that ends up on `PATH` then still resolves the same root instead of the everyday
install (#604). Because the runtime is pinned, `<base>/<tag>/runtime/bin/finishup` resolves that
root even when the variables are unset or dropped by a host, hook, or shell; exporting them to the
same root is fine. Exporting either one to a different root than the pin is refused
(`isolation_root_conflict`), and exporting the two to different roots is refused
(`isolation_root_env_conflict`: set both to one root or unset `YOETZ_ISOLATED_ROOT`; the instance
needs no disposal), rather than obeyed.

Instances built from a revision before the FinishUP rename (for upgrade tests) ship only
`runtime/bin/yoetz` and the `yoetz` package and read `YOETZ_ISOLATED_ROOT`. Every
`provision_test_instance.py` command probes `runtime/bin/finishup` first, then `runtime/bin/yoetz`,
and drives whichever package that runtime ships, including the retained-runtime clean-up in
`dispose`. Substitute `bin/yoetz` for `bin/finishup` in the commands below for such an instance.

Verify before use:

```text
<base>/<tag>/runtime/bin/finishup instance status --json
<base>/<tag>/runtime/bin/finishup service isolation --json
```

Expect `mode: isolated`, `binding: runtime_pin` (or `environment_and_pin`), the requested
`lifecycle`, the exact `source_ref`, `runtime_provenance: matched`, and `path_identity` digests
that differ from the everyday install's own `finishup service isolation --json`. Those are
path-identity digests: they show which roots each runtime uses, not that any file's bytes are
unchanged; add `--content-digests` to observe the selected config's bytes (SHA-256, size,
existence, time; never content). The report is
digest-only; only `create` echoes the exact root, once, for local review.

## Run the snapshot and tests against it

Start its service in the foreground for a test, or let the first control command start it on
demand:

```text
<base>/<tag>/runtime/bin/finishup service run
<base>/<tag>/runtime/bin/finishup service status --json
```

The service refuses to start, with a bounded token and exit 20, when the instance is past its
expiry (`instance_expired`), when the pin and marker disagree (`installation_identity_mismatch`),
or when a labeled marker sits in ambient state (`instance_lifecycle_requires_isolated_root`).

Host integration against a snapshot follows the host runbooks; register the snapshot's absolute
launcher (never a bare `finishup`) and, for Codex external registration and Cursor native artifacts,
the root binding those hosts already carry. The everyday install keeps its own registrations
untouched.

For Codex external registration, run `integrate codex mcp preview|install|status|preview-remove|remove`
through that snapshot's own absolute launcher and the explicitly selected testing Codex home.
The preview now emits the snapshot's direct console script, verified against its installed RECORD
and runtime pin (#654). Status should report `yoetz_owned` and `isolated_exact`; repeat install is
a no-op, and an explicit route change keeps the same executable. A different instance's launcher
or root, a symlink alias, or modified script is protected as foreign. Use the direct command in
the preview, and still obtain real registered-child evidence before passing the parity gate.

The unattended [dogfood CI](dogfood-ci.md) lane provisions one such snapshot per (host, OS) cell on
a GitHub-hosted runner and disposes it at the end of the job.

Ordinary source tests do not need an instance: `uv run pytest <path>` from the checkout uses the
checkout's `.venv`, which is unpinned. Provision an instance when a test or dogfood must exercise
an installed launcher, a real service, a host registration, or the upgrade path.

Advancing the checkout does not change a running snapshot: the runtime holds the wheel that was
built, and `instance status` reports `runtime_provenance: drifted` if the runtime prefix or
package version the marker recorded no longer matches. Create a new snapshot for newer code; do
not reinstall into an existing one.

## Concurrency

- One tag per worker or job. Two workers must never share a `<base>/<tag>`; the second `create`
  is refused (`instance_exists`) and the second service start is refused
  (`service_already_running`) because the root's singleton is already held.
- Snapshots can run at the same time as each other and as the everyday install; their locks,
  endpoints, storage, config, cache, and logs are disjoint by construction. The packaged
  regression `tests/packaging/test_instance_lifecycle.py` proves one everyday-equivalent install
  plus two snapshots from two revisions concurrently.
- `tests/packaging` itself still shares install roots under `~/.yz-*` and must not run
  concurrently with another pytest run; that restriction is unchanged.

## Dispose

```text
uv run python scripts/provision_test_instance.py dispose --base ~/.yz-instances --tag pr604 \
    [--retain-logs ~/.yz-instances/retained]
```

The snapshot's own launcher runs `finishup instance dispose --root <base>/<tag>/state`: it probes
the root's singleton lock, sends the stamped holder (and nothing else) a bounded stop, waits up to
the drain window, optionally copies the log files to `<retain>/<installation_id>/`, removes the
root, and removes the pin that named it. The script then prunes unused retained release runtimes and removes the runtime and wheel.
If a host still holds a retained-runtime lease, it reports `runtime_in_use` and keeps those
runtime files; close that instance's host sessions and retry. It never kills a bridge to remove
a copy. Repeating
`dispose` reports `absent` and exits 0. `dispose` refuses roots without a persistent or
disposable marker (`instance_not_disposable`): it cannot remove the everyday install or an
unlabeled ADR-026 root. If a holder does not release within the window
(`instance_service_running`), the root is left in place; stop that runtime's service and retry.

Expiry is a serving limit, not a sweeper: an expired snapshot refuses to start until disposed.
Disposal deletes files; it is not secure erasure.

## Recovering a workstation whose everyday service was replaced

Symptom: every everyday `finishup` command answers `service_incompatible` and points at
`finishup service restart`, after a test runtime reached the ambient endpoint and superseded the
everyday service (the diagnostics ring shows `control_handshake`/`service_incompatible` followed
by `service_supersede`).

Recovery, on a local terminal, using the everyday install by absolute path:

```text
~/.local/bin/finishup service restart
~/.local/bin/finishup service status --json
```

Then make sure host registrations name the everyday launcher by absolute path, and provision test
runtimes with `--bind-runtime` (the script always does) so they can never resolve ambient state
again.


### Capability subprocess environments (#673)

Capability raw JSON-RPC, MCP SDK and direct cancellation/EOF children use
`tests/capability/child_environment.py`. Their private per-test HOME lives outside shared temp;
`FINISHUP_ISOLATED_ROOT` is replaced explicitly and HOME/XDG paths are rebased together. Test teardown
removes only that test tree. `FINISHUP_CANDIDATE_PYTHON` still chooses the exact candidate interpreter;
a conflicting runtime pin refuses the test root instead of falling back to its original instance.
For installed service tests, provision the candidate at the helper's exact root and use its
absolute interpreter. No ambient vault or credentials are copied.

## Setup order and exact targeting (#737)

Use the pinned absolute launcher returned by provisioning for every step. Inspect
`<launcher> setup status --next --operation local --project <project> --json` first. Start the
selected service, initialize/unlock the vault through its supported human ceremony, and establish
the private repository grant. For AI-powered review, configure the provider before preparing a
provider-backed repository grant, then approve that exact grant. Preview the common host
connection with its executable, private configuration root and project; accept only its returned
request/digest, then launch a fresh host. Connection-only installation can happen before provider
sign-in. No generic `--accept` grants credentials, disclosure or activation authority.

For Codex, plugin/MCP/provider status all accept `--codex-home` and report
`inspected_codex_home`; `--codex-path` selects the binary. Precedence for read-only default selection
is explicit home, `CODEX_HOME`, `CODEX_TESTING_HOME`, then `~/.codex`. Both home variables are forced
to the selected value for each Codex subprocess. Plugin removal still requires an explicit home;
use it for MCP removal and reconnection too. Do not retarget the process by changing only one
ambient variable. A foreign home is preserved; use a newly created mode-0700 home for a separate
installation, and inspect any project marketplace conflict independently. When discovery finds more
than one Codex executable, provider status stays unread for the agent route and prints a quoted
continuation with `--codex-path <exact-executable>` and the selected `--codex-home`; pass the same
selector to every follow-up probe. The continuation retains the invoking launcher and isolation
root. An explicitly missing selector reports the same bounded next action without echoing the path.

A service-dependent approval first probes the selected service without starting it. Known
unavailability preserves the pending identity; inspect consent status and retry that same valid
identity after recovery. Atomic claiming remains the authorization boundary. Post-claim service
loss consumes the review, as do denial, cancellation and expiry. Never invent a replacement
attestation or treat the preflight as authority.

`finishup setup vault` initializes or unlocks only the selected installation's storage using the
existing protected terminal ceremony. It diagnoses credential-store availability, retains the
explicit passphrase fallback where needed, and stops before provider selection or privacy grants.
It requires a local interactive terminal; agents show that continuation without supplying secrets.
