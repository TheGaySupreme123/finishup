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
   only that wheel, installed with `--compile-bytecode` and `SOURCE_DATE_EPOCH` in the install
   child's environment, so uv writes checked-hash bytecode the retained runtime reuses (the epoch
   also reaches any build backend uv runs for an sdist dependency in that install, nothing else). Every uv
   command runs under umask 022 and the script then clears group and other write on the runtime
   it created (uv may hard-link files from a cache written under a looser umask), so an operator with Ubuntu's umask 0002 gets a runtime FinishUP accepts. Because
   such files are hard links, clearing their group write also changes the matching files in
   uv's cache (for example 0664 to 0644); that only tightens the operator's own cache. A
   previously downloaded uv-managed interpreter that a shared group can write is not changed;
   the instance's service then names `release_runtime_group_writable` and its repair.
4. The snapshot's own launcher runs `finishup instance create --root <base>/<tag>/state --lifecycle
   ... --source-ref <sha> --package-digest <sha256> --bind-runtime`, which creates the root
   (owner-only), seals `state/instance-identity.json`, and writes `yoetz-instance-pin.json` into
   the runtime's virtual environment. Creation is whole or nothing (ADR-028, 2026-10-14
   amendment): if the pin cannot be written, for example because another account owns the
   runtime, the command fails with `runtime_pin_unwritable` (exit 20) after removing the marker
   and the directories it created, so the same command succeeds once the runtime is the
   operator's own; it no longer leaves a half-created root that a retry reports as
   `instance_exists`. The script removes its whole `<base>/<tag>` tree on any failure as before.
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
the root binding those hosts already carry. The Codex plugin activation cache is bound the same
way: its `.mcp.json` names that snapshot's proven absolute launcher and, when the snapshot is
isolated, both isolation-root spellings. A foreign `finishup` earlier on `PATH` is not the plugin
command (issue #1076). Hook commands in that cache are not pinned: they stay the portable
basename `finishup` and still resolve through `PATH`. The project plugin source stays the
portable bare command. The everyday
install keeps its own registrations untouched.

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

## Replay recorded hook payloads through two builds (#1083)

`scripts/hook_replay.py` proves that a change to the hook path does not change what hooks do. It
feeds the same recorded payloads through two revisions, each in its own disposable snapshot, and
compares every exit code, stdout and stderr byte, the `observe drain` after each callback, each
workspace's `observe status` read right after its own last callback, its ledger history read back
through `status`, and every accepted ledger event with the payload bytes it binds, exported from
the stopped snapshot.

The proof is one `replay` per build, the old build being the merged predecessor and the new one the
change's head. Run them one after the other, never at the same time, on an otherwise idle machine,
with one shared `--work-root`:

```text
uv run python -I scripts/hook_replay.py corpus --rollout <codex-rollout.jsonl> \
    [--rollout ...] --max-calls 24 --out corpus.json
uv run python -I scripts/hook_replay.py replay --checkout . --revision <old> --tag rpo \
    --python <python3.14> --base <instances> --corpus corpus.json --work-root <work> \
    --mode pinned --admission-clock due --fixed-observation-key --out old.json
uv run python -I scripts/hook_replay.py replay --checkout . --revision <new> --tag rpn \
    --python <python3.14> --base <instances> --corpus corpus.json --work-root <work> \
    --mode pinned --admission-clock due --fixed-observation-key --out new.json
uv run python -I scripts/hook_replay.py compare old.json new.json --report report.md
```

`compare` exits 0 only when its verdict is IDENTICAL. Workspace paths are hashed into keyed
commitments and recorded in each session, so `compare` refuses two records replayed under different
work roots and names that cause.

What the corpus holds:

- Codex callbacks are rebuilt from a rollout, in the shapes pinned by
  `fixtures/observations/codex-post-tool-outcomes-0.157.1.case.json`. Each callback fires at the
  rollout position where its call or output landed, and its `transcript_path` names a copy of the
  rollout that has grown to that point. Stop fires after the turn's final reply and carries it as
  `last_assistant_message`, as Codex sends it; when `--max-calls` cuts the turn short, Stop fires
  right after the last selected output instead, so give `--max-calls` at least the turn's replayed
  call count for the proof.
- Claude Code and Cursor sessions use the ordinary profiles, built from the repository's recorded
  shapes.
- Malformed stdin for each host, invalid workflow requests through the CLI, and schema-validation
  probes in fresh installed-runtime processes cover the rejection paths.

Both builds use the same workspace paths, which are fresh `git` repositories with a fixed commit.

How the replay runs:

- **Isolation.** Every instance process gets a scratch `HOME` and `CODEX_HOME`, and
  `PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring`, so it never reads host configuration or
  the OS keychain. The vault is initialized and the Private privacy recipe chosen through
  `scripts/dogfood_ci/ceremony.py`, with a passphrase generated for the run and never written down.
- **Pinned controls, equal for both builds.** Each callback runs through the retained interpreter
  with the hook budgets in `PINNED_HOOK_BUDGETS` raised, the end-to-end
  `_HOOK_TOTAL_BUDGET_SECONDS` included. The service runs with its background observation sweep,
  lineage recovery and coordination retry paused, so every row reaches the ledger through the
  callback itself or the `observe drain` that follows it, in replay order. `--admission-clock due`
  makes every held admission row due at the next flush instead of after two or five wall-clock
  seconds. `--fixed-observation-key` writes one observation key into each snapshot before its first
  service start, so keyed commitments, source identities and the advice order they decide are the
  same in both builds. A build that is merely slower then takes the branch a faster one takes.
- **No setting for the workspace fingerprint.** The pre-call workspace walk has its own 0.75 s
  budget and must finish before the host's hook timeout; neither has a setting, so pinned mode
  cannot raise them. The replay workspaces hold one empty commit, so the walk takes milliseconds
  on an idle machine. A walk that missed its deadline would record the call's workspace effect as
  unavailable, which `compare` reports as a difference rather than hiding it.
- **Not replayed: the MCP bridge, which this change does not touch.** `finishup mcp serve` builds
  the full schema catalog as it starts, because its tool descriptors are generated from it, so every
  bridge validation takes the unchanged full-catalog path in both builds. The replay drives hook
  callbacks, CLI requests and schema probes instead. `tests/unit/test_hook_replay.py` checks that a
  bridge process keeps the full catalog; `tests/unit/protocol/test_lazy_schema_catalog.py` covers
  the lazy path per schema: every schema's `$ref` closure resolves as in the full catalog, every
  schema decides a corpus of workflow frames as the stock validator does, and every rejection
  reports exactly what the full catalog reports.
- **Cleanup.** The replay stops only the service it started, then disposes the snapshot.

How `compare` decides:

- **Refusals.** A failed or partial read is never compared: a setup step or drain that exited
  nonzero, a status read that did not follow its workspace's last callback, a history page, the
  service stop or the ledger export failing, an exported hash chain that does not recompute from its
  own bytes, two runs under different controls or work roots, two records whose pinned hook budgets
  (`PINNED_HOOK_BUDGETS`, kept in each record) are missing or unequal, a pinned run replayed without
  both proof controls (`--fixed-observation-key` and `--admission-clock`), or a fixed key that was
  asked for and not written.
- **Exact comparison.** Every compared part must be equal after normalizing only values that differ
  between two runs of one build: identifiers that are random or digests over a run's random task
  ids, matched one-to-one by where they occur; vault-keyed payload commitments; routine-read summary
  digests, which carry receipt times; named service clock fields, each checked to fall inside the
  run; wall-time figures and wall-time-derived values at named `observe status` paths; and the order
  of one call's captured tool input and output evidence, which the materializer emits in random
  object-id order and which is compared as a set of full events. The wall-time-derived values are
  the delivery-lag and pass-timing histograms' bucket counts, `hard_cap_breach_count` and
  `recent_hard_cap_breach_count` (passes over a wall-time cap), `dropped_sample_count` (timing
  samples lost to a bounded lock wait), the `store_lock_long_hold` rows (a store lock held a second
  or more) with their counts, and the selection state's byte size and utilization, which hold the
  timing figures; every other count, outcome and limit is compared. With the fixed key,
  observation-keyed values and the advice finding identifiers derived from them are compared
  exactly, and a renamed value that is the same in both runs fails the comparison, so the
  self-control replay shows that everything renamed is generated per run. A list of identifiers is
  an unordered set only where its producer sorts it by value; an advice ranking is compared in
  order.
- **The lazy path was taken.** The verdict also requires that no valid hook callback of the new
  build built the full schema catalog, that at least one parsed its schemas lazily, and that every
  callback that loaded schemas in the old build loaded them lazily in the new one.
- **Pinned only.** Only the pinned runs decide. `--mode shipped` and the `latency` command run the
  launcher untouched and give latency figures only.

**Result (#1087).** The proof ran on Linux x86_64 (a shared 4-CPU container, Python 3.14.6) with a
corpus of 106 items: 20 Codex callbacks rebuilt from a synthetic rollout of 8 tool calls, the 19
Claude Code and 13 Cursor ordinary-profile callbacks, 27 malformed hook payloads, 8 invalid CLI
requests and 19 schema probes. The merged predecessor and this change compared IDENTICAL: 677
compared parts, including 59 ledger events with their full payloads. In the new build 30 of the 52
valid hook callbacks parsed only their schemas (92 documents) and none built the full catalog; the
old build built it in the same 30. A second replay of the change compared IDENTICAL with the first.

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
installation, and inspect any project marketplace conflict independently. When discovery finds several Codex executables, provider status reads each against the selected
home. Agreeing registrations are usable; disagreement or failed readings print a quoted
continuation with `--codex-path <exact-executable>` and the selected `--codex-home`. The configured
Codex runtime is read first when discoverable, otherwise the newest reported version. Pass the same
selectors to admission preview and grant and to every follow-up probe. The continuation retains the invoking launcher and isolation
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

## Owner view with Touch ID: manual check on a real Mac (#1073)

Automation cannot answer an Apple LocalAuthentication dialog, so this is the release check for the
service-side macOS presence provider behind `finishup receipt --owner-view` (ADR-009 round 5,
ADR-016 decision 4 amendment). Run it on a Mac logged in at the desktop, from Terminal or iTerm,
against a disposable instance and never the everyday installation. Run it once with Touch ID and
once using the dialog's password option (or on a Mac without Touch ID). Record the macOS version,
the chip, and each observed result on the owning issue. Status: this check has not been run, and
the Codex check the owner asked for has not been run either; an independent Claude review
(2026-10-14) ran in its place.

1. From a clean checkout at the revision under test, provision and verify an instance:

   ```text
   uv run python scripts/provision_test_instance.py create --base ~/.yz-instances --tag touchid \
       --lifecycle disposable --expires-in 4
   L=~/.yz-instances/touchid/runtime/bin/finishup
   $L instance status --json        # mode isolated, the exact source_ref
   ```

2. `$L setup vault` and keep the platform credential store. Expect
   `Secure vault setup (platform credential store auto-unlock)` and `Vault ready.`. This is the
   system-keychain shape: a passphrase vault whose generated passphrase you were never shown.
3. In a scratch Git repository, open a task and record a check from the `start` and `check`
   templates in `guidance/request-templates.md`, replacing every identifier with the values the
   `start` result returns. Build one receipt request with `format: markdown`, `include: full` and
   `redaction_profile: full_local`. `$L receipt --request '<receipt JSON>' --json` is the agents'
   view: any undeclared repository name the check found reads
   `(receipt prose withheld: repository_excerpt)`.
4. Run `$L receipt --owner-view --request '<receipt JSON with a new request_id>'`. Expect
   `Confirmation code for this request: xxxx-xxxx` first, then the preview (task, format, profile,
   scope), `Authorization: os_user_presence`, and a line naming Touch ID or your login password
   with the same code. A system dialog appears that names your full FinishUP receipt and shows that
   code. Approve it: the full receipt prints with the names spelled out, and the command exits 0.
Each dialog that does not approve lengthens the wait before the next one: 5, 15, 30, 60, 120,
then 300 seconds, reset by an approval or by 10 minutes without a miss, and cleared by
`$L service restart`. A dialog cancelled within 2 seconds does not lengthen the wait, but the next
one still waits 5 seconds. The steps below approve between misses so each wait stays at 5 seconds.

5. Repeat step 4 and choose Cancel in the dialog. Expect `owner_view_refused: the
   operating-system confirmation was cancelled or did not confirm it is you`, nothing on stdout,
   and a nonzero exit. Run step 4 again at once: expect `owner_view_refused: recent
   confirmations did not succeed`, naming `finishup service restart` and `--use-passphrase`, and no
   dialog. Wait 5 seconds and run step 4 again: a dialog appears; approve it (this resets the
   wait).
6. Repeat step 4 and leave the dialog unanswered. After about a minute it closes by itself;
   expect `owner_view_refused: ... was not answered within a minute`. Wait 5 seconds, run step 4
   and approve.
7. Repeat step 4 and press Ctrl-C in the terminal at least 2 seconds after the dialog appears. The
   dialog should close at once and nothing is shown. Wait 5 seconds; a new `$L receipt
   --owner-view` raises a fresh dialog; approve it. Then repeat step 4, press Ctrl-C as soon as
   the dialog appears, and run step 4 again at once: expect `owner_view_refused: recent
   confirmations did not succeed` and no dialog. After 5 seconds step 4 raises a dialog again,
   and the wait has not grown; approve it.
8. With a dialog from step 4 on screen, run step 4 again in a second terminal. Expect
   `owner_view_busy` naming that second command's code, which differs from the dialog's, and
   `finishup service restart` for the case with nothing on screen; no second dialog. Approve the
   first dialog.
9. Agent shells, per host, each pointed at this instance's launcher (approve nothing; wait out
   each backoff between attempts, or run `$L service restart`):
   - Claude Code: ask the agent to run the step-4 command through its Bash tool. Expect
     `owner_view_requires_terminal` and no dialog. Then ask it to run the same command wrapped
     in a pseudo-terminal (`script -q /dev/null $L receipt --owner-view --request ...`): expect
     a dialog on your screen; cancel it, and the agent gets `owner_view_refused` and no withheld
     name.
   - Codex: ask the agent to run it through `exec_command` with a pseudo-terminal. Expect a
     dialog on your screen; cancel it, and the agent gets `owner_view_refused` and no withheld
     name. Without a pseudo-terminal, expect `owner_view_requires_terminal`.
   - Cursor: ask the agent to run it in its terminal. If that terminal is a pseudo-terminal,
     expect the Codex result; otherwise `owner_view_requires_terminal`. Record which.
10. Over SSH, to record what happens:
    - With the service still running from the desktop session, run step 4 from an SSH session to
      the same Mac. Expect the dialog on the Mac's own screen, not in the SSH terminal; cancel it
      there. `$L receipt --owner-view --use-passphrase ...` asks for the passphrase instead;
      this vault's passphrase was generated, so press Ctrl-C at the prompt.
    - `$L service stop`, then run step 4 from the SSH session, which starts the service there.
      Expected, unverified: the service cannot show a dialog, and because this vault's
      passphrase is kept in the credential store the command ends with `owner_view_unavailable`
      naming `--use-passphrase`, with no passphrase prompt.
11. `$L service stop` and dispose of the instance
    (`uv run python scripts/provision_test_instance.py dispose --base ~/.yz-instances --tag
    touchid`). If Keychain Access still lists that instance's `bundle-…` auto-unlock entry, delete
    it; it is scoped to the disposed instance's path.
