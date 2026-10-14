# Observation selection performance baseline

This runbook records the public safe baseline used for issue #687. It is a
measurement of the observation boundary at revision
`e56f7d0a873281ea05c95a0bcb8eb348d65cce4a` on `codex/repair-host-observation`.
It is not an acceptance result for the selection implementation.

The workload is deterministic and synthetic. It uses eight host session lanes,
paired `PreToolUse`/`PostToolUse` hook events, successful routine reads,
failures, denials, cancellation, a mutation, a negative verification, retry
and recovery, ambiguous shell work, and FinishUP closure reads. Payloads contain
only fixed labels and digests. The run uses an owner only state directory under
`/private/tmp`; it starts no service, opens no vault, reads no session corpus,
and performs no native content capture. The capture column is therefore an
eligible content byte estimate, not captured content or a provenance result.

The exact JSON outputs are retained as local operator evidence outside the
repository. The committed replay harness is
[benchmark_observation_selection.py](../../scripts/benchmark_observation_selection.py).
To replay against the exact baseline source, point the harness from a checkout
that contains the script at a separate clean checkout whose `HEAD` is the
baseline revision. Binding `PYTHONPATH` to the clean checkout prevents the
working tree's implementation modules from being imported:

```text
BASELINE_CHECKOUT=/path/to/clean/e56f7d0a873281ea05c95a0bcb8eb348d65cce4a
HARNESS_CHECKOUT=/path/to/checkout/with/benchmark
PYTHONPATH="$BASELINE_CHECKOUT/src" UV_CACHE_DIR=<task-cache> \
  uv run --project "$BASELINE_CHECKOUT" python \
  "$HARNESS_CHECKOUT/scripts/benchmark_observation_selection.py" \
  --revision e56f7d0a873281ea05c95a0bcb8eb348d65cce4a \
  --checkout "$BASELINE_CHECKOUT" \
  --counts 512 2048 8192 --fanout 8
```

The table below was captured before the implementation worktree changed by a
temporary public safe replay with the same count and fanout shape; its command
and full JSON files are listed in the local evidence manifest. A 512 event
cross check with the committed harness against the same clean revision is
retained separately because that harness includes additional protected classes
and the production envelope mapper. Do not mix those two report shapes when
comparing timings or serialized byte totals.

## Baseline measurements

The current revision has a 512 row outbox limit, a 1,048,576 byte serialized
workspace state limit, a 256 open pre event limit, and a 256 retained envelope
limit. The SQLite capture ticket limit is independent and was not exercised by
this structural only replay.

| Hook events | Spool bytes | Outbox admitted | Outbox overflow | Final state bytes | State writes | Serialized bytes written | Encode time | Peak RSS (MB) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 512 | 197,554 | 488 | 0 | 666,754 | 512 | 196,623,474 | 22.93 s | 37.1 |
| 2,048 | 790,686 | 512 | 1,434 | 802,311 | 2,048 | 1,341,202,265 | 98.09 s | 48.4 |
| 8,192 | 3,163,186 | 512 | 7,272 | 954,623 | 8,192 | 7,046,911,597 | 417.43 s | 43.7 |

The 488 rows at 512 and the overflow counts at larger workloads account for
successful FinishUP status reads being suppressed by the existing self observation
delivery filter. All envelopes were locally accepted in these runs, while the
retained envelope view remained capped at 256. A full or empty outbox therefore
does not describe the upstream write or retention cost.

The observed hook append p50/p95/p99 latencies were 0.140/0.183/0.258 ms,
0.153/0.241/0.460 ms, and 0.160/0.256/0.430 ms for 512, 2,048, and 8,192
events. Local ingest p50/p95/p99 were 0.246/0.394/0.623 ms,
0.288/0.530/0.965 ms, and 0.336/0.590/0.912 ms. The outbox timing includes
both projected state encoding and full queue rejection: its p50/p95/p99 were
24.205/44.121/49.636 ms at 512, 0.054/39.063/54.257 ms at 2,048, and
0.089/14.023/39.596 ms at 8,192. The mixed full cap timings must not be read as
a throughput improvement.

The dominant sustainable constraint is repeated whole state serialization. The
average serialized bytes per attempted event rose from about 384 KiB at 512 to
655 KiB at 2,048 and 860 KiB at 8,192, even though the final state stayed below
the one MiB ceiling. Raising the queue target alone would preserve this write
amplification and would still leave the independent capture ticket budget
unchanged.

An unpinned working tree spot check, captured before the final protected-retry
replay shape was added, is a regression signal rather than an acceptance
result. Its Focused/512 case reduced pending rows from 482 to 348, but increased
cumulative serialized bytes from 196.8 MB to 254.6 MB and outbox p99 from 37.2
ms to 177.3 ms. The selected path also raised final state from 666.7 KiB to
838.3 KiB. These values must be rerun after the implementation is committed;
they do not establish a shipped performance target.

## Provisional budget proposals

These are engineering targets derived from the baseline, not measured
post-change results:

* Keep Focused/512 as the only default. Treat 2,048 and 8,192 as candidate
  profiles until an append oriented or sidecar representation demonstrates
  bounded serialized bytes, pending pair state, capture ticket occupancy, and
  control plane responsiveness.
* Preserve at least 25% of the one MiB state ceiling for authority, loss, and
  transition accounting. A selected admission path should therefore trigger
  reduction before approximately 786 KiB, while retaining protected records
  and reporting the pressure dimension.
* In the same synthetic environment, keep hook append p99 at or below 1 ms and
  local ingest p99 at or below 2 ms. These are regression guards for this
  harness, not host wide latency guarantees.
* Report cumulative serialized bytes and write count alongside admitted rows.
  A lower ledger row count is insufficient evidence when upstream envelopes,
  capture work, or rejection accounting still incur the same writes.
* Measure the independent 512 capture ticket budget and captured content bytes
  before advertising any larger capacity. This structural harness does not
  establish that budget.

After implementation, rerun the same workload for all six Focused/Detailed and
512/2,048/8,192 combinations. Record selected versus effective settings,
summary input counts, protected individual deliveries, capture extraction
attempts, replayable rejection accounting, and the same timing and serialized
byte fields. Do not fill this baseline table with those results until they are
actually measured at a pinned revision.

## Custom capacity (#828)

Issue #828 adds owner-selected custom queue counts from 64 to 8,192 rows on the
same byte ladder as the profiles: 1 KiB of queue bytes per row, a state document
of `max(1 MiB, 2 × queue bytes)`, and the 16 MiB state-document safety ceiling.
No custom count has been measured with this harness or any other, and no result
in this runbook applies to one. Status and every capacity preview report
`validation_status: not_validated` until measured evidence exists.

The benchmark phase above still owns the defaults: Focused/512 stays the only
default, and #828 does not change it. When that phase runs, include at least
one custom count between the profiles (for example 1,024) and the 8,192 ceiling
case, and record the same serialized-byte, write-count and latency fields. A
No FinishUP cap row cannot be measured because the structural queue has no
uncapped mode; the 16 MiB state document is the reason it is unsupported.

## Coverage limits

This baseline exercises the Codex shaped local hook spool and local observation
store in one process. It does not prove Claude Code or Cursor hook behavior,
service RPC drain throughput, SQLite capture ticket exhaustion, native encrypted
capture, restart or crash recovery, concurrent workspace writers, AI-powered
review, or receipt coverage. The eligible content byte estimate is not evidence
that content was captured, delivered, selected for a check, or available for a
receipt.

## Concurrent host-adapter repair probe (#689–#691)

The separate [hook probe](../../scripts/benchmark_observation_hooks.py) runs eight
concurrent processes against one fresh owner-only store. It invokes the Codex,
Claude Code and Cursor adapters with synthetic pre-tool events, using their native
payload shapes. The retained fixture begins with 250 envelopes, 60 pending rows
and 199 quarantined rows (approximately 366 KiB). Interpreter startup is excluded;
Codex's stream-module cold import inside the adapter is included. No service,
vault, vendor host, transcript corpus or native content capture is involved.

On 2026-09-10, the same harness compared source baseline
`f98d6d6315141e6b07f3cf38c6fd566dfc4fd584` with an independent installed wheel built
from clean revision `55c81ed1ae6f10878f6c6ea4aaee86bfa3189428`. The wheel digest was
`sha256:028da76beaaa4e0a8c3c99fbcf981fa372f0d18268dbb4e69f1ce5bdc7a8096e`.
Times below are milliseconds, rounded to the nearest millisecond. With eight
samples, nearest-rank p95 and p99 both equal the maximum; this small probe cannot
establish tail latency or a host deadline guarantee.

| Adapter | Baseline retained p50 / p95 / p99 / max | Installed retained p50 / p95 / p99 / max | Installed fresh p50 / p95 / p99 / max | Baseline / installed retained inputs |
| --- | --- | --- | --- | --- |
| Codex | 2002 / 3316 / 3316 / 3316 | 825 / 1338 / 1338 / 1338 | 398 / 484 / 484 / 484 | 7/8 / 8/8 |
| Claude Code | 1223 / 1888 / 1888 / 1888 | 560 / 1060 / 1060 / 1060 | 50 / 114 / 114 / 114 | 8/8 / 8/8 |
| Cursor | 1348 / 1980 / 1980 / 1980 | 473 / 971 / 971 / 971 | 48 / 120 / 120 / 120 | 8/8 / 8/8 |

Every installed retained run ended with 68 pending and the original 199
quarantined rows; every fresh run ended with eight pending and zero quarantine.
All eight supplied identities were retained, with zero unaccounted inputs and
zero new recorded loss. Delivered inputs were zero because RPC was disabled.
The baseline Codex run returned neutral success for one input that never reached
admission accounting; its 2002 ms rejection is included in the baseline timing,
not counted as successful throughput. The JSON report separates retained and
not-retained invocation times and reports accounting before and after.

To reproduce the installed side from a checkout containing this harness:

```text
uv run python scripts/provision_test_instance.py create \
  --base "$HOME/.yz-instances" --tag obs689 --lifecycle disposable --expires-in 8 \
  --revision 55c81ed1ae6f10878f6c6ea4aaee86bfa3189428

env -u FINISHUP_ISOLATED_ROOT "$HOME/.yz-instances/obs689/runtime/bin/python" \
  scripts/benchmark_observation_hooks.py --fanout 8 --retained
env -u FINISHUP_ISOLATED_ROOT "$HOME/.yz-instances/obs689/runtime/bin/python" \
  scripts/benchmark_observation_hooks.py --fanout 8
```

The retention regression separately compares final encoded bytes against the
original linear eviction algorithm for 700 envelopes, 176 pending rows and 700
quarantine entries. It requires at most 16 full encodes and retains all 176
pending identities after reopening. Logical-clock tests cover hard-pressure
recovery, accepted-buffer transfers, projected aggregate bytes and ended-session
generation fences. Control-failure tests cover all four sources (the three hook
sources plus Codex session streams), bounded retries, connection stop, retained
replay identity and rotated payload-free diagnostics.

These are implementation and adapter results. They do not complete the issues'
real vendor-host parent/delegate workload, encrypted capture, fresh native
control-rejection trace, upgrade over a running older service, or the six larger
profile combinations described above. The fix removes repeated retention encodes
and repeated batch preflight, moves Codex cold preparation outside the store
lock, and shares the elapsed drain budget. Connection setup may use its reserved
preflight allowance after subtracting snapshot time; service calls retain the
original drain deadline, so a slow connection cannot reset it. It does not replace the JSON store
with an append-oriented representation, interrupt synchronous durable writes,
or establish an end-to-end timeout guarantee. Historical quarantine cannot be
attributed from the new diagnostic format. Keep those acceptance limits visible
when assessing the linked PR.


## Shared-store contention repair (#689, reopened 2026-09-26)

The reopened incident (three concurrent native hosts on `0.3` at
`f0693e93e35e58a6b77f7dee30937e82cdd73963`) showed process and thread store-lock timeouts,
multi-second hooks, a failed child recheck and a stalled delivery queue. Before changing code, the
repair measured where the lock time went. One pre-tool hook pass took the store lock five
separate times and held it about 270 ms on the 366 KiB fixture below, mostly re-parsing and
re-encoding the whole document. Each acquisition had its own two-second wait, and a
waiter that timed out while resolving its workspace was reported as `workspace_unconsented`.
The service sweep took the lock two to four times per delivered row, loaded every workspace under
one hold, and could leave a cancelled worker running beside the next pass.

The repair keeps the document format and every durability rule, and changes who holds the lock and
for how long: lock-free committed reads, one transaction per hook capture and per answered sweep
row, the document parsed and its members encoded before the cross-process flock is requested,
members spliced as cached
canonical fragments on write, already-validated envelopes neither re-validated nor re-decoded on a
re-read, hook lock waits bounded by the host window, and payload-free holder facts on every
timeout. After it, a warm capture batch holds the lock 24–44 ms. Encoding a 2.1 MB state takes
9 ms instead of 244 ms, and re-reading it after another writer's commit takes 65 ms instead of
500 ms (12 ms instead of 98 ms at 384 KiB). Written bytes are identical to inline encoding.

The concurrent probe was extended with `--pending-rows` (accepted rows in the retained fixture;
above 60 it selects Largest capacity) and `--drain` (the real service sweeper runs in the probe
process against the same store, delivering to an acknowledging stub for at most 60 seconds after
the hooks finish). It was run on 2026-09-26 in a 4-vCPU Linux container (x86_64, Python 3.14.6)
against a clean worktree of the tested revision (baseline) and this change (fix). Times are
milliseconds for the adapter call, interpreter start excluded. "Retained" counts inputs that were
pending or delivered afterwards. With at most 16 samples, p95 is close to the maximum, and these
figures are not tail-latency guarantees.

| State | Hooks | Sweeper | Baseline retained per host (p50 / max) | Fix retained per host (p50 / max) |
| --- | ---: | --- | --- | --- |
| 366 KiB, 60 rows | 8 | no | 8, 8, 8 of 8 (1,818–2,213 / ≤3,271) | 8, 8, 8 of 8 (804–1,030 / ≤1,229) |
| 366 KiB, 60 rows | 16 | no | 10, 11, 12 of 16 (3,980–4,311 / ≤5,404) | 16, 16, 16 of 16 (1,839–2,263 / ≤2,695) |
| 366 KiB, 60 rows | 16 | yes | 11, 10, 9 of 16; a sweep pass failed on a lock timeout in two runs | 16, 16, 16 of 16; all 76 rows delivered, no sweep failure |
| 1.9 MB, 2,000 rows | 8 | no | 2, 2, 3 of 8 (3,077–3,166 / ≤6,393) | 8, 8, 8 of 8 (2,238–2,421 / ≤3,095) |
| 1.9 MB, 2,000 rows | 8 | yes | 2, 2, 1 of 8; 179–183 of 2,001 delivered after 60 s | 7, 5, 6 of 8; all 2,005–2,007 delivered 17–23 s after the hooks |
| 1.9 MB, 2,000 rows | 16 | no | 3, 3, 2 of 16 | 13, 2, 2 of 16 |

Host order in each cell is Codex, Claude Code, Cursor. Every baseline loss was recorded as
`workspace_unconsented` or the generic `observe`, and baseline sweeps also failed on store-lock
`TimeoutError`. Every loss after the fix is a named `store_lock_timeout` with the holder's role,
phase and hold time. Neither run recorded a service-side lock timeout.

The last row is the known limit. With 16 cold hook processes on four cores, each one spends
several hundred milliseconds of CPU parsing and priming a 1.9 MB document before it can queue.
In a diagnostic run of that shape, 10 of 14 timeouts reached the lock with their host-window
budget already spent outside it (0 ms waited) and the rest waited at most 180 ms, behind holders
of 18–482 ms. Lock scheduling cannot fix that; the fix bounds
the hooks and names the loss. Reducing per-process whole-document cost (an append-oriented
representation, ADR-022 decision 23) remains the path if native workloads reach that shape. Two
fairness mechanisms were measured and not kept: a 2 ms lock poll interval and a
background-yields-to-foreground marker each moved 8-way/1.9 MB retention by less than run-to-run
noise (39 versus 40 and 38 versus 40 of 48 inputs).
The final revision moves that parse inside the process-local lock (still before the flock) after a
stress run showed a later-arriving in-process thread could otherwise commit first; a repeat of the
366 KiB 16-way row and the 1.9 MB 8-way sweeper row on that revision retained 16, 16, 16 and 8, 5,
5 inputs, with every row delivered.

To reproduce, with the baseline in a separate clean worktree:

```text
BASELINE=/path/to/clean/f0693e93e35e58a6b77f7dee30937e82cdd73963
PYTHONPATH="$BASELINE/src" env -u FINISHUP_ISOLATED_ROOT uv run python \
  scripts/benchmark_observation_hooks.py --retained --fanout 16 --drain
env -u FINISHUP_ISOLATED_ROOT uv run python \
  scripts/benchmark_observation_hooks.py --retained --fanout 8 --pending-rows 2000 --drain
```

This is adapter and in-process sweeper evidence on Linux. It is not the issue's native acceptance
run. That run still needs installed Codex, Claude Code and Cursor parent/delegate sessions on the
macOS instance, real service RPC, vault and ledger, encrypted native capture, a child recheck, and
a final receipt; Linux/WSL host coverage remains separately untested.

## Capture-inventory recovery regression (#695)

The recovery regression must start from unknown capture accounting and an empty outbox, reject a
new native failed-command input, then run the real service catalog inventory callback without a
fresh hook. The test must distinguish a complete inventory from genuine spare capacity and verify
subsequent encrypted-object readback, exact preservation of prior loss, and task isolation.

The focused cases are in `tests/integration/service/test_capture_inventory_recovery.py` and
`tests/unit/application/test_capture_recovery_scheduling.py`. They cover two real SQLite task
stores and catalog routes, transient and permanently incomplete inventory, restart, cancellation
while publication is running, off-loop blocked task reads and both file-backed catalog scans, workspace/session fairness, real
capture count pressure, and host-shaped Claude Code, Codex and Cursor parent/worker lanes. Runtime
routing and control transport are in-process test doubles. These cases do not establish vendor
installation, host deadline, full-daemon IPC throughput, or native concurrent delegation acceptance.

Continue to run the existing fresh/retained concurrent adapter probe separately. Its latency and
accounting measurements remain adapter-only evidence. `tests/integration/service/test_selection_loss_recovery.py` separately verifies loss-to-task
history and real check coverage with no subsequent native event, including committed-ledger/
failed-acknowledgement restart recovery. These assertions use exact routed lanes and never
reinterpret unattributed workspace totals as task loss. Neither a probe nor a recovery summary
proves that every local loss has a known task attribution.
