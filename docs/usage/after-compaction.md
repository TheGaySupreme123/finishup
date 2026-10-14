# When your agent's context is compacted

Long tasks make a coding agent compact its context: the host replaces the working conversation
with a summary and the agent carries on from that summary. The summary holds what the agent
remembers of its own work. It does not reliably hold what Yoetz recorded about it: which
obligations are still open, which findings are waiting for an answer, what the last check
concluded, which outputs the task declared.

When the host starts the agent again after a compaction, Yoetz adds a short recap of that state to
the context the agent is given. It is what `status` reports at that moment, written out once so the
agent does not have to rediscover it:

```text
Yoetz recap after context compaction. Each line below was read from the task ledger through
status just now and names its source.
ids: task tsk_..., session ses_..., writer wri_... [source hook mapping]; use these held ids ...
frontier: 604 (sha256:c6a3f00ac6a3f00) [source status compact head frontier].
plan: 4 declared, 2 open obligations (plan event evt_...). [source status compact @604]
readiness: action_required; receipt would read unresolved_findings_remain; agent-actionable: obligations_open, findings_unanswered [source ...]
open obligations (2): obl_... "Port the kimi detector ..."; obl_... [source status compact @604].
findings awaiting your response (2; 1 to do; reviewer text, advisory): fnd_... p1 ...
last check: action_required on frontier 600 (check event evt_...) [source status compact ...].
declared deliverables (2): out/result.json (obl_... open); out/figures (obl_... resolved) [...]
next: resolve the agent-actionable items above; status (held ids) lists each with its detail.
```

## What to expect

- **Every line says where it came from.** The status view and the ledger position it was read at,
  the recorded check, or the hook's own mapping. The recap does not add facts of its own, and it
  does not decide anything: the "next" line only restates the readiness state `status` already
  reports.
- **It is bounded.** About two and a half thousand characters at most. When the budget cannot hold
  a section, a line says which sections were left out so the agent asks `status` for them.
- **It only says what it was told.** Text that your privacy settings keep out of agent context
  stays out of the recap. A fact `status` did not carry reads "not reported", never a guess.
- **It can lag.** If some of the agent's most recent tool activity has not reached the ledger yet,
  the recap says how many local rows were still waiting; the facts above that line may not include
  that work.
- **It is not evidence.** It records nothing and does not strengthen a receipt. `status` is the live
  read, and a receipt still rests on what was recorded and checked.

## Where it appears

| Agent host | After a compaction |
|---|---|
| Codex | The recap is added to the re-ground text Codex shows its agent when the session starts again. |
| Claude Code | The same, through Claude Code's session-start context. |
| Cursor | Not shown. Cursor does not tell Yoetz when it compacts, so the agent re-grounds with `status` as before. |

A resumed session (as opposed to a compacted one) and a brand-new session are unchanged.

## If the recap looks wrong

Ask the agent to call `status` with its held session and writer ids. The recap and `status` read the
same ledger, so a difference means work happened after the recap was read. If a recap never appears
on a host that should show it, the session-start hook could not read `status` in time; the agent then
gets the ordinary start-up text for that situation (for example, that the service is unavailable)
instead of the recap.
