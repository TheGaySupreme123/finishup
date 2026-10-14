---
name: finishup
description: Use for material multi-step, resumable, delegated, or verification-heavy Codex work. In a new session read guidance and discover schemas, then call start before substantive work; follow recovery on failure and ask for intro and guidance if startup remains blocked. Also use when a FinishUP finding, Stop message or receipt needs an answer.
---

# FinishUP for Codex

The first workflow operation is `start`, after a discovery step that reads guidance and
discovers schemas. This includes `read_guidance` and commands. Read
`finishup://guidance/agent-instructions.md` before `start`; page and verify empty or clipped
guidance. After start, that core is the operating card; other pages only when a result names
them. See [startup.md](references/startup.md).

Capacity and cost changes need a disclosed choice: never choose a larger or uncapped local
observation capacity for an ordinary task; change it only on request, after the user accepts
the preview in `finishup://guidance/workflow.md#change-local-retention-capacity`.

At closure, `ready_with_limitations` means nothing further is to do: request the receipt
without another check; `standing_limitations` are disclosed, never tasks.
A `respond` does not clear a finding.
If a later check cannot prove your repair (a FinishUP limit), verify it and respond `self_verified`; never `finishup-blocker`.
On a limitation request, if the requirement may be met but cannot be verified here, respond `acknowledged` with the reason; `acknowledged_not_done` only when you know it is not met (receipt keeps `unresolved_findings_remain`).
Never empty or withdraw a working deliverable over a finding or an "empty if unsolved" clause.
