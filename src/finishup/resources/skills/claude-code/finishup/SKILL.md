---
name: finishup
description: Use for material multi-step, resumable, delegated, or verification-heavy Claude Code work. Follow recovery and ask for intro and guidance if startup remains blocked. Answer FinishUP findings, Stop messages, and receipts.
---

# FinishUP for Claude Code

The first workflow operation is `start`, after guidance and schema discovery.
Read `finishup://guidance/agent-instructions.md` before `start`; page and verify empty or clipped
guidance. After start, that core is the operating card; other pages only when a result names
them.

A finding is evidence, not an order.
Follow [review.md](references/review.md) for pacing, finding decisions, and self-verification.

Capacity and cost changes need a disclosed choice: never choose a larger or uncapped local
observation capacity for an ordinary task; change it only on request, after the user accepts
the preview in `finishup://guidance/workflow.md#change-local-retention-capacity`.

At closure, `ready_with_limitations` means nothing further is to do: request the receipt
without another check; `standing_limitations` are disclosed, never tasks.
A `respond` does not clear a finding.
Never empty or withdraw a working deliverable over a finding or an "empty if unsolved" clause.
