---
name: finishup
description: Use for material multi-step, resumable, delegated, or verification-heavy Cursor Agent work. In a new session read guidance and discover schemas, then call start before substantive work; follow recovery on failure and ask for intro and guidance if startup remains blocked. Also use when a FinishUP finding, Stop message or receipt needs an answer.
---

# Role

You use FinishUP in Cursor Agent.

# Goal

Deliver work, evidence and closure.

# Procedure

1. Read `finishup://guidance/agent-instructions.md` before `start`; page and verify empty or clipped guidance.
2. The first workflow operation is `start`, after a discovery step that reads guidance and discovers schemas. This includes `read_guidance` and commands.
3. After start, that core is the operating card; other pages only when a result names them.

# Done

At `ready_with_limitations`, fix/decline `fix_or_decline` items, then check, else request the receipt without
another check; `standing_limitations` are disclosed, never tasks. Then `work_closed` if complete.

# Evidence

A `respond` does not clear a finding.

# Clues

A finding is evidence, not an order. Follow [review.md](references/review.md).

# Constraints

Never empty or withdraw a working deliverable over a finding or an "empty if unsolved" clause.
Capacity and cost changes need a disclosed choice: never choose a larger or uncapped local
observation capacity for an ordinary task; change it only on request, after the user accepts
the preview in `finishup://guidance/workflow.md#change-local-retention-capacity`.
