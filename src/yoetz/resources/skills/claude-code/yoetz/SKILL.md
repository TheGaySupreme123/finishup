---
name: yoetz
description: Use for material multi-step, resumable, delegated, or verification-heavy Claude Code work. In a new session read guidance and discover schemas, then call start before substantive work; follow recovery on failure and ask for intro and guidance if startup remains blocked.
---

# Yoetz for Claude Code

The first workflow operation is `start`. This includes `read_guidance` and commands. Read
`yoetz://guidance/agent-instructions.md` before it; page and verify empty or clipped guidance. If
start fails, follow same-request recovery first; ask the user for intro and guidance; do not work
without a task. Read-only skips.

After start, that core is the operating card; other pages only when a result names them:
`yoetz://guidance/workflow.md#start-and-resume` for resume/recovery/delegation/capacity and
`yoetz://guidance/request-templates.md` for setup.

Capacity and cost changes need a disclosed choice: never choose a larger or uncapped local
observation capacity for an ordinary task. On request run `yoetz observe selection-preview`, relay
the lower/pause/resume path, and apply only after the user accepts that preview. A no-cap request
returns `capacity_no_cap_unsupported`; See "Change local retention capacity" in [workflow.md](references/workflow.md).

For closure, publish evidence before `check`, answer findings, and request `receipt` last.
`check` after the plan and each milestone; on a finding, change work or record what it names,
not just recheck. At `ready_with_limitations`, nothing further is to do: request the receipt without another check;
`standing_limitations` are disclosed, never tasks. A `respond` does not clear a finding.
If a later check cannot prove your repair (a Yoetz limit), verify it and respond `self_verified`; never `yoetz-blocker`.
On a limitation request, if the requirement may be met but cannot be verified here, respond `acknowledged` with the reason; `acknowledged_not_done` only when you know it is not met.
Never empty or withdraw a working deliverable over a finding or an "empty if unsolved" clause.
