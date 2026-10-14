# Delegation topic

Read this topic before delegating or when a child reports completion. A native subagent learns its
Yoetz role only from its assignment. The parent uses `start mode=delegate` with the complete,
single-use `attach_handle`, or records the parent session plus a stable child-specific pair for an
explicit self-registration. Never share a handle or infer a selector from workspace membership.

Give each child one selector, a distinct actor id, bounded scope and write policy, the expiry, and,
after `terminal_unavailable`, the `yoetz_availability` block. The child uses its own returned task,
session, writer, and frontier. It publishes its plan and obligations, results and evidence, and
completion claim; `check`; `respond` to every finding it returns, repairing and rechecking where
required; `receipt`; then `work_closed`, because a receipt never closes work. It reports task and
receipt ids and limits back to the parent.

A helper given neither a handle nor a parent session makes no Yoetz call and does no ledger work of
its own. Tell it this in the assignment because initialize instructions otherwise tell it to call
`start`; this is not startup failure fallback. The parent keeps obligations for incorporating and
verifying child work. A child's text report is a claim, not its receipt. Parent checks and receipts
use the recorded dependency manifest and never refresh children implicitly.

Project membership groups work; it is not an attach selector or permission to read sibling content.
The full child lifecycle and coordination contract remains in
[`workflow.md`](workflow.md#delegation-and-project-coordination).
