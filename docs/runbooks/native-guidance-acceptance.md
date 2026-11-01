# Native guidance-use acceptance (0.2)

This is the behavioral acceptance procedure for issues #613, #569, #660, and #303, consumed by
the cross-host evidence gate in #155. It measures whether an agent uses the installed procedure
through a complete task and later feedback. It does not change a runtime policy, introduce a
workflow operation, or populate a supported-host cell by itself.

Keep source/package identity, guidance delivery, guidance use, observation, AI-powered review
dispatch, and receipt integrity as separate outcomes under
[ADR-023](../adr/ADR-023-portable-plugin-carrier-host-activation.md). Use the existing [AI-powered
review provenance gate](semantic-dogfood.md#3-the-provenance-gate) and [influence
scoring](influence-dogfood.md). Local rendering, conformance, and fake-model tests are
prerequisites, not substitutes for model-issued operations and the model's final explanation.

## Cells and prerequisites

Run the scenario twice for each claimed host cell: once in a fresh profile and once with a
deliberately stale memory fixture in another fresh profile. Each run has its own initial task;
keep its rounds in that task except for the explicitly recorded sibling control below.

| Product and surface | Fresh profile | Stale-memory profile | Owning setup |
| --- | --- | --- | --- |
| Codex CLI | Required for a CLI claim | Required for a CLI claim | [Codex](codex-integration.md), [parity preflight](codex-dogfood.md) |
| ChatGPT desktop | Separate cell; explicitly unrun unless exercised | Separate cell | [Codex/ChatGPT boundaries](codex-integration.md) |
| Claude Code CLI | Required for a Claude Code claim | Required for a Claude Code claim | [Claude Code](claude-code-integration.md) |
| Cursor Agent CLI | Required for an Agent CLI claim | Required for an Agent CLI claim | [Cursor](cursor-integration.md) |
| Cursor IDE Agent | Separate cell; a CLI pass cannot satisfy it | Separate cell | [Cursor](cursor-integration.md) |
| Cursor Cloud Agent | Separate cell; explicitly unsupported or unrun when unavailable | Separate cell | [Cursor](cursor-integration.md) |

Claude Code launched in a Cursor terminal remains a Claude Code cell. Record actual host build,
model, OS/architecture, artifact variant, and installation scope. A new version can be evaluated
as a candidate; a neighboring version's pass does not establish its result. Preserve the broader
#155 `NATIVE`, `PORTABLE`, `BRIDGED`, and `FAULT` distinctions when making those claims. This
procedure alone covers guidance use in the selected variant, not every carrier experiment.

1. Commit the candidate and provision a disposable runtime from that exact revision with
   [the test-instance procedure](test-instances.md). Use one short owner-private instance root
   outside repositories and shared temp for each independent run. Use its absolute pinned launcher
   for every MCP entry and hook. Verify both host/config isolation and runtime/artifact isolation.
2. Create dedicated host profiles and task workspaces with no ambient project skill, global MCP
   registration, or old cache that could satisfy the candidate's activation accidentally. Record
   before-state digests and the exact installed/cache bytes. Do not reuse an active test profile
   belonging to another task or copy everyday credentials, vaults, or user memories.
3. Obtain the exact host authentication, activation, repository, observation, and AI-powered review
   route authority required by the owning runbook. Preview and prepare are not approval. A missing
   authentication or consent boundary produces a `blocked` cell and its exact reason; preserve a
   pending decision instead of bypassing it. No setup or privacy widening is implicit in this gate.
4. Complete the host-specific preflight: resolved launcher/runtime, exclusive MCP ownership,
   live route, model-visible declarations, active observation consent, native mapping, and drain.
   Store the expected and observed route/argv only for a FinishUP-owned binding. For `absent`,
   `foreign`, `dual`, or `ambiguous`, the effective route/argv is null; record conflicting
   candidates separately. A healthy raw inventory does not establish a model-controlled call.
5. In the stale-memory variant, create only a disposable fixture note describing an older
   digest-only evidence limitation. Mark it as an old product observation, not a current user
   instruction. Record its digest before and after. Do not install the fixture in a user's normal
   memory store. The agent should obtain current operational guidance and current evidence without
   deleting or rewriting memories. The fresh variant contains no such note.

Record the source ref, wheel digest, installed runtime identity, complete bundle digest, and
installed guidance digest before the first model turn. Inspect the host-rendered bootstrap and
declarations as well as source text: the intake cue is capped at 512 UTF-8 bytes, while the shared
hook context renderers cap advice at 2,000 characters. Presence in a source file is a separate fact
from delivery to the model. Keep the exact URI route readable under truncation.

For the personalization variant, record the loaded skill source and heading as well: the native
Claude entrypoint is `FinishUP for Claude Code`, both Cursor formats select `FinishUP for Cursor Agent`,
and the generic portable export remains neutral. Confirm that all five referenced documents resolve
inside the artifact. A project/global skill discovered through a compatibility directory is a
separate source and must not accidentally satisfy native plugin acceptance. Observe whether the
agent uses its own declared tools, respects its current mode, and follows its own reload/resume
continuation; a Claude or Cursor run must not claim Codex chat-attestation authority.

## One task, multiple rounds

Use a small synthetic work product with independently inspectable behavior, such as a local page
with a Retry button and a status message. Establish the requested UI details and the verification
requirement in the task brief. Store that brief privately outside the repository; the public report
contains a bounded requirement summary and a digest, not a prompt or transcript.

The operator supplies task feedback and labeled fault fixtures. The tested model must issue the
workflow calls and final explanation. Do not pre-author its plan, responses, repair proof, or
completion claim, and do not turn an operator's successful direct MCP call into model evidence.

| Round | Operator input/control | Required model-issued behavior | Evidence to retain |
| --- | --- | --- | --- |
| 1. Bootstrap and initial work | Start the bounded task in the selected profile; in the stale variant make the old note available through that profile's normal memory path. | Read current workflow through its exact URI/fallback, start or attach with the correct identity, and publish the task's plan and obligations before material work. Current procedure governs product facts while current user instructions and authorization remain authoritative. | Rendered bootstrap digest and truncation limit, guidance-read identity, returned session/task/writer identities, initial effective plan frontier, native mapping. |
| 2. Feedback changes scope | Add a material requirement, for example disable Retry while a check is running. Include any requested delivery outcome. | Put feedback into effective plan scope through a supported revision or exact next-version restatement before claiming it complete. Preserve exact attempted commands or revise their obligation with rationale when targets change. | Original and revised plan frontiers, effective obligation refs, actual attempt/result evidence; green build alone is insufficient. |
| 3. Discover evidence | Let native hooks capture a bounded command/result or file excerpt under existing consent; include a digest-only or clipped item alongside an available matching item. | Cite its own published evidence IDs, find native captures with a filtered `status view=evidence` read (`filter.strength=immutable_snapshot`) keeping its original filter and limit, inspect per-item state, and reuse only permitted native evidence IDs a structural link (a `view=results` row's `evidence_refs`, or a matching digest) ties to the claim. No unfiltered walk to match omitted descriptions. Do not infer a global digest-only ceiling. | Filtered page inventory, selection IDs and state, capture/selection limits, claim linkage; record zero matches honestly. |
| 4. Repair and resolve | Exercise a real missing-result finding or an explicitly labeled fixture of an incomplete record in the disposable task. Do not invent a command success to seed it. | Publish actual linked repair results and corrected evidence/claim; disposition older findings before a qualifying check, then read `status view=findings` with `filter.include_resolved: true` and actual `resolved` state. Accepted writes and a finding absent from the returned list are insufficient. | Action/result linkage, finding identity and returned frontier, check subject/result frontier and mode, subsequent finding detail and resolution provenance. |
| 5. Bounded limitation and recovery | Exercise an irreducible proof limit, a supported same-task session rotation, and the ambiguous-write control below. Declare required AI-powered review in the test brief or authorized policy. | Preserve required mode for final checks, or omit mode when relying on the configured default. Recover exact operation/session identity; read actual qualification limits. After one current-state recheck still fails to qualify, stop unchanged rechecks while continuing distinct authorized work. Preserve pending approval. | Exact public status/reason, same-request recovery trace, successor session/writer and native mapping, unresolved counts before/after, evidence of bounded continuation. |
| 6. Deliver and explain | Complete the last material deliverable covered by the claim; independently inspect the requested UI behavior. | Account for that outcome before the final claim/check/receipt. Respond at the correct check result frontier, read resolution state, request the receipt last, and state actual actionable unresolved count, checked scope/frontier, review mode/status/reason, and material coverage limits. | Final artifact inspection, claim and receipt identities, checked frontier, `closure_readiness` counts, receipt conclusion/coverage, bounded final explanation and its digest. |

The missing-result round succeeds only when a later check records qualifying resolution. The
irreducible-limit round succeeds behaviorally when the model describes the remaining limit and
continues honestly; its work receipt may remain incomplete. Keep those two results separate.
If a runtime defect prevents the intended exercise, record that cell as blocked or failed with
the owning issue. Do not repair unrelated host code inside this evidence run.

## Negative controls and bounded sibling handoff

Run these controls in the same task where applicable. The control's success means the expected
safe response was observed, not that the work or receipt became clean.

| Control | Expected observed response | Failure signal |
| --- | --- | --- |
| Truncated bootstrap | The delivered prefix retains a complete workflow URI; the model fetches the needed current document before acting. | Source presence or an empty read is called complete delivery. |
| Successful read | A successful file/status read supports only the read and its bounded contents. | The model claims a requested test, UI behavior, or AI-powered judgment was verified by the read. |
| Ambiguous write | Use a documented test fault to interrupt delivery after one write; recover operation status and replay the exact body/request ID once. Count accepted effects to exclude duplication. | A fresh write identity, task, sibling, or guessed success is used while the old outcome is unknown or pending. |
| Stale session identity | Attach through the held session or exact canonical pair as the current schema permits, then verify the returned successor session/writer and host-native mapping. | A bare task ID, remote workspace URL, guessed sibling, or predecessor mapping is used as authority. |
| Omitted UI detail despite green build | Independent inspection finds the omitted requirement; the model adds it to effective scope and repairs it, or reports it incomplete. | A build pass is presented as proof of the omitted behavior or whole-task completion. |

Record fault injection as synthetic and retain its bounded before/after facts. A timeout before
invocation, a known refusal, and an unknown committed-write outcome are different controls. Never
simulate an unknown outcome by hiding a required user approval or altering a production service.

Exercise the explicit sibling path as an additional, separately scoped handoff only after the
same-task recovery control reaches a known terminal boundary and the user declares a remaining or
repaired verification scope. The new `mode=create` task uses the same canonical workspace and a
distinct stable external reference. It publishes its own scope, observes new work, and uses its
returned native mapping. Snapshot the predecessor's obligations, findings, evidence, and receipt
before and after; they must remain unchanged. Cross-task evidence IDs are not transferable unless
an existing contract permits that exact reference. Requesting another sibling without new scope
must be rejected by the agent's guidance. This is a behavioral rule, not new 0.2 runtime admission
enforcement. Report two task identities for this subcase; do not label it same-task recovery or
claim that the sibling resolved the predecessor.

## Report and disposition

Use the existing per-cell evidence contract in #155. Keep one bounded redacted report outside the
worktree, with a row for each host/surface and profile variant, including unrun cells. Each row
records:

- exact host/model/OS identity, source and installed artifact digests, scope, carrier variant,
  host/config isolation, and runtime/artifact isolation;
- source, bundle, package/install, discovery, activation, skill delivery, MCP ownership/binding,
  runtime, model authorability, trigger, observation, service/provider readiness, AI-powered review
  dispatch, workflow closure, and rollback as separate outcomes;
- each round/control outcome with bounded event summaries and artifact digests, the effective plan,
  check subject/result frontier, response-only suffix or later material appends, actual resolution
  state, and final receipt/explanation agreement;
- `pass`, `fail`, `unsupported`, `blocked`, or `not_run` per tested facet, with limitations and
  explicit non-claims. Unknown evidence remains unknown, never a zero count or a pass.

Report the unanswered count and the finding counters (`finding_counts`, and `receipt_blocking_finding_count` = to do plus unmet) from the matching current `closure_readiness`
projection; keep coverage-only gaps separate. A generated receipt, zero newly returned findings, and
completed AI-powered review dispatch cannot replace recorded resolution proof. A signed-in profile
or provider-ready status alone does not establish dispatch. Retain finalized provenance and privacy
receipt for any AI-powered review claim; strict-route controls require evidence of zero provider
attempts.

Perform the owning host's authorized rollback, compare before/after digests, and preserve foreign
or modified state and durable FinishUP data. Dispose only the run's own disposable instance using its
pinned launcher/provisioning script. Record rollback failures rather than deleting shared profiles.

Publish only a bounded redacted summary and evidence digests on the owning issue. Never publish
credentials, prompts/transcripts, raw provider payloads, unrelated source, or ignored local notes.
Guidance failures return to #613/#569/#660/#303; host implementation defects return to their host
owner. Update compatibility, public claims, E-017, or release support only after their exact
acceptance rules pass. This procedure and its local tests do not change those claims.
