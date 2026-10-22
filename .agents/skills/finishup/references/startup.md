# Startup topic

Read this topic when a session is new, resumes after compaction, attaches to an existing task, or
needs to author a `start` call. The small `agent-instructions.md` core is the only mandatory read
before an ordinary configured `start`; this topic supplies the exact shape when the schema or prior
binding is not already in context.

Use the current `start` schema. Mint one fresh lowercase UUIDv4 `request_id` with the `req_` prefix
and retain it across an unknown or pending outcome. Supply `mode`, `task_title`, the user's complete
`task_statement`, `requested_view`, `actor`, `client`, and either the complete held `session_id` or
the canonical absolute `workspace_ref` plus `external_ref` pair. A pair is the identity boundary:
do not attach with a bare task id, infer a selector from workspace membership, or reuse a sibling's
pair. A child uses its authenticated attach handle or its explicit parent selector.

`start` is the first workflow operation before substantive edits, state-changing commands, research,
or delegation. If work began first, call `start` now, publish a bounded plan naming the uncovered
prefix, and preserve that limit in the receipt. A read-only question or a helper whose assignment
has neither a child handle nor parent selector has no startup task of its own.

The plan follows the state returned by `start`, not a version guessed from the session:

1. `start` records intent, delivery and known constraints. If no plan exists, use its first-plan
   template: `plan_published` with `plan_version: 1` and the obligations in the same batch.
2. After bounded exploration and before the first material edit, refine the existing plan with
   `plan_revised`: if its current version is N, send `plan_version: N+1` and
   `supersedes_plan_version: N`. For example, version 1 refines to 2 superseding 1; never revise
   version 1 superseding 0. On attach, use the held version or the latest `plan_published`/`plan_revised` payload in
   `status view=history`; if unavailable, follow the typed continuation, never guess a version.
3. Map each instruction requirement to a testable obligation. Explicitly carry, supersede or
   waive earlier obligations. A new obligation is `carried`, never `added` or `updated`.
   Meaning changes need a new obligation id; supersede the old one with a reason and replacement
   ids. Existing meaning fields stay immutable.

Do not edit before this refinement and its plan check. Exact bodies:
`finishup://guidance/request-templates.md#publish-work-plan-plus-obligation` and
`finishup://guidance/request-templates.md#publish-work-revised-plan`.

Decompose the user's request yourself: one obligation per stated requirement, reported symptom,
constraint, or deliverable, including the ones that look hard or contradictory. Each obligation's
`source_refs` names the event that recorded the task statement: the newest event that carried
`task_statement` (`session_opened`, `session_resumed`, `plan_published` or `plan_revised`),
listed by `status view=history` with `filter.schema_name`. An event that repeats the current
statement unchanged does not replace it, and citing any event that carried that same statement
counts; a changed statement must be mapped again. Put every file, command, or output
the request names in `requested_items` (`item_kind` `file`, `command`, or `change`). Hooks record a
command's keyed commitment, never its text, so a requested command stays disclosed as
`command_attempt_uncorroborated` on the receipt (a standing limitation, not a finding): also cite
the observed run's `res_` id (`status view=results`) as the obligation's resolution evidence.
FinishUP checks only that structural link, never the wording: a plan with obligations but none citing
the statement, or a completion claim on no plan or an explicit empty scope, returns an
agent-actionable `task_requirement_unmet` finding naming the statement event id. When the request
truly asks for no material work, answer it with a `decision_recorded` whose statement holds the
exact line `finishup-no-material-work:<statement event id>` and a rationale; it counts only while no
file changed. Then run `check` once on the refined plan before editing; subsequent checks follow
[delivery and review pacing](review.md).

If `start` fails, retain its exact request and correlation identity. Follow the typed continuation
and same-request recovery, including a named one-time repair, before asking the user for intro and
guidance. An unknown or pending write is not failure: read `status view=operation` with the exact
`operation_request_id` and replay the same body only when the stored state permits it. Do not invent
a task, session, writer, receipt, or replacement request. If startup remains blocked without a
supported recovery, pause material work and report the boundary.

For a resumed or handed-off task, read `status` before publishing or claiming anything. The full
cadence, startup failure precedence, selectors, and handoff table remain in
[`workflow.md`](workflow.md#start-and-resume).

## Code mode

One JavaScript `exec` cell per FinishUP call (`tools.mcp__finishup__*`). The `// @exec`
pragma and `yield_time_ms` apply only to that cell. Direct MCP, `exec_command` and
`write_stdin` are not cells; do not set `yield_time_ms` on them. Discover the declaration
before calling:

```js
const decl=name=>{const d=ALL_TOOLS.find(t=>t.name===`mcp__finishup__${name}`)?.description??"";const i=d.indexOf("exec tool declaration:");text(i<0?d:d.slice(i))};decl("start");
```

Read a page through its structured result:

```js
const g=await tools.mcp__finishup__read_guidance({uri:"finishup://guidance/workflow.md",page:"0",page_size:"1024"});const p=g.structuredContent;if(!p||p.ok!==true||typeof p.text!=="string")throw new Error("guidance page missing");const n=new TextEncoder().encode(p.text).length;if(n!==p.page_byte_count||p.revision!==p.digest||p.complete!==(Number(p.page)+1===Number(p.page_count)))throw new Error("guidance page metadata mismatch");text(JSON.stringify(p));
```

Mint every id with this helper:

```js
const uuid4=()=>{const c=globalThis.crypto;if(typeof c?.randomUUID==="function")return c.randomUUID().toLowerCase();const b=new Uint8Array(16);if(typeof c?.getRandomValues==="function")c.getRandomValues(b);else for(let i=0;i<16;i++)b[i]=Math.floor(Math.random()*256);// fallback: not cryptographic
b[6]=b[6]&15|64;b[8]=b[8]&63|128;const h=[...b].map(x=>x.toString(16).padStart(2,"0")).join("");return h.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,"$1-$2-$3-$4-$5")};const newId=p=>`${p}_${uuid4()}`;
```

Use the bridge deadline for each cell: `start`, `publish_work` and `status` 30000 each; `respond`
and `receipt` 50000; `check` 300000, or 30000 with `mode: inspect` (a read). Set `yield_time_ms`
at or above the call deadline; keep builds, tests and other non-FinishUP work in separate cells, not
a series of short waits.

```js
// @exec: {"yield_time_ms": 300000}
const request_id=newId("req");const r=await tools.mcp__finishup__check({...checkRequest,request_id});text(JSON.stringify({ request_id, result: r.structuredContent }));
```
