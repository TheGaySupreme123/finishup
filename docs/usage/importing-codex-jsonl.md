# Importing bounded Codex JSONL

`finishup import` is a local support command for a retained `codex exec --json` stream. It is not a
seventh MCP operation, does not read Codex rollout files, and does not authorize AI-powered review
or any other network disclosure.

The request names an already-open FinishUP session/writer, the exact supported Codex profile, and at
most 4 MiB of base64-encoded JSONL. Stderr is excluded in this version:

```json
{
  "schema_version": "1.0.0",
  "codex_capability_profile_id": "codex-exec-jsonl/0.139.0/v1",
  "codex_version": "0.139.0",
  "exit_status": 0,
  "mapping_version": "codex-jsonl/1.0.0",
  "request_id": "req_...",
  "session_id": "ses_...",
  "source_bytes_base64": "...",
  "source_encoding": "base64",
  "source_kind": "file",
  "stderr_captured_bytes": 0,
  "stderr_present": false,
  "stderr_truncated": false,
  "writer_id": "wri_..."
}
```

Run `finishup import --input request.json --json`. The first call stores the encrypted source and
exact publication plan but publishes nothing. It returns `PRIVACY_AUTHORITY_REQUIRED`; inspect
`finishup consent status --json`. The pending item shows bounded danger text and a structural preview
with source/manifest/plan/target digests, the exact task/session/profile, counts, and enforced
limits. It never includes transcript lines or excerpts, and it explicitly reports reasoning and
reviewer-egress inclusion as false.

Approve from a supported trusted local review surface, or ask a capable first-party agent to relay
an explicit current-chat decision for that exact pending item after it shows you the warning. A
chat relay is agent-attested, not host-verified proof. Denial publishes nothing.

After approval, replay the identical import request. The owner-only authorization is not a token
you copy into the request: FinishUP matches it internally, resumes the stored plan, publishes bounded
batches plus one import-report evidence event, and consumes the authorization at terminal
completion. A changed source, manifest, request target, session, profile/version, mapping version,
plan, or limit contract needs a new preview and decision.

The parser excludes reasoning and keeps malformed, unknown, oversized, or unsupported records as
explicit coverage gaps. The encrypted exact source remains local. Imported events therefore prove
only what the bounded import observed; they do not gain cooperative authorship or hook-observed
coverage.
