# Elevated bootstrap peer patterns

Sources: ADR-015, ADR-016, `guidance/agent-instructions.md`, Codex sandbox/approval docs,
Claude Code permission-mode docs, MCP elicitation spec, and Cursor Cloud environment notes.

## Peer pattern summary

- Agent hosts separate technical containment from human approval. A sandbox, VM, or egress
  allowlist does not establish that a human approved one exact FinishUP operation.
- MCP elicitation may present reviewable non-secret information, but it does not establish a
  verified client/user authority channel and must not expose passwords, API keys, or equivalent
  secrets to the model.
- Out-of-band human interaction is strongest when the approval surface displays the exact target
  and keeps both authority and secret entry outside the agent-visible channel.

## Mapping to ADR-015/016

- `prepare` lets an agent request elevation and inspect only operation, risk class, bounded danger
  text, exact digests, expiry, pending ID, and the fixed `finishup consent review` command.
- `review` requires a verified foreground console, reloads and validates the pending record, and
  consumes the request once on approval, denial, cancellation, expiry, or failure.
- Vault initialization generates and verifies its secret inside the trusted helper. Provider
  credential set/rotate collect their secrets inside the same confidential review surface.
- There is no standing FinishUP `--yolo`, agent-held grant, generic headless passphrase/unlock API, or
  authority-bearing caller argument.

## Agent-facing status

- Report the v2 pending projection exactly and refuse preparation when catalog
  `implemented=false`.
- Ask the human to run `finishup consent review` directly in a foreground console.
- If the console or pending validation is unavailable, report the bounded structural error and do
  not suggest another approval or secret channel.
- After completion, expose only sanitized structural success/failure/audit facts.

## Never expose to an agent-capable channel

- Vault passphrases, reauthentication secrets, provider API keys, access tokens, OAuth/device
  codes, or recovery material.
- Any reusable approval value, generated initialization passphrase, credential-store value,
  confidential transport detail, bearer capability, or vault capability.
- Owner-only pending paths, environment secret values, process arguments containing secrets,
  config files containing secrets, prompts/transcripts, or hidden reasoning.
