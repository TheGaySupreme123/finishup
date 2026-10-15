# Consent topic

Read this topic before setup, privacy, settings, provider credentials, vault operations, imports,
or recommendation decisions. Normal conversation is the primary setup path, but a request is not
authority. Explain the exact choice and trade-off, then wait for the user's explicit current choice.

Recommendations are advisory: never silently choose a recipe, provider, model, target, privacy
level, or ceremony. For semantic review, explain `expanded_review` first, `assisted_review` as the
lower-disclosure option, `metadata_only` as structural review with per-request confirmation, and
`private` as no external semantics. Intent is not grant approval.

Use the trusted local `finishup consent review` / `finishup --privacy` route, or relay one exact pending
`authorize_command` target when the current host advertises that lane. On an install upgraded
through the transitional `yoetz` package, run these with the launcher the pending
`review_command` names. Show the danger text,
operation, digests, recipe, and complete `repository_privacy_preview`; warn once before credential
ingress. Relay only the exact pending fields. Keep credentials out of argv, environment, config,
MCP arguments, logs, and files. Never ask for or handle a vault passphrase. Denial, expiry, stale
authority, or incomplete review means no dispatch and no mutation.

A portable plugin is a carrier only, and its MCP ownership is mode-specific and exclusive:
`external_registration` omits `mcp.json`, so the existing host registration remains the sole owner;
`plugin_managed` includes the selected `mcp.json` route; this plugin is the sole owner, so do not
keep a duplicate native, project, user, or global registration.

Turning on AI-powered review for one task (a `decision_recorded` 1.1.0 `review_mode` switch,
[`review.md`](review.md)) is not a privacy decision and needs no new consent where the owner's
setting is `local_agent_opt_in`: the owner gave that standing permission at setup. Under
`local_owner_approval` each review still waits for the owner; under `local_only` the task stays
local; under `ai_powered` every task is reviewed and a switch to local changes nothing. Only the
owner changes the setting (`finishup privacy conversations`): through the trusted ceremony when it
needs less of them, at once when it narrows.

Activation, installation, registration, and a host approval do not prove that the route is live or
that semantic review ran. Provider credentials require the repository grant and the exact
provider/model/endpoint profile. Use [`request-templates.md`](request-templates.md#setup-and-consent)
for complete bodies and the supported continuation.
