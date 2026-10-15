# ADR-049 — Per-conversation review mode and the hybrid default

**Status:** Accepted for [issue #1073](https://github.com/TheGaySupreme123/finishup/issues/1073)
(section 2.A, the FinishUP 0.3 relaunch) and [PR #1068](https://github.com/TheGaySupreme123/finishup/pull/1068).
Design gates: protocol, privacy/egress. Maintainer acknowledgement: the owner's brief on #1073
§2.A — every conversation starts local; the agent decides per task when AI-powered review is worth
it; choosing the recommended setup answer is the owner's standing permission for that; a strict
"local only, agents may not opt in" answer exists; existing installations keep their behaviour.
This ADR adds one released-family version (`decision_recorded` 1.1.0) and widens unreleased schema
versions in place (`check-recorded` and `check-result` 1.4.0, `status-result` 1.4.0,
`privacy-policy` 1.2.0, `event-draft` and `opaque-unknown-event-draft` 1.2.0). It adds no SQLite
migration. It grants no runtime, credential, disclosure, egress or destructive-action authority:
an agent's switch is a request, and disclosure stays bounded by the owner's repository policy, the
never-send set and the privacy gateway.
**Implemented by:** `src/finishup/domain/events.py` (`ReviewMode`, `DecisionRecordedPayload.review_mode`,
`CheckReviewMode`, `CheckRecordedPayload.review_mode`), `src/finishup/domain/privacy.py`
(`ConversationReview`, `PrivacyPolicy.conversation_review`, `effective_conversation_review`,
composition, diff order), `src/finishup/kernel/review_mode.py` (resolution),
`src/finishup/application/check.py` (`_resolve_check_review_mode`, applied after the case is
frozen), `src/finishup/application/status.py` (`status_review_mode`),
`src/finishup/application/egress.py` (owner-approval gate),
`src/finishup/service/ready_composition.py` (the reader and the background-advice gate),
`src/finishup/kernel/receipt_builder.py` (the receipt sentence),
`src/finishup/domain/review_mode_render.py`, `src/finishup/cli/render.py`,
`src/finishup/mcp/summaries.py`, `src/finishup/cli/setup.py`, `src/finishup/cli/privacy_setup.py`,
`src/finishup/cli/app.py` (`finishup privacy conversations`), `src/finishup/tui/`,
`scripts/generate_schemas.py`, `guidance/review.md`, `guidance/agent-instructions.md`,
`guidance/request-templates.md`, `guidance/consent.md`.
**Relates to:** ADR-006 (AI-powered review provider profile), ADR-009 (data egress and privacy;
decision 14 amended below), ADR-012 (first-run setup; review-mode recommendation amended below),
ADR-018 (MCP route ceiling), ADR-021 (recommended defaults).

## Context

Until now an installation had one review posture. A first run chose AI-powered review or local
only; the answer decided the registered MCP route (`policy` or `strict`) and, once a provider and
a privacy grant existed, every task asked for AI-powered review on every check. That made the
choice coarse in both directions: owners who wanted review only where it pays had to pay for it on
every typo fix, and owners who chose local only had registered a route that could never review a
task that needed it without re-registering the host connection.

The owner's 0.3 decision is a hybrid default. A task (a conversation: one FinishUP task and its
sessions) starts with FinishUP's local checks. The agent working on it decides, per task, when
AI-powered review is worth it and switches that task on; from then on that task's checks are
AI-powered until it switches back. The owner's recommended setup answer is the standing permission
for that switch. A strict "local only, agents may not opt in" answer stays available, and
existing installations keep their behaviour. The benchmark's arm D runs exactly this shipped
default, so it must work for an autonomous agent with one cheap call through the MCP tools every
host already has.

## Decisions

1. **The switch is a `decision_recorded` 1.1.0 draft.** 1.1.0 is an additive superset of the
   released 1.0.0 that requires one field, `review_mode: "ai_powered" | "local"`; 1.0.0 refuses it.
   A decision rides 1.1.0 exactly when it carries the switch, so every other decision keeps its
   1.0.0 bytes and every old ledger replays unchanged. The decision's event id and ledger sequence
   say when; its `authority` actor says by whom; its `rationale` says why. One `publish_work`
   draft is the whole opt-in, on every host (Codex, Claude Code, Cursor) through the same MCP
   path, and the CLI `publish` path accepts the same draft. The payload's `authority` is what the
   author declared; the event envelope's actor and its service-derived assurance say who recorded
   it, and the receipt credits the switch to that recorded actor (decision 8).

2. **A task's mode is resolved from its standing switches and the owner's setting.** The latest
   switch that is neither redacted nor superseded decides what the task asked for; without one the
   task asks for its owner default. `kernel/review_mode.py` turns that into what a check runs in.
   A task that asked for AI-powered review still runs local, with a closed reason, when the owner
   explicitly chose local only (`owner_local_only`), when the host connection is registered on the
   strict route (`route_local_only`), when the installation's verification settings turn review
   off for checks that name no mode (`review_disabled`), or when AI-powered review is not set up
   for the repository (`ai_review_not_set_up`), in that order. Under `ai_powered` (explicit, or the
   released reading of decision 4) the owner reviews every task: a switch to local is recorded but
   decides nothing, so no switch can drop the owner's required review (review round 1); such a task
   runs local only where review cannot run at all (`route_local_only`, `review_disabled`), and an
   unavailable reviewer keeps its honest required-review gap.

3. **The owner setting is `PrivacyPolicy.conversation_review`** (privacy-policy wire 1.2.0),
   narrowest first: `local_only`, `local_owner_approval`, `local_agent_opt_in` (recommended),
   `ai_powered`. It lives in the vault-backed policy, so an agent cannot change it by editing a
   file. Moving to a wider value is a widening and goes through the trusted decision ceremony;
   moving narrower applies at once. The repository row decides; the installation row is only the
   default a repository without its own value inherits; any narrower composition keeps the setting
   that needs more of the owner. `local_owner_approval` makes every AI-powered review in that
   repository (a switched task's, or an explicit per-check request) wait for the owner's
   per-request decision exactly like `confirm_every_request`. No value widens what may be sent.
   An explicit `local_only` is also enforced at the privacy gateway: `semantic-review` egress
   (checks and background advice) is refused `blocked_by_policy`, re-checked against the refreshed
   policy immediately before dispatch, so a failed setting read or a narrowing while a check is in
   flight cannot send a review; the fixed-literal credential probe keeps its own consent. A
   repository-bound proposal never widens the installation row's setting (like the
   credential-heuristic opt-out): an explicit row value stays as it is, and an unset row whose
   inference channel that proposal turns on (a fresh install's first grant) takes the narrower of
   the repository's answer and `local_agent_opt_in`, so other repositories do not fall back to
   the released "every task" reading and an "every task" answer never widens them (review round
   2); a row whose inference channel was already on keeps its released reading. A repository's
   first grant asks the conversation question whatever the installation row it inherits already
   sends, and the chat grant path, which asks nothing, starts there too (default
   `local_agent_opt_in`, or the installation row's own explicit setting where that is narrower).
   A first grant that sends nothing for review (Private) reads as local only, never as the
   inherited hybrid: because the repository row composes with the installation row, it records an
   explicit `local_only` where the composed policy it starts from carries a setting, and no
   setting where nothing is inherited (released bytes stay); the terminal and chat paths build the
   same candidate (review round 3). With a reviewer bound, `finishup --privacy`'s AI-powered
   review listing words Assisted review for the route: on an unreviewed route it is the default
   but not recommended, and its draft records no data-use evidence requirement.

4. **Upgrade rule: unset means released.** A policy written before the field existed encodes
   nothing, so its bytes, digest and every meet and receipt digest are unchanged. It reads as the
   released behaviour: `ai_powered` where its inference channel is on, `local_only` where it is
   off. Where the owner's policy has no explicit setting and the task recorded no switch, a check
   keeps its released behaviour exactly and records no review mode, so existing installations'
   checks and receipts do not change until the owner chooses a setting or an agent switches a
   task. Only an explicit `local_only` tells an agent the owner chose local checks; a released
   policy with inference off says `ai_review_not_set_up`.

5. **Check-time resolution happens after the case is frozen**, from the frozen projection and the
   owner's setting read at that moment, and its result is recorded on `check_recorded` 1.4.0 as
   `review_mode` (`mode`, `source` = `conversation_default` | `conversation_switch` |
   `check_request`, optional `local_reason`, and `switch_event_id` exactly when the task's own
   switch chose it). Replay reads the recorded value; nothing is re-derived. A check that names no
   mode runs in its task's mode: in a local task it becomes `deterministic_only` on a route that did
   not require AI-powered review (`semantic_route_required: false`), so it completes at local
   coverage and discloses that. A check that names an AI-powered mode is its own one-check request
   under the effective policy; under an explicit `local_only` it runs local, and a
   `semantic_required` request there keeps its requirement, so the missing review stays an honest
   gap rather than a clean local result; on the strict route it records `route_local_only`. A
   check that names `deterministic_only` lowers the requirement only in a task local by a choice
   its owner's setting allows. A `final_review: true` check that names no mode, in a task that
   already used AI-powered review (a recorded check whose review succeeded, or that deferred a
   required review before the first edit) and now runs local, is the closing review the task owes:
   it runs as its own request (`source` `check_request`) under the effective policy (review round
   1). Where the owner's setting cannot be read the check fails closed: a check that names no mode
   runs local checks only under the configured requirement and records no mode, and a check that
   named its mode keeps it while the gateway enforces the policy.

6. **Availability** (`ai_review_available`) means a reviewer is bound with AI-powered review not
   disabled, its credential or subscription login is structurally present (the same memoized
   facts provider status reads; an unreadable fact counts as present, so a locked vault never
   strands a switched task), the repository has a privacy grant of its own, and the composed
   policy's inference channel is on. A task without a repository-bound route reads the
   installation-wide setting and reports review unavailable; so does a repository without its own
   grant (review round 2): status, the terminal interface and `finishup privacy conversations
   status` say "AI-powered review is not set up for this repository", its checks follow the
   inherited setting (under the hybrid they complete locally) and an agent's opt-in there records
   `ai_review_not_set_up`. Under a released installation row (unset, inference on) such a check
   still takes the released repository-grant handoff.

7. **Status shows the mode** (`status-result` 1.4.0 `review_mode`: `mode`, `requested`, `setting`,
   `setting_explicit`, `ai_review_available`, optional `local_reason`, `switch_event_id`,
   `switch_sequence`), read from
   the head projection on the serving route, never at `at_frontier`. `mode` is what the next check
   that names no mode runs in. Closure readiness (status, the inspection check, the Stop gate)
   follows the same rule as the check: a task that runs local by its owner's explicit setting or
   its own switch is not asked for an AI-powered review it will never run (neither
   `semantic_review_not_requested` nor `closing_review_required` as agent work), while a task under
   a policy that predates the setting keeps the released requirement, and under `ai_powered` no
   task is local by choice. A task that already used AI-powered review still owes its closing
   review after it runs local again; the Stop gate's `check` with `final_review: true` supplies it
   (decision 5). The switch is itself that material delta: a `decision_recorded` that sets
   `review_mode` is a `closing_review_delta` (`kernel/closing_review_delta`, ADR-033). A decision
   that leaves `review_mode` unset stays bookkeeping and does not ask for another closing review.
   A check whose recorded mode carries a `local_reason` asked for review that its
   task's setting kept local, so no recheck can supply it: like an undeliverable review status, it
   makes the closing review current rather than owed forever. A released `local_only` reading
   (`setting_explicit` false) is worded "AI-powered review is not set up for this repository", not
   as the owner forbidding opt-in, in status, the terminal interface and
   `finishup privacy conversations status`.

8. **Every rendering says which mode and why.** CLI check, status and JSON receipt, the terminal
   interface (which uses the CLI renderers), and the MCP summaries print one "Review mode: local
   (FinishUP); ..." or "Review mode: AI-powered review; ..." line from one shared module, closed
   tokens and validated event ids only. A task that asked and still runs local gets the exact
   continuation: `ai_review_not_set_up` names the one-time owner setup (`finishup --set`, or
   `finishup provider codex-subscription setup`, then `finishup --privacy`; `finishup provider
   status` shows what is missing); `owner_local_only` says plainly the owner chose local only;
   `route_local_only` names `finishup setup run --route-profile policy`; `review_disabled` says the
   verification settings turn review off. The receipt's `limitations_and_coverage` section names
   each standing switch by sequence, event id, the actor the ledger recorded (actor id, actor type
   and assurance) and the declared `authority`, then the mode the applicable check ran in; a task
   without a switch whose applicable check recorded a mode gets the mode sentence alone (a local
   one: "The applicable check ran local checks only (FinishUP); AI-powered review was not requested
   for this task."). A check that recorded no mode (a policy that predates the setting, no switch)
   adds nothing, so released receipt bytes stay. The MCP receipt summary points at those
   sentences with fixed wording ("review mode switched in this task ...", "review mode: local
   (FinishUP); limitations section says how the check ran") for a JSON receipt; a markdown or
   text receipt's summary carries no pointer (its human text is the receipt itself, and matching
   fixed openings there could match recorded prose). No decision statement or rationale reaches
   any MCP text. The wire shape has golden vectors (`fixtures/canonical/review-mode-1.4.0`,
   CAN-020; renumbered from CAN-018 at the release merge, which the publish-action-notices
   vectors already held).

9. **First-run setup asks three answers, all on the policy route.** (1) "FinishUP
   (recommended): local checks; your agent can turn on AI-powered review for a task when it
   helps" — reviewer setup plus a privacy policy carrying `local_agent_opt_in`; (2) "FinishUP,
   local only (agents may not opt in)" — the Private recipe carrying an explicit `local_only`;
   (3) "AI-powered review on every task" — `ai_powered`. The default is (1). All three register the
   `policy` MCP route so the owner can let an agent opt in later without re-registering; the
   privacy policy, not the route, decides what may be sent. The prompt wizard, the host-connection
   path and the terminal interface's first run ask the same question and set up what it chose;
   so does `/connect` for Claude Code and Cursor. Codex `/connect` asks no review question: it
   inspects or repairs the connection on its configured route (the Codex runbook says so), and
   `finishup setup run --route-profile policy` re-registers a strict one. Answers (1) and (3) list the privacy recipes with `assisted_review` as the
   default choice, marked recommended only for a provider route with reviewed data-use evidence
   (never the released Private recommendation a subscription reviewer would get); Private stays
   selectable and warns that tasks stay local under it. Answer (2)'s Private confirmation defaults
   to Yes: it is a narrowing the owner already chose. A first AI-powered review grant made
   later through `finishup --set` or `--privacy` asks the same conversation question once
   (default `local_agent_opt_in`); re-approving a policy that already sends work asks nothing and
   keeps its setting. With a reviewer bound, `finishup --privacy` lists the AI-powered review
   recipes (Assisted review by default, recommended only on a reviewed route, the Private warning)
   instead of the released recommendation on a repository's first grant and wherever tasks start
   local under agent opt-in or owner approval, so a subscription reviewer's owner is not granted
   Private on Enter (review round 3); with no reviewer bound, or an unset setting on an existing
   grant, it keeps the released recommendation. `finishup privacy conversations agent-opt-in|
   owner-approval|local-only|ai-powered|status` changes and shows it for the current repository;
   in a repository without its own grant any setting but local only walks that repository's grant
   with the setting drafted in, inherited or not (review round 3), and needs a local terminal.

10. **Non-interactive setup keeps the strict default for a fresh registration** and preserves an
    existing route (#389 / ADR-018). It answers no review question and writes no privacy policy,
    so a policy route would let nothing more happen until the owner sets up AI-powered review
    interactively, which offers the re-registration; a harness that wants agent opt-in passes
    `--route-profile policy` explicitly.

11. **Background advice stays under the released rule.** Background observation advice is not a
    check any task asked for, and an owner-approval setting cannot hold a background request for a
    human, so it dispatches only where the owner's effective setting is `ai_powered` (including
    every released policy with inference on). A switched task gets AI-powered review on every
    check; it does not start background advice. Admission applies the same test, so a repository
    whose tasks start local writes no advice row; the dispatch check stays as a backstop.

## Alternatives rejected

- **A dedicated event family for the switch.** Cleaner to read, but a new family needs migration
  0017 to rebuild the events table's family check, which is design-gated storage work; the
  projection already keeps decisions, their supersession and redaction. Revisit if a later change
  needs the switch to carry more than a mode.
- **Keep the route as the review switch.** A strict registration cannot review a task that needs
  it, and a re-registration is a host change the agent cannot make; the route stays a ceiling an
  owner may still choose (`--route-profile strict`), not the mode.
- **Seed the hybrid into every new installation's durable policy.** It would change the seeded
  policy bytes every installation and fixture shares; the explicit setup answer carries it instead.
- **Strict route for the local-only answer.** It would refuse a later opt-in without re-registering,
  which the owner asked to avoid.

## Consequences

Under the hybrid default a typical task costs local checks only, and AI-powered review runs where
the agent judged it worth it, with every switch on the record and in the receipt. An agent that
switches where nothing is set up, where the owner chose local only, or on a strict route keeps
working locally with the exact continuation. Existing installations see no change in their checks
or receipts until their owner chooses a setting. Owners who chose the local-only answer now run on
the policy route; host auto-reviewers that hold every open-world `check` (ADR-018 issue #467
amendment) can hold their checks too until the owner grants host admission or re-registers with
`--route-profile strict`.

## Risks and open questions

- **Overloading `decision_recorded`.** Readers that list decisions see switches as decisions; that
  is intended (a switch is a decision on the record), but a future reader that wants only plan
  decisions must filter `review_mode`.
- **Status reads the head, not `at_frontier`.** A status read pinned to an earlier frontier still
  reports the current mode; the check's recorded `review_mode` is the per-check truth.
- **Availability is structural.** A present but rejected credential or an expired subscription
  login still reads available; the check then reports the provider outcome honestly.
- **Strict-route registrations from earlier local-only setups** cannot opt in until the owner
  re-registers; the `route_local_only` continuation names the command.
- **Background advice under the hybrid** is off by decision 11; a follow-up may let a switched
  task under `local_agent_opt_in` admit it.

## Host and platform decisions

Codex, Claude Code and Cursor: the same MCP path (one `publish_work` draft, then checks that name
no mode). No host-specific behaviour. The startup guidance points at `review.md`, where the
trigger-first procedure lives, inside the 8 KiB startup budget. macOS, Linux and WSL 2 behave the
same; nothing here is platform-specific.

## Verification

`tests/unit/kernel/test_review_mode.py`, `tests/unit/application/test_check_review_mode.py`,
`tests/unit/application/test_conversation_review_egress.py`,
`tests/integration/application/test_conversation_review_mode.py`,
`tests/integration/closure/test_review_mode_closing_review.py`,
`tests/integration/service/test_review_mode_second_repository.py`,
`tests/unit/protocol/test_review_mode_fixture.py`, `tests/unit/mcp/test_summaries_receipt_review_mode.py`,
`tests/unit/cli/test_elevated.py`,
`tests/unit/application/test_privacy_policy.py`, `tests/tui/test_commands.py`,
`tests/integration/service/test_ready_composition.py`,
`tests/unit/domain/test_decision_review_mode.py`, `tests/unit/domain/test_review_mode_render.py`,
`tests/unit/privacy/test_conversation_review_policy.py`,
`tests/unit/cli/test_privacy_conversations.py`,
`tests/unit/cli/test_privacy_setup_conversation_question.py`,
`tests/unit/cli/test_setup_review_mode.py`, `tests/subprocess/test_setup_wizard_cli.py`,
`tests/tui/test_first_run.py`, `tests/conformance/surfaces/test_review_mode_guidance.py`,
`tests/conformance/surfaces/test_host_mandatory_guidance_budget.py`.
