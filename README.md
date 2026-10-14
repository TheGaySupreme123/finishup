<p align="center">
  <a href="https://finishup.dev"><img src="https://raw.githubusercontent.com/TheGaySupreme123/finishup/main/landing/public/assets/finishup-logo.png" alt="FinishUP" width="320"></a>
</p>

<h1 align="center">Agents claim they're done.<br>FinishUP checks if they actually did.</h1>

<p align="center">
  <a href="https://pypi.org/project/finishup/"><img src="https://img.shields.io/pypi/v/finishup?style=flat-square&label=PyPI" alt="PyPI version"></a>
  <a href="https://github.com/TheGaySupreme123/finishup/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="Apache-2.0 license"></a>
  <a href="https://github.com/TheGaySupreme123/finishup/actions/workflows/pr-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/TheGaySupreme123/finishup/pr-ci.yml?branch=main&style=flat-square&label=CI" alt="CI status"></a>
</p>

<p align="center">
  <a href="https://www.producthunt.com/products/yoetz?embed=true&utm_source=badge-featured&utm_medium=badge&utm_campaign=badge-yoetz"><img src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1254021&theme=light&t=1789716006971" alt="FinishUP - Check to see if AI really completed a task or if it had gaps | Product Hunt" width="250" height="54"></a>
</p>

<p align="center">
  <a href="https://finishup.dev">finishup.dev</a> ·
  <a href="https://github.com/TheGaySupreme123/finishup/tree/main/docs/usage">Docs</a> ·
  <a href="https://github.com/TheGaySupreme123/finishup/releases">Releases</a> ·
  <a href="https://github.com/TheGaySupreme123/finishup/blob/main/CHANGELOG.md">Changelog</a>
</p>

FinishUP is a local-first, open-source system for recording structured work evidence, checking it
with local checks, and producing **honest receipts about what was and was not verified**.

It is built for agent-assisted work. An agent publishes bounded facts about what it is doing — plan,
claims, actions, results, evidence — into a local ledger; FinishUP checks that record with versioned
local policy packs, optionally adds advisory AI-powered review inside a privacy policy you
control, and issues a receipt whose wording never outruns its coverage.

The thing FinishUP refuses to do is the point. It will not tell you work is correct. It will tell you
exactly what was checked, at what coverage, and what remains open.

## What it looks like

```text
$ codex
› Refactor the rate limiter. Keep the /limits response shape and make sure tests pass.

• I'll plan this first and record the obligations in finishup.

• Called finishup.start
  └ task tsk_9c2e1b40 · session ses_9c2e1b40-01
• Called finishup.publish_work
  └ accepted · plan + 3 obligations

• Edited src/limiter.py (+118 -74)
• Ran pytest -q
  └ 41 passed

• Tests pass. Checking with finishup before I claim done.

• Called finishup.check
  └ action_required · 2 findings
    ✗ stale_evidence_for_changed_state — "tests pass" cites a run older than the last edit
    ✗ requested_item_never_attempted — the /limits response shape was never verified

• Fair catch. Fixing, then re-running.

• Edited src/limiter.py (+9 -4)
• Ran pytest -q
  └ 43 passed
• Called finishup.respond
  └ acknowledged
• Called finishup.check
  └ no_issue_detected
• Called finishup.receipt
  └ unresolved_findings_remain · deterministic · coverage-bounded

Done. The limiter is refactored, and the receipt still carries the two findings I hit on the way.
```

Both findings map to real rules in the shipped local policy pack, checked against nothing
but the published record — no repository access, no model, no interpretation. And the receipt keeps
carrying them after the fix: a later clean check never erases what was caught.

## Install

```sh
# Install the latest published version from PyPI — the canonical distribution
uv tool install --managed-python --python 3.14.6 finishup

# Via npm — a dependency-free launcher that makes the same persistent uv install (needs uv)
npx finishup

# One-off run without installing (needs uv: https://docs.astral.sh/uv/)
uvx --python 3.14 finishup
```

FinishUP needs Python 3.14. You do not need to have it: `uv` downloads the exact interpreter on
demand, whatever other Pythons are on the machine, and the install is not affected by them.
`pip install finishup` on an older Python cannot work, because the package requires 3.14. The npm
package bundles no Python and no FinishUP code and never installs `uv` itself; it makes the same
`uv tool install` and launches the exact matching Python distribution. FinishUP runs on macOS and Linux (certified on
macOS arm64 and Linux x86-64 (glibc 2.28+); other Linux architectures install and report themselves as untested —
see [Linux](docs/usage/install-and-first-run.md#linux)); on Windows, install it inside WSL 2 — see
[Windows](docs/usage/install-and-first-run.md#windows).

> [!TIP]
> **Let your agent set it up.** Paste this into your coding agent and it walks you through
> installation, showing you every proposed change first:
>
> ```text
> I want to install FinishUP (https://github.com/TheGaySupreme123/finishup). Start by fetching its
> agent install guide and follow it exactly:
>
> curl -fsSL https://raw.githubusercontent.com/TheGaySupreme123/finishup/main/docs/usage/agent-start.md
>
> It tells you what to run yourself, what to ask me, and where to hand me the terminal. If your
> sandbox blocks that fetch, ask me to approve it or to paste the guide. Setup's questions are
> mine to answer, so ask me each one and wait, and show me any proposed change before it is
> applied.
> ```

`finishup` at a terminal opens a full-screen interface, and the first run walks setup inside it:
what was detected, whether you trust this project, the exact proposed change, and an explicit
approval before anything is applied. You do not need to know what MCP, hooks, policy digests, or
vaults are to finish it, and you are never asked to configure a provider — local verification is
complete without one. Everything non-interactive is unchanged: pipes, redirects, CI, `--help`,
`--json`, named subcommands, and `finishup mcp serve` behave exactly as before, and `FINISHUP_TUI=0`
selects the prompt-loop menu instead.

Full walkthrough: [Install and first run](docs/usage/install-and-first-run.md) and
[The terminal interface](docs/usage/terminal-interface.md). A coding agent installing FinishUP for
its user should follow [Agent start](docs/usage/agent-start.md): setup's questions appear only on
the human's own terminal, and that page says what to run, what to ask, and what to recommend.

Harness observation is opt-in per project, and source files and configuration are never
activation proof. For Codex, setup offers one standing-trust preview bound to the exact selected
Codex executable and an explicitly selected, existing Codex home. Before consent, only that
executable's `--version` runs, with both Codex home variables redirected to a fresh owner-private
temporary home that is removed afterward; setup does not inspect the approved home's plugin
inventory. Only explicit digest-bound approval permits the scoped inventory/add commands and
disclosed marketplace, config, scratch, and versioned-cache effects in the selected home. Claude
Code and Cursor hooks are installed through `finishup integrate claude ...` and
`finishup integrate cursor ...` with the same preview-then-approve shape. What a hook keeps differs by
host: consented Codex events may retain secret-scanned, encrypted tool output and changed-file
bytes as captured evidence; Claude Code and Cursor hooks keep only structural facts — FinishUP tool
names, lifecycle events, digests — and discard prompts, transcripts, paths, and results before
storage. Under every host, even an `active` result proves installed inventory and cache/config
state for future sessions—not that a later session loaded a hook or delivered an observation.

## What's in the box

| | |
| --- | --- |
| **Six operations, two surfaces** | `start`, `publish_work`, `check`, `respond`, `status`, `receipt` — identical contracts on the CLI and over MCP. Everything else is a bounded support surface, not a seventh operation. |
| **Works with any MCP agent** | No integration, no installed skill, no configuration. Codex, Claude Code, and Cursor have first-party integrations because each host's skill or plugin surface delivers the guidance natively — but integration buys ergonomics, never a stronger claim. |
| **Honest receipts** | Coverage, provenance, freshness, findings, and limitations stay separate. A clean local check is never presented as proof that work is correct. |
| **Zero-egress by default** | A fresh installation runs local checks only and is fully useful offline; nothing leaves your machine before first-run setup commits a policy. |
| **Privacy-gated AI-powered review** | An optional reviewer model reads a bounded, minimized packet built from the ledger — never your repository — behind explicit provider binding and reauthenticated policy authority. |
| **A full-screen terminal interface** | First run, status, privacy, provider, integration, service, and receipt flows in one interface; no secret ever enters it. |
| **Recoverable local durability** | Encrypted task bundles, generation-fenced single-writer storage, deterministic replay, backup/restore, and forward-only migrations. |

See [The six operations](docs/usage/six-operations.md) for the protocol and
[Receipts and coverage](docs/usage/receipts-and-coverage.md) for what a receipt does and does not
say.

## Private by default

A fresh installation's unconfigured seed is **zero-egress and local-only**: nothing leaves your
machine before first-run setup commits a policy, and FinishUP is fully useful in that state. Setup's
proposed privacy policy states whether FinishUP may check PyPI for package updates (default yes, with an
opt-out). That bounded check carries only the `finishup` package identity and version, never task or
user content, and it never upgrades the package for you; decline it for a zero-network installation.
Rerunning setup does not suspend or revoke an existing standing policy: ordinary activity remains
governed by that policy until the user commits a replacement.

External AI-powered review is a separate explicit decision. When you choose it, the CLI's
recommended `assisted-review` recipe shows and confirms a standing policy that sends the reviewer a
structured packet built from the ledger — goal, obligations, claims, timeline, local findings and
their bases, coverage gaps, and bounded problem-local excerpts already recorded in the case.
Sensitive and confidential content is off, and the never-send set is absolute. Policy loosens only
through a reauthenticated decision you make: the trusted local ceremony, or your explicit
current-chat approval of one exact prepared, previewed, expiring consent target that a capable agent
relays for you. That relay is the agent's assertion, which FinishUP cannot independently authenticate,
so the local ceremony remains the stronger path.

Provider setup distinguishes **OpenAI API / compatible API** from **Codex with ChatGPT
subscription**. The subscription route binds one exact Codex app-server and dedicated home; Codex
owns ChatGPT login and the upstream OpenAI request, while FinishUP receives no OAuth credential. It
still sends only the privacy-approved packet and records the weaker observable boundary explicitly.

Review then runs direct-to-agent: the reviewer returns a bounded challenge, the agent acts, supplies
evidence, revises, disputes, or states a limitation, and rechecks. No human prompt for routine
retries.

See [Privacy and AI-powered review](docs/usage/privacy-and-semantic-review.md) and
[`PRIVACY.md`](PRIVACY.md).

## How it is put together

One trusted persistent local service owns the encryption keys, decrypted state, storage writers,
privacy authority, and provider access. CLI, MCP, and the terminal interface are clients — they
hold none of those things. The interface in particular is presentation only: it dispatches through
the same application services the commands do, and no secret ever enters it, because credential
entry suspends the interface and hands the terminal to the existing confidential ceremony.
External disclosure is denied by default and must pass centralized classification, policy,
minimization, secret scanning, exact destination binding, and durable structural audit.

See [Architecture](docs/architecture.md).

## Releases you can verify

Every release is more than a tag. The tag workflow builds each distribution once, tests those exact
candidate bytes, publishes them to PyPI and npm through dedicated approval environments, and
attaches the same approved artifacts to the
[GitHub release](https://github.com/TheGaySupreme123/finishup/releases) alongside `SHA256SUMS`, an
SBOM, the support matrix, known limitations, the release-evidence bundle, and a `VERIFY.md` that
walks through checking the bytes you installed. Post-publication jobs re-download the public
artifacts and compare them to the approved bytes.

Release notes are curated by hand for every release — highlights, an explicit "what this release
does not claim" section, and the full changelog — and live versioned in
[`docs/releases/`](docs/releases/).

## Documentation

- [Using FinishUP](docs/usage/) — install, the terminal interface, operations, privacy, providers,
  receipts.
- [Architecture](docs/architecture.md) — topology, module map, honesty rules.
- [`docs/adr/`](docs/adr/) — architecture decisions; the top authority for public behavior.
- [`docs/INTERFACES.md`](docs/INTERFACES.md) — shared names, types, ports, trust boundaries.
- [`docs/OPEN_QUESTIONS.md`](docs/OPEN_QUESTIONS.md) — the decision ledger: every decision taken,
  each release gate's dated disposition, and what evidence a stronger claim would need.
- [`docs/`](docs/) — full index, including protocol pages and runbooks.

## Status

FinishUP **0.3.0** is the next public-alpha release candidate. It lets several agents work in
independent tasks within one repository, adds a backup-first upgrade path for 0.2 task data,
and carries every 0.2.2 install fix. **0.2.2** remains the published release until the release
gates pass; see the [0.3.0 notes](docs/releases/v0.3.0.md) for changes and validation limits.
Every public claim in
[`docs/public-claims.json`](docs/public-claims.json) is bound to real checked-in evidence: a claim flagged `evidenced` has concrete test or fixture coverage, with its non-live
suites exercised in per-PR CI; a claim whose own wording names still-missing capability or drill
evidence stays `not_yet_evidenced` and is not asserted as release evidence. Every reviewed provider
preset resolves to a real runtime
factory, so a preset you can select is a preset FinishUP can dispatch — but none of the non-official
presets has recorded live evidence yet, so none is claimed as a confirmed working endpoint. That
claim stays gated by the capability evidence described in
[ADR-006](docs/adr/ADR-006-semantic-provider-profile.md).

## Contributing

Contributions are welcome with a high bar: search for duplicates, open an issue first, wait for
maintainer acknowledgement on design-gated areas, and disposition every review comment — including
code-review agents — before merge. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`AGENTS.md`](AGENTS.md).

- Bugs and change requests: GitHub issues (use the forms; blank issues are disabled).
- Security: [`SECURITY.md`](SECURITY.md) — private vulnerability reporting or `support@finishup.dev`.
- Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — `support@finishup.dev`.

Private strategy and architecture drafting inputs under `docs/architecture/` are intentionally
gitignored. The public ADRs, docs, code, and tests must remain self-contained without them.

Licensed under the [Apache License 2.0](LICENSE), using the official unmodified license text and the
SPDX expression `Apache-2.0`; FinishUP does not add a fabricated project-wide ownership notice.
