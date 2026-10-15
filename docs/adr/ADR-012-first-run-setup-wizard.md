# ADR-012 — First-run setup wizard, automated MCP registration, and the npm launcher

**Status:** Working decision (2026-07-22), founder-authorized amendment of ADR-007 decisions 3, 7,
and 9. Release ratification still requires the packaging evidence gates those decisions already
carry; nothing here manufactures platform or capability evidence.
**Implemented by:** `src/finishup/ports/harness_mcp.py`,
`src/finishup/application/harness_mcp.py`,
`src/finishup/adapters/integrations/codex_discovery.py`,
`src/finishup/adapters/integrations/codex_mcp.py`,
`src/finishup/adapters/integrations/codex_marketplace.py`, `src/finishup/cli/setup.py`,
`support/npm-launcher/package.json`, `support/npm-launcher/bin/finishup.js`,
`support/npm-launcher/README.md`, plus the amended `src/finishup/cli/app.py`,
`src/finishup/config/paths.py`, and `docs/runbooks/codex-integration.md`; the 2026-10-14
several-projects amendment by `src/finishup/adapters/integrations/host_projects.py` (record and
setup lock), `src/finishup/application/host_connection.py` (`SharedProjectsStep`,
`apply_connection`), `src/finishup/cli/codex_connection.py`, and `src/finishup/cli/host_connection.py`
(continuations).
**Relates to:** ADR-005 (Codex capability identity), ADR-007 (packaging/release), ADR-009
(privacy/egress), ADR-010 (harness integration port).

## Context

A fresh `uvx finishup` landed a new user in front of a help screen and a runbook: find Codex, run
`codex mcp get`/`codex mcp add` by hand, start the service, run privacy setup, then the
credential ceremony. Every one of those steps was correct and deliberately manual, but nothing
connected them, and the npm ecosystem had no path at all — ADR-007 deferred `npx finishup` until it
had "its own provenance, Python/uv delegation, upgrade, and platform contract". This ADR supplies
exactly those contracts and connects the steps without weakening any existing trust boundary.

## Decisions

1. **`finishup setup` is a new top-level support sub-app** with `run` (the wizard) and `status`
   (read-only posture). The wizard orchestrates only operations a local human could already run by
   hand: Codex discovery, the runbook's check-then-add MCP registration behind
   preview→confirm→execute, a service reachability check, and the existing privacy and
   provider-credential ceremonies. Founder-authorized amendment (2026-08-04): before registration,
   interactive first run chooses a complete `local_only` path or an AI-powered review path.
   Founder-authorized amendment (2026-08-05): the AI-powered review path is offered first and is the
   pre-selected answer in both the prompt-loop wizard and the terminal interface. This is a property
   of that question only. It changes no seeded state: the durable policy an installation starts with
   is still `local_only`, the answer binds no provider, stores no credential, and commits no policy,
   and local-only remains one keystroke away. The reason for the recommendation is that an
   installation that never reaches the AI-powered review path can only ever report local-check
   coverage, and a first-run default that quietly guarantees that outcome under-serves the operator
   who came for review. The same amendment requires that the answer be taken *before* the MCP
   registration it determines, and that the registered route follow from it — registering first and
   asking after is how an AI-powered review install ends up ceilinged on the strict route. The
   latter path registers the policy route, configures the provider and credential, then renders one
   exact recommended `assisted_review` policy only when the exact provider route has current
   reviewed no-training evidence and retention no longer than 30 days; otherwise it recommends
   `private`. Accepting that exact draft asks nothing further; declining it opens the named recipes,
   which materialize directly into a draft, with only `custom` reaching field-level configuration in
   five grouped sections. Both paths propose the reviewed exact disclosure and hand widening to the
   separately reauthenticated trusted decision ceremony. On a real local TTY it may invoke the
   already-reviewed hidden-input vault initialize/unlock and credential ceremony; it adds no secret
   field to wizard arguments, configuration, reports, MCP, or agent context. Noninteractive setup
   remains a report plus explicit follow-up commands and never chooses egress. The AI-powered review
   `assisted_review` is repository-scoped, problem-local, and does not require recurring prompts
   after its trusted policy commit. Unknown, stale, broad, or account-unqualified evidence never
   earns the recommendation and remains an informed explicit choice only. It is a starting draft,
   not consent. `private` remains the fail-safe no-egress choice, while Metadata only, expanded, and
   custom policies remain explicit. `finishup --privacy` enters the same short recommended-first
   ceremony at any later time. **Amendment (issue #164, 2026-08-09):** when a user asks a capable
   first-party agent for help finishing exact provider credential or repository privacy setup, the
   agent may relay an explicit current-chat instruction through `finishup consent authorize` after one
   warning without requiring a second local-terminal ceremony. FinishUP binds the exact action but
   cannot independently authenticate the chat provenance; the trusted CLI/TUI remains recommended
   and always available. The setup update advisory's version parser is a declared, exactly pinned
   core dependency; a clean installed-artifact gate imports and enters `setup run` so
   development-only transitive packages cannot hide a missing runtime dependency. **Amendment
   (issues #204 and #205, 2026-08-12):** first-run setup asks whether the proposed privacy policy
   should enable the structural PyPI update check (default yes). It carries that boolean into the
   recommended or named recipe before rendering the exact candidate; it changes no other recipe
   field, creates no authority itself, and never bypasses candidate confirmation or the existing
   trusted service decision ceremony. Declining produces the genuine zero-network `private`
   candidate rather than silently restoring the recipe default.

   Repository scope comes only from the service's trusted locator path. CLI and TUI supply their
   actual working directory; MCP supplies its configured/session working directory. The service
   resolves the canonical Git common root (or resolved non-Git directory), commits it under the
   installation key, and discards the raw path. Public `workspace_ref` remains a task-attachment
   selector and cannot select privacy authority. A proposal for a new repository may combine a
   necessary machine-ceiling widening with insertion of the first repository row; setup renders the
   complete two-part change and binds one approval to one authority digest and atomic CAS.

   Upgrades preserve previously accepted machine-policy bytes. Eligible pre-upgrade routes consume
   bounded migration entitlements when their trusted repository locator next arrives; if none existed,
   one bounded first-repository carry-forward is available. This automatic step only narrows existing
   authority and does not ask again. New repositories beyond those entitlements remain Private.

2. **Bounded bare-invocation change (amends ADR-007 decision 3).** The root Typer app drops
   `no_args_is_help=True`; the root callback reproduces the historical help output for every bare
   invocation except one case: stdin and stdout are both real TTYs **and** the completion marker
   (`state_dir()/setup-wizard.json`, schema `yoetz.setup-wizard-marker/1`) is absent. Only then
   does bare `finishup` launch the interactive wizard. Non-TTY, CI, piped, `--help`, and every named
   subcommand invocation are byte-for-byte unchanged. The marker is permanent once a mutating
   wizard run completes — a decline counts as completion; re-runs happen only via explicit
   `finishup setup run`. An unsafe or unreadable state directory never triggers the wizard.

3. **MCP registration becomes a first-class preview-gated operation** (`finishup integrate <harness>
   mcp status|preview|preview-remove|install|remove`), automating the exact two-command sequence the
   Codex runbook already mandates: `codex mcp get finishup --json` first. A nonzero named lookup is
   not absence by itself: the adapter runs a bounded `codex mcp list --json` fallback and accepts
   absence only when that successful structural listing contains no `finishup` name. A failed or
   malformed listing fails closed; a single matching entry is classified normally; duplicate
   matching names are ambiguous and fail closed. In ambient mode it runs the exact `codex mcp add
   finishup -- finishup mcp serve --host codex` command; under ADR-026 isolation it runs `codex mcp add finishup --env
   FINISHUP_ISOLATED_ROOT=<validated-root> -- finishup mcp serve --host codex`. It does so only after that positive
   absence observation; a foreign same-name entry is
   preserved and refused with `foreign_entry_present` — there is no force path. The structural
   JSON parser rejects duplicate keys, nonstandard constants, and truncated output. Codex exposes
   no compare-and-add token, so operators must quiesce non-cooperating MCP configuration writers
   during the accepted apply; no atomic exclusion is claimed inside the final subprocess window.
   Success is
   verified by re-reading state, not by trusting the add exit code. Registration remains a fact
   separate from skill installation and from Codex capability support (E-002/E-013 are untouched);
   "registered" never implies "Codex will successfully connect".

   **Amended 2026-09-04 — isolated external registration (issue #561).** The environment shape is
   closed: ambient has none; isolated has only the exact `FINISHUP_ISOLATED_ROOT` pair. Preview binds
   and displays that root, apply passes it through Codex's native `--env`, and observation verifies
   the stored value. Missing/different known roots request re-registration; arbitrary keys,
   inherited-variable names, and malformed environment shapes remain foreign with no force path.
   Ambient preview digests keep schema token `/1`; isolated registration and unregistration use
   additive `/2` tokens so the new root field cannot alter the older digest contract silently.

   **Founder-authorized Codex activation repair (2026-08-03).** An accepted setup now also installs
   the packaged project skill at `.agents/skills/finishup` before it installs the structural plugin
   sources and registers MCP. A directory at `.agents/plugins/finishup` is not reported as Codex
   plugin activation: current Codex requires marketplace registration plus an explicit plugin add,
   and setup does not silently mutate that global trust/configuration surface. The plugin directory
   remains a managed source bundle for guidance and hook definitions; the project skill is the
   discoverable project-local activation cue. On an unprofiled Codex release, setup may install the
   byte-exact reviewed skill after the enclosing digest-bound project approval, but reports
   compatibility as `unsupported` and automatic activation as untested. The standalone
   `integrate skill install` command retains its exact capability gate.

   **Amended 2026-08-12 — consent-based Codex plugin activation (issues #204 and #205).** Setup
   may now offer the additional Codex activation needed for installed hook sources to run, but the
   live-smoke correction is load-bearing: repository marketplace bytes plus a plugin-enable TOML
   block do **not** prove activation. Codex also requires the plugin in the canonical inventory and
   loads hooks from its versioned plugin cache.

   Activation is bound to the exact executable selected during discovery and an existing absolute,
   non-symlink Codex home explicitly supplied by the owner end to end. It never derives that home
   from a basename, wrapper behavior, ambient environment, or pre-consent diagnostic. Before
   consent, preview runs only that executable's `--version`, forcing both `CODEX_HOME` and
   `CODEX_TESTING_HOME` to a fresh owner-private temporary home. Codex may create scratch even for
   its version command, so setup removes that temporary home afterward. It performs no canonical
   inventory read against the selected home before approval, preserving first-run zero-egress and
   no-selected-home-mutation truth.

   The preview digest binds the selected executable path and SHA-256, parsed version, explicit home,
   exact repository marketplace before/after bytes, exact config presence/preimage and append-only
   after bytes, managed source-tree digest, versioned cache target and preimage, intended cache
   digest, temporary-private-home probe environment, forced selected-home activation environment,
   and the exact post-consent `plugin list --marketplace finishup --json` and
   `plugin add finishup@finishup --json` commands. Setup displays the bounded targets, environments,
   commands, digests, resulting blocks, possible scratch/cache/config/marketplace effects, and
   standing-trust warning before asking for explicit approval.

   After consent, apply forces both home variables to the approved home, takes an owner-only
   activation lock, re-probes the exact executable and bound preimages, refuses stale or foreign
   state, preserves unrelated marketplace entries and config text, CAS-fences each write, and runs
   the scoped inventory/add commands through that selected executable. A failure after a write or
   add preserves already-approved marketplace/config/cache partial state and reports failure for an
   honest retry. It performs no pathname rollback: a verify-then-delete or overwrite could race a
   concurrent replacement. Post-apply inspection calls the canonical inventory and reports
   `active` only when the managed source is installed, repository marketplace and selected-home
   configuration are exact, inventory says `finishup@finishup` is installed and enabled from this
   repository, and the inventory's versioned cache is byte-identical to the managed plugin tree.
   Otherwise the closed state is
   `installed_not_activated`, `not_installed`, or `foreign`; installed bytes, configuration, cache,
   and inventory remain separately reported facts. `not_installed` is source absence only; a
   modified or untrusted byte-present tree is `installed_not_activated` and never `active`
   (issue #347). Declining changes none of them. This ceremony
   authorizes a standing Codex trust change for future sessions in that exact Codex home; it does
   not prove that a later session loaded a hook or delivered an observation.

   **Amended 2026-08-15 — version-gated async observation hooks (issue #271).** Codex releases
   before `0.148.0-alpha.6` recognize `"async": true` but discard non-`SessionEnd` command
   handlers that declare it; they do not downgrade those handlers to synchronous execution. The
   managed plugin renderer therefore emits async pure-ingress handlers only when the exact probed
   Codex version parses as SemVer/PEP 440 and is at least `0.148.0-alpha.6`. Missing, malformed,
   oversized, and older versions fail closed to the bounded synchronous form so observation is
   slower rather than absent. Advice-bearing handlers and `SessionEnd` remain synchronous on every
   version.

   The selected version also binds the rendered source marker, activation preview's managed-source
   and intended-cache digests, and every apply-time source re-render. Setup may preview a transition
   from either byte-exact managed hook variant, but apply requires the intended variant before its
   first mutation; arbitrary or modified trees remain refused. Crossing the capability boundary
   consequently requires the ordinary digest-bound plugin refresh and activation approval. The
   committed/unprobed plugin tree is the conservative synchronous variant.

   **Amended 2026-08-21 — canonical source, host-rendered cache, and managed refresh (issues
   #387 and #388).** Live testing on an async-capable host showed the previous amendment's
   version-threaded *source* render deadlocks activation: the committed project tree deliberately
   carries the canonical async-free render (pinned by packaging tests), so comparing it against
   the host-specific render fails `modified_copy` forever and `inspect_activation` reads
   `not_installed` with everything else in place. The corrected split is: the project-tree plugin
   source is always the canonical (`codex_version=None`) render — the wizard's project-source
   preview/inspect/install never thread the probed version, and the committed tree stays
   byte-stable — while host-specific rendering belongs only to the activation cache layer. The
   probe version selects the intended cache bytes; `plugin add` copies the canonical source, and
   apply then atomically replaces that marker-identified copy with the exact previewed
   host-rendered bytes and verifies the bound install digest. A source tree that reads as
   `installed` is a byte-exact canonical or host-variant render; a tree that instead byte-matches
   its own valid `yoetz.codex-plugin-install/1` marker (a prior managed render, including the
   async-variant or an older-guidance form) is replaceable by install without `replace_modified`,
   while genuinely modified trees keep the `modified_copy` refusal.

   The same marker rule repairs same-version cache refresh: package version `0.1.0` is stable
   while plugin content drifts, so a previously activated home's versioned cache can differ from
   the fresh render without being foreign. A cache tree carrying a valid install marker that
   byte-matches its own inventory is classified replaceable — preview binds its digest as the
   cache preimage, apply atomically swaps the whole directory, and a cache changed between preview
   and apply still refuses as `preview_stale`. `destination_conflict` remains reserved for
   foreign, marker-inconsistent, or modified cache trees. `active` now requires the versioned
   cache to match the host-specific render rather than the managed source bytes.

   **Amended 2026-08-21 — explicit route input and honest activation reporting (issues #389 and
   #390).** `setup run` and `integrate <harness> mcp preview|install` accept an explicit
   `--route-profile strict|policy`. Without that input, an existing finishup-owned registration keeps
   its observed route — the structural configuration derivation (including its fail-closed
   exception fallback) applies only to a fresh registration, and non-interactive `--accept` alone
   never changes an existing route (guided `setup run|status|disconnect --host codex` too since
   2026-10-15; see "Several projects in one host configuration", item 5). The interactive wizard still derives the route from the
   review-mode answer, and any transition of an existing owned route is shown in the confirmed
   preview and reported as `route_profile_before` → `route_profile`. Separately, when an explicit
   Codex home was supplied, the registration and readiness `plugin_activation` blocks echo the
   bound home/config path and the actual activation failure reason instead of resetting to
   `codex_home_required`, and unobserved readiness facts are reported as null rather than asserted
   `false`.

   **Amended 2026-08-25 — consent-gated Codex marketplace and MCP removal (issue #419).** Setup
   writes remain reversible through the same digest-bound `--accept` lane as activation and MCP
   install, not through `plugin_artifact_apply`. `finishup integrate codex plugin
   preview|status|remove` classifies ownership with `inspect_activation`, then runs
   `codex plugin remove finishup@finishup --json` and, when the `[marketplaces.finishup]` table
   byte-matches the finishup render, `codex plugin marketplace remove finishup --json`. It deletes
   repository `.agents/plugins/marketplace.json` only when a retained no-follow descriptor still
   byte- and inode-matches through a private quarantine rename, and it deletes
   only digest-matched versioned cache trees. `--purge-cache` is required to delete other
   finishup-managed version directories; it is default-off. Foreign, modified, dual, or otherwise
   conflicting entries refuse with `remove_refused` and name the conflicting surface. The removal
   preview binds the exact trusted project root as well as the selected executable, Codex
   home, configuration/cache preimages, planned host commands, and cache-purge choice. A second
   removal is `already_absent`. Preview and apply read cache trees through the same no-follow,
   descriptor-relative total-entry/depth/path/file-count/per-member/aggregate-byte bounds. Apply
   retains the validated version descriptor across quarantine rename, revalidates the exact
   approved member set and bytes before and during unlink, and never blanket-deletes newly observed
   names. It restores the exact version name when an observable content race invalidates the
   quarantine snapshot before the first unlink but still reports the crossed mutation boundary as
   `write_failed`, and preserves the remainder after deletion starts.
   Malformed output after a mutating host command is outcome-unknown `write_failed`, never a
   pre-mutation source error. A mismatch after any host/config/filesystem mutation is reported as `write_failed`, not the
   pre-mutation retry signal `preview_stale`; successful cache-only deletion carries that mutation
   fence into every final inventory/config/activation/skill verifier. Ordinary POSIX
   files still expose a final non-CAS write/unlink window to a non-cooperating same-UID writer, so
   owners must quiesce concurrent cache/config/marketplace writers during accepted removal and no atomic content
   exclusion is claimed. The skill tree, consent records, and observation store are
   intentionally left in place. `finishup integrate <harness> mcp preview-remove` exposes the exact
   unregistration digest; noninteractive `remove` requires that digest plus `--accept` before it
   unregisters an owned external `finishup` MCP entry with `codex mcp remove finishup`. Apply immediately
   re-reads the entry and refuses a foreign replacement or changed owned route observed before the
   name-based remove. Codex exposes no compare-and-remove token, so the preview warns
   `host_remove_not_compare_and_swap`; the owner must quiesce concurrent MCP config writers and no
   atomic exclusion is claimed inside the final subprocess window. An already-absent entry is
   `noop`. The same positive-absence fallback applies to every pre/post removal read, so a generic
   failed `get` cannot become a false no-op or successful unregistration. Interactive removal
   shows the command, route, all warning tokens, and exact preview digest before confirmation.
   **Amended 2026-09-26 (issue #860):** a returned nonzero removal exit still receives the bounded
   post-state probe. Only positive absence completes unregistration, with the payload-free
   `host_remove_returned_nonzero` warning in the versioned `yoetz.mcp-removal/1` outcome. Present or
   unreadable post-state and mutating-command exceptions retain non-success; the CLI supplies a
   selected-runtime/home/binary status continuation before any fresh preview. The host mutation is
   never silently retried. CLI and setup disconnect preserve this outcome and clear applied-route
   state only after verified absence. The existing non-CAS warning and ownership fences remain.
   After activation removal,
   observe/inspect reports
   `installed_not_activated` when the managed plugin source remains (issues #387 and #347),
   including a modified copy, and
   `not_installed` only when that source is also absent.

   **Amended 2026-08-29 — target-bound activation recommendation recovery (issue #463).** An
   accepted or declined `codex-plugin-activation` recommendation is no longer a package-version-wide
   decision. Its digest-only identity binds the resolved executable, executable bytes and version,
   canonical Codex home, activation preview, and intended host-rendered cache. Before suppressing
   advice, `recommend list` re-inspects that exact target. A currently active target stays quiet;
   any actionable target observed as `installed_not_activated` receives fresh advice even if an
   accepted history row has the same digest, unless an unchanged exact-target decline applies.
   Decline is equally target-bound and grants nothing. Non-previewable foreign, modified, or
   ambiguous state clears stale advice for the automatic path and requires manual review. Apply
   still re-previews, prints the exact digest and bounded preimages, requires the post-preview
   confirmation, durably records that authority before host mutation, and refuses stale state.

The short `finishup --set --fireworks --model MODEL` and `finishup --set --grok --model MODEL` paths are
provider-only entries into the same setup ceremonies. They derive internal provider bindings and
always collect the API key through hidden TTY
input. Credential-valued command arguments are not accepted, so noninteractive setup cannot bypass
the local confidential ceremony. Repeating the same command updates the exact stored profile
credential through generation-CAS.

**Amended 2026-07-28 — deterministic model suggestions.** Every reviewed provider preset carries a
repository-owned, default-first model suggestion tuple capped at ten entries. Interactive
`finishup provider endpoint` selectors, the endpoint menu, and the provider-only `finishup --set` paths
use the same numbered picker and always show a custom model-ID entry. An explicit `--model` bypasses
the picker unchanged. Owner-declared endpoints remain manual because the repository cannot know
their model namespace. The picker performs no provider request: CLI/setup code owns no outbound
provider channel or credential, and ADR-006/009 require actual dispatch to remain behind the
service privacy gateway. Catalog entries are reviewed convenience metadata, not proof of account
availability, structured-output interoperability, provider data use, or E-007 capability.

4. **A sibling port, not an `IntegrationsPort` extension (amends ADR-010 by addition only).**
   `HarnessMcpPort` (`ports/harness_mcp.py`) owns registration with its own closed types
   (`HarnessBinary`, `McpRegistrationState/Action/Reason`, digest-bound preview/command/result).
   Skill install types carry trusted-project file semantics (`project_root`, `file_changes`,
   managed markers) that registration must not reuse. ADR-010's guarantee is preserved: adding a
   harness is still one `HarnessId` value plus adapters, with no port or registry change.

5. **Discovery is pure observation.** `discover_codex_binaries` scans `$PATH` plus reviewed app
   locations: the standard macOS Codex Desktop resource directory and the resource directory from
   the Windows Store package family `OpenAI.Codex_2p2nqsd0c76g0`, resolved by a bounded read-only
   package query. Linux has no official Codex App distribution today, so no app path is fabricated.
   Exact allowlisted names are `codex` and `codex-testing` on POSIX, with `.exe`/`.cmd` forms on
   Windows. Results are deduped by resolved target while keeping the visible candidate path, then
   version-probed
   `codex --version` with a bounded timeout, and always reports `untested` compatibility (E-002:
   a version string is not support evidence). Interactive setup first presents the automatically
   detected supported harnesses — exactly **Codex** in v0.1 — as a numbered choice, then presents a
   separate numbered installation choice when several Codex executables exist. Human-facing copy
   uses the brand names **FinishUP** and **Codex**; the executable, command, and MCP server identifiers
   remain the protocol-owned lowercase `finishup`/`codex` tokens. Non-interactive runs fail closed on
   multiple installations and require `--codex-path`. Every registration preview requires an
   explicit `Y` or `N` answer with no implicit default; `--accept` remains the explicit automation
   path. Discovery never widens to `codex-*`: in particular, `codex-testing-update` is not executed
   or presented as an installation. macOS and Windows therefore combine app and CLI installations;
   Linux uses the identical selection flow for the official CLI surfaces that actually exist.

6. **The npm launcher is a protected public distribution surface (amends ADR-007 decision 7).**
   `support/npm-launcher/` contains a dependency-free `package.json` (registry name
   `finishup`, version locked to the PyPI version) and `bin/finishup.js`, which requires `uv` on PATH
   (printing install guidance and exiting nonzero otherwise), makes the exact version a
   persistent tool with `uv tool install --quiet --python 3.14 finishup==<version>` (a no-op once
   present), and delegates to a versionless `uvx --python 3.14 finishup`, which runs that installed
   tool environment rather than a cache-backed one, with untouched arguments and the child's
   exact exit code. It bundles no Python, downloads nothing itself, and duplicates no
   wizard logic — first-run behavior lives once, in the Python CLI. The persistent install was
   added for issue #766: host hooks and MCP entries bind the absolute launcher that configured
   them, and a bare `uvx` bound them to uv's prunable cache, so `uv cache clean` silently broke
   every connected host. The separate deliberate release decision was made for v0.1.0 on
   2026-08-20 (issue #366): the tagged workflow publishes the exact prebuilt npm tarball only after
   matching PyPI publication, using npm trusted publishing and post-publication byte verification.

7. **The confidential boundaries remain exact.** The wizard never accepts a secret by flag,
   ordinary stdin, environment, config, report, or MCP. A local interactive run may enter the
   existing confidential helper, which reads vault and provider secrets with hidden `/dev/tty`
   input and sends them only over YZS1. Noninteractive setup never provisions a credential.
   Human setup and provider-status output renders only a constant `********` presence mask after the
   trusted service confirms the configured profile has a credential; confirmed absence and
   unreadable state remain distinct. The mask never reflects secret bytes or secret length. A
   repeated setup run recomposes the service after binding and observes that exact profile. When
   presence is confirmed, it asks whether to reuse the stored credential (default) or replace it
   through the same hidden-input ceremony. If an initial credential write commits but its result
   frame is lost, setup may recover only from the configured profile's trusted presence bit. A
   replacement started with presence already true cannot use that bit as proof that the new value
   committed; an ambiguous replacement remains failed instead of inheriting the old value's
   presence as success.

8. **Founder-authorized on-demand service start (2026-07-22 amendment).** A mutating interactive
   setup run and the MCP bridge may invoke the shared fixed-command service launcher when the
   authenticated endpoint is absent. The launcher executes only the current installed
   `python -m finishup service run`, supplies no caller path/config/provider/secret argument, strips
   secret-shaped inherited environment names, detaches using the reviewed platform process flags,
   and reconnects to the singleton winner. The service stops after 7,200 seconds of true
   quiescence; a later MCP tool call may start a generation-fenced successor. A locked successor
   remains locked and still requires local-human unlock.

9. **Maintainer-authorized start-first initialization continuation (2026-08-31 amendment, issue
   #512).** The installed agent workflow requires `start` before substantive work and treats
   non-retryable errors as terminal, so a pristine install answering that first `start` with a
   bare non-retryable `VAULT_LOCKED` contradicted the workflow it shipped with (the 2026-08-31
   issue #334 dogfood stopped exactly there). When a workflow call fails with non-retryable
   `vault_locked` and one bounded fresh-handshake probe proves
   `state=locked,vault_mode=uninitialized`, the MCP bridge attaches the typed
   `vault_initialization_required` continuation to the public error: closed-literal
   `prepare_command`/`review_command`/`authorize_command` tokens, the pending TTL, and the
   original request id as `replay_request_id`. The continuation routes into the unchanged
   ADR-015 consent ceremony — exact user decision, helper-generated secret, no agent-visible
   secret bytes, agent-chat attestation only per ADR-015 decision 5/ADR-016 decision 5 — and
   ends with one exact replay of the original `start` request identity, which is idempotent by
   construction because the failed call reserved nothing. Hard locks, recovery states, probe
   failures, and every initialized-vault outcome keep their existing answers; the Cursor host
   profile omits `authorize_command`. `finishup setup run` remains the human-first path this ADR
   defined; the continuation is the agent-flow bridge to the same ceremonies, never a new
   authority.

## Consequences

### Shared desktop onboarding (2026-09-20, issue #767, 0.2.4)

The maintainer retargeted #767 from 0.3 to `main` for 0.2.4. First run may discover
Codex, Claude Code, regular Cursor IDE, and Cursor Agent CLI through executable/version probes.
A directory alone is not an installation. This supersedes the original Codex-only and explicit
Cursor-selection restrictions. Desktop scope remains macOS, Linux, and Windows through WSL 2;
native Windows and mobile are not added. Discovery never certifies an untested combination.

Human and agent setup share installation/project selection, review posture, one complete preview
and integration approval, remaining-stage application, status, and disconnect. Ordinary screens
explain consequential choices; exact paths, digests and adapter details remain inspectable.
The new explicit entrypoint is `setup run --host codex|claude|cursor-ide|cursor-cli`. An agent
previews first, presents the changes, and repeats the exact paths, route, request ID and preview
digest with `--accept`. Generic acceptance cannot approve an unseen connection plan. The old
path-explicit Codex wizard remains a compatibility entrypoint.

The connection digest binds the request, host/version/executable, configuration root, project,
route, launcher/isolation identity, adapter previews and changes. Apply re-previews the whole
composition before consuming authority. Claude's new `connect` action installs or updates its
owned source/marketplace and plugin, then enables it under one action-bound review. Standalone
`install` continues to leave the plugin disabled. Read-back determines the remaining stages after
interruption; already enabled exact state is a no-op.

Cursor composes a native plugin with an external project MCP entry. CLI uses
`registered-project`; IDE uses `mcp-roots`. One `plugin_artifact_apply` review covers the complete
composition and retains OS-authenticated presence. Only after consuming it does the coordinator
mint an in-process, single-use `setup_composition` capability for the exact child plugin digest.
This is not reuse or a second consumption of the original consent. The MCP step retains its exact
preimage/replacement checks. The external-registration plugin does not alter those MCP bytes.
When it creates a missing private configuration directory, only that planned directory identity
may change: the project inode, configuration identities/preimages and replacement must still
match. Foreign/modified configuration and unrelated pending approvals are preserved and refused.

Codex reuses its existing setup authority and skill/activation/MCP checks. Disconnect removes its
activation, owned MCP entry and exact owned project skill, retaining inactive plugin sources and
FinishUP data. Cursor disconnect removes the user plugin and the selected project's owned MCP entry;
other projects are not swept. Its user-wide plugin scope is shown as a consequential choice.
Claude disconnect uses its project-scoped uninstall/marketplace removal lifecycle.

Partial or ambiguous outcomes remain incomplete. A new preview reports remaining stages without
reusing a stale approval. No-op stages require no new review. Linux/WSL TUI approval hands control
to the trusted terminal for OS authentication. Integration approval grants no observation,
provider-credential or disclosure authority. Installed, enabled/configured, reload-required and
connection-observed are separate facts; only a fresh native session can prove discovery and start.

### Several projects in one host configuration (2026-10-14, issue #1058)

Owner direction (2026-10-14, recorded on #1058; design gates: storage, release): one Codex home,
Claude Code config root or Cursor config root must support several FinishUP-connected projects,
connected one after another. Only a genuinely conflicting duplicate is refused.

1. **Shared versus per project.** Each host keeps some FinishUP pieces once per configuration root
   and serves every project from them; setup for a second project adds only that project's
   pieces and leaves the shared ones as they are.
   - *Codex:* shared: the user-level `mcp_servers.finishup` registration, the one
     `[marketplaces.finishup]` binding, `[plugins."finishup@finishup"]`, and the plugin cache (with its
     hooks and plugin skills). Per project: `.agents/plugins` (manifest and plugin source), the
     project skill, observation consent, check policy trust, and `.codex/config.toml` admission.
     The binding names one connected project (its *anchor*); a binding to another project that
     still serves the exact FinishUP manifest is the shared marketplace, not a conflict.
   - *Claude Code:* shared: the marketplace source under the config root and its
     `known_marketplaces.json` entry. Per project: the project-scope install, its enable flag and
     its `extraKnownMarketplaces` declaration.
   - *Cursor:* shared: the user plugin (hooks, skill). Per project: the project MCP entry.
2. **Who is connected: verified members and possible users.** Codex and Cursor do not list
   which projects use the shared pieces, so FinishUP keeps
   `<config root>/.yoetz-connected-projects.json` (canonical JSON `{"projects": [...]}`, plus
   `"unknown_members": true` when membership is uncertain). The file name is a frozen legacy
   identifier: it does not follow the MCP server key, so a later rename of that key keeps the
   records earlier builds wrote. The record is read only when it is a regular file owned by the
   invoking account with no group or other permission bits. It is written by a compare-then-rename:
   re-read and compared with the bytes the approved plan read (its digest is bound into the plan),
   then published through a 0600 temporary file in the same directory, fsync, rename and a
   parent-directory fsync. A crash leaves the old record or the new one, never a partial one. A
   record that fails these checks stops setup before any change
   (`connection_projects_record_invalid` on every `setup run|status|disconnect`; the Codex
   adapters say `source_invalid` with `conflict: connected_projects`). The continuation names
   the file and says to make it owner-only again (`chmod 600`) or restore it; if it must be
   removed, Cursor then treats membership as unknown, and for Codex every project should be
   connected again before any is disconnected. Claude Code itself lists one project-scope row per
   project, so that host needs no record.
   Each installation also keeps a *membership witness* beside its setup lock
   (`<state dir>/host-config-locks/<key>.members`, same format and checks, 0600): every project it
   recorded for the root minus those it saw disconnect, deleted when the shared pieces go. It is
   maintained best effort after each record write and only ever names projects the record named.
   - *Verified members* are the projects the record names and, for Codex, the project the home's
     `[marketplaces.finishup]` binding names (a home bound before this amendment has no record, and
     earlier releases served one project per home). Only a verified member is recorded by a later
     connect, becomes the Codex binding's anchor, or makes a disconnect `detach`. Status and
     previews name only members whose checkout still exists and serves the manifest.
   - *Possible users* (Codex) are live checkouts that serve the exact FinishUP manifest and a plugin
     source matching its own install marker, never a verified member under any spelling of its
     path, from two sources: the witness's projects, always, so a record deleted by hand or lost
     does not make this installation forget who connected (2026-10-15 review); and, while the
     record is missing with shared pieces present or marked `unknown_members`, the home's
     `[projects."<path>"]` rows with `trust_level = "trusted"`. A trust row is not evidence of a
     connection (every FinishUP checkout carries those files), and neither source is current
     verification, so a possible user is never recorded and never becomes the anchor. It only
     keeps the shared pieces, and `unknown_members` stays set while one exists. Reconnecting the
     project records it as a verified member. Residual: a record lost while this installation has
     no witness for the root (it was written by another installation, or this state directory was
     reset) falls back to the binding and trusted checkouts only. Cursor has no equivalent list:
     shared pieces found without a record make membership unknown, and that state survives later
     connects. Status (Codex `codex_home_possible_projects` and `membership_unknown`; Cursor
     `membership_unknown`) and every preview (`membership_unknown`, plus Codex `possible_users`,
     also in `integrate codex plugin preview`) disclose it.
3. **Reverse path.** Disconnecting a project while another verified live member remains removes
   only the project's pieces (Codex: `detach`, which moves the binding to a remaining verified
   member before this project's manifest goes; Claude Code: `plugin uninstall --scope project`
   plus removing the project's exact own `extraKnownMarketplaces` declaration, without the
   unscoped `marketplace remove`; Cursor: the project MCP entry without the user plugin). The last
   project's disconnect removes the shared pieces and the record. A deleted project, or one whose
   path is now a symlink, does not keep the shared pieces; neither does a Codex member whose
   checkout no longer serves its manifest and marker-valid plugin source (it already reads
   `installed_not_activated`; reconnecting it restores both). Preview and apply count other
   projects the same way: Claude Code keeps a deleted project's row, which therefore holds
   nothing open, and the last live project's unscoped `marketplace remove` also clears it; a
   project whose own install is already gone skips the project-scope uninstall (Claude Code
   fails it) and removes only the shared marketplace and source that remain. A Codex binding
   whose project is deleted or lost its manifest (Codex then fails every plugin command in the
   home) moves to a remaining verified member on `detach`, or, with none left, goes with the
   shared pieces: its exact tables and managed cache trees are removed directly, since no
   `codex plugin` command works through it; the same holds under `--remove-shared`. Only a
   connected project (one the record names, under any spelling) may move or remove such a
   binding: the anchor's manifest may be absent only for now (a branch switch, `git clean`, an
   unmounted volume), so a project that never connected removes only its own pieces and leaves
   the binding and every shared piece alone. A removal of the shared pieces names connected
   projects whose directory exists but that do not serve the manifest right now
   (`unserved_members`, CLI `members_not_serving`), and every plan names `rebind_to`. The Codex
   user-level MCP registration stays whenever another project still uses the shared pieces (a
   serving verified member or a possible user), whatever this project's own state: re-running
   the disconnect of an already detached project, or disconnecting one that never connected,
   leaves it (disclosed as retained, with `shared_with`), and a detached project does not report
   `configured` (2026-10-15 review round 2). That also holds while another recorded project's
   directory exists but its plugin files are absent right now (a branch switch, `git clean`, an
   unmounted volume): a project the record does not name removes only its own pieces, the
   removal plan says it keeps the shared ones (`keeps_shared`, also when its outcome is
   `already_absent`), and the disclosure names the projects they stay for (`shared_with`); with
   the binding removed by hand, a member detaches while another recorded member serves, keeping
   the plugin table, cache and record. The guided `setup run|status|disconnect` stop before any
   change when the record cannot be read (`connection_projects_record_invalid`) or the selected
   configuration root is a symlink (`target_unsafe`); a damaged membership witness is only a
   safety net and names no one (see the residual above). Should reading membership still fail
   during a disconnect plan, the registration stays (`membership_unknown`) (review round 3). When
   the pieces stay for the dangling binding's project and its directory is missing right now
   (an unmounted volume, a moved checkout), the plan names it (`shared_with` and
   `members_missing`, rendered "directory missing right now") instead of "other connected
   projects"; when no live project keeps them, an `unchanged` disconnect also names the exact
   `setup disconnect --remove-shared` preview as the way out, since that project cannot
   disconnect itself while its directory is gone (triage, 2026-10-15). `setup status --host codex`
   uses the same split: only a connected project (activation `active`) reports `enabled` and
   `configured`; for a detached or never-connected one the shared registration is
   `shared_registration_retained`. Uncertainty keeps the pieces: unknown Cursor membership, and a Codex scan of other projects
   that stopped at its bound of 32, keep them on an ordinary disconnect. A Codex disconnect that
   would leave possible users but no verified member to carry the binding refuses before any
   change (`remove_refused` with `conflict: membership_unverified`; CLI reason
   `membership_unverified`) rather than guess: its continuation names the possible users and
   offers reconnecting the one that uses FinishUP, or previewing `--remove-shared`. Among the setup
   commands, only the explicit `setup disconnect --remove-shared` removes the shared pieces for
   every project. Its preview and the interactive consent say it is home-wide and name the
   connected projects that stop using FinishUP (`shared_removed_from`) and any `possible_users`; it
   still refuses while another project's Codex configuration needs the registration or the scan
   is incomplete. The low-level commands stay home-wide by design but say so (decision
   2026-10-15): `integrate codex mcp preview-remove|remove` names the projects that lose the
   user-level registration (`shared_with`, `possible_users`, warning
   `mcp_registration_shared_with_other_projects`) and its preview digest binds them;
   `integrate cursor plugin preview --action remove` names who uses the user plugin
   (`shared_with`, `membership_unknown`, `shared_removed_for_every_project`), not bound into the
   artifact digest; `integrate codex plugin remove` uses the same removal plan as `setup
   disconnect` (detach, refusals); `integrate claude plugin remove` removes the project-scope
   install and, like `setup disconnect`, keeps the shared marketplace while another live project
   has its row.
4. **Genuine duplicates.** One directory reached through a second path (a symlink, a letter-case
   variant, a moved directory) is refused on connect as `project_connected_via_other_path`, with
   the path already connected and the way out: disconnecting the project under its current path
   also clears the entry under the other path. A Codex binding to a project that no longer
   serves its manifest is moved to the connecting project; a binding to anything else stays
   `destination_conflict`.
5. **Not a duplicate; the review mode is shared.** The MCP route profile, launcher and isolation
   root are properties of the shared Codex registration and the shared Claude Code source (Cursor
   keeps the route in each project's own MCP entry): connecting a project with another route
   re-registers or re-renders them for every project in that configuration. That changes the
   other projects' review mode, local only (`strict`) or AI-powered review under the configured
   privacy policy (`policy`), so every path that can rewrite them names it:
   `route_profile_before`, `route_changes_for` (the other serving members) and
   `route_changes_possible_for` (possible users), plus a sentence naming those projects and both
   modes. `setup run|disconnect --host` binds them into the plan digest (also in text-mode
   previews); the TUI first-run Codex preview shows them and no longer says "verified, not
   replaced" when it re-registers; the historical Codex wizard (`setup run` with Codex as the
   only host found, or `--codex-path`) prints the sentence in its preview and refuses a bare
   `--accept` that would change other projects (`route_change_affects_other_projects`, with the
   guided `setup run --host codex` continuation); `integrate codex mcp preview|install` reports
   them and its preview digest binds them, and an install that would change other projects
   needs that digest; `integrate claude plugin preview` reports them, and its preview digest
   already binds every project's install row (`installed_plugins.json`). Decision (2026-10-15):
   disclosure, not an extra flag. A `policy` route does not by itself
   send anything; every network channel still needs the user's privacy policy and consent
   (ADR-009), and the hybrid default (#1068) moves new setups to `policy` for every review
   choice, where a flag would fire on every upgrade. A registration from another FinishUP
   installation stays `foreign_entry_present`.
   Review round 3 (2026-10-15): the current mode is read from the registration itself
   (`observe`), never inferred from a planned re-registration, which may change only the
   launcher or isolation root (a legacy bare `yoetz mcp serve ... --semantic off` entry stays
   local only). Membership that cannot be read is unknown, not "no other projects": on the
   historical wizard and `integrate codex mcp` paths (an unreadable record, or a `--codex-home`
   reached through a symlink) a mode change reports `membership_unknown: true`, which the
   preview digest binds, so a bare `--accept` is refused (`route_change_affects_other_projects`),
   and `integrate codex mcp preview-remove|remove` report it with the shared warning and bind
   it. The guided `setup run --host codex` and the TUI stop before any change instead
   (`connection_projects_record_invalid`, adapter `source_invalid`, or `target_unsafe` for a
   symlinked configuration root). A damaged membership witness names no one and does not make
   membership unknown. The refusal names the exact preview command, with the same
   `--route-profile`.
   *Missing route input.* Without `--route-profile`, non-interactive `setup run|status|disconnect
   --host codex` (and `setup status --next` outside `--operation review`) keep the home's
   registered mode, read from its FinishUP-owned registration, as the historical wizard and
   `integrate codex mcp` already did (#389); only a fresh home (no FinishUP registration) registers
   `strict`, so fresh-home behaviour is unchanged. Claude Code and Cursor still use `strict`
   without the flag. An interactive answer is explicit route input: today it registers `strict`
   or `policy` from the review-mode choice, and under the hybrid default (#1068, release branch)
   every interactive answer registers `policy`. Either way a change to a home that other projects
   use goes through the disclosure above, and a non-interactive fresh registration stays
   `strict`.
6. **One setup at a time per configuration root.** Every setup apply for any host through
   `apply_connection` (`setup run|disconnect`, `/connect` for Claude Code and Cursor) holds an
   exclusive `flock` from plan revalidation through the shared changes and the record update, so
   a concurrent setup finds the earlier one's changes and is stale rather than losing a member.
   The lock is a file of its own, `<state dir>/host-config-locks/<sha256>.lock`
   (`host_projects.lock_path_for`), not a lock on any host directory, and unrelated roots under
   one parent never share a lock. It also means the lock needs no part of the configuration root:
   Cursor and Claude Code then create a root whose parents do not exist yet without a manual
   `mkdir`. Codex does not: its setup still requires an existing Codex home and refuses an absent
   one as `target_untrusted`, now with a continuation naming the `mkdir -p -m 700`; closing that
   parity gap is an open follow-up. The key is the target's
   resolved absolute path in Unicode NFC, case-folded, so every spelling of one root on a
   case-insensitive or normalising filesystem (macOS) reaches one lock; two distinct roots that
   differ only in case merely serialise. The file is created 0600 inside an owner-only 0700
   directory with no symlinked path component (a symlinked state directory is refused, as
   everywhere else), opened without following a symlink, and used only when it is a regular file
   the invoking account owns. Two first setups racing to create the directory both proceed. Lock
   files are never removed: unlinking one while another setup waits on it would split the lock.
   A lock that cannot be created, opened or taken is `connection_lock_unavailable` before any
   change, with a continuation naming the lock folder; there is no unlocked fallback.
   Limits: the lock serialises setups run by one FinishUP installation (one state directory). A setup
   from another installation or isolation root against the same configuration root is not
   serialised by it; the record's compare-then-rename refuses a record changed before the compare
   but cannot exclude a change in the window between the compare and the rename. Codex
   activation and removal also hold the home's own `.yoetz-marketplace-activation.lock` (inside
   the home, so it does span installations); the TUI first-run Codex connect, the historical
   `--codex-path` wizard, `recommend accept codex-plugin-activation` and `integrate codex plugin
   remove` hold only that in-home lock, not the per-configuration lock. The low-level
   `ConnectionPlan.apply_reviewed_steps()` does not take the lock; callers apply through
   `apply_connection`.
7. **Untested lock boundary.** The lock file is exercised by unit tests on macOS (APFS) and
   Linux (ext4), and natively on Linux (ext4) by the Codex 0.144.6 and Claude Code 2.1.300 runs
   recorded in the host runbooks. It is untested where FinishUP's state directory sits on NFS,
   SMB/CIFS, a WSL DrvFS (`/mnt/c`) mount, or another network or FUSE filesystem. There `flock`
   may be refused (setup then stops as `connection_lock_unavailable`, which is safe) or may hold
   only on the local machine, so two machines running setup against one configuration root at
   the same moment would not exclude each other; the record's compare-then-rename is then the
   only guard. The default state directories (`~/Library/Application Support/finishup` on macOS,
   `~/.local/state/finishup` on Linux and inside WSL 2's Linux filesystem, or the earlier `yoetz`
   folders an upgraded installation keeps using in place, ADR-048) are local; this matters
   only for a relocated state directory or isolation root.
8. **Terminal interface.** The TUI `/connect` and `/disconnect` use the same plans, but
   `--remove-shared` is CLI-only (`setup disconnect --remove-shared`), and the TUI shows its
   generic continuation for the refusals above (`membership_unverified`,
   `connection_projects_record_invalid`, `connection_lock_unavailable`); the exact continuation
   is the CLI's `setup disconnect`/`setup status` for that project. Both are open follow-ups.

### Cursor local selection amendment (2026-08-22, issue #153)

Cursor does not enter ambient first-run discovery. It is selected explicitly with an exact local
configuration root and, when MCP project state participates, an exact trusted project. Preview
shows portable versus native format, full artifact identity, user scope, current managed/modified/
foreign state, MCP ownership/source/route, and every warning before any mutation. Apply re-reads
that state and requires the same request ID and preview digest. Install, replace, and remove are
whole-directory atomic operations; modified, unmanaged, dual, foreign, ambiguous, symlinked, or
recovery-required state is preserved and refused.

The wizard never searches regular Cursor state to configure an isolated target and never mutates
Cursor caches. For planned `0.2`, issue #412 defers operational SDK configuration: retained
TypeScript/Python package, `sdk.v1`, sandbox/approval, precedence, and `settingSources` facts are
metadata-only experimental fixtures and the wizard does not present them as a configurable or
supported cell. A future design-gated amendment may restore a separate explicit SDK row only with
operational proof. Observation consent remains a later independent decision and is not implied by
plugin installation.

A new user's path is now: `npx finishup` or `uvx finishup` → interactive wizard → detected-harness
selection (Codex in v0.1) → installation selection when needed → explicit `Y`/`N` confirmation →
local-only or AI-powered review choice → discoverable project skill → structural plugin/hook sources
→ route-matched Codex MCP registration → on-demand local service → trusted repository binding →
local vault/provider ceremonies when AI-powered review was chosen → recommendation-first privacy
review → separately reauthenticated privacy decision. Each mutating step is previewed, digest-bound,
and individually declinable; `finishup setup status` reports the same posture read-only at any time.
The CLI support-command matrix grows by one (`setup`), recorded in the conformance contract test in
the same change.

**Amendment (ADR-023, 2026-08-21, issue #149): host-derived artifact projection behind the
unchanged wizard.** The setup ordering and user experience above do not change: project skill,
then structural plugin sources, then explicitly approved activation, then MCP verification, each
previewed, digest-bound, and individually declinable. What changes is backend selection only: the
structural plugin-source step becomes a projection of the neutral `PortablePluginPlan`, chosen
from the detected host profile — the portable Agent Plugins artifact in the host's own client
plugin root where the host supports it, a generated native projection in that host's distinct
documented native root where it does not. The user never chooses a root, format, or migration
path. Artifact preview/apply, host activation, MCP registration, and observation consent remain
separately reported facts, and setup status additionally reports the closed `McpOwnershipState`
(`absent|external|plugin|dual|foreign|ambiguous`): dual, foreign, and ambiguous ownership are
explicit reported states that setup never silently resolves or overwrites. For Codex the plugin
root stays `.agents/plugins/finishup`; a format migration there is a whole-directory,
marker-identified, digest-bound replacement under this ADR's existing preview/apply and activation
ceremony, and the bespoke layout remains the shipping control until a portable projection is
capability-proven and explicitly approved. This amendment grants no new authority: the wizard's
narrow approval covers exactly what it covered before, and the standalone portable
install/remove/activation-apply paths, once implemented by #150, take the ADR-016 `review_only`
lane instead (ADR-023 decision 11).

Issue #150 implements portable artifact render/preview/status and the exact
`plugin_artifact_apply` review-only consumer. The shipping wizard still selects the native Codex
control until a later capability cell proves portable discovery and activation. A portable
preview therefore creates no activation claim: status keeps rendered bytes, installed bytes, MCP
ownership, discovery, activation, and skill delivery separate.

Issue #151 adds the optional plugin-managed backend without changing this authority order. Setup
must select `external_registration` or `plugin_managed`, and for the latter select `strict` or
`policy`, before rendering the preview. The preview shows and binds the current ownership state,
exact route argv, schema/renderer version, and complete bytes. `dual`, `foreign`, `ambiguous`, or a
changed owner refuses apply without overwrite. Activation follows artifact apply and never counts
as privacy/provider consent. Rollback removes only exact managed bytes (restoring the retained exact
native tree when present); it preserves foreign host config and all FinishUP durable state. PATH or
executable failure is a capability diagnostic after activation, never permission to inject shell
configuration, environment values, or credentials.

Package replacement changes binaries, not accepted trust bytes. Installed-wheel proof is still
required before issue #139 can close: consecutive real checks must prove distinct attempt authority
and receipts in one approved repository, and a second repository must remain blocked. Router routing
and issue #141's foreground disclosure continuation are outside this wizard change.

The cost is one bounded exception to the previously uniform bare-invocation behavior, and a second
distribution surface to keep in version lockstep — enforced by a packaging test that compares the
npm launcher version to the Python package version.

## Alternatives considered

**Reuse `IntegrationsPort` for registration.** Rejected: the skill types' project-root and
file-inventory fields would be dead or misleading for a global registration, and overloading them
would weaken the ADR-010 fork guarantee.

**Trigger the wizard from the npm bootstrap script.** Rejected: it cannot serve `uvx finishup`
users and would duplicate first-run logic in two languages with drift risk.

**Offer a force-replace for foreign MCP entries.** Rejected for v0.1: the runbook's
preserve-and-review rule stands; a foreign entry is reported with a manual follow-up instead.

**A `FINISHUP_SKIP_SETUP_WIZARD` environment opt-out.** Rejected: the non-TTY guard already covers
automation, and the marker covers humans; an ambient env escape would make first-run silently
skippable by inherited shell configuration.


## Verification defaults amendment (issue #303)

Maintainer decision: new configurations propose `verification.semantic = "required"` and
`verification.max_findings = 10` (the existing upper bound). Required review preserves completed
local-check results; absent, denied, unavailable or invalid providers yield the existing terminal
AI-powered review status and incomplete coverage, never fabricated success. Explicit
`deterministic_only` remains the bounded local option.

Existing configuration files retain their explicit values. Missing verification leaves in an
existing file resolve to the released `optional` / `3` defaults; loading and upgrades do not rewrite
it. A deliberate migration previews and explicitly writes `required` / `10` using the existing
configuration writer. Unrelated rewrites must materialize the effective old values. A missing
configuration file uses the new defaults. Neither case grants disclosure authority.

The existing reviewed-route `assisted_review` recommendation remains the privacy proposal. The
exact repository-scoped categories, selection bounds, provider posture and retention are shown by
the current trusted privacy ceremony; acceptance is still required. Unknown, stale or
account-unqualified provider posture does not acquire a reviewed assurance. Existing durable policy
bytes stay unchanged. Editing verification settings cannot enable egress or silently migrate policy.
